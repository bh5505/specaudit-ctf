"""Shared stdlib MCP HTTP clients for curated arms.

Two transports live here:
- SseMcpSession: legacy HTTP+SSE (spec 2024-11-05). One long-lived SSE
  GET plus session-scoped JSON-RPC POSTs; responses arrive as SSE
  message events matched by JSON-RPC id. Upstream deprecated this
  transport 2025-03-26; it is kept for servers that still speak it
  (Burp today).
- StreamableHttpClient: Streamable HTTP (spec 2025-03-26+). One POST
  per message; response is application/json or a finite SSE body.

Both enforce the shared guards: MAX_MCP_BYTES caps, credential
redaction, redirect refusal, CR/LF endpoint refusal.

Transport-gate properties (the seven named by the HTTP-MCP
held_reason): P1 https-or-literal-loopback endpoints per
HttpTransportPolicy; P2 no token passthrough (only an explicitly
configured ArmCredential is sent, its value scrubbed from every
output); P3/P4 OAuth resource+audience binding with PKCE, conditional
and fail-closed (OAuthRequiredError when a server demands OAuth and
the arm has no OAuth configuration); P5 Origin emission plus
single-origin session pinning; P6 resolve-once DNS pinning with
rebinding refusal; P7 the loopback OAuth callback receiver - the only
listener this module ever creates, and it never speaks MCP.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import http.server
import json
import queue
import re
import secrets
import socket
import threading
import time
from typing import Any, Callable
from urllib import parse as urllib_parse
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

MAX_MCP_BYTES = 512 * 1024
MAX_MCP_ROWS = 200
MCP_CALL_TIMEOUT = 10
PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "specaudit-ctf-extension"
CLIENT_VERSION = "1.0"
USER_AGENT = f"{CLIENT_NAME}/{CLIENT_VERSION}"
_REDACT_RE = re.compile(r"(token|password|passwd|secret|api[_-]?key|authorization|bearer|cookie)", re.IGNORECASE)

# Transport-gate constants (P5/P7).
LOOPBACK_IPS = ("127.0.0.1", "::1")
BIND_ANY_IPS = ("0.0.0.0", "::")
# Non-browser clients have no real web origin; this names the local
# loopback identity so conforming servers have an Origin to validate.
LOCAL_ORIGIN = "http://127.0.0.1"
OAUTH_CALLBACK_PATH = "/callback"
DEFAULT_CALLBACK_TIMEOUT = 120.0


def redact(text: str) -> str:
    return _REDACT_RE.sub("[redacted]", text)


def redact_values(text: str, values: set[str]) -> str:
    """Scrub exact credential values (P2) on top of keyword redaction.

    A server can echo a configured credential back without any
    keyword nearby; the exact-value replacement closes that channel.
    """
    for value in sorted(values, key=len, reverse=True):
        if value:
            text = text.replace(value, "[redacted]")
    return text


class HttpTransportPolicy:
    """Endpoint-shape policy (P1): which URLs a transport may dial.

    - loopback(): literal 127.0.0.1/[::1] endpoints only; http or
      https. For arms whose real upstream is a local server (Burp,
      Metasploit).
    - remote_https(): https to non-loopback hosts only. The default
      and the policy for remote-armed catalogs (GTI, Prowler,
      Semgrep); loopback endpoints are refused outright so a rebinding
      name or a misconfigured local front cannot smuggle traffic.
    - general_http(): http or https to any host. NOT part of the
      HTTP-MCP gate - this shape exists for non-MCP REST arms (ZAP,
      Caldera) whose endpoints are operator-scoped lab resources, so
      their accepted URL set stays what it was before the gate. Only
      the shared shape rules apply (no userinfo, bind-any, zone IDs,
      or control characters).
    """

    __slots__ = ("name", "loopback_only", "allow_loopback_http")

    def __init__(self, name: str, loopback_only: bool, allow_loopback_http: bool) -> None:
        self.name = name
        self.loopback_only = loopback_only
        self.allow_loopback_http = allow_loopback_http

    @classmethod
    def loopback(cls) -> "HttpTransportPolicy":
        return cls("loopback-http", loopback_only=True, allow_loopback_http=True)

    @classmethod
    def remote_https(cls) -> "HttpTransportPolicy":
        return cls("remote-https", loopback_only=False, allow_loopback_http=False)

    @classmethod
    def general_http(cls) -> "HttpTransportPolicy":
        return cls("general-http", loopback_only=False, allow_loopback_http=True)

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return "HttpTransportPolicy(%s)" % self.name


def endpoint_problem(url: str | None, policy: HttpTransportPolicy | None = None) -> str | None:
    """Return why *url* is refused for *policy*, or None if it is valid."""
    if policy is None:
        policy = HttpTransportPolicy.remote_https()
    if url is None:
        return "no endpoint configured"
    # Reject control characters even before stripping; trailing CR/LF
    # would otherwise be hidden by strip() and allow injection payloads.
    if "\r" in url or "\n" in url or "\x00" in url:
        return "endpoint contains control characters"
    text = url.strip()
    if not text:
        return "empty endpoint"
    parsed = urllib_parse.urlparse(text)
    if parsed.scheme not in ("http", "https"):
        return "scheme must be http(s)"
    host = (parsed.hostname or "").lower()
    if not host:
        return "endpoint must name a host"
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return "userinfo in endpoint URL is not allowed"
    try:
        parsed.port  # noqa: B018 - property access validates the port
    except ValueError:
        return "invalid port"
    if "%" in host:
        return "zone-id addresses are not allowed"
    if host in BIND_ANY_IPS:
        return "bind-any addresses are not allowed"
    is_loopback = host in LOOPBACK_IPS
    if policy.name == "general-http":
        pass  # non-MCP REST arms: scheme and loopback are operator-scoped
    elif policy.loopback_only:
        if not is_loopback:
            return "policy %s allows only literal loopback endpoints" % policy.name
        if parsed.scheme == "http" and not policy.allow_loopback_http:
            return "policy %s does not allow http" % policy.name
    else:
        if is_loopback:
            return "policy %s refuses loopback endpoints" % policy.name
        if parsed.scheme != "https":
            return "policy %s requires https (http is only for literal loopback endpoints)" % policy.name
    return None


def configured_http_url(url: str | None, policy: HttpTransportPolicy | None = None) -> str | None:
    """Return a stripped http(s) URL the policy allows, else None."""
    if url is None:
        return None
    if endpoint_problem(url, policy) is not None:
        return None
    return url.strip()


def _origin(parsed: urllib_parse.ParseResult) -> tuple[str, str, int]:
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        raise RuntimeError("endpoint host is required")
    if scheme not in ("http", "https"):
        raise RuntimeError("unsupported scheme: %s" % parsed.scheme)
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise RuntimeError("invalid endpoint port") from exc
    return scheme, host, port


def origin_string(parsed: urllib_parse.ParseResult) -> str:
    """RFC 6454 origin string (default ports elided) - the OAuth
    resource parameter and the token-store key."""
    scheme, host, port = _origin(parsed)
    default = 443 if scheme == "https" else 80
    if port == default:
        return "%s://%s" % (scheme, host)
    return "%s://%s:%d" % (scheme, host, port)


def resolve_sse_endpoint(base_url: str, event_data: str) -> str:
    """Resolve an SSE endpoint event to a same-origin http(s) POST URL."""
    ep = (event_data or "").strip()
    if not ep:
        raise RuntimeError("no SSE endpoint")
    if "\r" in ep or "\n" in ep or "\x00" in ep:
        raise RuntimeError("SSE endpoint contains control characters")
    # Protocol-relative URLs would inherit the base scheme and switch host.
    if ep.startswith("//"):
        raise RuntimeError("SSE endpoint must be same-origin")
    parsed_ep = urllib_parse.urlparse(ep)
    if parsed_ep.scheme:
        if parsed_ep.scheme not in ("http", "https"):
            raise RuntimeError("SSE endpoint scheme not allowed")
        resolved = ep
    else:
        # Preserve absolute-path semantics (RFC 3986): urljoin without stripping
        # leading "/" so "/sse" resolves at the origin root, not under base path.
        resolved = urllib_parse.urljoin(base_url + "/", ep)
    parsed = urllib_parse.urlparse(resolved)
    base = urllib_parse.urlparse(base_url)
    if _origin(parsed) != _origin(base):
        raise RuntimeError("SSE endpoint must be same-origin")
    return resolved


class _RefuseRedirect(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError("HTTP redirect refused")


def _read1(fp: Any, n: int) -> bytes:
    # read1 returns available bytes; read(n) can wait for a full buffer.
    if n <= 0:
        return b""
    if hasattr(fp, "read1"):
        data = fp.read1(n)
    else:
        data = fp.read(n)
    return data or b""


class _SseBody:
    """HTTP body that decodes chunked encoding without waiting for EOF."""

    def __init__(self, resp: http.client.HTTPResponse) -> None:
        self._fp = resp.fp
        self._chunked = bool(getattr(resp, "chunked", False))
        self._remain = 0
        self._eof = False

    def read(self, n: int) -> bytes:
        if self._eof or n <= 0:
            return b""
        if not self._chunked:
            return _read1(self._fp, n)
        out = bytearray()
        while len(out) < n and not self._eof:
            if self._remain <= 0:
                if out:
                    return bytes(out)
                if not self._begin_chunk():
                    self._eof = True
                    break
                if self._remain == 0:
                    self._eof = True
                    break
            piece = _read1(self._fp, min(n - len(out), self._remain))
            if not piece:
                self._eof = True
                break
            out.extend(piece)
            self._remain -= len(piece)
            if self._remain == 0:
                # Chunked trailer is CRLF (2 bytes) but may arrive split
                # across TCP packets when using read1; drain exactly 2 bytes.
                need = 2
                got_all = bytearray()
                while need > 0:
                    got = _read1(self._fp, need)
                    if not got:
                        break
                    got_all.extend(got)
                    need -= len(got)
                # Strictly should be b"\r\n"; tolerate lone \n for robustness.
                if got_all and bytes(got_all) not in (b"\r\n", b"\n"):
                    pass
        return bytes(out)

    def _begin_chunk(self) -> bool:
        line = bytearray()
        while len(line) < 256 and not line.endswith(b"\n"):
            part = _read1(self._fp, 1)
            if not part:
                return False
            line.extend(part)
        raw = bytes(line).strip()
        # Ignore chunk extensions after ';' per RFC 7230.
        raw = raw.split(b";", 1)[0].strip()
        try:
            self._remain = int(raw, 16)
        except ValueError as exc:
            raise RuntimeError("invalid chunk size") from exc
        return True


# --- P2: explicit per-arm credentials -----------------------------------


class ArmCredential:
    """A header the OPERATOR configured for one arm (P2).

    The transport sends nothing unless an arm hands it one of these;
    it never reads the environment itself, never touches netrc, and
    every secret_values entry (plus the header value itself) is
    registered in the session redaction set.
    """

    __slots__ = ("header_name", "header_value", "secret_values")

    def __init__(
        self,
        header_name: str,
        header_value: str,
        secret_values: tuple[str, ...] = (),
    ) -> None:
        self.header_name = header_name
        self.header_value = header_value
        self.secret_values = tuple(secret_values)

    @classmethod
    def bearer(cls, token: str) -> "ArmCredential":
        return cls("Authorization", "Bearer " + token, (token,))


# --- P3/P4: OAuth resource binding + PKCE (conditional, fail-closed) ----


class OAuthRequiredError(RuntimeError):
    """A server demanded OAuth and the transport is not configured."""


def parse_resource_metadata_url(www_authenticate: str | None) -> str | None:
    """RFC 9728: extract resource_metadata from a WWW-Authenticate header."""
    if not www_authenticate:
        return None
    match = re.search(r'resource_metadata="([^"]+)"', www_authenticate, re.IGNORECASE)
    return match.group(1) if match else None


def _jwt_payload(token: str) -> dict[str, Any] | None:
    """Decode a JWT payload WITHOUT verifying the signature.

    This is an audience-binding check, not an authenticity claim:
    authenticity rides on TLS to the AS plus PKCE on the code exchange.
    Returns None for opaque tokens (aud then not client-verifiable).
    """
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    try:
        payload = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def token_aud_covers(token: str, resource: str) -> bool:
    """True when the token's aud covers *resource* (or is opaque).

    Opaque tokens cannot be inspected client-side; their binding is
    enforced structurally by per-(arm, resource) token storage that
    refuses cross-origin reuse.
    """
    payload = _jwt_payload(token)
    if payload is None:
        return True
    aud = payload.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    if not isinstance(aud, list):
        return False
    normalized = {str(item).rstrip("/") for item in aud}
    return resource.rstrip("/") in normalized


class OAuthConfig:
    """Per-arm OAuth settings. No arm configures one today; the
    machinery is implemented and hermetically evidenced so an upstream
    that speaks RFC 9728 can be armed without new transport code.

    fetch_json/fetch_post_form are injectable for hermetic tests; the
    defaults perform pinned, proxy-free https requests only.
    on_authorization(url) is invoked when the operator must complete
    the consent step in a browser; there is no default - an arm that
    arms OAuth must provide one (fail-closed).
    """

    __slots__ = ("arm_id", "client_id", "scopes", "on_authorization", "fetch_json", "fetch_post_form")

    def __init__(
        self,
        arm_id: str,
        client_id: str,
        scopes: tuple[str, ...] = (),
        on_authorization: Callable[[str], None] | None = None,
        fetch_json: Callable[[str, float], dict[str, Any]] | None = None,
        fetch_post_form: Callable[[str, dict[str, str], float], dict[str, Any]] | None = None,
    ) -> None:
        self.arm_id = arm_id
        self.client_id = client_id
        self.scopes = tuple(scopes)
        self.on_authorization = on_authorization
        self.fetch_json = fetch_json
        self.fetch_post_form = fetch_post_form


class _CallbackRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "mcp-oauth-callback/1.0"

    def log_message(self, *args: Any) -> None:
        pass

    def _answer(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib_parse.urlparse(self.path)
        if parsed.path != OAUTH_CALLBACK_PATH:
            self._answer(404, "not found")
            return
        params = dict(urllib_parse.parse_qsl(parsed.query))
        self.server.callback_params = params  # type: ignore[attr-defined]
        self._answer(200, "authorization complete; you may close this window.")

    # Any other method - including POST of JSON-RPC - is refused. This
    # receiver never speaks MCP (P7).
    def do_POST(self) -> None:
        self._answer(404, "not found")

    def do_PUT(self) -> None:
        self._answer(404, "not found")

    def do_DELETE(self) -> None:
        self._answer(404, "not found")


class LoopbackCallbackReceiver:
    """The only listener the transport ever creates (P7).

    Binds 127.0.0.1 on an ephemeral port, serves exactly one callback
    path with a non-MCP response, stops after one callback (or a
    bounded idle timeout), and never binds anything else.
    """

    def __init__(self, timeout: float = DEFAULT_CALLBACK_TIMEOUT) -> None:
        self.timeout = timeout
        self._server = http.server.HTTPServer(("127.0.0.1", 0), _CallbackRequestHandler)
        self._server.timeout = 0.25
        if self._server.server_address[0] != "127.0.0.1":  # pragma: no cover - impossible today
            self._server.server_close()
            raise RuntimeError("callback receiver must bind loopback")
        self.port = int(self._server.server_address[1])
        self._closed = False

    @property
    def redirect_uri(self) -> str:
        return "http://127.0.0.1:%d%s" % (self.port, OAUTH_CALLBACK_PATH)

    def wait_for_callback(self) -> dict[str, str]:
        """Block until one callback-path request arrives, then return it."""
        if self._closed:
            raise RuntimeError("callback receiver is closed")
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if getattr(self._server, "callback_params", None) is not None:
                return dict(self._server.callback_params)  # type: ignore[attr-defined]
            self._server.handle_request()
        raise RuntimeError("timed out waiting for OAuth callback")

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._server.server_close()


class OAuthAuthorizationFlow:
    """One authorization-code attempt: PKCE S256 + state + resource."""

    def __init__(
        self,
        client_id: str,
        resource_origin: str,
        scopes: tuple[str, ...] = (),
        state: str | None = None,
        verifier: str | None = None,
    ) -> None:
        self.client_id = client_id
        self.resource_origin = resource_origin
        self.scopes = tuple(scopes)
        self.state = state if state is not None else secrets.token_urlsafe(24)
        # RFC 7636: verifier 43-128 chars from the unreserved alphabet.
        self.verifier = verifier if verifier is not None else secrets.token_urlsafe(48)
        digest = hashlib.sha256(self.verifier.encode("ascii")).digest()
        self.code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def authorization_url(self, authorization_endpoint: str, redirect_uri: str) -> str:
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "resource": self.resource_origin,
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "state": self.state,
        }
        if self.scopes:
            params["scope"] = " ".join(self.scopes)
        separator = "&" if "?" in authorization_endpoint else "?"
        return authorization_endpoint + separator + urllib_parse.urlencode(params)

    def validate_callback(self, params: dict[str, str]) -> str:
        if params.get("error"):
            raise RuntimeError("authorization error: %s" % redact(str(params["error"])))
        if params.get("state") != self.state:
            raise RuntimeError("OAuth state mismatch - refusing callback")
        code = params.get("code")
        if not code:
            raise RuntimeError("OAuth callback missing code")
        return code

    def exchange(
        self,
        token_endpoint: str,
        redirect_uri: str,
        code: str,
        fetch_post_form: Callable[[str, dict[str, str], float], dict[str, Any]] | None = None,
        timeout: float = MCP_CALL_TIMEOUT,
    ) -> str:
        fields = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
            "code_verifier": self.verifier,
        }
        fetch = fetch_post_form or _https_form_post
        data = fetch(token_endpoint, fields, timeout)
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise RuntimeError("token endpoint returned no access_token")
        if not token_aud_covers(token, self.resource_origin):
            raise RuntimeError("token audience does not cover resource %s - refusing" % self.resource_origin)
        return token


def _as_metadata_url(authorization_server: str) -> str:
    """RFC 8414 authorization-server metadata URL for an issuer root."""
    server = authorization_server.rstrip("/")
    if not configured_http_url(server, HttpTransportPolicy.remote_https()):
        raise RuntimeError("authorization server must be an https origin: %s" % redact(server))
    parsed = urllib_parse.urlparse(server)
    path = parsed.path or ""
    well_known = "/.well-known/oauth-authorization-server" + path
    return urllib_parse.urlunparse(
        (parsed.scheme, parsed.netloc, well_known, "", parsed.query, "")
    )


def _https_json_get(url: str, timeout: float) -> dict[str, Any]:
    if not configured_http_url(url, HttpTransportPolicy.remote_https()):
        raise RuntimeError("OAuth metadata URL must be https: %s" % redact(url))
    opener = urllib_request.build_opener(
        _RefuseRedirect(), urllib_request.ProxyHandler({})
    )
    req = urllib_request.Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}, method="GET")
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read(MAX_MCP_BYTES + 1)
    if len(raw) > MAX_MCP_BYTES:
        raise RuntimeError("OAuth metadata exceeds MAX_MCP_BYTES")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("OAuth metadata is not a JSON object")
    return data


def _https_form_post(url: str, fields: dict[str, str], timeout: float) -> dict[str, Any]:
    if not configured_http_url(url, HttpTransportPolicy.remote_https()):
        raise RuntimeError("OAuth token endpoint must be https: %s" % redact(url))
    opener = urllib_request.build_opener(
        _RefuseRedirect(), urllib_request.ProxyHandler({})
    )
    body = urllib_parse.urlencode(fields).encode("utf-8")
    req = urllib_request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read(MAX_MCP_BYTES + 1)
    if len(raw) > MAX_MCP_BYTES:
        raise RuntimeError("OAuth token response exceeds MAX_MCP_BYTES")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("OAuth token response is not a JSON object")
    return data


class OAuthAuthorizationManager:
    """Drives discovery + the code flow for one arm.

    Tokens are stored keyed by (arm_id, resource origin) and never
    served for a different origin (P3 cross-origin refusal).
    """

    def __init__(self, config: OAuthConfig) -> None:
        self._config = config
        self._tokens: dict[tuple[str, str], str] = {}

    def token_for(self, resource_origin: str) -> str | None:
        return self._tokens.get((self._config.arm_id, resource_origin))

    def authorize(self, resource_metadata_url: str, resource_origin: str, timeout: float) -> str:
        cached = self.token_for(resource_origin)
        if cached is not None:
            return cached
        fetch_json = self._config.fetch_json or _https_json_get
        metadata = fetch_json(resource_metadata_url, timeout)
        servers = metadata.get("authorization_servers")
        if not isinstance(servers, list) or not servers:
            raise RuntimeError("protected-resource metadata lists no authorization_servers")
        as_metadata = fetch_json(_as_metadata_url(str(servers[0])), timeout)
        authorization_endpoint = as_metadata.get("authorization_endpoint")
        token_endpoint = as_metadata.get("token_endpoint")
        if not isinstance(authorization_endpoint, str) or not isinstance(token_endpoint, str):
            raise RuntimeError("authorization-server metadata lacks endpoints")
        flow = OAuthAuthorizationFlow(self._config.client_id, resource_origin, self._config.scopes)
        receiver = LoopbackCallbackReceiver(timeout=timeout)
        try:
            url = flow.authorization_url(authorization_endpoint, receiver.redirect_uri)
            if self._config.on_authorization is None:
                raise OAuthRequiredError(
                    "OAuth authorization for arm %r requires an operator consent step; "
                    "no on_authorization handler is configured - refusing"
                    % self._config.arm_id
                )
            self._config.on_authorization(url)
            params = receiver.wait_for_callback()
            code = flow.validate_callback(params)
        finally:
            receiver.close()
        token = flow.exchange(
            token_endpoint,
            receiver.redirect_uri,
            code,
            fetch_post_form=self._config.fetch_post_form,
            timeout=timeout,
        )
        self._tokens[(self._config.arm_id, resource_origin)] = token
        return token


# --- P6: resolve-once DNS pinning ----------------------------------------


class DnsPin:
    """Resolve the endpoint host once and dial only that address.

    The connection subclasses override _create_connection (the single
    dial site in http.client), keeping TLS SNI, certificate
    verification, and Host headers bound to the configured NAME while
    the TCP dial goes to the pinned IP. Happy-eyeballs fallback is
    structurally absent: one getaddrinfo result, one address, and a
    guard that refuses to dial any other (host, port).
    """

    def __init__(self, url: str) -> None:
        parsed = urllib_parse.urlparse(url)
        self.scheme, self.host, self.port = _origin(parsed)
        self._resolved = False
        self._addr: tuple[str, int] | None = None

    def resolve(self) -> tuple[str, int]:
        if self._resolved:
            return self._addr  # type: ignore[return-value]
        infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        if not infos:
            raise RuntimeError("endpoint host does not resolve: %s" % self.host)
        _family, _socktype, _proto, _canonname, sockaddr = infos[0]
        ip = sockaddr[0]
        if self.host not in LOOPBACK_IPS and ip in LOOPBACK_IPS:
            raise RuntimeError(
                "hostname %r resolves to a loopback address - DNS-rebinding signature, refusing"
                % self.host
            )
        self._addr = (ip, sockaddr[1] or self.port)
        self._resolved = True
        return self._addr

    def _dial(self, address: tuple[str, int], timeout: float, source_address: Any = None) -> socket.socket:
        # Never dial anything but the pinned endpoint (host, port); both
        # http.client and urllib apply the same scheme default port, so a
        # mismatch can only mean a request escaped the session's origin.
        if address != (self.host, self.port):
            raise RuntimeError("pin violation: refusing to dial %r" % (address,))
        pinned = self.resolve()
        return socket.create_connection(pinned, timeout, source_address)

    def conn_class(self, secure: bool) -> type[http.client.HTTPConnection]:
        self.resolve()
        base: type[http.client.HTTPConnection] = (
            http.client.HTTPSConnection if secure else http.client.HTTPConnection
        )
        dial = self._dial

        class _PinnedConnection(base):  # type: ignore[misc, valid-type]
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                # Base __init__ binds socket.create_connection as an
                # instance attribute (3.12); rebind to the pinned dial.
                self._create_connection = dial

        return _PinnedConnection

    def opener(self) -> urllib_request.OpenerDirector:
        """Proxy-free, redirect-refusing opener with pinned handlers."""
        http_class = self.conn_class(secure=False)
        https_class = self.conn_class(secure=True)
        pin = self

        class _PinnedHTTPHandler(urllib_request.HTTPHandler):
            def __init__(self, conn_class: type[http.client.HTTPConnection]) -> None:
                super().__init__()
                self._conn_class = conn_class

            def http_open(self, req: urllib_request.Request) -> Any:
                return self.do_open(self._conn_class, req)

        class _PinnedHTTPSHandler(urllib_request.HTTPSHandler):
            def __init__(self, conn_class: type[http.client.HTTPConnection]) -> None:
                super().__init__()
                self._conn_class = conn_class

            def https_open(self, req: urllib_request.Request) -> Any:
                return self.do_open(self._conn_class, req, context=self._context)

        return urllib_request.build_opener(
            _RefuseRedirect(),
            urllib_request.ProxyHandler({}),
            _PinnedHTTPHandler(http_class),
            _PinnedHTTPSHandler(https_class),
        )


def register_secret_values(credential: ArmCredential, values: set[str]) -> None:
    values.add(credential.header_value)
    values.update(credential.secret_values)


class _OAuthChallenge(Exception):
    """Internal: a 401 carried RFC 9728 resource metadata."""

    def __init__(self, resource_metadata_url: str) -> None:
        super().__init__(resource_metadata_url)
        self.resource_metadata_url = resource_metadata_url


class SseMcpSession:
    """Minimal MCP client over legacy HTTP+SSE transport."""

    def __init__(
        self,
        base_url: str,
        timeout: float = MCP_CALL_TIMEOUT,
        policy: HttpTransportPolicy | None = None,
        credential: ArmCredential | None = None,
        oauth_config: OAuthConfig | None = None,
    ) -> None:
        self._policy = policy or HttpTransportPolicy.remote_https()
        problem = endpoint_problem(base_url, self._policy)
        if problem is not None:
            raise RuntimeError("invalid SSE endpoint URL: %s" % problem)
        self.base_url = base_url.strip().rstrip("/")
        self.timeout = timeout
        self._credential = credential
        self._secret_values: set[str] = set()
        if credential is not None:
            register_secret_values(credential, self._secret_values)
        self._oauth_config = oauth_config
        self._oauth_manager = OAuthAuthorizationManager(oauth_config) if oauth_config else None
        self._pin: DnsPin | None = None
        self._opener: urllib_request.OpenerDirector | None = None
        self._endpoint: str | None = None
        self._conn: http.client.HTTPConnection | None = None
        self._resp: http.client.HTTPResponse | None = None
        self._body: _SseBody | None = None
        self._reader: threading.Thread | None = None
        self._stop = threading.Event()
        self._messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self._rpc_id = 0
        self._lock = threading.Lock()
        self._connected = False

    def _scrub(self, text: str) -> str:
        return redact_values(redact(text), self._secret_values)

    def _set_credential(self, credential: ArmCredential) -> None:
        self._credential = credential
        register_secret_values(credential, self._secret_values)

    def _ensure_pin(self) -> DnsPin:
        if self._pin is None:
            self._pin = DnsPin(self.base_url)
            self._pin.resolve()
            self._opener = self._pin.opener()
        return self._pin

    def _origin_str(self) -> str:
        return origin_string(urllib_parse.urlparse(self.base_url))

    def _auth_headers(self) -> dict[str, str]:
        headers = {"Origin": LOCAL_ORIGIN, "User-Agent": USER_AGENT}
        if self._credential is not None:
            headers[self._credential.header_name] = self._credential.header_value
        return headers

    def _handle_oauth_challenge(self, challenge: _OAuthChallenge) -> None:
        if self._oauth_manager is None:
            raise OAuthRequiredError(
                "upstream requires OAuth (RFC 9728 resource metadata present) "
                "and this transport has no OAuth configuration - refusing"
            )
        origin = self._origin_str()
        token = self._oauth_manager.token_for(origin)
        if token is None:
            token = self._oauth_manager.authorize(challenge.resource_metadata_url, origin, self.timeout)
        self._set_credential(ArmCredential.bearer(token))

    def connect(self) -> None:
        if self._connected:
            return
        self._ensure_pin()
        try:
            self._open_sse()
        except _OAuthChallenge as challenge:
            self._handle_oauth_challenge(challenge)
            self._open_sse()
        self._wait_endpoint()
        init_result = self._rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            },
        )
        if isinstance(init_result, dict) and init_result.get("error"):
            raise RuntimeError(
                "initialize failed: %s" % self._scrub(json.dumps(init_result["error"]))
            )
        self._post_raw(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )
        self._connected = True

    def list_tools(self) -> list[dict[str, Any]]:
        result = self._rpc("tools/list", {})
        if not isinstance(result, dict):
            return []
        if result.get("error"):
            raise RuntimeError(
                "tools/list error: %s" % self._scrub(json.dumps(result["error"]))
            )
        tools = (result.get("result") or {}).get("tools") or []
        return tools if isinstance(tools, list) else []

    def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        result = self._rpc(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
        )
        if not isinstance(result, dict):
            raise RuntimeError("tools/call returned non-object")
        if result.get("error"):
            raise RuntimeError(
                "tools/call error: %s" % self._scrub(json.dumps(result["error"]))
            )
        payload = result.get("result")
        if isinstance(payload, dict):
            return payload
        return {"content": [], "isError": True}

    def close(self) -> None:
        self._stop.set()
        if self._resp is not None:
            try:
                self._resp.close()
            except OSError:
                pass
            self._resp = None
        self._body = None
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None
        if self._reader is not None and self._reader.is_alive():
            self._reader.join(timeout=1.0)
        self._reader = None
        self._connected = False

    def _next_id(self) -> int:
        with self._lock:
            self._rpc_id += 1
            return self._rpc_id

    def _open_sse(self) -> None:
        parsed = urllib_parse.urlparse(self.base_url)
        scheme, host, port = _origin(parsed)
        path = parsed.path or "/"
        if parsed.query:
            path = path + "?" + parsed.query
        headers = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
        headers.update(self._auth_headers())
        conn_class = self._ensure_pin().conn_class(secure=scheme == "https")
        if scheme == "https":
            import ssl

            ctx = ssl.create_default_context()
            self._conn = conn_class(host, port, timeout=self.timeout, context=ctx)
        else:
            self._conn = conn_class(host, port, timeout=self.timeout)
        self._conn.request("GET", path, headers=headers)
        resp = self._conn.getresponse()
        self._resp = resp
        if resp.status == 401:
            metadata_url = parse_resource_metadata_url(resp.getheader("WWW-Authenticate"))
            if metadata_url:
                raise _OAuthChallenge(metadata_url)
        if resp.status != 200:
            raise RuntimeError("SSE GET failed: HTTP %s" % resp.status)
        coding = (resp.getheader("Content-Encoding") or "").strip().lower()
        if coding and coding != "identity":
            raise RuntimeError("compressed SSE not supported")
        self._body = _SseBody(resp)
        self._reader = threading.Thread(
            target=self._read_loop,
            name="mcp-sse-reader",
            daemon=True,
        )
        self._reader.start()

    def _read_loop(self) -> None:
        buf = bytearray()
        while not self._stop.is_set():
            # Split frames on bytes; decoding first would desync on non-ASCII.
            while True:
                idx_crlf = buf.find(b"\r\n\r\n")
                idx_lf = buf.find(b"\n\n")
                if idx_crlf == -1 and idx_lf == -1:
                    break
                if idx_crlf != -1 and (idx_lf == -1 or idx_crlf <= idx_lf):
                    idx, sep_len = idx_crlf, 4
                else:
                    idx, sep_len = idx_lf, 2
                frame = bytes(buf[:idx]).decode("utf-8", errors="replace")
                del buf[: idx + sep_len]
                event_name = "message"
                data_lines: list[str] = []
                for line in frame.splitlines():
                    if line.startswith(":"):
                        continue
                    if line.startswith("event:"):
                        event_name = line[6:].strip() or "message"
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].lstrip())
                if not data_lines:
                    continue
                data = "\n".join(data_lines)
                if event_name == "endpoint":
                    self._endpoint = data.strip()
                    self._messages.put(
                        {"_sse_event": "endpoint", "data": data.strip()}
                    )
                elif event_name == "message":
                    try:
                        obj = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(obj, dict):
                        self._messages.put(obj)
                elif event_name == "error":
                    self._messages.put({"_sse_event": "error", "data": data})
            if self._body is None:
                break
            try:
                chunk = self._body.read(8192)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > MAX_MCP_BYTES * 4:
                self._messages.put(
                    {"_sse_event": "error", "data": "SSE frame buffer exceeds limit"}
                )
                break

    def _wait_endpoint(self) -> None:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self._endpoint:
                return
            try:
                msg = self._messages.get(timeout=0.1)
            except queue.Empty:
                continue
            if isinstance(msg, dict) and msg.get("_sse_event") == "endpoint":
                self._endpoint = str(msg.get("data") or "")
                if self._endpoint:
                    return
            if isinstance(msg, dict) and msg.get("_sse_event") == "error":
                raise RuntimeError("SSE error: %s" % self._scrub(str(msg.get("data"))))
        raise RuntimeError("timed out waiting for SSE endpoint event")

    def _resolve_endpoint(self) -> str:
        if not self._endpoint:
            raise RuntimeError("no SSE endpoint")
        return resolve_sse_endpoint(self.base_url, self._endpoint)

    def _post_raw(self, payload: dict[str, Any], _auth_retry: bool = True) -> None:
        url = self._resolve_endpoint()
        body = json.dumps(payload).encode("utf-8")
        if len(body) > MAX_MCP_BYTES:
            raise RuntimeError("request exceeds MAX_MCP_BYTES")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        headers.update(self._auth_headers())
        req = urllib_request.Request(url, data=body, headers=headers, method="POST")
        self._ensure_pin()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                total = 0
                while True:
                    chunk = resp.read(4096)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_MCP_BYTES:
                        raise RuntimeError("POST response exceeds MAX_MCP_BYTES")
        except HTTPError as exc:
            if exc.code == 401 and _auth_retry:
                metadata_url = parse_resource_metadata_url(
                    exc.headers.get("WWW-Authenticate") if exc.headers is not None else None
                )
                if metadata_url:
                    self._handle_oauth_challenge(_OAuthChallenge(metadata_url))
                    self._post_raw(payload, _auth_retry=False)
                    return
            try:
                err_body = exc.read(2048).decode("utf-8", errors="replace")
            except OSError:
                err_body = str(exc)
            raise RuntimeError(
                "HTTP %s: %s" % (exc.code, self._scrub(err_body[:800]))
            ) from exc
        except URLError as exc:
            raise RuntimeError("endpoint unreachable: %s" % self._scrub(str(exc))) from exc

    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        rpc_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": method,
            "params": params,
        }
        self._post_raw(payload)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                msg = self._messages.get(timeout=0.1)
            except queue.Empty:
                continue
            if not isinstance(msg, dict):
                continue
            if msg.get("_sse_event"):
                if msg.get("_sse_event") == "error":
                    raise RuntimeError(
                        "SSE error: %s" % self._scrub(str(msg.get("data")))
                    )
                continue
            if msg.get("id") == rpc_id:
                return msg
        raise RuntimeError(
            "timed out waiting for RPC id=%s method=%s" % (rpc_id, method)
        )




def _sse_first_message(raw: bytes, want_id: int | None) -> dict[str, Any]:
    """Return the first JSON message in a finite SSE body."""
    text = raw.decode("utf-8", errors="replace")
    for frame in re.split(r"\r?\n\r?\n", text):
        data_lines = [
            line[5:].lstrip()
            for line in frame.splitlines()
            if line.startswith("data:")
        ]
        if not data_lines:
            continue
        try:
            obj = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and (want_id is None or obj.get("id") == want_id):
            return obj
    raise RuntimeError("no JSON message in streamable HTTP SSE response")


class StreamableHttpClient:
    """Minimal MCP client over Streamable HTTP (spec 2025-03-26+).

    One POST per JSON-RPC message. A server replies with a JSON body or
    a finite ``text/event-stream`` body; both are capped at
    MAX_MCP_BYTES. Stateless servers need no session; when the server
    returns ``Mcp-Session-Id`` it is echoed on later requests - and
    never to any origin other than the one that issued it (P5).
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = MCP_CALL_TIMEOUT,
        policy: HttpTransportPolicy | None = None,
        credential: ArmCredential | None = None,
        oauth_config: OAuthConfig | None = None,
    ) -> None:
        self._policy = policy or HttpTransportPolicy.remote_https()
        problem = endpoint_problem(base_url, self._policy)
        if problem is not None:
            raise RuntimeError("invalid streamable HTTP endpoint URL: %s" % problem)
        self.base_url = base_url.strip().rstrip("/")
        self.timeout = timeout
        self._credential = credential
        self._secret_values: set[str] = set()
        if credential is not None:
            register_secret_values(credential, self._secret_values)
        self._oauth_config = oauth_config
        self._oauth_manager = OAuthAuthorizationManager(oauth_config) if oauth_config else None
        self._pin: DnsPin | None = None
        self._opener: urllib_request.OpenerDirector | None = None
        self._session_id: str | None = None
        self._session_origin: str | None = None
        self._origin_str = origin_string(urllib_parse.urlparse(self.base_url))
        self._rpc_id = 0

    def _scrub(self, text: str) -> str:
        return redact_values(redact(text), self._secret_values)

    def _set_credential(self, credential: ArmCredential) -> None:
        self._credential = credential
        register_secret_values(credential, self._secret_values)

    def _ensure_pin(self) -> DnsPin:
        if self._pin is None:
            self._pin = DnsPin(self.base_url)
            self._pin.resolve()
            self._opener = self._pin.opener()
        return self._pin

    def _handle_oauth_challenge(self, metadata_url: str) -> None:
        if self._oauth_manager is None:
            raise OAuthRequiredError(
                "upstream requires OAuth (RFC 9728 resource metadata present) "
                "and this transport has no OAuth configuration - refusing"
            )
        token = self._oauth_manager.token_for(self._origin_str)
        if token is None:
            token = self._oauth_manager.authorize(metadata_url, self._origin_str, self.timeout)
        self._set_credential(ArmCredential.bearer(token))

    def connect(self) -> None:
        if self._session_id is not None:
            return
        self._ensure_pin()
        _result, headers = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            },
        )
        session_id = headers.get("Mcp-Session-Id")
        if isinstance(session_id, str) and session_id.strip():
            self._session_id = session_id.strip()
            self._session_origin = self._origin_str
        self._request("notifications/initialized", {}, notification=True)

    def list_tools(self) -> list[dict[str, Any]]:
        result, _headers = self._request("tools/list", {})
        if not isinstance(result, dict):
            return []
        tools = result.get("tools") or []
        return tools if isinstance(tools, list) else []

    def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        result, _headers = self._request(
            "tools/call", {"name": name, "arguments": arguments or {}}
        )
        if not isinstance(result, dict):
            raise RuntimeError("tools/call returned non-object")
        if result.get("isError"):
            raise RuntimeError("tools/call error: %s" % self._scrub(json.dumps(result)))
        return result

    def close(self) -> None:
        # Stateless: each request was a standalone POST.
        self._session_id = None

    def _next_id(self) -> int:
        self._rpc_id += 1
        return self._rpc_id

    def _request(
        self,
        method: str,
        params: dict[str, Any],
        notification: bool = False,
        _auth_retry: bool = True,
    ) -> tuple[Any, Any]:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        rpc_id: int | None = None
        if not notification:
            rpc_id = self._next_id()
            payload["id"] = rpc_id
            payload["params"] = params
        body = json.dumps(payload).encode("utf-8")
        if len(body) > MAX_MCP_BYTES:
            raise RuntimeError("request exceeds MAX_MCP_BYTES")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Origin": LOCAL_ORIGIN,
            "User-Agent": USER_AGENT,
        }
        if self._credential is not None:
            headers[self._credential.header_name] = self._credential.header_value
        if self._session_id is not None:
            if self._session_origin != self._origin_str:
                raise RuntimeError(
                    "Mcp-Session-Id would cross origins - refusing (session pinning)"
                )
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib_request.Request(
            self.base_url, data=body, headers=headers, method="POST"
        )
        self._ensure_pin()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                if resp.status == 202:
                    return None, resp.headers
                raw = resp.read(MAX_MCP_BYTES + 1)
                if len(raw) > MAX_MCP_BYTES:
                    raise RuntimeError("response exceeds MAX_MCP_BYTES")
                resp_headers = resp.headers
        except HTTPError as exc:
            if exc.code == 401 and _auth_retry:
                metadata_url = parse_resource_metadata_url(
                    exc.headers.get("WWW-Authenticate") if exc.headers is not None else None
                )
                if metadata_url:
                    self._handle_oauth_challenge(metadata_url)
                    return self._request(method, params, notification, _auth_retry=False)
            try:
                err_body = exc.read(2048).decode("utf-8", errors="replace")
            except OSError:
                err_body = str(exc)
            raise RuntimeError(
                "HTTP %s: %s" % (exc.code, self._scrub(err_body[:800]))
            ) from exc
        except URLError as exc:
            raise RuntimeError("endpoint unreachable: %s" % self._scrub(str(exc))) from exc
        if not raw:
            if notification:
                return None, resp_headers
            raise RuntimeError("empty response for %s" % method)
        ctype = (resp_headers.get_content_type() or "").lower()
        if ctype == "text/event-stream":
            msg = _sse_first_message(raw, rpc_id)
        else:
            try:
                msg = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RuntimeError("invalid JSON response for %s" % method) from exc
        if not isinstance(msg, dict):
            raise RuntimeError("non-object response for %s" % method)
        if msg.get("error"):
            raise RuntimeError(
                "%s error: %s" % (method, self._scrub(json.dumps(msg["error"])))
            )
        return msg.get("result", msg), resp_headers
