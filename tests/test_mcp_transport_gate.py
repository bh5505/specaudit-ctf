"""Hermetic MCP transport evidence.

Every test here is hermetic: fake endpoints on loopback, a stub
resolver, a fake authorization server. No live upstream is ever
contacted. The sections cover endpoint parsing, credentials, OAuth,
MCP origin/session behavior, DNS transport behavior, and OAuth callbacks.

- URL parsing accepts HTTP(S) endpoints without classifying host addresses
- P2 no token passthrough (explicit ArmCredential only, values scrubbed)
- P3 OAuth resource + audience binding (RFC 9728/8414/8707, fail-closed)
- P4 PKCE S256 + state
- P5 Origin emission + single-origin session pinning
- P6 resolve-once DNS pinning + inert proxies
- P7 loopback OAuth callback receiver (the only listener; never MCP)
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib import request as urllib_request

import pytest

from extension.arms.mcp_client import (
    ArmCredential,
    DnsPin,
    LoopbackCallbackReceiver,
    OAuthAuthorizationFlow,
    OAuthAuthorizationManager,
    OAuthConfig,
    OAuthRequiredError,
    SseMcpSession,
    StreamableHttpClient,
    _as_metadata_url,
    _jwt_payload,
    configured_http_url,
    endpoint_problem,
    origin_string,
    parse_resource_metadata_url,
    redact_values,
    token_aud_covers,
)
from urllib.parse import urlparse

# --- fakes ----------------------------------------------------------------


class _GateState(dict):
    """Shared fake-server state: captured requests + behavior flags."""

    def __init__(self) -> None:
        super().__init__(
            requests=[],
            posted=[],
            stop=False,
            metadata_url="https://as.example.invalid/.well-known/oauth-protected-resource",
            secret=None,
        )


class _GateStreamableHandler(BaseHTTPRequestHandler):
    server_version = "stub-gate/1.0"

    def log_message(self, *args: Any) -> None:
        pass

    def _record(self, body: bytes | None = None) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        headers = {k.lower(): v for k, v in self.headers.items()}
        state["requests"].append({"path": self.path, "headers": headers})

    def _reply(self, status: int, body: bytes, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        self._record()
        msg = json.loads(raw.decode("utf-8"))
        authorization = (self.headers.get("Authorization") or "").strip()
        mode = state.get("mode")
        if mode == "require_auth" and not authorization:
            self._reply(
                401,
                b'{"error":"unauthorized"}',
                {"WWW-Authenticate": 'Bearer resource_metadata="%s"' % state["metadata_url"]},
            )
            return
        if mode == "always_401_meta":
            self._reply(
                401,
                b'{"error":"unauthorized"}',
                {"WWW-Authenticate": 'Bearer resource_metadata="%s"' % state["metadata_url"]},
            )
            return
        if mode == "always_401_plain":
            self._reply(401, b'{"error":"nope"}', {"WWW-Authenticate": 'Bearer realm="x"'})
            return
        if mode == "echo_secret" and state.get("secret"):
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(("leaked: %s" % state["secret"]).encode("utf-8"))
            return
        if msg.get("method") == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return
        payload = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"content": []}}
        if msg.get("method") == "tools/list":
            payload["result"] = {"tools": [{"name": "get_domain_report"}]}
        extra = {"Mcp-Session-Id": "sess-gate-1"} if msg.get("method") == "initialize" else None
        self._reply(200, json.dumps(payload).encode("utf-8"), extra)


@pytest.fixture
def gate_streamable_server():
    state = _GateState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GateStreamableHandler)
    server.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d/" % server.server_address[1], state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


class _SseGateHandler(BaseHTTPRequestHandler):
    server_version = "stub-gate-sse/1.0"

    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        state["requests"].append(
            {"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}
        )
        if state.get("mode") == "always_401_meta":
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                'Bearer resource_metadata="%s"' % state["metadata_url"],
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(b"event: endpoint\ndata: /sse\n\n")
        self.wfile.flush()
        answered: set[int] = set()
        while not state["stop"]:
            try:
                for msg in list(state["posted"]):
                    if msg.get("id") in answered:
                        continue
                    answered.add(msg.get("id"))
                    frame = {
                        "jsonrpc": "2.0",
                        "id": msg.get("id"),
                        "result": (
                            {"tools": [{"name": "get_proxy_http_history"}]}
                            if msg.get("method") == "tools/list"
                            else {}
                        ),
                    }
                    self.wfile.write(
                        b"event: message\ndata: "
                        + json.dumps(frame).encode("utf-8")
                        + b"\n\n"
                    )
                self.wfile.write(b": ping\n\n")
                self.wfile.flush()
            except OSError:
                return
            time.sleep(0.05)

    def do_POST(self) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        state["posted"].append(json.loads(raw.decode("utf-8")))
        state["requests"].append(
            {"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}
        )
        self.send_response(202)
        self.end_headers()


@pytest.fixture
def gate_sse_server():
    state = _GateState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SseGateHandler)
    server.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d/sse" % server.server_address[1], state
    finally:
        state["stop"] = True
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _make_jwt(aud: str) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"aud": aud}).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    return "header.%s.signature" % payload


# --- URL parsing -----------------------------------------------------------


def test_endpoint_url_parsing_does_not_classify_host_addresses() -> None:
    # The operator selects and owns the endpoint. Parsing accepts both
    # HTTP(S) schemes across loopback, private, and public host forms.
    for url in (
        "http://127.0.0.1:9876",
        "http://localhost:9876",
        "http://10.0.0.5:9876",
        "http://mcp.example.invalid:9876",
        "https://127.0.0.1:9443",
        "https://mcp.example.invalid/mcp",
    ):
        assert endpoint_problem(url) is None
        assert configured_http_url(url) == url

    for invalid in (
        "ftp://mcp.example.invalid",
        "http:///missing-host",
        "http://mcp.example.invalid:junk",
        "http://u:p@mcp.example.invalid",
        "http://mcp.example.invalid/\r\nX: y",
    ):
        assert endpoint_problem(invalid) is not None
        assert configured_http_url(invalid) is None


def test_arm_endpoint_configuration_uses_url_parsing_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from extension.arms.burp.arm import BurpArm
    from extension.arms.gti.arm import GtiArm
    from extension.arms.prowler.arm import ProwlerArm

    endpoints = (
        ("BURP_MCP_ENDPOINT", BurpArm),
        ("GTI_MCP_ENDPOINT", GtiArm),
        ("PROWLER_MCP_ENDPOINT", ProwlerArm),
    )
    for variable, arm_type in endpoints:
        for url in (
            "http://localhost:9876",
            "http://10.0.0.5:9876",
            "http://mcp.example.invalid",
        ):
            monkeypatch.setenv(variable, url)
            assert arm_type().endpoint_url() == url
        monkeypatch.setenv(variable, "ftp://mcp.example.invalid")
        assert arm_type().endpoint_url() is None


# --- P2: no token passthrough ---------------------------------------------


def test_p2_no_credentials_on_the_wire_without_configuration(
    gate_streamable_server, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, state = gate_streamable_server
    for key in (
        "HTTP_AUTHORIZATION",
        "SEMGREP_APP_TOKEN",
        "VT_APIKEY",
        "AWS_ACCESS_KEY_ID",
        "MCP_AUTH_TOKEN",
        "NETRC",
    ):
        monkeypatch.setenv(key, "poisoned-secret-%s" % key)
    client = StreamableHttpClient(url, timeout=5)
    client.connect()
    client.list_tools()
    for request in state["requests"]:
        assert "authorization" not in request["headers"]
        assert "cookie" not in request["headers"]


def test_p2_configured_credential_sent_and_scrubbed(gate_streamable_server) -> None:
    url, state = gate_streamable_server
    secret = "op-secret-DO-NOT-LEAK-0123456789"
    state["secret"] = secret
    state["mode"] = "echo_secret"
    client = StreamableHttpClient(
        url, timeout=5, credential=ArmCredential.bearer(secret)
    )
    with pytest.raises(RuntimeError) as err:
        client._request("tools/list", {})  # noqa: SLF001 - exercising the wire directly
    assert secret not in str(err.value)
    assert "[redacted]" in str(err.value)
    sent = [r for r in state["requests"] if "authorization" in r["headers"]]
    assert sent and sent[0]["headers"]["authorization"] == "Bearer " + secret
    client.close()


def test_p2_redact_values_scrubs_exact_values() -> None:
    assert redact_values("x op-secret-1 y", {"op-secret-1"}) == "x [redacted] y"
    assert redact_values("clean", set()) == "clean"


# --- P3: OAuth resource + audience binding --------------------------------


def test_p3_parse_resource_metadata_url() -> None:
    header = 'Bearer realm="mcp", resource_metadata="https://as.example/.well-known/oauth-protected-resource"'
    assert (
        parse_resource_metadata_url(header)
        == "https://as.example/.well-known/oauth-protected-resource"
    )
    assert parse_resource_metadata_url('Bearer realm="only"') is None
    assert parse_resource_metadata_url(None) is None
    assert parse_resource_metadata_url("") is None


def test_p3_401_with_resource_metadata_fails_closed_unconfigured(
    gate_streamable_server,
) -> None:
    """The N/A evidence for no-OAuth arms: a server demanding OAuth is
    refused, never talked around."""
    url, state = gate_streamable_server
    state["mode"] = "always_401_meta"
    client = StreamableHttpClient(url, timeout=5)
    with pytest.raises(OAuthRequiredError, match="no OAuth configuration"):
        client.connect()


def test_p3_401_without_resource_metadata_is_a_plain_error(
    gate_streamable_server,
) -> None:
    url, state = gate_streamable_server
    state["mode"] = "always_401_plain"
    client = StreamableHttpClient(url, timeout=5)
    with pytest.raises(RuntimeError, match="HTTP 401") as err:
        client.connect()
    assert not isinstance(err.value, OAuthRequiredError)


def test_p3_jwt_audience_matrix() -> None:
    assert _jwt_payload("not-a-jwt") is None
    assert _jwt_payload(_make_jwt("https://mcp.example.com")) == {"aud": "https://mcp.example.com"}
    assert token_aud_covers(_make_jwt("https://mcp.example.com"), "https://mcp.example.com")
    assert token_aud_covers(_make_jwt("https://mcp.example.com/"), "https://mcp.example.com")
    assert not token_aud_covers(_make_jwt("https://other.example"), "https://mcp.example.com")
    # Opaque tokens: binding enforced structurally by per-origin storage.
    assert token_aud_covers("opaque-reference-token", "https://mcp.example.com")


def test_p3_as_metadata_url_builds_rfc8414_path() -> None:
    assert (
        _as_metadata_url("https://as.example.com")
        == "https://as.example.com/.well-known/oauth-authorization-server"
    )
    assert (
        _as_metadata_url("https://as.example.com/prefix")
        == "https://as.example.com/.well-known/oauth-authorization-server/prefix"
    )
    with pytest.raises(RuntimeError, match="https"):
        _as_metadata_url("http://as.example.com")


def _fake_metadata_fetch(calls: list[str]) -> Any:
    def fetch(url: str, timeout: float) -> dict[str, Any]:
        calls.append(url)
        if url.endswith("oauth-protected-resource"):
            return {"resource": "https://mcp.example.com", "authorization_servers": ["https://as.example.com"]}
        return {
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token",
        }

    return fetch


def test_p3_manager_full_flow_and_cross_origin_refusal() -> None:
    calls: list[str] = []
    posted_fields: list[dict[str, str]] = []
    origin = "https://mcp.example.com"
    token = _make_jwt(origin)

    def fetch_post(url: str, fields: dict[str, str], timeout: float) -> dict[str, Any]:
        calls.append(url)
        posted_fields.append(fields)
        return {"access_token": token, "token_type": "Bearer"}

    seen_urls: list[str] = []

    def on_authorization(url: str) -> None:
        seen_urls.append(url)
        # Simulate the AS redirecting the operator's browser back.
        threading.Thread(target=_browser_sim, args=(url,), daemon=True).start()

    config = OAuthConfig(
        arm_id="test-arm",
        client_id="client-1",
        on_authorization=on_authorization,
        fetch_json=_fake_metadata_fetch(calls),
        fetch_post_form=fetch_post,
    )
    manager = OAuthAuthorizationManager(config)
    got = manager.authorize("https://as.example.com/.well-known/oauth-protected-resource", origin, 5.0)
    assert got == token
    assert manager.token_for(origin) == token
    # Cross-origin reuse refused: no token for a different origin.
    assert manager.token_for("https://other.example.com") is None
    # The authorization URL carried the resource parameter and S256 PKCE.
    assert len(seen_urls) == 1
    assert "resource=https%3A%2F%2Fmcp.example.com" in seen_urls[0]
    assert "code_challenge_method=S256" in seen_urls[0]
    # And the code exchange actually transmitted the PKCE verifier.
    assert posted_fields and posted_fields[0]["grant_type"] == "authorization_code"
    assert "code_verifier" in posted_fields[0] and posted_fields[0]["code_verifier"]


def _hit_url(url: str) -> None:
    time.sleep(0.1)
    try:
        urllib_request.urlopen(url, timeout=5.0)
    except Exception:  # noqa: BLE001 - surfacing happens via the wait/timeout assertions
        pass


def _browser_sim(authorize_url: str) -> None:
    """Simulate the operator's browser: complete consent, land on the
    loopback receiver with code + the flow's own state."""
    from urllib.parse import parse_qs

    query = parse_qs(urlparse(authorize_url).query)
    redirect = query["redirect_uri"][0]
    state = query["state"][0]
    separator = "&" if "?" in redirect else "?"
    _hit_url(redirect + separator + "code=c-sim&state=" + state)


def test_p3_resource_metadata_mismatch_refused() -> None:
    """A resource server pointing discovery at a resource that is not the
    origin being served is a redirect-to-attacker-AS attempt."""
    calls: list[str] = []

    def fetch(url: str, timeout: float) -> dict[str, Any]:
        calls.append(url)
        return {"resource": "https://attacker.example", "authorization_servers": ["https://as.example.com"]}

    manager = OAuthAuthorizationManager(
        OAuthConfig(arm_id="test-arm", client_id="client-1", fetch_json=fetch)
    )
    with pytest.raises(RuntimeError, match="names resource"):
        manager.authorize(
            "https://as.example.com/.well-known/oauth-protected-resource",
            "https://mcp.example.com",
            1.0,
        )
    # Refused before any AS discovery.
    assert calls == ["https://as.example.com/.well-known/oauth-protected-resource"]


def test_p3_mismatch_refusal_redacts_configured_origin() -> None:
    """Automatic-review sweep 5: the configured origin is interpolated
    into the refusal message and must be keyword-redacted like the
    declared one — a userinfo-bearing origin cannot leak its password
    fragment into logs."""

    def fetch(url: str, timeout: float) -> dict[str, Any]:
        return {"resource": "https://attacker.example", "authorization_servers": ["https://as.example.com"]}

    manager = OAuthAuthorizationManager(
        OAuthConfig(arm_id="test-arm", client_id="client-1", fetch_json=fetch)
    )
    with pytest.raises(RuntimeError) as excinfo:
        manager.authorize(
            "https://as.example.com/.well-known/oauth-protected-resource",
            "https://user:secret-password@target.example.com",
            1.0,
        )
    message = str(excinfo.value)
    assert "secret-password" not in message
    assert "[redacted]" in message


def test_p3_sse_repeat_challenge_is_terminal(gate_sse_server) -> None:
    """SSE path: a server that keeps demanding OAuth after a completed
    flow terminates with a public error, never an internal exception."""
    url, state = gate_sse_server
    state["mode"] = "always_401_meta"
    origin = origin_string(urlparse(url))

    def fetch_json(fetch_url: str, timeout: float) -> dict[str, Any]:
        if fetch_url.endswith("oauth-protected-resource"):
            return {"resource": origin, "authorization_servers": ["https://as.example.com"]}
        return {
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token",
        }

    def on_authorization(auth_url: str) -> None:
        threading.Thread(target=_browser_sim, args=(auth_url,), daemon=True).start()

    session = SseMcpSession(
        url,
        timeout=5,
        oauth_config=OAuthConfig(
            arm_id="sse-test",
            client_id="client-1",
            on_authorization=on_authorization,
            fetch_json=fetch_json,
            fetch_post_form=lambda u, f, t: {"access_token": _make_jwt(origin)},
        ),
    )
    try:
        with pytest.raises(RuntimeError, match="re-challenged"):
            session.connect()
    finally:
        session.close()


def test_p3_as_metadata_endpoints_must_be_https() -> None:
    """Server-controlled AS metadata can name an http authorize/token
    endpoint; both are refused before the browser or the exchange ever
    sees them (auto-review CRITICAL fix, PR #30 sweep)."""
    state = {"as_calls": 0}

    def fetch(url: str, timeout: float) -> dict[str, Any]:
        if url.endswith("oauth-protected-resource"):
            return {"resource": "https://mcp.example.com", "authorization_servers": ["https://as.example.com"]}
        state["as_calls"] += 1
        if state["as_calls"] == 1:
            return {
                "authorization_endpoint": "http://attacker.example/authorize",
                "token_endpoint": "https://as.example.com/token",
            }
        return {
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "http://attacker.example/token",
        }

    manager = OAuthAuthorizationManager(
        OAuthConfig(arm_id="test-arm", client_id="client-1", fetch_json=fetch)
    )
    with pytest.raises(RuntimeError, match="authorization_endpoint must be https"):
        manager.authorize(
            "https://as.example.com/.well-known/oauth-protected-resource",
            "https://mcp.example.com",
            1.0,
        )
    # The token endpoint gets the same pre-flight refusal (second
    # discovery round via the stateful fake).
    with pytest.raises(RuntimeError, match="token_endpoint must be https"):
        manager.authorize(
            "https://as.example.com/.well-known/oauth-protected-resource",
            "https://mcp.example.com",
            1.0,
        )


def test_p3_resource_origin_comparison_is_case_insensitive() -> None:
    """RFC 6454 hosts compare case-insensitively: a server declaring
    https://MCP.Example.com matches the lowercase origin (PR #30 sweep)."""
    calls: list[str] = []

    def fetch(url: str, timeout: float) -> dict[str, Any]:
        calls.append(url)
        if url.endswith("oauth-protected-resource"):
            return {"resource": "https://MCP.Example.com", "authorization_servers": ["https://as.example.com"]}
        return {
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token",
        }

    manager = OAuthAuthorizationManager(
        OAuthConfig(arm_id="test-arm", client_id="client-1", fetch_json=fetch)
    )
    # No on_authorization handler: the case-normalized resource passes
    # the origin check and fails at the honest operator-step refusal
    # (not at the origin mismatch).
    with pytest.raises(OAuthRequiredError, match="on_authorization"):
        manager.authorize(
            "https://as.example.com/.well-known/oauth-protected-resource",
            "https://mcp.example.com",
            1.0,
        )


def test_p3_manager_requires_on_authorization() -> None:
    calls: list[str] = []
    config = OAuthConfig(
        arm_id="test-arm",
        client_id="client-1",
        on_authorization=None,
        fetch_json=_fake_metadata_fetch(calls),
    )
    manager = OAuthAuthorizationManager(config)
    with pytest.raises(OAuthRequiredError, match="on_authorization"):
        manager.authorize(
            "https://as.example.com/.well-known/oauth-protected-resource",
            "https://mcp.example.com",
            1.0,
        )


def test_p3_wrong_audience_token_refused() -> None:
    origin = "https://mcp.example.com"
    flow = OAuthAuthorizationFlow("client-1", origin)

    def fetch_post(url: str, fields: dict[str, str], timeout: float) -> dict[str, Any]:
        return {"access_token": _make_jwt("https://attacker.example")}

    with pytest.raises(RuntimeError, match="audience does not cover"):
        flow.exchange("https://as.example.com/token", "http://127.0.0.1:1/callback", "code-x", fetch_post_form=fetch_post)


def test_p3_client_terminates_after_one_oauth_retry(gate_streamable_server) -> None:
    """A server that keeps challenging OAuth after a completed flow gets
    exactly one authorized retry, then a terminal error - no loop."""
    url, state = gate_streamable_server
    state["mode"] = "always_401_meta"
    origin = origin_string(urlparse(url))
    auth_calls: list[str] = []

    def fetch_json(url: str, timeout: float) -> dict[str, Any]:
        if url.endswith("oauth-protected-resource"):
            return {"resource": origin, "authorization_servers": ["https://as.example.com"]}
        return {
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token",
        }

    def fetch_post(url: str, fields: dict[str, str], timeout: float) -> dict[str, Any]:
        return {"access_token": _make_jwt(origin)}

    def on_authorization(auth_url: str) -> None:
        auth_calls.append(auth_url)
        threading.Thread(target=_browser_sim, args=(auth_url,), daemon=True).start()

    client = StreamableHttpClient(
        url,
        timeout=5,
        oauth_config=OAuthConfig(
            arm_id="gate-test",
            client_id="client-1",
            on_authorization=on_authorization,
            fetch_json=fetch_json,
            fetch_post_form=fetch_post,
        ),
    )
    with pytest.raises(RuntimeError, match="HTTP 401"):
        client.connect()
    assert len(auth_calls) == 1  # one flow, one retry, then terminal


def test_p3_client_runs_flow_and_retries_with_token(gate_streamable_server) -> None:
    url, state = gate_streamable_server
    state["mode"] = "require_auth"
    origin = origin_string(urlparse(url))
    token = _make_jwt(origin)

    def fetch_json(url: str, timeout: float) -> dict[str, Any]:
        if url.endswith("oauth-protected-resource"):
            return {"resource": origin, "authorization_servers": ["https://as.example.com"]}
        return {
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token",
        }

    def fetch_post(url: str, fields: dict[str, str], timeout: float) -> dict[str, Any]:
        return {"access_token": token}

    def on_authorization(auth_url: str) -> None:
        threading.Thread(target=_browser_sim, args=(auth_url,), daemon=True).start()

    client = StreamableHttpClient(
        url,
        timeout=5,
        oauth_config=OAuthConfig(
            arm_id="gate-test",
            client_id="client-1",
            on_authorization=on_authorization,
            fetch_json=fetch_json,
            fetch_post_form=fetch_post,
        ),
    )
    client.connect()
    tools = client.list_tools()
    assert tools == [{"name": "get_domain_report"}]
    # The retry carried the audience-bound bearer token.
    later = [r for r in state["requests"] if "authorization" in r["headers"]]
    assert later and later[0]["headers"]["authorization"] == "Bearer " + token


# --- P4: PKCE S256 + state -------------------------------------------------


def test_p4_pkce_s256_and_resource_in_authorization_url() -> None:
    flow = OAuthAuthorizationFlow("client-1", "https://mcp.example.com", scopes=("mcp",))
    url = flow.authorization_url("https://as.example.com/authorize", "http://127.0.0.1:45000/callback")
    query = urlparse(url).query
    from urllib.parse import parse_qs

    params = {k: v[0] for k, v in parse_qs(query).items()}
    assert params["code_challenge_method"] == "S256"
    assert params["code_challenge"] == flow.code_challenge
    assert params["resource"] == "https://mcp.example.com"
    assert params["state"] == flow.state
    assert params["client_id"] == "client-1"
    # The challenge is exactly BASE64URL(SHA256(verifier)).
    import hashlib

    expect = base64.urlsafe_b64encode(
        hashlib.sha256(flow.verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert expect == flow.code_challenge


def test_p4_verifier_entropy() -> None:
    flow = OAuthAuthorizationFlow("client-1", "https://mcp.example.com")
    assert 43 <= len(flow.verifier) <= 128
    assert all(c.isalnum() or c in "-_~" for c in flow.verifier)
    other = OAuthAuthorizationFlow("client-1", "https://mcp.example.com")
    assert flow.verifier != other.verifier
    assert flow.state != other.state


def test_p4_state_mismatch_refused() -> None:
    flow = OAuthAuthorizationFlow("client-1", "https://mcp.example.com", state="st-1")
    with pytest.raises(RuntimeError, match="state mismatch"):
        flow.validate_callback({"code": "c", "state": "st-2"})
    with pytest.raises(RuntimeError, match="missing code"):
        flow.validate_callback({"code": "", "state": "st-1"})
    with pytest.raises(RuntimeError, match="authorization error"):
        flow.validate_callback({"error": "access_denied", "state": "st-1"})
    assert flow.validate_callback({"code": "c", "state": "st-1"}) == "c"


# --- P5: Origin emission + session pinning --------------------------------


def test_p5_origin_header_emitted_on_streamable_requests(gate_streamable_server) -> None:
    url, state = gate_streamable_server
    client = StreamableHttpClient(url, timeout=5)
    client.connect()
    client.list_tools()
    assert state["requests"]
    # The Origin names the endpoint's own origin (port included): strict
    # same-origin validators (e.g. the Burp MCP server's DNS-rebinding
    # guard) reject a port-less loopback constant.
    expected_origin = origin_string(urlparse(url))
    for request in state["requests"]:
        assert request["headers"].get("origin") == expected_origin


def test_p5_origin_header_emitted_on_sse_requests(gate_sse_server) -> None:
    url, state = gate_sse_server
    session = SseMcpSession(url, timeout=5)
    try:
        session.connect()
        tools = session.list_tools()
        assert tools == [{"name": "get_proxy_http_history"}]
        assert state["requests"]
        expected_origin = origin_string(urlparse(url))
        for request in state["requests"]:
            assert request["headers"].get("origin") == expected_origin
    finally:
        session.close()


def test_p5_session_id_never_crosses_origins(gate_streamable_server) -> None:
    """Defense-in-depth: base_url is immutable by construction, so the
    only reachable shape is an internal inconsistency - which the guard
    must still refuse before any wire IO."""
    url, _state = gate_streamable_server
    client = StreamableHttpClient(url, timeout=5)
    client._session_id = "sess-tampered"  # noqa: SLF001 - deliberate tamper
    client._session_origin = "https://elsewhere.example"
    with pytest.raises(RuntimeError, match="cross origins"):
        client._request("tools/list", {})  # noqa: SLF001


def test_p5_sse_post_endpoint_same_origin_only() -> None:
    from extension.arms.mcp_client import resolve_sse_endpoint

    base = "http://127.0.0.1:9876/sse"
    assert resolve_sse_endpoint(base, "/messages?x=1") == "http://127.0.0.1:9876/messages?x=1"
    with pytest.raises(RuntimeError, match="same-origin"):
        resolve_sse_endpoint(base, "http://evil.example/messages")
    with pytest.raises(RuntimeError, match="same-origin"):
        resolve_sse_endpoint(base, "//evil.example/messages")


# --- P6: DNS pinning --------------------------------------------------------


def test_p6_resolve_once_and_pin_violation_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    pin = DnsPin("http://127.0.0.1:9876")
    assert pin.resolve() == ("127.0.0.1", 9876)
    assert pin.resolve() == ("127.0.0.1", 9876)
    assert calls == ["127.0.0.1"]  # exactly one resolution
    with pytest.raises(RuntimeError, match="pin violation"):
        pin._dial(("other.example", 80), 1.0)  # noqa: SLF001


def test_p6_pinned_dial_uses_pin_not_name() -> None:
    """The dial goes to the PINNED address while Host stays the NAME."""
    seen: dict[str, Any] = {}

    class _HostCapture(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            seen["host"] = self.headers.get("Host")
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    # The redirected test socket only needs the universally configured loopback.
    # The independently asserted TEST-NET pin still differs from this endpoint.
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HostCapture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    resolves: list[str] = []
    dialed: list[tuple[str, int]] = []
    # The fake DNS resolves the NAME to a TEST-NET address;
    # create_connection records what it
    # was asked to dial (the pin) and redirects to the real server.
    pinned_ip = "192.0.2.1"

    def fake_getaddrinfo(host: str, port_: int, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        resolves.append(host)
        if host == "name.example.invalid":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (pinned_ip, port_))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port_))]

    original_getaddrinfo = socket.getaddrinfo
    original_create_connection = socket.create_connection

    def fake_create_connection(address: tuple[str, int], timeout: float = 5.0, source_address: Any = None) -> socket.socket:
        dialed.append(address)
        return original_create_connection(("127.0.0.1", address[1]), timeout, source_address)

    socket.getaddrinfo = fake_getaddrinfo  # type: ignore[assignment]
    socket.create_connection = fake_create_connection  # type: ignore[assignment]
    try:
        pin = DnsPin("http://name.example.invalid:%d" % port)
        conn_class = pin.conn_class(secure=False)
        conn = conn_class("name.example.invalid", port, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()
        assert response.status == 200
        conn.close()
        assert seen["host"] == "name.example.invalid:%d" % port
        # The dial went to the pinned address, never the name; the name
        # was resolved exactly once.
        assert dialed == [(pinned_ip, port)]
        assert resolves.count("name.example.invalid") == 1
    finally:
        socket.getaddrinfo = original_getaddrinfo  # type: ignore[assignment]
        socket.create_connection = original_create_connection  # type: ignore[assignment]
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_p6_no_second_resolution_when_dial_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        calls.append(host)
        # An unroutable TEST-NET address; the dial then fails.
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    pin = DnsPin("http://name.example.invalid:9/")
    conn_class = pin.conn_class(secure=False)
    with pytest.raises(OSError):
        conn = conn_class("name.example.invalid", 9, timeout=1.0)
        conn.request("GET", "/")
    # The NAME is never resolved a second time; the dial's internal
    # create_connection sees only the pinned IP literal.
    assert calls.count("name.example.invalid") == 1


def test_p6_proxy_environment_is_inert(
    gate_streamable_server, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, _state = gate_streamable_server
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(key, "http://127.0.0.1:9")
    client = StreamableHttpClient(url, timeout=5)
    client.connect()
    assert client.list_tools() == [{"name": "get_domain_report"}]


# --- P7: the loopback callback receiver -------------------------------------


def test_p7_receiver_binds_loopback_ephemeral_and_captures_one_callback() -> None:
    receiver = LoopbackCallbackReceiver(timeout=5.0)
    port = receiver.port
    assert receiver.redirect_uri == "http://127.0.0.1:%d/callback" % port
    threading.Thread(
        target=_hit_url, args=("http://127.0.0.1:%d/callback?code=c-1&state=s-1" % port,),
        daemon=True,
    ).start()
    params = receiver.wait_for_callback()
    assert params == {"code": "c-1", "state": "s-1"}
    receiver.close()
    # After close the socket is gone: a further callback cannot be served.
    with pytest.raises(RuntimeError, match="closed"):
        receiver.wait_for_callback()


def test_p7_receiver_answers_non_callback_paths_with_404() -> None:
    receiver = LoopbackCallbackReceiver(timeout=5.0)
    port = receiver.port

    def probe() -> None:
        time.sleep(0.05)
        for path in ("/", "/other", "/mcp", "/sse"):
            try:
                urllib_request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=2.0)
            except Exception as exc:  # noqa: BLE001 - 404 arrives as HTTPError
                assert getattr(exc, "code", None) == 404, path
        # Any non-GET method on the callback path is refused too.
        import urllib.error

        request = urllib_request.Request(
            "http://127.0.0.1:%d/callback" % port, data=b"{}", method="POST"
        )
        try:
            urllib_request.urlopen(request, timeout=2.0)
            raise AssertionError("POST to the receiver must not succeed")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        # The real callback still works after the noise.
        _hit_url("http://127.0.0.1:%d/callback?code=c-2&state=s-2" % port)

    threading.Thread(target=probe, daemon=True).start()
    assert receiver.wait_for_callback() == {"code": "c-2", "state": "s-2"}
    receiver.close()


def test_p7_receiver_times_out_bounded() -> None:
    receiver = LoopbackCallbackReceiver(timeout=0.3)
    start = time.monotonic()
    with pytest.raises(RuntimeError, match="timed out"):
        receiver.wait_for_callback()
    assert time.monotonic() - start < 5.0
    receiver.close()
