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
"""

from __future__ import annotations

import http.client
import json
import queue
import re
import socket
import threading
import time
from typing import Any
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


def redact(text: str) -> str:
    return _REDACT_RE.sub("[redacted]", text)


def configured_http_url(url: str | None) -> str | None:
    """Return a stripped http(s) URL that names a host, else None."""
    if url is None:
        return None
    # Reject control characters even before stripping; trailing CR/LF
    # would otherwise be hidden by strip() and allow injection payloads.
    if "\r" in url or "\n" in url or "\x00" in url:
        return None
    text = url.strip()
    if not text:
        return None
    if "\r" in text or "\n" in text or "\x00" in text:
        return None
    parsed = urllib_parse.urlparse(text)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if "@" in parsed.netloc:
        return None
    return text


def _origin(parsed: urllib_parse.ParseResult) -> tuple[str, str, int]:
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        raise RuntimeError("endpoint host is required")
    if scheme not in ("http", "https"):
        raise RuntimeError("unsupported scheme: %s" % parsed.scheme)
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port


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


_POST_OPENER = urllib_request.build_opener(_RefuseRedirect)


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


class SseMcpSession:
    """Minimal MCP client over legacy HTTP+SSE transport."""

    def __init__(self, base_url: str, timeout: float = MCP_CALL_TIMEOUT) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
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

    def connect(self) -> None:
        if self._connected:
            return
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
                "initialize failed: %s" % redact(json.dumps(init_result["error"]))
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
                "tools/list error: %s" % redact(json.dumps(result["error"]))
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
                "tools/call error: %s" % redact(json.dumps(result["error"]))
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
            "User-Agent": USER_AGENT,
        }
        if scheme == "https":
            import ssl

            ctx = ssl.create_default_context()
            self._conn = http.client.HTTPSConnection(
                host, port, timeout=self.timeout, context=ctx
            )
        else:
            self._conn = http.client.HTTPConnection(
                host, port, timeout=self.timeout
            )
        self._conn.request("GET", path, headers=headers)
        resp = self._conn.getresponse()
        self._resp = resp
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
                raise RuntimeError("SSE error: %s" % redact(str(msg.get("data"))))
        raise RuntimeError("timed out waiting for SSE endpoint event")

    def _resolve_endpoint(self) -> str:
        if not self._endpoint:
            raise RuntimeError("no SSE endpoint")
        return resolve_sse_endpoint(self.base_url, self._endpoint)

    def _post_raw(self, payload: dict[str, Any]) -> None:
        url = self._resolve_endpoint()
        body = json.dumps(payload).encode("utf-8")
        if len(body) > MAX_MCP_BYTES:
            raise RuntimeError("request exceeds MAX_MCP_BYTES")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": USER_AGENT,
        }
        req = urllib_request.Request(url, data=body, headers=headers, method="POST")
        try:
            with _POST_OPENER.open(req, timeout=self.timeout) as resp:
                total = 0
                while True:
                    chunk = resp.read(4096)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_MCP_BYTES:
                        raise RuntimeError("POST response exceeds MAX_MCP_BYTES")
        except HTTPError as exc:
            try:
                err_body = exc.read(2048).decode("utf-8", errors="replace")
            except OSError:
                err_body = str(exc)
            raise RuntimeError(
                "HTTP %s: %s" % (exc.code, redact(err_body[:800]))
            ) from exc
        except URLError as exc:
            raise RuntimeError("endpoint unreachable: %s" % redact(str(exc))) from exc

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
                        "SSE error: %s" % redact(str(msg.get("data")))
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
    returns ``Mcp-Session-Id`` it is echoed on later requests.
    """

    def __init__(self, base_url: str, timeout: float = MCP_CALL_TIMEOUT) -> None:
        validated = configured_http_url(base_url)
        if validated is None:
            raise RuntimeError("invalid streamable HTTP endpoint URL")
        self.base_url = validated.rstrip("/")
        self.timeout = timeout
        self._session_id: str | None = None
        self._rpc_id = 0

    def connect(self) -> None:
        if self._session_id is not None:
            return
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
            raise RuntimeError("tools/call error: %s" % redact(json.dumps(result)))
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
            "User-Agent": USER_AGENT,
        }
        if self._session_id is not None:
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib_request.Request(
            self.base_url, data=body, headers=headers, method="POST"
        )
        try:
            with _POST_OPENER.open(req, timeout=self.timeout) as resp:
                if resp.status == 202:
                    return None, resp.headers
                raw = resp.read(MAX_MCP_BYTES + 1)
                if len(raw) > MAX_MCP_BYTES:
                    raise RuntimeError("response exceeds MAX_MCP_BYTES")
                resp_headers = resp.headers
        except HTTPError as exc:
            try:
                err_body = exc.read(2048).decode("utf-8", errors="replace")
            except OSError:
                err_body = str(exc)
            raise RuntimeError(
                "HTTP %s: %s" % (exc.code, redact(err_body[:800]))
            ) from exc
        except URLError as exc:
            raise RuntimeError("endpoint unreachable: %s" % redact(str(exc))) from exc
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
                "%s error: %s" % (method, redact(json.dumps(msg["error"])))
            )
        return msg.get("result", msg), resp_headers
