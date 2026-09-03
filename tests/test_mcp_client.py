"""Shared MCP client (SSE + streamable HTTP) and policy base tests."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from extension.arms.burp import sse as burp_sse
from extension.arms.mcp_client import (
    MAX_MCP_BYTES,
    HttpTransportPolicy,
    SseMcpSession,
    StreamableHttpClient,
    redact,
)
from extension.arms.policy_base import ToolPolicy


# --- policy base --------------------------------------------------------


def test_tool_policy_ordering_and_messages() -> None:
    policy = ToolPolicy(allowed={"a_ok"}, blocked={"a_bad"})
    assert policy.refuse_reason("a_ok") is None
    # Shape first.
    assert policy.refuse_reason("a-ok!") == "invalid tool name: 'a-ok!'"
    # Explicit blocklist before allowlist misses.
    assert policy.refuse_reason("a_bad") == "tool 'a_bad' is blocked"
    # Allowlist miss last.
    assert policy.refuse_reason("a_other") == "tool 'a_other' is not on the allowlist"


def test_burp_sse_shim_reexports_shared_client() -> None:
    assert burp_sse.SseMcpSession is SseMcpSession
    assert burp_sse.redact is redact


# --- streamable HTTP client (hermetic) ----------------------------------


class _Handler(BaseHTTPRequestHandler):
    server_version = "stub-streamable/1.0"

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        msg = json.loads(body.decode("utf-8"))
        state["requests"].append(
            {
                "method": msg.get("method"),
                "session": self.headers.get("Mcp-Session-Id"),
            }
        )
        if msg.get("method") == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return
        rpc_id = msg.get("id")
        if msg.get("method") == "tools/call":
            name = (msg.get("params") or {}).get("name")
            if name == "sse_reply":
                payload = json.dumps(
                    {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": []}}
                )
                data = b"event: message\ndata: " + payload.encode("utf-8") + b"\n\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if name == "boom":
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"token abc secret bearer")
                return
            if name == "huge":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"x" * (MAX_MCP_BYTES + 1))
                return
            if name == "tool_error":
                payload = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {"isError": True, "content": []},
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
        if msg.get("method") == "tools/list":
            payload = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {"tools": [{"name": "semgrep_scan"}]},
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": []}}
        ).encode("utf-8")
        self.send_response(200)
        if msg.get("method") == "initialize":
            self.send_header("Mcp-Session-Id", "sess-1")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def streamable_server():
    state: dict[str, Any] = {"requests": []}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d/" % server.server_address[1], state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_streamable_client_json_roundtrip_and_session_echo(
    streamable_server: tuple[str, dict[str, Any]],
) -> None:
    url, state = streamable_server
    client = StreamableHttpClient(url, timeout=5, policy=HttpTransportPolicy.loopback())
    client.connect()
    assert client._session_id == "sess-1"
    tools = client.list_tools()
    assert tools == [{"name": "semgrep_scan"}]
    result = client.call_tool("semgrep_scan", {"config": "rules:"})
    assert result == {"content": []}
    client.close()
    # Session id echoed on requests after initialize; notification posted.
    methods = [req["method"] for req in state["requests"]]
    assert methods[0] == "initialize"
    assert "notifications/initialized" in methods
    posted = [req for req in state["requests"] if req["method"] != "initialize"]
    assert all(req["session"] == "sess-1" for req in posted)


def test_streamable_client_parses_sse_response(
    streamable_server: tuple[str, dict[str, Any]],
) -> None:
    url, _state = streamable_server
    client = StreamableHttpClient(url, timeout=5, policy=HttpTransportPolicy.loopback())
    client.connect()
    assert client.call_tool("sse_reply") == {"content": []}


def test_streamable_client_http_error_redacted(
    streamable_server: tuple[str, dict[str, Any]],
) -> None:
    url, _state = streamable_server
    client = StreamableHttpClient(url, timeout=5, policy=HttpTransportPolicy.loopback())
    client.connect()
    with pytest.raises(RuntimeError) as err:
        client.call_tool("boom")
    assert "[redacted]" in str(err.value)
    assert "token" not in str(err.value).lower()


def test_streamable_client_oversize_response_rejected(
    streamable_server: tuple[str, dict[str, Any]],
) -> None:
    url, _state = streamable_server
    client = StreamableHttpClient(url, timeout=5, policy=HttpTransportPolicy.loopback())
    client.connect()
    with pytest.raises(RuntimeError, match="exceeds MAX_MCP_BYTES"):
        client.call_tool("huge")


def test_streamable_client_tool_iserror_raises(
    streamable_server: tuple[str, dict[str, Any]],
) -> None:
    url, _state = streamable_server
    client = StreamableHttpClient(url, timeout=5, policy=HttpTransportPolicy.loopback())
    client.connect()
    with pytest.raises(RuntimeError, match="tools/call error"):
        client.call_tool("tool_error")


def test_streamable_client_refuses_invalid_url() -> None:
    """Constructor preflights the URL (CR/LF, scheme, userinfo)."""
    for bad in ("http://127.0.0.1:9/\r\nX: y", "ftp://x", "http://u:p@h", "not a url"):
        with pytest.raises(RuntimeError, match="invalid streamable HTTP endpoint"):
            StreamableHttpClient(bad)
