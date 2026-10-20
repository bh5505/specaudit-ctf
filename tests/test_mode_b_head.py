"""Alternative-head MCP lists and invokes the Burp stub. No live Burp."""

from __future__ import annotations

import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from typing import Any

import pytest

from extension.arms.burp import ARM_ID, BurpArm
from extension.arms.burp.policy import ENV_ENDPOINT
from extension.contract import Extension
from extension.mcp_server import TOOLS, McpServer
from tests.test_alt_head_mcp import _call, _content_json, _content_text

UNKNOWN_ID = "no-such-arm"


class _HitState:
    def __init__(self) -> None:
        self.http_hits = 0
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.responses: queue.Queue[dict[str, Any] | None] = queue.Queue()


def _make_hit_handler(state: _HitState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: Any) -> None:
            pass

        def do_GET(self) -> None:
            state.http_hits += 1
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(b"event: endpoint\ndata: /messages\n\n")
            self.wfile.flush()
            while True:
                try:
                    response = state.responses.get(timeout=0.2)
                except queue.Empty:
                    continue
                if response is None:
                    return
                frame = "event: message\ndata: %s\n\n" % json.dumps(response)
                try:
                    self.wfile.write(frame.encode())
                    self.wfile.flush()
                except OSError:
                    return

        def do_POST(self) -> None:
            state.http_hits += 1
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method = request.get("method")
            params = request.get("params", {})
            if method == "initialize":
                result: Any = {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "stub", "version": "1"},
                }
            elif method == "tools/list":
                result = {"tools": [{"name": "url_encode"}, {"name": "list_tools"}]}
            elif method == "tools/call":
                name = params.get("name")
                arguments = params.get("arguments", {})
                state.calls.append((str(name), dict(arguments)))
                result = {
                    "content": [{"type": "text", "text": json.dumps({"tool": name})}],
                    "isError": False,
                }
            else:
                result = {}
            if "id" in request:
                state.responses.put({"jsonrpc": "2.0", "id": request["id"], "result": result})
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()

    return Handler


@pytest.fixture
def stub_sse() -> Any:
    state = _HitState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_hit_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    url = "http://%s:%d" % (host, port)
    try:
        yield url, state
    finally:
        state.responses.put(None)
        server.shutdown()
        thread.join(timeout=2)


def _head(url: str) -> McpServer:
    return McpServer(
        extension=Extension(arms={ARM_ID: BurpArm(endpoint=url, timeout=5)})
    )


def test_head_tools_are_only_list_describe_invoke(
    stub_sse: tuple[str, _HitState],
) -> None:
    url, state = stub_sse
    response = _head(url).handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response is not None
    names = [tool["name"] for tool in response["result"]["tools"]]
    assert names == list(TOOLS)
    assert names == ["list", "describe", "invoke", "run_range"]
    assert state.http_hits == 0
    assert state.calls == []


def test_head_lists_and_describes_burp_without_dialing(
    stub_sse: tuple[str, _HitState],
) -> None:
    url, state = stub_sse
    server = _head(url)
    rows = _content_json(_call(server, "list"))
    burp = next(row for row in rows if row["id"] == ARM_ID)
    assert burp["kind"] == "arm"
    described = _content_json(_call(server, "describe", {"id": ARM_ID}))
    assert described["id"] == ARM_ID
    assert described["kind"] == "arm"
    assert state.http_hits == 0
    assert state.calls == []


def test_head_invoke_burp_reads_work_over_loopback(
    stub_sse: tuple[str, _HitState],
) -> None:
    """MCP head invocation reaches Burp and dials the loopback stub."""
    url, state = stub_sse
    server = _head(url)
    listed = _call(server, "invoke", {"id": ARM_ID, "action": "list_tools"})
    assert listed["result"]["isError"] is False
    result = _content_json(listed)
    assert result["ok"] is True
    assert result["arm_id"] == ARM_ID
    assert result["action"] == "list_tools"
    assert result["output"] is not None
    # The SSE endpoint was really dialed.
    assert state.http_hits >= 1


def test_head_stdio_list_and_invoke_burp_stub(
    stub_sse: tuple[str, _HitState],
) -> None:
    url, state = stub_sse
    server = _head(url)
    stdin = StringIO(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "list", "arguments": {}},
            }
        )
        + "\n"
        + json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "invoke",
                    "arguments": {
                        "id": ARM_ID,
                        "action": "url_encode",
                        "args": {"content": "a b"},
                    },
                },
            }
        )
        + "\n"
    )
    stdout = StringIO()
    assert server.serve(stdin=stdin, stdout=stdout) == 0
    lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
    assert len(lines) == 2
    rows = json.loads(json.loads(lines[0])["result"]["content"][0]["text"])
    assert any(
        row["id"] == ARM_ID and row["kind"] == "arm"
        for row in rows
    )
    invoked = json.loads(lines[1])
    assert invoked["result"]["isError"] is False
    result = _content_json(invoked)
    assert result["ok"] is True
    assert result["arm_id"] == ARM_ID
    assert result["action"] == "url_encode"
    assert result["output"] is not None
    assert state.http_hits >= 1
    assert state.calls  # through the hardened transport


def test_head_default_extension_uses_env_stub(
    stub_sse: tuple[str, _HitState],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, state = stub_sse
    monkeypatch.setenv(ENV_ENDPOINT, url)
    server = McpServer(extension=Extension())
    response = _call(server, "invoke", {"id": ARM_ID, "action": "list_tools"})
    assert response["result"]["isError"] is False
    assert _content_json(response)["ok"] is True
    assert state.http_hits >= 1  # dialed through the hardened transport


def test_head_invoke_unknown_id_does_not_dial_stub(
    stub_sse: tuple[str, _HitState],
) -> None:
    url, state = stub_sse
    response = _call(_head(url), "invoke", {"id": UNKNOWN_ID, "action": "list_tools"})
    assert response["result"]["isError"] is True
    payload = json.loads(_content_text(response))
    assert payload["ok"] is False
    assert payload["arm_id"] == UNKNOWN_ID
    assert isinstance(payload["error"], str)
    assert state.http_hits == 0
    assert state.calls == []
