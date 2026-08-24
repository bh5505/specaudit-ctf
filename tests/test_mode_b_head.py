"""Alternative-head MCP lists and invokes the Burp stub. No live Burp."""

from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from io import StringIO
from typing import Any

import pytest

from extension.arms.burp import ARM_ID, BurpArm
from extension.arms.burp.policy import ENV_ENDPOINT
from extension.contract import Extension
from extension.mcp_server import TOOLS, McpServer
from tests.test_alt_head_mcp import _call, _content_json, _content_text
from tests.test_arm_burp import _StubState, _make_handler
from tests.test_contract import UNKNOWN_ID


class _HitState(_StubState):
    def __init__(self) -> None:
        super().__init__()
        self.http_hits = 0


def _make_hit_handler(state: _HitState) -> type:
    inner = _make_handler(state)

    class Handler(inner):
        def do_GET(self) -> None:
            state.http_hits += 1
            super().do_GET()

        def do_POST(self) -> None:
            state.http_hits += 1
            super().do_POST()

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


def test_head_lists_and_describes_curated_burp_without_dialing(
    stub_sse: tuple[str, _HitState],
) -> None:
    url, state = stub_sse
    server = _head(url)
    rows = _content_json(_call(server, "list"))
    burp = next(row for row in rows if row["id"] == ARM_ID)
    assert burp["kind"] == "arm"
    assert burp["curated"] is True
    described = _content_json(_call(server, "describe", {"id": ARM_ID}))
    assert described["id"] == ARM_ID
    assert described["curated"] is True
    assert state.http_hits == 0
    assert state.calls == []


def test_head_invokes_burp_stub(
    stub_sse: tuple[str, _HitState],
) -> None:
    url, state = stub_sse
    server = _head(url)
    listed = _call(server, "invoke", {"id": ARM_ID, "action": "list_tools"})
    assert listed["result"]["isError"] is False
    listed_payload = _content_json(listed)
    assert listed_payload["ok"] is True
    assert listed_payload["arm_id"] == ARM_ID
    assert listed_payload["output"]["edition"] == "professional"

    encoded = _call(
        server,
        "invoke",
        {"id": ARM_ID, "action": "url_encode", "args": {"content": "a b"}},
    )
    assert encoded["result"]["isError"] is False
    encoded_payload = _content_json(encoded)
    assert encoded_payload["ok"] is True
    assert encoded_payload["output"]["data"] == "a+b"
    assert state.http_hits > 0
    assert ("url_encode", {"content": "a b"}) in state.calls


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
    assert any(row["id"] == ARM_ID and row["curated"] is True for row in rows)
    invoked = json.loads(json.loads(lines[1])["result"]["content"][0]["text"])
    assert invoked["ok"] is True
    assert invoked["output"]["data"] == "a+b"
    assert state.http_hits > 0
    assert ("url_encode", {"content": "a b"}) in state.calls


def test_head_default_extension_uses_env_stub(
    stub_sse: tuple[str, _HitState],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, state = stub_sse
    monkeypatch.setenv(ENV_ENDPOINT, url)
    server = McpServer(extension=Extension())
    result = _content_json(_call(server, "invoke", {"id": ARM_ID, "action": "list_tools"}))
    assert result["ok"] is True
    assert result["output"]["edition"] == "professional"
    assert state.http_hits > 0


def test_head_invoke_unknown_id_does_not_dial_stub(
    stub_sse: tuple[str, _HitState],
) -> None:
    url, state = stub_sse
    response = _call(_head(url), "invoke", {"id": UNKNOWN_ID, "action": "list_tools"})
    assert response["result"]["isError"] is True
    assert "unknown id" in _content_text(response).lower()
    assert state.http_hits == 0
    assert state.calls == []
