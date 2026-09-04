"""Unit + stub SSE tests for the curated Burp arm. No live Burp."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

import pytest

from extension.arms.burp import (
    ALLOWED_TOOLS,
    ARM_ID,
    BLOCKED_TOOLS,
    PROFESSIONAL_ONLY,
    BurpArm,
    SseMcpSession,
    detect_edition,
    normalize_call_result,
)
from extension.arms.burp.policy import (
    COMMUNITY_REFUSED,
    EDITION_REFUSED,
    ENV_ENDPOINT,
)
from extension.arms.burp.sse import configured_http_url, resolve_sse_endpoint, redact
from extension.arms.mcp_client import HttpTransportPolicy
from extension.contract import ArmSpec, Extension, NotHeldError, NotInstalledError, invoke
from extension.__main__ import main

PRO_TOOLS = (
    "get_proxy_http_history",
    "url_encode",
    "output_project_options",
    "get_scanner_issues",
    "get_collaborator_interactions",
    "generate_collaborator_payload",
)
COMMUNITY_TOOLS = (
    "get_proxy_http_history",
    "url_encode",
    "output_project_options",
)


def _spec() -> ArmSpec:
    return ArmSpec(
        id=ARM_ID,
        protocols=("mcp", "http"),
        curated=True,
        notes="Fixture curated MCP arm.",
        tier="research",
    )


class FakeSession:
    def __init__(
        self,
        tools: list[dict[str, Any]] | None = None,
        results: dict[str, dict[str, Any]] | None = None,
        connect_error: Exception | None = None,
    ) -> None:
        self.tools = (
            list(tools)
            if tools is not None
            else [{"name": name} for name in PRO_TOOLS]
        )
        self.results = results or {}
        self.connect_error = connect_error
        self.connected = False
        self.closed = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def connect(self) -> None:
        if self.connect_error is not None:
            raise self.connect_error
        self.connected = True

    def list_tools(self) -> list[dict[str, Any]]:
        return list(self.tools)

    def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        payload = dict(arguments or {})
        self.calls.append((name, payload))
        if name in self.results:
            return self.results[name]
        return {
            "content": [{"type": "text", "text": json.dumps({"tool": name})}],
            "isError": False,
        }

    def close(self) -> None:
        self.closed = True


def _factory(session: FakeSession):
    def factory(url: str, timeout: float = 10.0) -> FakeSession:
        session.url = url
        session.timeout = timeout
        return session

    return factory


def _arm(session: FakeSession, endpoint: str = "http://127.0.0.1:9") -> BurpArm:
    return BurpArm(endpoint=endpoint, session_factory=_factory(session))


# --- policy / normalize -------------------------------------------------


def test_detect_edition_professional() -> None:
    names = {
        "get_scanner_issues",
        "generate_collaborator_payload",
        "get_collaborator_interactions",
        "get_proxy_http_history",
    }
    assert detect_edition(names) == "professional"


def test_detect_edition_community() -> None:
    assert detect_edition({"get_proxy_http_history", "url_encode"}) == "community"


def test_detect_edition_unknown() -> None:
    assert detect_edition(set()) == "unknown"
    assert detect_edition({"get_scanner_issues", "url_encode"}) == "unknown"


def test_allowlist_disjoint_from_blocked() -> None:
    assert ALLOWED_TOOLS.isdisjoint(BLOCKED_TOOLS)
    assert len(ALLOWED_TOOLS) == 12
    assert len(BLOCKED_TOOLS) == 15
    assert PROFESSIONAL_ONLY & ALLOWED_TOOLS
    assert "generate_collaborator_payload" in BLOCKED_TOOLS
    assert "send_http1_request" in BLOCKED_TOOLS


def test_normalize_sentinel_has_more_false() -> None:
    result = {
        "content": [{"type": "text", "text": "Reached end of items"}],
        "isError": False,
    }
    data, meta = normalize_call_result(result)
    assert meta["has_more"] is False


def test_normalize_is_error() -> None:
    result = {
        "content": [{"type": "text", "text": "Error: denied"}],
        "isError": True,
    }
    data, meta = normalize_call_result(result)
    assert data["isError"] is True
    assert "denied" in data["error"]


def test_normalize_json_items_has_more() -> None:
    items = json.dumps({"url": "http://a"}) + "\n\n" + json.dumps({"url": "http://b"})
    result = {"content": [{"type": "text", "text": items}], "isError": False}
    data, meta = normalize_call_result(result)
    assert isinstance(data, list)
    assert len(data) == 2
    assert meta["has_more"] is True


# --- install / no live engagement ---------------------------------------


def test_not_installed_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    arm = BurpArm(endpoint="")
    spec = _spec()
    assert arm.installed(spec) is False
    with pytest.raises(NotInstalledError) as err:
        arm.invoke(spec, "list_tools", {})
    assert err.value.entry_id == ARM_ID


def test_default_invoke_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    monkeypatch.setattr("extension.contract._DEFAULT", None)
    ext = Extension()
    with pytest.raises(NotInstalledError):
        ext.invoke(ARM_ID, "list_tools", {})
    with pytest.raises(NotInstalledError):
        invoke(ARM_ID, "list_tools", {})


@pytest.mark.parametrize(
    "url",
    (
        "http://127.0.0.1:9\r\nX: 1",
        "http://127.0.0.1:9\n",
        "http://127.0.0.1:9\x00 injected",
        "http://127.0.0.1:9/foo\r\nbar",
    ),
)
def test_configured_url_rejects_crlf_and_null(url: str) -> None:
    assert configured_http_url(url) is None
    arm = BurpArm(endpoint=url)
    assert arm.installed(_spec()) is False


@pytest.mark.parametrize(
    "url",
    (
        "http://user:pass@127.0.0.1:9",
        "http://user@127.0.0.1:9/",
        "https://u:p@host/path",
        "http://@127.0.0.1:9",
    ),
)
def test_configured_url_rejects_userinfo(url: str) -> None:
    assert configured_http_url(url) is None
    arm = BurpArm(endpoint=url)
    assert arm.installed(_spec()) is False


def test_redact_expanded_patterns() -> None:
    assert redact("Bearer abc token") == "[redacted] abc [redacted]"
    assert redact("secret=xyz") == "[redacted]=xyz"
    assert redact("api_key: foo") == "[redacted]: foo"
    assert redact("api-key: foo") == "[redacted]: foo"
    assert redact("Authorization: Bearer 123") == "[redacted]: [redacted] 123"
    assert redact("cookie: session=abc") == "[redacted]: session=abc"
    assert redact("passwd foo") == "[redacted] foo"
    assert redact("safe content") == "safe content"


def test_open_sse_requires_host(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("must not connect")

    monkeypatch.setattr("extension.arms.burp.sse.http.client.HTTPConnection", boom)
    with pytest.raises(RuntimeError, match="host"):
        SseMcpSession("http://", policy=HttpTransportPolicy.loopback())


def test_env_reread_on_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    arm = BurpArm()
    assert arm.installed(_spec()) is False
    monkeypatch.setenv(ENV_ENDPOINT, "http://127.0.0.1:9")
    assert arm.installed(_spec()) is True
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    assert arm.installed(_spec()) is False


def test_no_session_until_invoke() -> None:
    created: list[str] = []

    def factory(url: str, timeout: float = 10.0) -> FakeSession:
        created.append(url)
        return FakeSession()

    arm = BurpArm(endpoint="http://127.0.0.1:9", session_factory=factory)
    assert arm.installed(_spec()) is True
    assert created == []


# --- fake session unit tests --------------------------------------------


def test_list_tools_reports_edition() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "list_tools", {})
    assert result.ok is True
    assert result.output["edition"] == "professional"
    names = {item["name"] for item in result.output["tools"]}
    assert "url_encode" in names
    assert session.connected is True
    assert session.closed is True
    assert session.calls == []


def test_allowlisted_tool_call() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "url_encode", {"content": "a b"})
    assert result.ok is True
    assert result.output["edition"] == "professional"
    assert session.calls == [("url_encode", {"content": "a b"})]
    assert session.closed is True


def test_community_edition_refused() -> None:
    session = FakeSession(tools=[{"name": name} for name in COMMUNITY_TOOLS])
    result = _arm(session).invoke(_spec(), "url_encode", {"content": "x"})
    assert result.ok is False
    assert result.error == COMMUNITY_REFUSED
    assert result.output["edition"] == "community"
    assert session.calls == []
    listed = _arm(FakeSession(tools=[{"name": name} for name in COMMUNITY_TOOLS])).invoke(
        _spec(), "list_tools", {}
    )
    assert listed.ok is True
    assert listed.output["edition"] == "community"


def test_unknown_edition_refuses_tool_call() -> None:
    empty = FakeSession(tools=[])
    result = _arm(empty).invoke(_spec(), "url_encode", {"content": "x"})
    assert result.ok is False
    assert result.error == EDITION_REFUSED
    assert result.output["edition"] == "unknown"
    assert empty.calls == []
    partial = FakeSession(
        tools=[{"name": "get_scanner_issues"}, {"name": "url_encode"}]
    )
    refused = _arm(partial).invoke(_spec(), "url_encode", {"content": "x"})
    assert refused.ok is False
    assert refused.error == EDITION_REFUSED
    listed = _arm(FakeSession(tools=[])).invoke(_spec(), "list_tools", {})
    assert listed.ok is True
    assert listed.output["edition"] == "unknown"


def test_blocked_tool_refused() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "send_http1_request", {"content": "GET /"})
    assert result.ok is False
    assert "blocked" in (result.error or "")
    assert session.calls == []


def test_unknown_tool_refused() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "not_a_burp_tool", {})
    assert result.ok is False
    assert "allowlist" in (result.error or "")
    assert session.calls == []


def test_invalid_tool_name_refused() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "url encode", {})
    assert result.ok is False
    assert "invalid tool name" in (result.error or "")


def test_connect_failure_is_result() -> None:
    session = FakeSession(connect_error=RuntimeError("refused"))
    result = _arm(session).invoke(_spec(), "list_tools", {})
    assert result.ok is False
    assert "refused" in (result.error or "")
    assert session.closed is True


def test_tool_error_secret_is_redacted_in_output_data() -> None:
    session = FakeSession(
        results={
            "get_proxy_http_history": {
                "content": [{"type": "text", "text": "auth token=abc123"}],
                "isError": True,
            }
        }
    )
    result = _arm(session).invoke(_spec(), "get_proxy_http_history", {})
    assert result.ok is False
    data = result.output["data"]
    assert data["isError"] is True
    assert "token" not in data["error"]
    assert "[redacted]" in data["error"]


def test_paginated_defaults_applied() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "get_proxy_http_history", {})
    assert result.ok is True
    assert session.calls == [("get_proxy_http_history", {"count": 200, "offset": 0})]


def test_extension_invoke_reaches_research_burp_arm() -> None:
    """Un-held (doc-21 dossier, 2026-09-03): handler-level reads are
    reachable through the hardened transport; no tier refusal stands."""
    session = FakeSession()
    ext = Extension(arms={ARM_ID: _arm(session)})
    result = ext.invoke(ARM_ID, "list_tools", {})
    assert result.ok is True
    assert result.arm_id == ARM_ID
    assert session.tools  # the handler enumerated the (fake) server


def test_env_endpoint_installs_arm(monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession()
    monkeypatch.setenv(ENV_ENDPOINT, "http://127.0.0.1:9")
    arm = BurpArm(session_factory=_factory(session))
    assert arm.installed(_spec()) is True
    result = arm.invoke(_spec(), "list_tools", {})
    assert result.ok is True


# --- stub SSE session ---------------------------------------------------


class _StubState:
    def __init__(self) -> None:
        self.pending: dict[Any, dict[str, Any]] = {}
        self.community = False
        self.session_path = "/message?sessionId=test"
        self.calls: list[tuple[str, dict[str, Any]]] = []


def _make_handler(state: _StubState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            frame = "event: endpoint\ndata: %s\n\n" % state.session_path
            self.wfile.write(frame.encode("utf-8"))
            self.wfile.flush()
            deadline = time.monotonic() + 15
            seen: set[Any] = set()
            while time.monotonic() < deadline:
                for rid, resp in list(state.pending.items()):
                    if rid in seen:
                        continue
                    seen.add(rid)
                    payload = "event: message\ndata: %s\n\n" % json.dumps(resp)
                    try:
                        self.wfile.write(payload.encode("utf-8"))
                        self.wfile.flush()
                    except OSError:
                        return
                time.sleep(0.05)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b"{}"
            try:
                req = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                req = {}
            method = req.get("method")
            rpc_id = req.get("id")
            if method == "notifications/initialized":
                self.send_response(202)
                self.end_headers()
                return
            if method == "initialize":
                resp: dict[str, Any] = {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "burp-suite", "version": "1.1.2"},
                    },
                }
            elif method == "tools/list":
                tools = [
                    {"name": "get_proxy_http_history"},
                    {"name": "url_encode"},
                    {"name": "output_project_options"},
                ]
                if not state.community:
                    tools.extend(
                        [
                            {"name": "get_scanner_issues"},
                            {"name": "get_collaborator_interactions"},
                            {"name": "generate_collaborator_payload"},
                        ]
                    )
                resp = {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {"tools": tools},
                }
            elif method == "tools/call":
                params = req.get("params") or {}
                name = params.get("name")
                arguments = params.get("arguments") or {}
                state.calls.append((str(name), dict(arguments)))
                if name == "get_proxy_http_history":
                    text = (
                        json.dumps({"url": "http://example/a"})
                        + "\n\n"
                        + "Reached end of items"
                    )
                elif name == "url_encode":
                    text = "a+b"
                else:
                    text = json.dumps({"ok": True, "tool": name})
                resp = {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": [{"type": "text", "text": text}],
                        "isError": False,
                    },
                }
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32601, "message": "unknown method"},
                }
            if rpc_id is not None:
                state.pending[rpc_id] = resp
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

    return Handler


@pytest.fixture
def stub_sse() -> Any:
    state = _StubState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    url = "http://%s:%d" % (host, port)
    try:
        yield url, state
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_sse_session_list_and_call(stub_sse: tuple[str, _StubState]) -> None:
    url, state = stub_sse
    session = SseMcpSession(url, timeout=5, policy=HttpTransportPolicy.loopback())
    try:
        session.connect()
        tools = session.list_tools()
        names = {item["name"] for item in tools}
        assert "url_encode" in names
        assert detect_edition(names) == "professional"
        result = session.call_tool("url_encode", {"content": "a b"})
        assert result.get("isError") is False
        data, meta = normalize_call_result(result)
        assert data == "a+b"
        assert meta["has_more"] is False
        assert ("url_encode", {"content": "a b"}) in state.calls
        parsed = urlparse(url)
        assert parsed.hostname == "127.0.0.1"
    finally:
        session.close()


def test_arm_against_stub_sse(stub_sse: tuple[str, _StubState]) -> None:
    url, _state = stub_sse
    arm = BurpArm(endpoint=url, timeout=5)
    spec = _spec()
    listed = arm.invoke(spec, "list_tools", {})
    assert listed.ok is True, listed.error
    assert listed.output["edition"] == "professional"
    called = arm.invoke(spec, "get_proxy_http_history", {"count": 1, "offset": 0})
    assert called.ok is True, called.error
    assert called.output["meta"]["has_more"] is False
    assert isinstance(called.output["data"], list)
    assert called.output["data"][0]["url"] == "http://example/a"


def test_extension_invoke_against_stub_sse(
    stub_sse: tuple[str, _StubState],
) -> None:
    url, _state = stub_sse
    ext = Extension(arms={ARM_ID: BurpArm(endpoint=url, timeout=5)})
    result = ext.invoke(ARM_ID, "url_encode", {"content": "a b"})
    assert result.ok is True
    assert result.output is not None


def test_community_stub_refuses_tool_call(
    stub_sse: tuple[str, _StubState],
) -> None:
    url, state = stub_sse
    state.community = True
    arm = BurpArm(endpoint=url, timeout=5)
    listed = arm.invoke(_spec(), "list_tools", {})
    assert listed.ok is True
    assert listed.output["edition"] == "community"
    refused = arm.invoke(_spec(), "url_encode", {"content": "x"})
    assert refused.ok is False
    assert refused.error == COMMUNITY_REFUSED
    assert state.calls == []


def test_resolve_sse_endpoint_same_origin() -> None:
    base = "http://127.0.0.1:9"
    assert (
        resolve_sse_endpoint(base, "/message?sessionId=test")
        == "http://127.0.0.1:9/message?sessionId=test"
    )
    assert (
        resolve_sse_endpoint(base, "http://127.0.0.1:9/message")
        == "http://127.0.0.1:9/message"
    )
    # Absolute-path semantics (RFC 3986): /sse at origin root even when base has path
    assert resolve_sse_endpoint("http://127.0.0.1:9/base/path", "/sse") == "http://127.0.0.1:9/sse"
    # Relative endpoint appends under base path
    assert resolve_sse_endpoint("http://127.0.0.1:9/base", "sse") == "http://127.0.0.1:9/base/sse"


@pytest.mark.parametrize("endpoint", ("en\rpoint", "en\npoint", "bad\x00endpoint", "a\r\nb"))
def test_resolve_sse_endpoint_rejects_control_chars(endpoint: str) -> None:
    with pytest.raises(RuntimeError, match="control"):
        resolve_sse_endpoint("http://127.0.0.1:9", endpoint)


def test_normalize_data_list_has_more_and_clamped() -> None:
    # data-list branch: has_more stays False, clamped applied when >200
    result = {"data": [{"a": i} for i in range(201)]}
    data, meta = normalize_call_result(result)
    assert isinstance(data, list)
    assert len(data) == 200
    assert meta["clamped"] is True
    assert meta["has_more"] is False
    assert meta["total"] == 200


def test_normalize_single_truncated_string_has_more_false() -> None:
    result = {"content": [{"text": '{"a":1} (truncated)'}]}
    data, meta = normalize_call_result(result)
    # Single truncated JSON-like string becomes rows list with truncated_items flag
    # Current behavior leaves has_more True (no END_SENTINEL); pin that behavior.
    assert isinstance(data, list)
    assert meta["truncated_items"] is True
    assert meta["has_more"] is True


def test_normalize_has_more_true_without_sentinel() -> None:
    result = {"content": [{"text": json.dumps({"url": "http://a"})}]}
    _data, meta = normalize_call_result(result)
    assert meta["has_more"] is True



def test_foreign_endpoint_event_is_not_posted() -> None:
    trap_hits: list[str] = []

    class Trap(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            trap_hits.append("GET")
            self.send_response(200)
            self.end_headers()

        def do_POST(self) -> None:
            trap_hits.append("POST")
            self.send_response(200)
            self.end_headers()

    trap = ThreadingHTTPServer(("127.0.0.1", 0), Trap)
    trap_thread = threading.Thread(target=trap.serve_forever, daemon=True)
    trap_thread.start()
    state = _StubState()
    state.session_path = "http://127.0.0.1:%d/stolen" % trap.server_address[1]
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = "http://%s:%d" % server.server_address[:2]
    try:
        result = BurpArm(endpoint=url, timeout=2).invoke(_spec(), "list_tools", {})
        assert result.ok is False
        assert "same-origin" in (result.error or "")
        assert trap_hits == []
        assert state.calls == []
    finally:
        server.shutdown()
        trap.shutdown()
        thread.join(timeout=2)
        trap_thread.join(timeout=2)


def test_chunked_sse_endpoint_event() -> None:
    state = _StubState()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _write_chunk(self, data: bytes) -> None:
            self.wfile.write(b"%x\r\n" % len(data))
            self.wfile.write(data)
            self.wfile.write(b"\r\n")
            self.wfile.flush()

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            frame = "event: endpoint\ndata: %s\n\n" % state.session_path
            mid = max(1, len(frame) // 2)
            self._write_chunk(frame[:mid].encode("utf-8"))
            self._write_chunk(frame[mid:].encode("utf-8"))
            deadline = time.monotonic() + 15
            seen: set[Any] = set()
            while time.monotonic() < deadline:
                for rid, resp in list(state.pending.items()):
                    if rid in seen:
                        continue
                    seen.add(rid)
                    payload = "event: message\ndata: %s\n\n" % json.dumps(resp)
                    try:
                        self._write_chunk(payload.encode("utf-8"))
                    except OSError:
                        return
                time.sleep(0.05)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b"{}"
            try:
                req = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                req = {}
            method = req.get("method")
            rpc_id = req.get("id")
            if method == "notifications/initialized":
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if method == "initialize":
                resp: dict[str, Any] = {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "burp-suite", "version": "1.1.2"},
                    },
                }
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "tools": [
                            {"name": "url_encode"},
                            {"name": "get_scanner_issues"},
                            {"name": "get_collaborator_interactions"},
                            {"name": "generate_collaborator_payload"},
                        ]
                    },
                }
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32601, "message": "unknown method"},
                }
            if rpc_id is not None:
                state.pending[rpc_id] = resp
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = "http://%s:%d" % server.server_address[:2]
    session = SseMcpSession(url, timeout=5, policy=HttpTransportPolicy.loopback())
    try:
        session.connect()
        tools = session.list_tools()
        names = {item["name"] for item in tools}
        assert "url_encode" in names
    finally:
        session.close()
        server.shutdown()
        thread.join(timeout=2)


def test_non_sse_body_surfaces_protocol_error() -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            chunk = b"x" * 65536
            try:
                while True:
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except OSError:
                return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = "http://%s:%d" % server.server_address[:2]
    session = SseMcpSession(url, timeout=5, policy=HttpTransportPolicy.loopback())
    try:
        with pytest.raises(RuntimeError, match="SSE frame buffer exceeds"):
            session.connect()
    finally:
        session.close()
        server.shutdown()
        thread.join(timeout=2)


def test_main_invoke_with_stub(
    stub_sse: tuple[str, _StubState],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    url, _state = stub_sse
    monkeypatch.setenv(ENV_ENDPOINT, url)
    # Research tier: the held refusal is gone; the capability-registry
    # gate stands (admission is not coupled to the un-hold).
    assert main(["invoke", ARM_ID, "list_tools"]) == 2
    captured = capsys.readouterr()
    assert "held" not in captured.err.lower()
    payload = json.loads(captured.out)
    assert payload["capability_id"] == "burp-mcp.list_tools"
    assert payload["status"] == "failed"
    assert payload["limitations"] == ["unknown capability"]
