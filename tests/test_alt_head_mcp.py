"""Alternative-head MCP surface: list, describe, invoke, run_range."""

from __future__ import annotations

import json
import subprocess
import sys
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from extension.contract import Extension
from extension.mcp_server import TOOLS, _MAX_BYTES, McpServer, main
from extension.range import DEFAULT_SEED, SCHEMA_ID
from tests.test_contract import (
    CURATED_ARM_ID,
    FIXTURE_ARM_ID,
    METHODOLOGY_ID,
    UNKNOWN_ID,
    FakeCliTransport,
    _fixture_catalog,
)

ROOT = Path(__file__).resolve().parents[1]
HEADS = ROOT / "extension" / "heads"


def _server(fake: FakeCliTransport | None = None) -> tuple[McpServer, FakeCliTransport]:
    transport = fake or FakeCliTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": transport},
        arms={FIXTURE_ARM_ID: transport},
    )
    return McpServer(extension=ext), transport


def _content_text(response: dict[str, Any]) -> str:
    content = response["result"]["content"]
    assert content
    return str(content[0]["text"])


def _content_json(response: dict[str, Any]) -> Any:
    return json.loads(_content_text(response))


def _call(
    server: McpServer, name: str, arguments: dict[str, Any] | None = None, *, req_id: int = 1
) -> dict[str, Any]:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    assert response is not None
    return response


def test_tools_list_is_only_list_describe_invoke() -> None:
    server, _ = _server()
    response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response is not None
    names = [tool["name"] for tool in response["result"]["tools"]]
    assert names == list(TOOLS)
    assert names == ["list", "describe", "invoke", "run_range"]


def test_mcp_list_and_invoke_use_fake_transport() -> None:
    server, fake = _server()
    listed = _call(server, "list")
    assert listed["result"]["isError"] is False
    rows = _content_json(listed)
    assert any(row["id"] == FIXTURE_ARM_ID for row in rows)

    described = _call(server, "describe", {"id": FIXTURE_ARM_ID})
    assert _content_json(described)["id"] == FIXTURE_ARM_ID

    invoked = _call(
        server, "invoke", {"id": FIXTURE_ARM_ID, "action": "echo", "args": {"x": 1}}
    )
    result = _content_json(invoked)
    assert invoked["result"]["isError"] is False
    assert result["ok"] is True
    assert result["arm_id"] == FIXTURE_ARM_ID
    assert result["action"] == "echo"
    assert result["output"] == {"echo": {"x": 1}}
    assert fake.calls == [(FIXTURE_ARM_ID, "echo", {"x": 1})]


def test_mcp_invoke_unknown_id_is_tool_error() -> None:
    server, fake = _server()
    response = _call(server, "invoke", {"id": UNKNOWN_ID, "action": "ping"})
    assert "error" not in response
    assert response["result"]["isError"] is True
    assert "unknown id" in _content_text(response).lower()
    assert fake.calls == []


def test_mcp_invoke_methodology_only_does_not_call_transport() -> None:
    fake = FakeCliTransport(installed_ids={METHODOLOGY_ID})
    server, _ = _server(fake)
    response = _call(server, "invoke", {"id": METHODOLOGY_ID, "action": "extract"})
    assert response["result"]["isError"] is True
    assert "not an arm" in _content_text(response).lower()
    assert fake.calls == []


def test_mcp_invoke_missing_action_is_invalid_params() -> None:
    server, fake = _server()
    response = _call(server, "invoke", {"id": FIXTURE_ARM_ID})
    assert response["error"]["code"] == -32602
    assert "action" in response["error"]["message"].lower()
    assert fake.calls == []


def test_mcp_invoke_non_mapping_args_is_invalid_params() -> None:
    server, fake = _server()
    response = _call(
        server, "invoke", {"id": FIXTURE_ARM_ID, "action": "echo", "args": "nope"}
    )
    assert response["error"]["code"] == -32602
    assert "args" in response["error"]["message"].lower()
    assert fake.calls == []


def test_unknown_tool_and_inventory_methods_are_rejected() -> None:
    server, fake = _server()
    unknown = _call(server, "inventory")
    assert unknown["error"]["code"] == -32602
    assert "unknown tool" in unknown["error"]["message"]
    for method in ("resources/list", "resources/read", "inventory/list"):
        response = server.handle({"jsonrpc": "2.0", "id": 7, "method": method})
        assert response is not None
        assert response["error"]["code"] == -32601
    assert fake.calls == []


def test_initialize_advertises_tools_only() -> None:
    server, _ = _server()
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
        }
    )
    assert response is not None
    assert response["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert response["result"]["serverInfo"]["name"] == "specaudit-ctf"
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_serve_ndjson_list_and_invoke() -> None:
    server, fake = _server()
    stdin = StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        + "\n"
        + json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "invoke",
                    "arguments": {"id": FIXTURE_ARM_ID, "action": "echo", "args": {"n": 2}},
                },
            }
        )
        + "\n"
    )
    stdout = StringIO()
    assert server.serve(stdin=stdin, stdout=stdout) == 0
    lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
    assert len(lines) == 2
    listed = json.loads(lines[0])
    assert [tool["name"] for tool in listed["result"]["tools"]] == list(TOOLS)
    invoked = json.loads(lines[1])
    payload = json.loads(invoked["result"]["content"][0]["text"])
    assert payload["ok"] is True
    assert fake.calls == [(FIXTURE_ARM_ID, "echo", {"n": 2})]


def test_serve_invalid_content_length_is_framed_parse_error() -> None:
    server, _ = _server()
    stdin = StringIO("Content-Length: abc\r\n\r\n")
    stdout = StringIO()
    assert server.serve(stdin=stdin, stdout=stdout) == 0
    raw = stdout.getvalue()
    assert raw.lower().startswith("content-length:")
    response = json.loads(raw.split("\r\n\r\n", 1)[1])
    assert response["error"]["code"] == -32700
    assert "content-length" in response["error"]["message"].lower()


def test_serve_oversized_content_length_rejected_before_body() -> None:
    server, _ = _server()
    stdin = StringIO(f"Content-Length: {_MAX_BYTES + 1}\r\n\r\n")
    stdout = StringIO()
    assert server.serve(stdin=stdin, stdout=stdout) == 0
    raw = stdout.getvalue()
    assert raw.lower().startswith("content-length:")
    response = json.loads(raw.split("\r\n\r\n", 1)[1])
    assert response["error"]["code"] == -32700
    assert "exceeds" in response["error"]["message"].lower()


def test_serve_bad_ndjson_is_parse_error() -> None:
    server, _ = _server()
    stdin = StringIO("{not-json\n")
    stdout = StringIO()
    assert server.serve(stdin=stdin, stdout=stdout) == 0
    raw = stdout.getvalue()
    assert not raw.lower().startswith("content-length:")
    response = json.loads(raw.strip())
    assert response["error"]["code"] == -32700


def test_serve_content_length_tools_call_list() -> None:
    server, _ = _server()
    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "list", "arguments": {}},
        }
    )
    stdin = StringIO(f"Content-Length: {len(request)}\r\n\r\n{request}")
    stdout = StringIO()
    assert server.serve(stdin=stdin, stdout=stdout) == 0
    raw = stdout.getvalue()
    assert raw.lower().startswith("content-length:")
    body = raw.split("\r\n\r\n", 1)[1]
    response = json.loads(body)
    rows = json.loads(response["result"]["content"][0]["text"])
    assert any(row["id"] == FIXTURE_ARM_ID for row in rows)


def test_module_mcp_list() -> None:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "extension.mcp_server"],
        cwd=ROOT,
        input=payload,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=15,
    )
    assert proc.returncode == 0, proc.stderr
    line = next(item for item in proc.stdout.splitlines() if item.strip().startswith("{"))
    body = json.loads(line)
    names = [tool["name"] for tool in body["result"]["tools"]]
    assert names == ["list", "describe", "invoke", "run_range"]


def test_module_mcp_invoke_live_catalog_not_installed() -> None:
    payload = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "invoke",
                    "arguments": {"id": CURATED_ARM_ID, "action": "list_tools"},
                },
            }
        )
        + "\n"
    )
    proc = subprocess.run(
        [sys.executable, "-m", "extension.mcp_server"],
        cwd=ROOT,
        input=payload,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=15,
    )
    assert proc.returncode == 0, proc.stderr
    line = next(item for item in proc.stdout.splitlines() if item.strip().startswith("{"))
    body = json.loads(line)
    assert body["result"]["isError"] is True
    assert "not installed" in body["result"]["content"][0]["text"].lower()


def test_head_launcher_does_not_import_cwd_extension(tmp_path: Path) -> None:
    fake_pkg = tmp_path / "extension"
    fake_pkg.mkdir()
    (fake_pkg / "__init__.py").write_text(
        "raise RuntimeError('cwd hijack')\n", encoding="utf-8"
    )
    (fake_pkg / "mcp_server.py").write_text(
        "raise RuntimeError('cwd hijack')\n", encoding="utf-8"
    )
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
    proc = subprocess.run(
        [sys.executable, str(HEADS / "claude-code" / "launch_mcp.py")],
        cwd=tmp_path,
        input=payload,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=15,
    )
    assert proc.returncode == 0, proc.stderr
    assert "hijack" not in proc.stderr
    line = next(item for item in proc.stdout.splitlines() if item.strip().startswith("{"))
    body = json.loads(line)
    names = [tool["name"] for tool in body["result"]["tools"]]
    assert names == ["list", "describe", "invoke", "run_range"]


def test_main_help() -> None:
    assert main(["--help"]) == 0


def test_head_profiles_and_manifests_exist() -> None:
    assert (HEADS / "claude-code.md").is_file()
    assert (HEADS / "codex-cli.md").is_file()
    assert (HEADS / "other-agent-cli.md").is_file()
    claude_plugin = json.loads(
        (HEADS / "claude-code" / ".claude-plugin" / "plugin.json").read_text(
            encoding="utf-8"
        )
    )
    claude_mcp = json.loads(
        (HEADS / "claude-code" / ".mcp.json").read_text(encoding="utf-8")
    )
    codex_plugin = json.loads(
        (HEADS / "codex-cli" / ".codex-plugin" / "plugin.json").read_text(
            encoding="utf-8"
        )
    )
    codex_mcp = json.loads(
        (HEADS / "codex-cli" / ".mcp.json").read_text(encoding="utf-8")
    )
    assert claude_plugin["name"] == "specaudit-ctf"
    claude_server = claude_mcp["mcpServers"]["specaudit-ctf"]
    assert claude_server["args"] == ["${CLAUDE_PLUGIN_ROOT}/launch_mcp.py"]
    assert claude_server["env"]["SPECAUDIT_CTF_ROOT"] == "${CLAUDE_PROJECT_DIR}"
    assert claude_server["env"]["PYTHONPATH"] == "${CLAUDE_PROJECT_DIR}"
    assert codex_plugin["mcpServers"] == "./.mcp.json"
    assert codex_mcp["mcp_servers"]["specaudit-ctf"]["args"] == ["launch_mcp.py"]
    claude_launch = HEADS / "claude-code" / "launch_mcp.py"
    codex_launch = HEADS / "codex-cli" / "launch_mcp.py"
    assert claude_launch.is_file()
    assert claude_launch.read_text(encoding="utf-8") == codex_launch.read_text(
        encoding="utf-8"
    )
    for skill in (
        HEADS / "claude-code" / "skills" / "specaudit-ctf" / "SKILL.md",
        HEADS / "codex-cli" / "skills" / "specaudit-ctf" / "SKILL.md",
    ):
        text = skill.read_text(encoding="utf-8")
        assert "list" in text and "describe" in text and "invoke" in text
        assert "inventory" not in text.lower()

def test_mcp_server_unknown_cli_args_returns_2() -> None:
    assert main(["--bogus"]) == 2


def test_mcp_invoke_falsy_non_mapping_args_are_invalid_params() -> None:
    server, fake = _server()
    for bad in (0, [], "", False):
        response = _call(server, "invoke", {"id": FIXTURE_ARM_ID, "action": "echo", "args": bad})
        assert response["error"]["code"] == -32602, bad
        assert "args" in response["error"]["message"].lower()
    assert fake.calls == []


def test_mcp_invoke_args_none_succeeds() -> None:
    server, fake = _server()
    response = _call(server, "invoke", {"id": FIXTURE_ARM_ID, "action": "echo", "args": None})
    # None is coerced to {} and should succeed as valid invoke
    assert "error" not in response
    assert fake.calls == [(FIXTURE_ARM_ID, "echo", {})]


def test_tool_defs_match_documented_surface_and_annotations() -> None:
    """Guard: the advertised tool surface matches the documented set exactly.

    Annotations follow MCP spec (stable since 2025-11-25). They are
    untrusted hints for clients, not enforcement; the fail-closed checks
    live in the tool handlers.
    """
    from extension.mcp_server import _TOOL_DEFS

    expected = {
        "list": {"readOnlyHint": True, "openWorldHint": False},
        "describe": {"readOnlyHint": True, "openWorldHint": False},
        "invoke": {"readOnlyHint": False, "openWorldHint": True},
        "run_range": {"readOnlyHint": True, "openWorldHint": True},
    }
    assert {tool["name"]: tool["annotations"] for tool in _TOOL_DEFS} == expected
    assert tuple(expected) == TOOLS


def test_run_range_returns_seed_stable_document() -> None:
    server, _fake = _server()
    response = _call(server, "run_range", {})
    assert "error" not in response
    assert response["result"]["isError"] is False
    payload = json.loads(response["result"]["content"][0]["text"])
    assert SCHEMA_ID == "range.lifecycle.v2"
    assert payload["schema"] == "range.lifecycle.v2"
    assert payload["live_aws"] is False
    assert payload["seed"] == DEFAULT_SEED
    # Fixture catalog auto-discovers an uninstalled curated arm; JSON-RPC
    # success is transport-only and must not hide degraded range status.
    assert payload["status"] == "degraded"
    assert payload["ok"] is False


def test_run_range_seed_validated_as_shape_error() -> None:
    server, _fake = _server()
    for bad in (True, 1.5, "123"):
        response = _call(server, "run_range", {"seed": bad})
        assert response["error"]["code"] == -32602, bad
        assert "seed" in response["error"]["message"].lower()


def test_run_range_arm_ids_restricted_to_curated() -> None:
    server, _fake = _server()
    response = _call(server, "run_range", {"arm_ids": [FIXTURE_ARM_ID]})
    assert "error" not in response
    assert response["result"]["isError"] is False
    payload = json.loads(response["result"]["content"][0]["text"])
    invoked = {
        row["arm_id"]
        for fixture in payload["fixtures"]
        for row in fixture["arms"]
    }
    assert invoked == {FIXTURE_ARM_ID}
    assert payload["schema"] == "range.lifecycle.v2"
    assert payload["status"] == "complete"
    assert payload["ok"] is True
    # Mixed lists fail closed entirely: one non-curated id refuses the call.
    bad = _call(server, "run_range", {"arm_ids": [FIXTURE_ARM_ID, "no-such-arm"]})
    assert bad["result"]["isError"] is True
    assert "curated" in bad["result"]["content"][0]["text"]


def test_run_range_explicit_empty_arm_ids_is_complete() -> None:
    server, _fake = _server()
    response = _call(server, "run_range", {"arm_ids": []})
    assert "error" not in response
    assert response["result"]["isError"] is False
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["schema"] == "range.lifecycle.v2"
    assert payload["status"] == "complete"
    assert payload["ok"] is True
    assert payload["coverage"]["attempted"] == []


def test_run_range_explicit_missing_arm_is_failed_transport_ok() -> None:
    server, _fake = _server()
    response = _call(server, "run_range", {"arm_ids": [CURATED_ARM_ID]})
    assert "error" not in response
    assert response["result"]["isError"] is False
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["schema"] == "range.lifecycle.v2"
    assert payload["status"] == "failed"
    assert payload["ok"] is False


def test_run_range_arm_ids_shape_rejected() -> None:
    server, _fake = _server()
    for bad in ("burp-mcp", [1, 2], [""]):
        response = _call(server, "run_range", {"arm_ids": bad})
        assert response["error"]["code"] == -32602, bad


def test_run_range_oversize_document_is_domain_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, _fake = _server()
    monkeypatch.setattr(
        "extension.mcp_server.run_range",
        lambda **_kwargs: {"pad": "x" * (_MAX_BYTES + 1)},
    )
    response = _call(server, "run_range", {})
    assert response["result"]["isError"] is True
    assert "exceeds" in response["result"]["content"][0]["text"]


def test_run_range_out_of_range_seed_is_domain_error() -> None:
    """RangeError from the runner maps to isError, not -32603."""
    server, _fake = _server()
    response = _call(server, "run_range", {"seed": 2**31})
    assert "error" not in response
    assert response["result"]["isError"] is True
    assert "seed out of range" in response["result"]["content"][0]["text"]
