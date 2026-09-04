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
from extension.range import SCHEMA_ID
from tests.test_contract import (
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


def test_mcp_list_and_describe_use_fixture_catalog() -> None:
    server, _fake = _server()
    listed = _call(server, "list")
    assert listed["result"]["isError"] is False
    rows = _content_json(listed)
    assert any(row["id"] == FIXTURE_ARM_ID for row in rows)

    described = _call(server, "describe", {"id": FIXTURE_ARM_ID})
    described_row = _content_json(described)
    assert described_row["id"] == FIXTURE_ARM_ID
    assert described_row["tier"] == "research"
    assert all("tier" in row for row in rows)


def test_mcp_invoke_unmanifested_action_is_failed_envelope() -> None:
    """X4-PUB: like the CLI, MCP refuses actions outside the X2 registry."""
    server, fake = _server()
    invoked = _call(
        server, "invoke", {"id": FIXTURE_ARM_ID, "action": "echo", "args": {"x": 1}}
    )
    result = _content_json(invoked)
    assert invoked["result"]["isError"] is True
    assert result["schema"] == "specaudit.ctf.execution-result.v1"
    assert result["status"] == "failed"
    assert result["transport_ok"] is False
    assert result["limitations"] == ["unknown capability"]
    assert fake.calls == []


def test_mcp_invoke_agent_wiz_list_tools_success_envelope() -> None:
    """The one manifested read-only action succeeds with a complete envelope."""
    server = McpServer()  # real catalog: agent-wiz ships no binary
    invoked = _call(
        server,
        "invoke",
        {"id": "agent-wiz", "action": "list_tools", "args": {}},
    )
    assert invoked["result"]["isError"] is False
    result = _content_json(invoked)
    assert result["schema"] == "specaudit.ctf.execution-result.v1"
    assert result["status"] == "complete"
    assert result["transport_ok"] is True
    assert result["capability_id"] == "agent-wiz.list_tools"
    assert result["coverage"]["complete"] == ["agent-wiz.list_tools"]
    assert result["artifacts"], "complete envelope must own a policy-report digest"
    assert invoked["result"]["structuredContent"] == result


def test_mcp_invoke_unknown_id_is_failed_envelope() -> None:
    server, fake = _server()
    response = _call(server, "invoke", {"id": UNKNOWN_ID, "action": "ping"})
    assert "error" not in response
    assert response["result"]["isError"] is True
    result = _content_json(response)
    assert result["status"] == "failed"
    assert result["transport_ok"] is False
    assert result["limitations"] == ["unknown capability"]
    assert fake.calls == []


def test_mcp_invoke_methodology_only_does_not_call_transport() -> None:
    fake = FakeCliTransport(installed_ids={METHODOLOGY_ID})
    server, _ = _server(fake)
    response = _call(server, "invoke", {"id": METHODOLOGY_ID, "action": "extract"})
    assert response["result"]["isError"] is True
    result = _content_json(response)
    assert result["status"] == "failed"
    assert result["limitations"] == ["methodology-only is never invocable"]
    assert fake.calls == []


def test_mcp_invoke_unadmitted_action_is_failed_envelope() -> None:
    # Zero live held rows remain: an UNADMITTED action on a research arm
    # is the honest refusal shape now (the held-tier envelope rule stays
    # pinned by the goldens in test_ctf_envelopes and the fixture tests
    # in test_support_tiers).
    server = McpServer()
    response = _call(server, "invoke", {"id": "metasploit-mcp", "action": "ping"})
    assert response["result"]["isError"] is True
    result = _content_json(response)
    assert result["status"] == "failed"
    assert result["limitations"] == ["unknown capability"]


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
    # probe-cli echo is outside the X2-PUB registry: fail-closed envelope.
    payload = json.loads(invoked["result"]["content"][0]["text"])
    assert invoked["result"]["isError"] is True
    assert payload["status"] == "failed"
    assert fake.calls == []


def test_serve_content_length_input_is_parse_error() -> None:
    """Stdio MCP framing is ndjson only; legacy Content-Length is refused."""
    server, _ = _server()
    stdin = StringIO("Content-Length: abc\r\n\r\n")
    stdout = StringIO()
    assert server.serve(stdin=stdin, stdout=stdout) == 0
    response = json.loads(stdout.getvalue().strip())
    assert response["error"]["code"] == -32700
    assert "content-length" not in stdout.getvalue().lower()[:15]


def test_serve_oversized_line_rejected() -> None:
    server, _ = _server()
    stdin = StringIO("{" + "x" * _MAX_BYTES + "\n")
    stdout = StringIO()
    assert server.serve(stdin=stdin, stdout=stdout) == 0
    response = json.loads(stdout.getvalue().strip())
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


def test_module_mcp_invoke_live_catalog_unconfigured() -> None:
    """metasploit-mcp is admitted research now: the live-catalog module
    path without an endpoint emits the honest not-installed envelope."""
    payload = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "invoke",
                    "arguments": {"id": "metasploit-mcp", "action": "list_tools"},
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
    envelope = json.loads(body["result"]["content"][0]["text"])
    assert envelope["status"] == "failed"
    assert envelope["limitations"] == ["arm is not installed"]


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
    # None means "absent, use default {}" and must not be a shape error.
    server = McpServer()
    response = _call(
        server,
        "invoke",
        {"id": "agent-wiz", "action": "list_tools", "args": None},
    )
    assert "error" not in response
    assert response["result"]["isError"] is False
    payload = _content_json(response)
    assert payload["status"] == "complete"


def test_tool_defs_match_documented_surface_and_annotations() -> None:
    """Guard: the advertised tool surface matches the documented set exactly.

    Annotations follow MCP spec (stable since 2025-11-25). They are
    untrusted hints for clients, not enforcement; the fail-closed checks
    live in the tool handlers. X4-PUB: invoke is read-only (the X2-PUB
    registry admits only in-process policy reads) and closed-world; the
    envelope-producing tools declare the execution-result.v1 output schema.
    """
    from extension.mcp_server import _TOOL_DEFS

    expected = {
        "list": {"readOnlyHint": True, "openWorldHint": False},
        "describe": {"readOnlyHint": True, "openWorldHint": False},
        "invoke": {"readOnlyHint": True, "openWorldHint": False},
        "run_range": {"readOnlyHint": True, "openWorldHint": False},
    }
    assert {tool["name"]: tool["annotations"] for tool in _TOOL_DEFS} == expected
    assert tuple(expected) == TOOLS
    for tool in _TOOL_DEFS:
        if tool["name"] in {"invoke", "run_range"}:
            assert tool["outputSchema"]["title"] == "specaudit.ctf.execution-result.v1"
        else:
            assert "outputSchema" not in tool
    run_range_tool = next(tool for tool in _TOOL_DEFS if tool["name"] == "run_range")
    arm_ids = run_range_tool["inputSchema"]["properties"]["arm_ids"]["description"]
    lowered = arm_ids.lower()
    assert "omitted" in lowered
    assert "empty" in lowered
    assert "degraded" in lowered


def test_run_range_returns_envelope_not_lifecycle_document() -> None:
    server, _fake = _server()
    response = _call(server, "run_range", {})
    assert "error" not in response
    # Auto-discovered curated arms include an unreachable one: degraded
    # inner status is carried inside the envelope, and isError mirrors the
    # CLI's nonzero exit without replacing the verdict.
    assert response["result"]["isError"] is True
    payload = json.loads(response["result"]["content"][0]["text"])
    assert SCHEMA_ID == "range.lifecycle.v2"
    assert payload["schema"] == "specaudit.ctf.execution-result.v1"
    assert payload["status"] == "degraded"
    assert payload["transport_ok"] is True
    assert payload["artifacts"], "range envelope owns a range-report digest"
    assert response["result"]["structuredContent"] == payload


def test_run_range_explicit_empty_arm_ids_is_complete() -> None:
    server, _fake = _server()
    response = _call(server, "run_range", {"arm_ids": []})
    assert "error" not in response
    assert response["result"]["isError"] is False
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["schema"] == "specaudit.ctf.execution-result.v1"
    assert payload["status"] == "complete"
    assert payload["coverage"]["attempted"] == []
    assert payload["artifacts"][0]["kind"] == "range-report"


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
    assert payload["schema"] == "specaudit.ctf.execution-result.v1"
    assert payload["status"] == "complete"
    assert payload["coverage"]["complete"] == [FIXTURE_ARM_ID]
    # Mixed lists fail closed entirely: one non-curated id refuses the run
    # with a failed envelope (never a partial complete).
    bad = _call(server, "run_range", {"arm_ids": [FIXTURE_ARM_ID, "no-such-arm"]})
    assert bad["result"]["isError"] is True
    result = json.loads(bad["result"]["content"][0]["text"])
    assert result["status"] == "failed"
    assert result["transport_ok"] is False
    assert result["artifacts"] == []


def test_run_range_arm_ids_shape_rejected() -> None:
    server, _fake = _server()
    for bad in ("burp-mcp", [1, 2], [""]):
        response = _call(server, "run_range", {"arm_ids": bad})
        assert response["error"]["code"] == -32602, bad


def test_run_range_huge_document_stays_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """X4-PUB: the envelope carries digests, never the document inline.

    A pathological inner document cannot inflate the tool result past the
    framed response size; only its digest is admitted.
    """
    server, _fake = _server()
    document = {"pad": "x" * (_MAX_BYTES + 1)}
    monkeypatch.setattr(
        "extension.range.runner.run_range",
        lambda **_kwargs: document,
    )
    response = _call(server, "run_range", {})
    assert "error" not in response
    text = response["result"]["content"][0]["text"]
    assert len(text) < _MAX_BYTES
    payload = json.loads(text)
    assert len(payload["artifacts"]) == 1
    # Pin the digest to the *patched* document's canonical bytes, so the
    # test proves the monkeypatch was exercised: a silently ineffective
    # patch target would produce the real (small) document's digest here.
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    expected = "sha256:" + __import__("hashlib").sha256(canonical).hexdigest()
    assert payload["artifacts"][0]["digest"] == expected


def test_run_range_out_of_range_seed_is_domain_error() -> None:
    """RangeError from the runner maps to isError with a failed envelope."""
    server, _fake = _server()
    response = _call(server, "run_range", {"seed": 2**31})
    assert "error" not in response
    assert response["result"]["isError"] is True
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert payload["limitations"] == ["range run failed"]


def test_mcp_unknown_tool_arguments_are_invalid_params() -> None:
    """Server-side input validation: the declared additionalProperties:false
    schemas are enforced, not just advertised (MCP spec: servers MUST
    validate tool inputs)."""
    server, fake = _server()
    cases = (
        ("invoke", {"id": "agent-wiz", "action": "list_tools", "bogus": 1}, "bogus"),
        ("run_range", {"seed": 1, "extra": True}, "extra"),
        ("describe", {"id": "agent-wiz", "detail": "full"}, "detail"),
        ("list", {"unexpected": []}, "unexpected"),
    )
    for tool, arguments, unknown_key in cases:
        response = _call(server, tool, arguments)
        assert response["error"]["code"] == -32602, (tool, arguments)
        # The message names the rejected key, proving *this* surface's
        # rejection rather than any incidental "unknown" wording.
        assert unknown_key in response["error"]["message"], (tool, unknown_key)
    assert fake.calls == []


def test_tool_argument_keys_derive_from_declared_schemas() -> None:
    """The enforced server-side surface is derived from _TOOL_DEFS, so it can
    never drift from the advertised inputSchemas."""
    from extension.mcp_server import _TOOL_ARGUMENT_KEYS, _TOOL_DEFS, TOOLS

    assert set(_TOOL_ARGUMENT_KEYS) == set(TOOLS)
    for tool in _TOOL_DEFS:
        schema_props = set(tool["inputSchema"].get("properties", {}))
        assert _TOOL_ARGUMENT_KEYS[tool["name"]] == frozenset(schema_props)
        for required in tool["inputSchema"].get("required", []):
            assert required in schema_props


def test_initialize_negotiation_fallbacks() -> None:
    # Expectations derive from the implementation constants, so adding an
    # older supported version cannot silently outdate this test.
    from extension.mcp_server import (
        _LATEST_PROTOCOL_VERSION,
        _SUPPORTED_PROTOCOL_VERSIONS,
        _initialize,
    )

    assert "1999-01-01" not in _SUPPORTED_PROTOCOL_VERSIONS
    for version in _SUPPORTED_PROTOCOL_VERSIONS:
        assert _initialize({"protocolVersion": version})["protocolVersion"] == version
    # Missing, non-string, and unsupported requests answer with the latest
    # supported version rather than echoing caller input.
    for params in ({}, {"protocolVersion": 123}, {"protocolVersion": "1999-01-01"}):
        assert _initialize(params)["protocolVersion"] == _LATEST_PROTOCOL_VERSION


def test_range_cli_arm_ids_whitespace_matches_mcp_shape(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Whitespace-only entries are shape errors on both transports; an empty
    value stays lifecycle-only; entries are otherwise kept verbatim so the
    curated-arm domain check is identical."""
    import json as _json

    from extension.range import __main__ as range_cli

    # Whitespace-only entry: usage error before dispatch, no envelope — the
    # CLI mirror of the MCP -32602 shape rejection.
    assert range_cli.main(["--arm-ids", " "]) == 2
    assert capsys.readouterr().out == ""

    # Empty value stays lifecycle-only (required-empty, may complete).
    assert range_cli.main(["--arm-ids", "", "--seed", "7"]) == 0
    capsys.readouterr()

    # Verbatim entries reach the curated check on BOTH transports. Run the
    # same logical request through the MCP tool and compare envelopes, so
    # the parity claim below is asserted, not assumed.
    assert range_cli.main(["--arm-ids", " burp-mcp"]) == 2
    cli_payload = _json.loads(capsys.readouterr().out)
    assert cli_payload["schema"] == "specaudit.ctf.execution-result.v1"
    assert cli_payload["status"] == "failed"
    assert cli_payload["transport_ok"] is False

    server = McpServer()
    response = _call(server, "run_range", {"arm_ids": [" burp-mcp"]})
    assert response["result"]["isError"] is True
    mcp_payload = _json.loads(response["result"]["content"][0]["text"])
    assert mcp_payload["schema"] == "specaudit.ctf.execution-result.v1"
    for field in ("status", "transport_ok", "limitations", "coverage"):
        assert mcp_payload[field] == cli_payload[field], field


def test_mcp_missing_required_id_is_invalid_params() -> None:
    """A missing or non-string id is a shape error (-32602) on both
    transports: the CLI's argparse refuses the missing positional with a
    usage error and no envelope; MCP answers -32602 without dispatch."""
    server, fake = _server()
    for bad in ({}, {"id": 7}, {"id": "  "}):
        arguments = {"action": "list_tools", **bad}
        response = _call(server, "invoke", arguments)
        assert response["error"]["code"] == -32602, bad
        assert "id" in response["error"]["message"].lower()
    assert fake.calls == []
