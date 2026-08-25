"""Fail-closed invoke contract and generic transports."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping
from urllib.error import URLError

import pytest

from extension.contract import (
    ArmSpec,
    Catalog,
    CatalogEntry,
    Extension,
    ExtensionError,
    HeadSpec,
    NotAHeadError,
    NotAnArmError,
    NotCuratedError,
    NotHeldError,
    NotInstalledError,
    Result,
    UnknownIdError,
    describe,
    invoke,
    list_entries,
)
from extension.__main__ import main
from extension.transports.cli import CliTransport
from extension.transports.mcp import McpTransport

ROOT = Path(__file__).resolve().parents[1]
CURATED_ARM_ID = "burp-mcp"
RESEARCH_ARM_ID = "checkov"
NON_CURATED_ARM_ID = "deepsec"
METHODOLOGY_ID = "vulnhunter"
UNKNOWN_ID = "no-such-arm"
FIXTURE_ARM_ID = "probe-cli"
FIXTURE_HEAD_ID = "agent-cli"


class FakeCliTransport:
    protocol = "cli"

    def __init__(
        self,
        *,
        installed_ids: set[str] | None = None,
        result: Result | None = None,
    ) -> None:
        self.installed_ids = set(installed_ids or ())
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.result = result

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id in self.installed_ids

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        payload = dict(args)
        self.calls.append((spec.id, action, payload))
        if self.result is not None:
            return self.result
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"echo": payload},
            error=None,
        )


def _entry(
    entry_id: str,
    *,
    kind: str = "arm",
    protocols: tuple[str, ...] = ("cli",),
    curated: bool = False,
    notes: str = "Fixture row.",
    tier: str = "research",
    held_reason: str | None = None,
) -> CatalogEntry:
    return CatalogEntry(
        id=entry_id,
        kind=kind,
        protocols=protocols,
        curated=curated,
        notes=notes,
        tier=tier,
        held_reason=held_reason,
    )


def _fixture_catalog() -> Catalog:
    return Catalog(
        [
            _entry(FIXTURE_ARM_ID, curated=True, notes="Fixture curated CLI arm."),
            _entry(FIXTURE_HEAD_ID, kind="head", notes="Fixture head."),
            _entry(METHODOLOGY_ID, kind="methodology-only", protocols=("none",)),
            _entry(NON_CURATED_ARM_ID, curated=False),
            _entry(
                CURATED_ARM_ID,
                protocols=("mcp", "http"),
                curated=True,
                notes="Fixture curated MCP arm.",
            ),
        ]
    )


def test_list_entries_reads_coverage_catalog() -> None:
    """Test that list_entries loads and returns the full coverage catalog."""
    rows = list_entries()
    ids = [row.id for row in rows]
    assert CURATED_ARM_ID in ids
    assert METHODOLOGY_ID in ids
    burp = next(row for row in rows if row.id == CURATED_ARM_ID)
    assert burp.kind == "arm"
    assert burp.curated is True
    assert burp.tier == "held"
    checkov = next(row for row in rows if row.id == RESEARCH_ARM_ID)
    assert checkov.curated is True
    assert checkov.tier != "maintained"


def test_describe_known_and_unknown() -> None:
    """Test describe() with valid and invalid entry IDs."""
    row = describe(CURATED_ARM_ID)
    assert row.id == CURATED_ARM_ID
    assert row.kind == "arm"
    assert row.tier == "held"
    assert row.held_reason
    with pytest.raises(UnknownIdError) as err:
        describe(UNKNOWN_ID)
    assert err.value.entry_id == UNKNOWN_ID


def test_invoke_unknown_id_is_hard_error() -> None:
    """Test that invoking an unknown ID raises UnknownIdError immediately."""
    with pytest.raises(UnknownIdError) as err:
        invoke(UNKNOWN_ID, "ping", {})
    assert isinstance(err.value, ExtensionError)
    assert err.value.entry_id == UNKNOWN_ID


def test_invoke_non_curated_arm_refused() -> None:
    """Test that invoking a non-curated arm raises NotCuratedError."""
    fake = FakeCliTransport(installed_ids={NON_CURATED_ARM_ID})
    ext = Extension(catalog=_fixture_catalog(), transports={"cli": fake})
    with pytest.raises(NotCuratedError) as err:
        ext.invoke(NON_CURATED_ARM_ID, "scan", {})
    assert err.value.entry_id == NON_CURATED_ARM_ID
    assert fake.calls == []


def test_invoke_methodology_only_refused() -> None:
    """Test that invoking a methodology-only entry raises NotAnArmError."""
    fake = FakeCliTransport(installed_ids={METHODOLOGY_ID})
    ext = Extension(transports={"cli": fake})
    with pytest.raises(NotAnArmError) as err:
        ext.invoke(METHODOLOGY_ID, "extract", {})
    assert err.value.kind == "methodology-only"
    assert fake.calls == []


def test_invoke_head_refused() -> None:
    """Test that invoking a head entry raises NotAnArmError."""
    fake = FakeCliTransport(installed_ids={FIXTURE_HEAD_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    with pytest.raises(NotAnArmError) as err:
        ext.invoke(FIXTURE_HEAD_ID, "run", {})
    assert err.value.kind == "head"
    spec = ext.head_spec(FIXTURE_HEAD_ID)
    assert isinstance(spec, HeadSpec)
    assert spec.id == FIXTURE_HEAD_ID
    with pytest.raises(NotAHeadError):
        ext.head_spec(FIXTURE_ARM_ID)


def test_invoke_curated_arm_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that invoking a curated but unavailable arm raises NotInstalledError."""
    monkeypatch.setattr("extension.arms.checkov.arm.resolve_binary", lambda: None)
    ext = Extension()
    with pytest.raises(NotInstalledError) as err:
        ext.invoke(RESEARCH_ARM_ID, "scan", {})
    assert err.value.entry_id == RESEARCH_ARM_ID


def test_invoke_held_arm_refused_even_if_curated() -> None:
    fake = FakeCliTransport(installed_ids={CURATED_ARM_ID})
    ext = Extension(transports={"mcp": fake}, arms={CURATED_ARM_ID: fake})
    with pytest.raises(NotHeldError) as err:
        ext.invoke(CURATED_ARM_ID, "list_tools", {})
    assert err.value.entry_id == CURATED_ARM_ID
    assert fake.calls == []


def test_invoke_fake_cli_transport_records_call() -> None:
    """Test that successful invocations record calls and return results."""
    fake = FakeCliTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    result = ext.invoke(FIXTURE_ARM_ID, "echo", {"x": 1})
    assert result.ok is True
    assert result.arm_id == FIXTURE_ARM_ID
    assert result.action == "echo"
    assert result.output == {"echo": {"x": 1}}
    assert fake.calls == [(FIXTURE_ARM_ID, "echo", {"x": 1})]


def test_invoke_non_mapping_args_refused() -> None:
    """Test that non-mapping args parameter is rejected with ExtensionError."""
    fake = FakeCliTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    with pytest.raises(ExtensionError) as err:
        ext.invoke(FIXTURE_ARM_ID, "echo", "oops")
    assert "args must be a mapping" in str(err.value)
    assert fake.calls == []


def test_cli_transport_runs_configured_command() -> None:
    """Test that CLI transport executes configured commands and parses JSON output."""
    script = (
        "import json,sys; "
        "print(json.dumps({'action': sys.argv[1], 'args': json.loads(sys.argv[2])}))"
    )
    transport = CliTransport(
        commands={FIXTURE_ARM_ID: [sys.executable, "-c", script]}
    )
    spec = ArmSpec(
        id=FIXTURE_ARM_ID,
        protocols=("cli",),
        curated=True,
        notes="Fixture curated CLI arm.",
    )
    assert transport.installed(spec) is True
    result = transport.invoke(spec, "echo", {"k": "v"})
    assert result.ok is True
    assert result.output == {"action": "echo", "args": {"k": "v"}}


def test_mcp_transport_not_installed_by_default() -> None:
    """Test that MCP transport is not installed by default without endpoint configuration."""
    spec = ArmSpec(
        id=CURATED_ARM_ID,
        protocols=("mcp", "http"),
        curated=True,
        notes="Fixture curated MCP arm.",
    )
    transport = McpTransport()
    assert transport.installed(spec) is False
    with pytest.raises(NotInstalledError):
        transport.invoke(spec, "ping", {})


def test_mcp_transport_http_tools_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that MCP transport makes HTTP requests with proper JSON-RPC format."""
    captured: dict[str, Any] = {}

    class _Resp:
        def read(self, n: int = -1) -> bytes:
            return json.dumps(
                {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
            ).encode("utf-8")

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def _urlopen(req: Any, timeout: float | None = None) -> _Resp:
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(
        "extension.transports.mcp.urllib_request.urlopen", _urlopen
    )
    spec = ArmSpec(
        id=CURATED_ARM_ID,
        protocols=("mcp",),
        curated=True,
        notes="Fixture curated MCP arm.",
    )
    transport = McpTransport(endpoints={CURATED_ARM_ID: "http://127.0.0.1/mcp"})
    assert transport.installed(spec) is True
    result = transport.invoke(spec, "ping", {"n": 2})
    assert result.ok is True
    assert result.output == {"ok": True}
    assert captured["url"] == "http://127.0.0.1/mcp"
    assert captured["body"]["method"] == "tools/call"
    assert captured["body"]["params"] == {"name": "ping", "arguments": {"n": 2}}


def test_mcp_transport_unreachable_is_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that unreachable MCP endpoints return failure results (not exceptions)."""
    def _urlopen(req: Any, timeout: float | None = None) -> Any:
        raise URLError("refused")

    monkeypatch.setattr(
        "extension.transports.mcp.urllib_request.urlopen", _urlopen
    )
    spec = ArmSpec(
        id=CURATED_ARM_ID,
        protocols=("mcp",),
        curated=True,
        notes="Fixture curated MCP arm.",
    )
    transport = McpTransport(endpoints={CURATED_ARM_ID: "http://127.0.0.1/mcp"})
    result = transport.invoke(spec, "ping", {})
    assert result.ok is False
    assert result.error is not None


def test_main_list_and_describe(capsys: pytest.CaptureFixture[str]) -> None:
    """Test the main() CLI entry point for list and describe commands."""
    assert main(["list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert any(row["id"] == CURATED_ARM_ID for row in listed)
    assert main(["describe", CURATED_ARM_ID]) == 0
    described = json.loads(capsys.readouterr().out)
    assert described["id"] == CURATED_ARM_ID
    assert described["curated"] is True
    assert described["tier"] == "held"


def test_main_invoke_unknown_id_is_hard_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test that invoking unknown ID via main() exits with error code 2."""
    assert main(["invoke", UNKNOWN_ID, "ping"]) == 2
    err = capsys.readouterr().err
    assert "unknown id" in err.lower()


def test_main_invoke_not_installed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test that invoking not-installed arm via main() exits with error code 2."""
    monkeypatch.setattr("extension.arms.checkov.arm.resolve_binary", lambda: None)
    assert main(["invoke", RESEARCH_ARM_ID, "scan"]) == 2
    err = capsys.readouterr().err
    assert "not installed" in err.lower()


def test_module_cli_list() -> None:
    """Test that the module CLI interface works via python -m extension list."""
    proc = subprocess.run(
        [sys.executable, "-m", "extension", "list"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    rows = json.loads(proc.stdout)
    assert any(row["id"] == CURATED_ARM_ID for row in rows)

def test_cli_transport_empty_argv_is_not_installed() -> None:
    spec = ArmSpec(id=FIXTURE_ARM_ID, protocols=("cli",), curated=True, notes="x")
    transport = CliTransport(commands={FIXTURE_ARM_ID: []})
    assert transport.installed(spec) is False
    with pytest.raises(NotInstalledError):
        transport.invoke(spec, "ping", {})


def test_mcp_transport_empty_stdio_argv_is_not_installed_but_preserved() -> None:
    spec = ArmSpec(id=FIXTURE_ARM_ID, protocols=("mcp",), curated=True, notes="x")
    transport = McpTransport(stdio_cmds={FIXTURE_ARM_ID: []})
    # Empty list is preserved (not discarded) but counts as not installed
    assert FIXTURE_ARM_ID in transport._stdio_cmds
    assert transport._stdio_cmds[FIXTURE_ARM_ID] == []
    assert transport.installed(spec) is False
    with pytest.raises(NotInstalledError):
        transport.invoke(spec, "ping", {})


def test_mcp_transport_non_object_body_is_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        def read(self, n: int = -1) -> bytes:
            return json.dumps([]).encode("utf-8")

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr("extension.transports.mcp.urllib_request.urlopen", lambda req, timeout=None: _Resp())
    spec = ArmSpec(id=CURATED_ARM_ID, protocols=("mcp",), curated=True, notes="x")
    transport = McpTransport(endpoints={CURATED_ARM_ID: "http://127.0.0.1/mcp"})
    result = transport.invoke(spec, "ping", {})
    assert result.ok is False
    assert result.error == "malformed JSON-RPC response"


def test_mcp_transport_non_dict_result_is_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        def read(self, n: int = -1) -> bytes:
            return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "not-dict"}).encode("utf-8")

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr("extension.transports.mcp.urllib_request.urlopen", lambda req, timeout=None: _Resp())
    spec = ArmSpec(id=CURATED_ARM_ID, protocols=("mcp",), curated=True, notes="x")
    transport = McpTransport(endpoints={CURATED_ARM_ID: "http://127.0.0.1/mcp"})
    result = transport.invoke(spec, "ping", {})
    assert result.ok is False
    assert result.error == "malformed tool result"


def test_mcp_transport_is_error_true_propagates_text(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        def read(self, n: int = -1) -> bytes:
            return json.dumps(
                {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "denied"}], "isError": True}}
            ).encode("utf-8")

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr("extension.transports.mcp.urllib_request.urlopen", lambda req, timeout=None: _Resp())
    spec = ArmSpec(id=CURATED_ARM_ID, protocols=("mcp",), curated=True, notes="x")
    transport = McpTransport(endpoints={CURATED_ARM_ID: "http://127.0.0.1/mcp"})
    result = transport.invoke(spec, "ping", {})
    assert result.ok is False
    assert result.error is not None and "denied" in result.error


def test_mcp_transport_empty_error_object_is_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        def read(self, n: int = -1) -> bytes:
            return json.dumps({"jsonrpc": "2.0", "id": 1, "error": {}}).encode("utf-8")

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr("extension.transports.mcp.urllib_request.urlopen", lambda req, timeout=None: _Resp())
    spec = ArmSpec(id=CURATED_ARM_ID, protocols=("mcp",), curated=True, notes="x")
    transport = McpTransport(endpoints={CURATED_ARM_ID: "http://127.0.0.1/mcp"})
    result = transport.invoke(spec, "ping", {})
    assert result.ok is False


def test_extension_main_unknown_args_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    """Test that unknown command-line arguments return exit code 2."""
    assert main(["--bogus"]) == 2


def test_cli_decode_strips_trailing_newline_on_invalid_json() -> None:
    """Test that CLI transport decoder strips trailing newlines from non-JSON output."""
    from extension.transports.cli import _decode_output

    assert _decode_output('not json\n') == "not json"


def test_invoke_with_none_args_uses_empty_dict() -> None:
    """Test that None args parameter is treated as empty dict (valid input)."""
    fake = FakeCliTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    result = ext.invoke(FIXTURE_ARM_ID, "echo", None)
    assert result.ok is True
    assert fake.calls == [(FIXTURE_ARM_ID, "echo", {})]


def test_invoke_empty_action_raises_error() -> None:
    """Test that empty string action is rejected with ExtensionError."""
    fake = FakeCliTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    with pytest.raises(ExtensionError) as err:
        ext.invoke(FIXTURE_ARM_ID, "", {})
    assert "action is required" in str(err.value)
    assert fake.calls == []


def test_invoke_whitespace_only_action_raises_error() -> None:
    """Test that whitespace-only action is rejected with ExtensionError."""
    fake = FakeCliTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    with pytest.raises(ExtensionError) as err:
        ext.invoke(FIXTURE_ARM_ID, "   ", {})
    assert "action is required" in str(err.value)
    assert fake.calls == []


def test_invoke_non_string_action_raises_error() -> None:
    """Test that non-string action types are rejected with ExtensionError."""
    fake = FakeCliTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    with pytest.raises(ExtensionError) as err:
        ext.invoke(FIXTURE_ARM_ID, 123, {})
    assert "action is required" in str(err.value)
    assert fake.calls == []


def test_arm_spec_from_non_arm_raises_error() -> None:
    """Test that arm_spec() on a non-arm entry raises NotAnArmError."""
    ext = Extension(catalog=_fixture_catalog())
    with pytest.raises(NotAnArmError) as err:
        ext.arm_spec(FIXTURE_HEAD_ID)
    assert err.value.kind == "head"


def test_head_spec_from_non_head_raises_error() -> None:
    """Test that head_spec() on a non-head entry raises NotAHeadError."""
    ext = Extension(catalog=_fixture_catalog())
    with pytest.raises(NotAHeadError) as err:
        ext.head_spec(FIXTURE_ARM_ID)
    assert err.value.kind == "arm"


def test_curated_arms_have_specialized_handlers() -> None:
    """P0 guard: every curated catalog arm ships a specialized handler."""
    ext = Extension()
    curated = [
        entry.id
        for entry in ext.list_entries()
        if entry.kind == "arm" and entry.curated
    ]
    assert curated, "catalog must curate at least one arm"
    for arm_id in curated:
        assert arm_id in ext.arms, arm_id


def test_default_extension_wires_drain_arms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Extension() maps the nine later arms; uninstalled list_tools is NotInstalled."""
    ids_and_mods = (
        ("routersploit", "routersploit"),
        ("sniper", "sniper"),
        ("zgrab2", "zgrab2"),
        ("dark-moon", "darkmoon"),
        ("pyrit", "pyrit"),
        ("deepsec", "deepsec"),
        ("vvah", "vvah"),
        ("ai-deep-sast", "aideepsast"),
        ("agent-wiz", "agentwiz"),
    )
    for env in (
        "ROUTERSPLOIT_BIN",
        "SNIPER_BIN",
        "ZGRAB2_BIN",
        "DARK_MOON_BIN",
        "PYRIT_BIN",
        "DEEPSEC_BIN",
        "VVAH_BIN",
        "AI_DEEP_SAST_BIN",
        "AGENT_WIZ_BIN",
    ):
        monkeypatch.delenv(env, raising=False)
    for _, mod in ids_and_mods:
        monkeypatch.setattr(
            f"extension.arms.{mod}.arm.resolve_binary", lambda: None
        )
    ext = Extension()
    for arm_id, _ in ids_and_mods:
        assert arm_id in ext.arms
        with pytest.raises(NotInstalledError):
            ext.invoke(arm_id, "list_tools", {})


def test_curated_arm_never_falls_back_to_generic_transport() -> None:
    """P0 guard: curated arm without a handler is a hard error."""
    fake = FakeCliTransport(installed_ids={RESEARCH_ARM_ID})
    ext = Extension(transports={"cli": fake}, arms={})
    with pytest.raises(ExtensionError) as err:
        ext.invoke(RESEARCH_ARM_ID, "anything", {})
    assert "specialized handler" in str(err.value)
    assert fake.calls == []
