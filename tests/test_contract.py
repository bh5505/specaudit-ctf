"""Catalog, invocation, and transport contract tests."""

from __future__ import annotations

import json
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
    NotInstalledError,
    Result,
    UnknownIdError,
    load_catalog,
)
from extension.__main__ import main
from extension.dispatch import dispatch_invoke
from extension.mcp_server import McpServer
from extension.transports.cli import CliTransport
from extension.transports.mcp import McpTransport

ARM_ID = "fixture-cli"
MCP_ARM_ID = "fixture-mcp"
HEAD_ID = "fixture-head"
METHODOLOGY_ID = "fixture-methodology"
UNKNOWN_ID = "no-such-entry"


class FakeTransport:
    protocol = "cli"

    def __init__(self, *, installed_ids: set[str] | None = None) -> None:
        self.installed_ids = set(installed_ids or ())
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id in self.installed_ids

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        payload = dict(args)
        self.calls.append((spec.id, action, payload))
        return Result(True, spec.id, action, {"echo": payload})


def _entry(
    entry_id: str,
    *,
    kind: str = "arm",
    protocols: tuple[str, ...] = ("cli",),
    notes: str = "Fixture entry.",
) -> CatalogEntry:
    return CatalogEntry(entry_id, kind, protocols, notes)


def _fixture_catalog() -> Catalog:
    return Catalog(
        [
            _entry(ARM_ID, notes="Fixture CLI arm."),
            _entry(MCP_ARM_ID, protocols=("mcp",), notes="Fixture MCP arm."),
            _entry(HEAD_ID, kind="head", notes="Fixture head."),
            _entry(
                METHODOLOGY_ID,
                kind="methodology-only",
                protocols=("none",),
                notes="Fixture methodology row.",
            ),
        ]
    )


def _extension(fake: FakeTransport | None = None) -> tuple[Extension, FakeTransport]:
    transport = fake or FakeTransport(installed_ids={ARM_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": transport},
        arms={ARM_ID: transport},
    )
    return ext, transport


def test_catalog_loads_full_coverage_and_serializes_four_fields() -> None:
    catalog = load_catalog()
    assert catalog.entries
    row = catalog.get("burp-mcp")
    assert row.kind == "arm"
    assert set(row.to_dict()) == {"id", "kind", "protocols", "notes"}


def test_catalog_rejects_duplicate_ids() -> None:
    with pytest.raises(ExtensionError, match="duplicate catalog id"):
        Catalog([_entry(ARM_ID), _entry(ARM_ID, kind="head")])


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ([], "mapping"),
        ({"id": "Bad ID", "kind": "arm", "protocols": ["cli"], "notes": "x"}, "kebab-case"),
        ({"id": ARM_ID, "kind": "unknown", "protocols": ["cli"], "notes": "x"}, "kind"),
        ({"id": ARM_ID, "kind": "arm", "protocols": [], "notes": "x"}, "protocols"),
        ({"id": ARM_ID, "kind": "arm", "protocols": ["none", "cli"], "notes": "x"}, "exclusive"),
        ({"id": ARM_ID, "kind": "arm", "protocols": ["cli"], "notes": " "}, "notes"),
    ],
)
def test_catalog_rejects_invalid_rows(
    tmp_path: Path, row: Any, message: str
) -> None:
    path = tmp_path / "coverage.yaml"
    import yaml

    path.write_text(yaml.safe_dump({"entries": [row]}), encoding="utf-8")
    with pytest.raises(ExtensionError, match=message):
        load_catalog(path)


def test_catalog_and_specs_expose_arm_and_head_shapes() -> None:
    ext, _ = _extension()
    arm = ext.arm_spec(ARM_ID)
    head = ext.head_spec(HEAD_ID)
    assert isinstance(arm, ArmSpec)
    assert arm.to_dict() == {
        "id": ARM_ID,
        "kind": "arm",
        "protocols": ["cli"],
        "notes": "Fixture CLI arm.",
    }
    assert isinstance(head, HeadSpec)
    assert head.to_dict()["kind"] == "head"
    with pytest.raises(NotAnArmError):
        ext.arm_spec(HEAD_ID)
    with pytest.raises(NotAHeadError):
        ext.head_spec(ARM_ID)


def test_describe_known_and_unknown_entries() -> None:
    ext, _ = _extension()
    assert ext.describe(ARM_ID).id == ARM_ID
    with pytest.raises(UnknownIdError) as err:
        ext.describe(UNKNOWN_ID)
    assert err.value.entry_id == UNKNOWN_ID


def test_invoke_calls_installed_arm_and_returns_its_result() -> None:
    ext, fake = _extension()
    result = ext.invoke(ARM_ID, "unrestricted-action-name", {"x": 1})
    assert result == Result(True, ARM_ID, "unrestricted-action-name", {"echo": {"x": 1}})
    assert fake.calls == [(ARM_ID, "unrestricted-action-name", {"x": 1})]


def test_invoke_uses_generic_transport_when_no_arm_handler_is_registered() -> None:
    fake = FakeTransport(installed_ids={ARM_ID})
    ext = Extension(
        catalog=_fixture_catalog(),
        transports={"cli": fake},
        arms={},
    )
    result = ext.invoke(ARM_ID, "echo", {"x": 1})
    assert result.ok is True
    assert fake.calls == [(ARM_ID, "echo", {"x": 1})]


def test_invoke_rejects_unknown_non_arm_and_uninstalled_entries() -> None:
    ext, fake = _extension(FakeTransport())
    with pytest.raises(UnknownIdError):
        ext.invoke(UNKNOWN_ID, "run", {})
    with pytest.raises(NotAnArmError):
        ext.invoke(HEAD_ID, "run", {})
    with pytest.raises(NotAnArmError):
        ext.invoke(METHODOLOGY_ID, "run", {})
    with pytest.raises(NotInstalledError):
        ext.invoke(ARM_ID, "run", {})
    assert fake.calls == []


@pytest.mark.parametrize("action", ["", "   ", 123, None])
def test_invoke_requires_nonempty_string_action(action: Any) -> None:
    ext, fake = _extension()
    with pytest.raises(ExtensionError, match="action is required"):
        ext.invoke(ARM_ID, action, {})
    assert fake.calls == []


def test_invoke_normalizes_none_args_and_rejects_non_mapping_args() -> None:
    ext, fake = _extension()
    ext.invoke(ARM_ID, "echo", None)
    assert fake.calls == [(ARM_ID, "echo", {})]
    with pytest.raises(ExtensionError, match="args must be a mapping"):
        ext.invoke(ARM_ID, "echo", "invalid")  # type: ignore[arg-type]
    assert len(fake.calls) == 1


def test_cli_transport_runs_configured_command_and_decodes_json() -> None:
    script = (
        "import json,sys; "
        "print(json.dumps({'action': sys.argv[1], 'args': json.loads(sys.argv[2])}))"
    )
    spec = ArmSpec(ARM_ID, ("cli",), "Fixture CLI arm.")
    transport = CliTransport(commands={ARM_ID: [sys.executable, "-c", script]})
    assert transport.installed(spec)
    result = transport.invoke(spec, "echo", {"k": "v"})
    assert result.ok
    assert result.output == {"action": "echo", "args": {"k": "v"}}


def test_cli_transport_reports_command_failure_as_result() -> None:
    spec = ArmSpec(ARM_ID, ("cli",), "Fixture CLI arm.")
    transport = CliTransport(
        commands={ARM_ID: [sys.executable, "-c", "import sys; print('bad'); sys.exit(3)"]}
    )
    result = transport.invoke(spec, "echo", {})
    assert result.ok is False
    assert result.output == "bad"
    assert "exit 3" not in (result.error or "")


def test_cli_transport_empty_command_is_not_installed() -> None:
    spec = ArmSpec(ARM_ID, ("cli",), "Fixture CLI arm.")
    transport = CliTransport(commands={ARM_ID: []})
    assert transport.installed(spec) is False
    with pytest.raises(NotInstalledError):
        transport.invoke(spec, "echo", {})


def test_mcp_transport_http_tools_call(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class Response:
        def read(self, n: int = -1) -> bytes:
            return json.dumps(
                {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ok"}]}}
            ).encode()

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def urlopen(req: Any, timeout: float | None = None) -> Response:
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode())
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("extension.transports.mcp.urllib_request.urlopen", urlopen)
    spec = ArmSpec(MCP_ARM_ID, ("mcp",), "Fixture MCP arm.")
    transport = McpTransport(endpoints={MCP_ARM_ID: "http://127.0.0.1/mcp"})
    assert transport.installed(spec)
    result = transport.invoke(spec, "list_tools", {"n": 2})
    assert result.ok
    assert result.output == {"content": [{"type": "text", "text": "ok"}]}
    assert captured["url"] == "http://127.0.0.1/mcp"
    assert captured["body"]["method"] == "tools/call"
    assert captured["body"]["params"] == {
        "name": "list_tools",
        "arguments": {"n": 2},
    }


def test_mcp_transport_unreachable_is_failure_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def urlopen(req: Any, timeout: float | None = None) -> Any:
        raise URLError("refused")

    monkeypatch.setattr("extension.transports.mcp.urllib_request.urlopen", urlopen)
    spec = ArmSpec(MCP_ARM_ID, ("mcp",), "Fixture MCP arm.")
    transport = McpTransport(endpoints={MCP_ARM_ID: "http://127.0.0.1/mcp"})
    result = transport.invoke(spec, "list_tools", {})
    assert result.ok is False
    assert result.error and "unreachable" in result.error


def test_mcp_transport_refuses_malformed_and_tool_error_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        body = b"[]"

        def read(self, n: int = -1) -> bytes:
            return self.body

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    response = Response()
    monkeypatch.setattr(
        "extension.transports.mcp.urllib_request.urlopen", lambda *args, **kwargs: response
    )
    spec = ArmSpec(MCP_ARM_ID, ("mcp",), "Fixture MCP arm.")
    transport = McpTransport(endpoints={MCP_ARM_ID: "http://127.0.0.1/mcp"})
    malformed = transport.invoke(spec, "list_tools", {})
    assert malformed.ok is False
    assert malformed.error == "malformed JSON-RPC response"

    response.body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"isError": True, "content": [{"type": "text", "text": "denied"}]},
        }
    ).encode()
    failed = transport.invoke(spec, "list_tools", {})
    assert failed.ok is False
    assert "denied" in (failed.error or "")


def test_dispatch_returns_direct_result_and_exit_status() -> None:
    ext, _ = _extension()
    outcome = dispatch_invoke(
        ext, arm_id=ARM_ID, action="echo", args={"value": 3}
    )
    assert outcome.exit_code == 0
    assert outcome.document == {
        "ok": True,
        "arm_id": ARM_ID,
        "action": "echo",
        "output": {"echo": {"value": 3}},
        "error": None,
    }


def test_dispatch_converts_invocation_errors_to_failure_result() -> None:
    ext, _ = _extension()
    outcome = dispatch_invoke(ext, arm_id=UNKNOWN_ID, action="echo")
    assert outcome.exit_code == 2
    assert outcome.document["ok"] is False
    assert outcome.document["arm_id"] == UNKNOWN_ID
    assert "unknown id" in outcome.document["error"]


def test_cli_list_describe_and_invoke_return_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ext, _ = _extension()
    monkeypatch.setattr("extension.__main__.Extension", lambda: ext)
    assert main(["list"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert any(row["id"] == ARM_ID for row in rows)

    assert main(["describe", ARM_ID]) == 0
    assert json.loads(capsys.readouterr().out)["id"] == ARM_ID

    assert main(["invoke", ARM_ID, "echo", '{"x":1}']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["output"] == {"echo": {"x": 1}}


def test_cli_invalid_args_and_unknown_entry_return_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ext, _ = _extension()
    monkeypatch.setattr("extension.__main__.Extension", lambda: ext)
    assert main(["invoke", ARM_ID, "echo", "[]"]) == 2
    invalid = json.loads(capsys.readouterr().out)
    assert invalid["ok"] is False
    assert "object" in invalid["error"]

    assert main(["invoke", UNKNOWN_ID, "echo"]) == 2
    unknown = json.loads(capsys.readouterr().out)
    assert unknown["ok"] is False
    assert "unknown id" in unknown["error"]


def test_mcp_server_list_describe_and_direct_invoke_result() -> None:
    ext, fake = _extension()
    server = McpServer(extension=ext)

    listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list", "arguments": {}}})
    assert listed is not None
    rows = json.loads(listed["result"]["content"][0]["text"])
    assert any(row["id"] == ARM_ID for row in rows)

    described = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "describe", "arguments": {"id": ARM_ID}}})
    assert described is not None
    assert json.loads(described["result"]["content"][0]["text"])["id"] == ARM_ID

    invoked = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "invoke", "arguments": {"id": ARM_ID, "action": "echo", "args": {"x": 4}}}})
    assert invoked is not None
    payload = json.loads(invoked["result"]["content"][0]["text"])
    assert invoked["result"]["isError"] is False
    assert payload["ok"] is True
    assert payload["output"] == {"echo": {"x": 4}}
    assert fake.calls == [(ARM_ID, "echo", {"x": 4})]
