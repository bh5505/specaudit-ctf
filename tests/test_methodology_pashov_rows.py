"""Pashov methodology-only rows: describable references, never invocable.

The three catalog rows referencing the pinned pashov/skills methodology
must resolve through ``describe`` and refuse invocation through the
existing generic non-arm path — no handler, no special-cased error, no
extra invocation surface anywhere.
"""

from __future__ import annotations

import json

import pytest

from extension.__main__ import main
from extension.contract import Extension, NotAnArmError
from extension.dispatch import dispatch_invoke
from extension.mcp_server import McpServer

METHODOLOGY_IDS = ("pashov-x-ray", "pashov-solidity-auditor", "pashov-fizz")


@pytest.mark.parametrize("entry_id", METHODOLOGY_IDS)
def test_describe_reports_methodology_only(entry_id: str) -> None:
    entry = Extension().describe(entry_id)
    assert entry.kind == "methodology-only"
    assert entry.protocols == ("none",)


@pytest.mark.parametrize("entry_id", METHODOLOGY_IDS)
def test_invoke_raises_not_an_arm(entry_id: str) -> None:
    with pytest.raises(NotAnArmError) as err:
        Extension().invoke(entry_id, "run", {})
    assert err.value.entry_id == entry_id
    assert err.value.kind == "methodology-only"


@pytest.mark.parametrize("entry_id", METHODOLOGY_IDS)
def test_dispatch_maps_methodology_only_to_generic_exit_two(entry_id: str) -> None:
    outcome = dispatch_invoke(Extension(), arm_id=entry_id, action="run")
    assert outcome.exit_code == 2
    assert outcome.document["ok"] is False
    assert outcome.document["arm_id"] == entry_id
    assert outcome.document["error"] == f"{entry_id} is methodology-only, not an arm"


@pytest.mark.parametrize("entry_id", METHODOLOGY_IDS)
def test_cli_invoke_refuses_methodology_only_via_generic_path(
    capsys: pytest.CaptureFixture[str], entry_id: str
) -> None:
    assert main(["invoke", entry_id, "run"]) == 2
    document = json.loads(capsys.readouterr().out)
    assert document["ok"] is False
    assert document["error"] == f"{entry_id} is methodology-only, not an arm"


@pytest.mark.parametrize("entry_id", METHODOLOGY_IDS)
def test_mcp_invoke_refuses_methodology_only_with_is_error(entry_id: str) -> None:
    server = McpServer(extension=Extension())
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "invoke",
                "arguments": {"id": entry_id, "action": "run"},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    document = json.loads(response["result"]["content"][0]["text"])
    assert document["ok"] is False
    assert document["error"] == f"{entry_id} is methodology-only, not an arm"
