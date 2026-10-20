"""Unit + stub tests for the curated metasploit arm. No live msfrpcd."""

from __future__ import annotations

import json
from typing import Any

import pytest

from extension.arms.metasploit import (
    ARM_ID,
    MetasploitArm,
)
from extension.arms.metasploit.policy import (
    ENV_ENDPOINT,
)
from extension.contract import ArmSpec, NotInstalledError

ALL_TOOLS = ("list_exploits", "list_active_sessions", "run_exploit", "send_session_command")


def _spec() -> ArmSpec:
    return ArmSpec(
        id=ARM_ID,
        protocols=("mcp",),
        notes="Fixture arm.",
    )


class FakeSession:
    def __init__(self, tools: list[dict[str, Any]] | None = None) -> None:
        self.tools = tools or [{"name": name} for name in ALL_TOOLS]
        self.calls: list[tuple[str, dict]] = []
        self.closed = False

    def connect(self) -> None:
        return None

    def list_tools(self) -> list[dict[str, Any]]:
        return list(self.tools)

    def call_tool(self, name: str, arguments: dict | None = None) -> dict[str, Any]:
        self.calls.append((name, dict(arguments or {})))
        return {"content": [{"type": "text", "text": json.dumps({"ok": name})}]}

    def close(self) -> None:
        self.closed = True


def _arm(session: FakeSession) -> MetasploitArm:
    return MetasploitArm(
        endpoint="http://127.0.0.1:8085",
        session_factory=lambda url, timeout=10.0: session,
    )


# --- install gate -------------------------------------------------------


def test_not_installed_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    arm = MetasploitArm()
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "list_exploits", {})


# --- tool listing and invocation ---------------------------------------


def test_list_tools_shows_supported_tools() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "list_tools", {})
    assert result.ok is True
    assert result.output["actions"] == sorted(ALL_TOOLS)


def test_advertised_read() -> None:
    session = FakeSession()
    result = _arm(session).invoke(
        _spec(), "list_active_sessions", {}
    )
    assert result.ok is True
    assert session.calls == [("list_active_sessions", {})]


def test_exploit_runs_with_operator_selected_targets() -> None:
    session = FakeSession()
    result = _arm(session).invoke(
        _spec(), "run_exploit", {"RHOSTS": "10.10.0.1"}
    )
    assert result.ok is True
    assert session.calls == [("run_exploit", {"RHOSTS": "10.10.0.1"})]


def test_supported_tool_missing_on_server_refused() -> None:
    session = FakeSession(tools=[{"name": "list_exploits"}])
    result = _arm(session).invoke(
        _spec(), "run_exploit", {"RHOSTS": "10.0.0.1"}
    )
    assert result.ok is False
    assert "not available on the server" in result.error


def test_unknown_action_lists_supported_tools() -> None:
    result = _arm(FakeSession()).invoke(_spec(), "exploit", {})
    assert result.ok is False
    assert "not available on the server" in result.error


def test_operator_selected_range_reaches_upstream() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "run_exploit", {"RHOSTS": "10.10.0.0/24"})
    assert result.ok is True
    assert session.calls == [("run_exploit", {"RHOSTS": "10.10.0.0/24"})]
