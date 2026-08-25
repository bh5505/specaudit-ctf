"""Unit + stub tests for the curated metasploit arm. No live msfrpcd."""

from __future__ import annotations

import json
from typing import Any

import pytest

from extension.arms.metasploit import (
    ALLOWED_TOOLS,
    ARM_ID,
    DISPATCH_TOOLS,
    MetasploitArm,
)
from extension.arms.metasploit.policy import (
    ENV_DISPATCH_SCOPE,
    ENV_ENDPOINT,
    audit_target,
    extract_targets,
)
from extension.contract import ArmSpec, NotInstalledError

ALL_TOOLS = tuple(ALLOWED_TOOLS) + tuple(DISPATCH_TOOLS)


def _spec() -> ArmSpec:
    return ArmSpec(
        id=ARM_ID,
        protocols=("mcp", "http"),
        curated=True,
        notes="Fixture arm.",
        tier="research",
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


# --- target extraction --------------------------------------------------


def test_extract_targets_enumerates_members() -> None:
    targets, refusal = extract_targets({"RHOSTS": "10.10.0.1 10.10.0.2, lab.hx"})
    assert refusal is None
    assert targets == ["10.10.0.1", "10.10.0.2", "lab.hx"]


def test_extract_targets_refuses_ranges() -> None:
    targets, refusal = extract_targets({"RHOST": "10.10.0.1-10.10.0.9"})
    assert targets is None
    assert "enumerated hosts" in refusal
    targets, refusal = extract_targets({"RHOSTS": "10.10.0.0/24"})
    assert targets is None


def test_extract_targets_none_when_absent() -> None:
    targets, refusal = extract_targets({"SESSION": 3})
    assert targets is None and refusal is None


def test_audit_target_prefers_hosts_then_sessions() -> None:
    assert audit_target({"RHOST": "10.0.0.1"}, ["10.0.0.1"]) == "10.0.0.1"
    assert audit_target({"SESSION": 3}, None) == "session:3"
    assert audit_target({"JOB_ID": 7}, None) == "job:7"
    assert audit_target({}, None) is None


# --- read tier ----------------------------------------------------------


def test_list_tools_shows_tiers() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "list_tools", {})
    assert result.ok is True
    assert result.output["read_tier"] == sorted(ALLOWED_TOOLS)
    assert result.output["dispatch_tier"] == sorted(DISPATCH_TOOLS)
    assert result.output["dispatch_armed"] is False


def test_allowlisted_read() -> None:
    session = FakeSession()
    result = _arm(session).invoke(
        _spec(), "list_active_sessions", {}
    )
    assert result.ok is True
    assert session.calls == [("list_active_sessions", {})]


# --- dispatch tier ------------------------------------------------------


def test_exploit_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_DISPATCH_SCOPE, raising=False)
    session = FakeSession()
    result = _arm(session).invoke(
        _spec(), "run_exploit", {"RHOSTS": "10.10.0.1"}
    )
    assert result.ok is False
    assert ENV_DISPATCH_SCOPE in result.error
    assert session.calls == []


def test_exploit_armed_in_scope_runs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    session = FakeSession()
    result = _arm(session).invoke(
        _spec(), "run_exploit", {"RHOSTS": "10.10.0.1 10.10.0.2"}
    )
    assert result.ok is True
    assert result.output["dispatch"]["target"] == "10.10.0.1,10.10.0.2"
    err = capsys.readouterr().err
    assert "arm=metasploit-mcp" in err and "action=run_exploit" in err


def test_exploit_one_member_out_of_scope_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    session = FakeSession()
    result = _arm(session).invoke(
        _spec(), "run_exploit", {"RHOSTS": "10.10.0.1 8.8.8.8"}
    )
    assert result.ok is False
    assert "outside the armed dispatch scope" in result.error
    assert "'8.8.8.8'" in result.error
    assert session.calls == []


def test_session_command_scope_presence_and_audit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "lab-internal")
    session = FakeSession()
    result = _arm(session).invoke(
        _spec(), "send_session_command", {"SESSION": 3, "COMMAND": "getuid"}
    )
    assert result.ok is True
    assert result.output["dispatch"]["target"] == "session:3"
    assert "target=session:3" in capsys.readouterr().err


def test_dispatch_tool_missing_on_server_refused() -> None:
    session = FakeSession(tools=[{"name": "list_exploits"}])
    result = _arm(session).invoke(
        _spec(), "run_exploit", {"RHOSTS": "10.0.0.1"}
    )
    assert result.ok is False
    assert "not available on the server" in result.error


def test_unknown_action_lists_dispatch_tier() -> None:
    result = _arm(FakeSession()).invoke(_spec(), "exploit", {})
    assert result.ok is False
    assert "dispatch tier" in result.error


def test_extract_targets_flag_shaped_refused() -> None:
    targets, refusal = extract_targets({"RHOST": "-h"})
    assert targets is None
    assert "flags" in refusal


def test_extract_targets_unbracketed_ipv6_refused() -> None:
    targets, refusal = extract_targets({"RHOST": "2001:db8::1"})
    assert targets is None
    assert "bracketed" in refusal
