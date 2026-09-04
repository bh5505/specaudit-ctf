"""Unit + stub tests for the curated Semgrep arm. No live semgrep."""

from __future__ import annotations

import json
import os
from typing import Any

import pytest

from extension.arms.semgrep import ALLOWED_TOOLS, ARM_ID, BLOCKED_TOOLS, SemgrepArm
from extension.arms.semgrep.policy import ENV_ENDPOINT, scan_config_refusal
from extension.contract import ArmSpec, Extension, NotHeldError, NotInstalledError

ALL_TOOLS = tuple(ALLOWED_TOOLS) + tuple(BLOCKED_TOOLS)


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
            else [{"name": name} for name in ALL_TOOLS]
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


def _arm(session: FakeSession, endpoint: str = "https://semgrep.example.invalid:9") -> SemgrepArm:
    return SemgrepArm(endpoint=endpoint, session_factory=_factory(session))


# --- install gate -------------------------------------------------------


def test_not_installed_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    arm = SemgrepArm()
    assert arm.endpoint_url() is None
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "semgrep_findings", {})


def test_env_endpoint_installs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_ENDPOINT, "https://semgrep.example.invalid:8899/")
    arm = SemgrepArm()
    assert arm.endpoint_url() == "https://semgrep.example.invalid:8899/"
    assert arm.installed(_spec()) is True


def test_endpoint_with_crlf_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_ENDPOINT, "http://127.0.0.1:8899/\r\nX: y")
    arm = SemgrepArm()
    assert arm.endpoint_url() is None
    assert arm.installed(_spec()) is False


# --- policy -------------------------------------------------------------


def test_blocked_tool_refused() -> None:
    session = FakeSession()
    arm = _arm(session)
    result = arm.invoke(_spec(), "security_check", {})
    assert result.ok is False
    assert "is blocked" in result.error
    assert session.calls == []


def test_unknown_tool_refused() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "semgrep_publish", {})
    assert result.ok is False
    assert "not on the allowlist" in result.error


def test_tool_not_on_server_refused() -> None:
    session = FakeSession(tools=[{"name": "semgrep_findings"}])
    result = _arm(session).invoke(_spec(), "supported_languages", {})
    assert result.ok is False
    assert "not available on the server" in result.error


def test_scan_config_egress_gate() -> None:
    assert scan_config_refusal({}) is not None
    assert "inline rule pack" in scan_config_refusal({})
    assert "registry" in scan_config_refusal({"config": "auto"})
    assert "registry" in scan_config_refusal({"config": "p/xss"})
    assert "URL" in scan_config_refusal({"config": "https://rules.example/r.yaml"})
    assert "NUL" in scan_config_refusal({"config": "rules:\n\x00"})
    assert scan_config_refusal({"config": "rules:\n  - id: x"}) is None


def test_scan_without_config_refused() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "semgrep_scan", {})
    assert result.ok is False
    assert "inline rule pack" in result.error
    assert session.calls == []


def test_scan_with_registry_config_refused() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "semgrep_scan", {"config": "auto"})
    assert result.ok is False
    assert "registry" in result.error
    assert session.calls == []


# --- invoke -------------------------------------------------------------


def test_list_tools() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "list_tools", {})
    assert result.ok is True
    assert {tool["name"] for tool in result.output["tools"]} == set(ALL_TOOLS)
    assert session.closed is True


def test_allowlisted_findings_call() -> None:
    session = FakeSession()
    result = _arm(session).invoke(_spec(), "semgrep_findings", {"limit": 10})
    assert result.ok is True
    assert session.calls == [("semgrep_findings", {"limit": 10})]


def test_scan_with_inline_config_runs() -> None:
    session = FakeSession()
    config = "rules:\n  - id: fixture\n    pattern: eval(...)"
    result = _arm(session).invoke(_spec(), "semgrep_scan", {"config": config})
    assert result.ok is True
    assert session.calls == [("semgrep_scan", {"config": config})]


def test_tool_iserror_is_failure() -> None:
    session = FakeSession(
        results={
            "semgrep_findings": {
                "content": [{"type": "text", "text": "token abc denied"}],
                "isError": True,
            }
        }
    )
    result = _arm(session).invoke(_spec(), "semgrep_findings", {})
    assert result.ok is False
    assert "[redacted]" in result.error


def test_connect_error_is_result_not_raise() -> None:
    session = FakeSession(connect_error=RuntimeError("endpoint unreachable: token x"))
    result = _arm(session).invoke(_spec(), "semgrep_findings", {})
    assert result.ok is False
    assert "[redacted]" in result.error


def test_rows_capped() -> None:
    rows = [{"i": i} for i in range(500)]
    session = FakeSession(
        results={
            "semgrep_findings": {
                "content": [
                    {"type": "text", "text": "\n\n".join(json.dumps(r) for r in rows)}
                ],
                "isError": False,
            }
        }
    )
    result = _arm(session).invoke(_spec(), "semgrep_findings", {})
    assert result.ok is True
    assert result.output["meta"]["clamped"] is True
    assert len(result.output["data"]) == 200


# --- extension wiring ---------------------------------------------------


def test_default_extension_wires_semgrep(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from extension.contract import Extension, NotInstalledError

    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    # Deterministic across hosts (Kali ships semgrep on PATH): pin the
    # binary env at a missing path so neither surface installs the arm.
    monkeypatch.setenv("SEMGREP_BIN", str(tmp_path / "missing-semgrep"))
    ext = Extension()
    assert "semgrep-mcp" in ext.arms
    with pytest.raises(NotInstalledError):
        ext.invoke("semgrep-mcp", "semgrep_findings", {})


def test_extension_invoke_with_env() -> None:
    """Research tier: MCP reads reachable through the arm wiring."""
    ext = Extension(
        arms={
            ARM_ID: type(
                "Wired",
                (),
                {
                    "ARM_ID": ARM_ID,
                    "protocol": "mcp",
                    "installed": lambda self, spec: True,
                    "invoke": lambda self, spec, action, args: _arm(
                        FakeSession()
                    ).invoke(spec, action, dict(args)),
                },
            )()
        }
    )
    result = ext.invoke(ARM_ID, "supported_languages", {})
    assert result.ok is True


def test_scan_config_multiline_body_not_prefix_matched() -> None:
    """Multi-line inline rule bodies are never prefix-matched (review fix).

    A YAML body can legitimately reference URLs or contain
    registry-shaped keys; only single-line tokens are egress-checked.
    """
    body = "p/example:\n  - id: x\n    references: https://r.example"
    assert scan_config_refusal({"config": body}) is None
    assert "URL" in scan_config_refusal({"config": "https://rules.example"})
    assert "registry" in scan_config_refusal({"config": "p/xss"})
