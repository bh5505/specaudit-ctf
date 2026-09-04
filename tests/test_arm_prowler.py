"""Unit + stub tests for the curated Prowler arm. No live cloud."""

from __future__ import annotations

import json
from typing import Any

import pytest

from extension.arms.prowler import ARM_ID, ProwlerArm
from extension.arms.prowler.policy import (
    CREDENTIAL_ENVS,
    ENV_ENDPOINT,
    refuse_reason,
)
from extension.contract import ArmSpec, Extension, NotHeldError, NotInstalledError


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
    ) -> None:
        self.tools = tools if tools is not None else []
        self.results = results or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False

    def connect(self) -> None:
        return None

    def list_tools(self) -> list[dict[str, Any]]:
        return list(self.tools)

    def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        payload = dict(arguments or {})
        self.calls.append((name, payload))
        if name in self.results:
            return self.results[name]
        return {"content": [{"type": "text", "text": json.dumps({"tool": name})}]}

    def close(self) -> None:
        self.closed = True


def _factory(session: FakeSession):
    def factory(url: str, timeout: float = 10.0) -> FakeSession:
        session.url = url
        session.timeout = timeout
        return session

    return factory


def _arm(session: FakeSession, endpoint: str = "https://prowler.example.invalid:9") -> ProwlerArm:
    return ProwlerArm(endpoint=endpoint, session_factory=_factory(session))


SERVER_TOOLS = [
    {"name": "prowler_findings_analyze"},
    {"name": "prowler_docs_search"},
    {"name": "prowler_hub_checks"},
    {"name": "prowler_cloud_scan_run"},
    {"name": "prowler_cloud_account_write"},
    {"name": "unrelated_tool"},
]


def _names() -> set[str]:
    return {tool["name"] for tool in SERVER_TOOLS}


@pytest.fixture(autouse=True)
def _creds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("PROWLER_API_KEY", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-fixture")


# --- install gate (endpoint AND credentials) -----------------------------


def test_not_installed_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    arm = ProwlerArm()
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "prowler_findings_analyze", {})


def test_endpoint_without_credentials_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_ENDPOINT, "https://prowler.example.invalid:8899")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    arm = ProwlerArm()
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "prowler_findings_analyze", {})


def test_endpoint_and_credentials_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_ENDPOINT, "https://prowler.example.invalid:8899")
    arm = ProwlerArm()
    assert arm.installed(_spec()) is True


# --- namespace policy ----------------------------------------------------


def test_scan_orchestration_namespace_blocked() -> None:
    reason = refuse_reason("prowler_cloud_scan_run", _names())
    assert reason is not None
    assert "cloud scan orchestration" in reason


def test_mutation_keyword_blocked() -> None:
    reason = refuse_reason("prowler_account_write", _names())
    assert reason is not None
    assert "mutation or scan-dispatch keyword" in reason


def test_scan_dispatch_family_blocked() -> None:
    # The upstream live-scan family must not slip through the prefix
    # allowlist (cross-review finding).
    for name in ("prowler_scan_aws", "prowler_scan", "prowler_run_checks"):
        reason = refuse_reason(name, _names())
        assert reason is not None, name
        assert "blocked" in reason


def test_off_namespace_refused() -> None:
    reason = refuse_reason("unrelated_tool", _names())
    assert reason is not None
    assert "namespace allowlist" in reason


def test_allowed_read_tools_pass() -> None:
    for name in ("prowler_findings_analyze", "prowler_docs_search", "prowler_hub_checks"):
        assert refuse_reason(name, _names()) is None, name


def test_not_available_on_server_refused() -> None:
    reason = refuse_reason("prowler_docs_other", _names())
    assert reason is not None
    assert "not available" in reason


# --- invoke --------------------------------------------------------------


def test_list_tools_and_allowed_call() -> None:
    session = FakeSession(tools=SERVER_TOOLS)
    arm = _arm(session)
    result = arm.invoke(_spec(), "list_tools", {})
    assert result.ok is True
    assert len(result.output["tools"]) == len(SERVER_TOOLS)

    result = arm.invoke(_spec(), "prowler_docs_search", {"q": "s3"})
    assert result.ok is True
    assert session.calls == [("prowler_docs_search", {"q": "s3"})]


def test_blocked_tool_never_reaches_session() -> None:
    session = FakeSession(tools=SERVER_TOOLS)
    result = _arm(session).invoke(_spec(), "prowler_cloud_scan_run", {})
    assert result.ok is False
    assert "blocked" in result.error
    assert session.calls == []


def test_tool_iserror_redacted() -> None:
    session = FakeSession(
        tools=SERVER_TOOLS,
        results={
            "prowler_docs_search": {
                "content": [{"type": "text", "text": "authorization: Bearer xyz"}],
                "isError": True,
            }
        },
    )
    result = _arm(session).invoke(_spec(), "prowler_docs_search", {})
    assert result.ok is False
    assert "[redacted]" in result.error
    assert "Bearer" not in result.error


def test_output_text_redacted() -> None:
    session = FakeSession(
        tools=SERVER_TOOLS,
        results={
            "prowler_findings_analyze": {
                "content": [
                    {"type": "text", "text": "api_key=abc123"},
                    {"type": "text", "text": " finding: open s3"},
                ],
                "isError": False,
            }
        },
    )
    result = _arm(session).invoke(_spec(), "prowler_findings_analyze", {})
    assert result.ok is True
    text = result.output["data"]
    # Shared redaction is keyword-level (same contract as the burp arm):
    # the credential keyword is masked in any output text.
    assert "[redacted]" in text
    assert "api_key" not in text


# --- extension wiring ----------------------------------------------------


def test_default_extension_wires_prowler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Research tier: without an endpoint the arm fails closed as
    not-installed (credential-gated install is unchanged)."""
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    for name in ("PROWLER_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    ext = Extension()
    assert "prowler-mcp" in ext.arms
    with pytest.raises(NotInstalledError):
        ext.invoke("prowler-mcp", "prowler_docs_search", {})


def test_success_text_capped() -> None:
    big = "x" * (500 * 1024)
    session = FakeSession(
        tools=SERVER_TOOLS,
        results={
            "prowler_docs_search": {
                "content": [{"type": "text", "text": big}],
                "isError": False,
            }
        },
    )
    result = _arm(session).invoke(_spec(), "prowler_docs_search", {})
    assert result.ok is True
    assert len(result.output["data"]) <= 512 * 1024
