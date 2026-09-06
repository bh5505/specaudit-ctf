"""Unit + stub tests for the curated Prowler arm. No live cloud, no
live endpoint - the exact-name inventory below mirrors the arm policy,
which is itself pinned from first-party source (see policy docstring)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from extension.arms.prowler import ARM_ID, ProwlerArm
from extension.arms.prowler.policy import (
    ALLOWED_TOOLS,
    BLOCKED_TOOLS,
    ENV_ENDPOINT,
    refuse_reason,
)
from extension.contract import ArmSpec, Extension, NotInstalledError


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


def _arm(
    session: FakeSession, endpoint: str = "http://127.0.0.1:8000/mcp"
) -> ProwlerArm:
    return ProwlerArm(endpoint=endpoint, session_factory=_factory(session))


# A representative first-party server surface (subset of the pinned
# inventory, one name per class plus the blocked shapes).
SERVER_TOOLS = [
    {"name": "prowler_hub_list_checks"},
    {"name": "prowler_docs_search"},
    {"name": "prowler_list_scans"},
    {"name": "prowler_get_scan"},
    {"name": "prowler_run_attack_paths_query"},
    {"name": "prowler_trigger_scan"},
    {"name": "prowler_cloud_findings_triage"},
    {"name": "not_a_prowler_tool"},
]


def _names() -> set[str]:
    return {tool["name"] for tool in SERVER_TOOLS}


# --- exact-name inventory pins (drift guard) ------------------------------


def test_inventory_counts_pinned() -> None:
    # 43 reads (31 tenant + 10 hub + 2 docs), 18 mutating, no overlap,
    # every name namespaced - pinned so upstream drift is a deliberate
    # re-pin, never a quiet shift.
    assert len(ALLOWED_TOOLS) == 43
    assert len(BLOCKED_TOOLS) == 18
    assert not (ALLOWED_TOOLS & BLOCKED_TOOLS)
    for name in ALLOWED_TOOLS | BLOCKED_TOOLS:
        assert name.startswith(("prowler_", "prowler_hub_", "prowler_docs_")), name
    assert "prowler_cloud_scan_run" not in ALLOWED_TOOLS


def test_read_admission_covers_each_namespace() -> None:
    hub = [n for n in ALLOWED_TOOLS if n.startswith("prowler_hub_")]
    docs = [n for n in ALLOWED_TOOLS if n.startswith("prowler_docs_")]
    tenant = [
        n
        for n in ALLOWED_TOOLS
        if not n.startswith(("prowler_hub_", "prowler_docs_"))
    ]
    assert len(hub) == 10
    assert len(docs) == 2
    assert len(tenant) == 31


def test_mutating_inventory_blocked() -> None:
    # Every mutating name pinned from the tenant tools source files:
    # scan triggers, mutelist writers, provider/integration writers,
    # role setting - refused even when the server lists them.
    for name in BLOCKED_TOOLS:
        reason = refuse_reason(name, _names() | {name})
        assert reason is not None, name
        assert "blocked" in reason


# --- policy ---------------------------------------------------------------


def test_hosted_namespace_blocked() -> None:
    reason = refuse_reason("prowler_cloud_findings_triage", _names())
    assert reason is not None
    assert "hosted cloud-management namespace" in reason


def test_unknown_names_refused_fail_closed() -> None:
    # The exact-allowlist miss is the containment for future upstream
    # mutating names (this replaced the 2026-09-04 keyword regex, which
    # collided with admitted reads like list_scans/get_scan).
    for name in ("unrelated_tool", "prowler_delete_everything", "prowler_scan_aws"):
        reason = refuse_reason(name, _names() | {name})
        assert reason is not None, name


def test_admitted_reads_pass() -> None:
    for name in (
        "prowler_hub_list_checks",
        "prowler_docs_search",
        "prowler_list_scans",
        "prowler_run_attack_paths_query",
    ):
        assert refuse_reason(name, _names()) is None, name


def test_not_available_on_server_refused() -> None:
    reason = refuse_reason("prowler_get_scan", set())
    assert reason is not None
    assert "not available" in reason


# --- install gate (endpoint env alone) ------------------------------------


def test_not_installed_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    arm = ProwlerArm()
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "prowler_hub_list_checks", {})


def test_endpoint_alone_installs_no_credentials_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The AWS-credential gate is withdrawn (2026-09-06): the
    # first-party server never reads AWS credentials - hub/docs are
    # unauthenticated, tenant tools use a server-held key. Ambient
    # cloud credentials in the client env neither help nor block.
    for name in ("AWS_ACCESS_KEY_ID", "AWS_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(ENV_ENDPOINT, "http://127.0.0.1:8000/mcp")
    arm = ProwlerArm()
    assert arm.installed(_spec()) is True

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-fixture")
    assert arm.installed(_spec()) is True


# --- endpoint policy (union) ----------------------------------------------


def test_union_policy_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    arm = ProwlerArm()
    # First-party local default: literal loopback http accepted.
    monkeypatch.setenv(ENV_ENDPOINT, "http://127.0.0.1:8000/mcp")
    assert arm.endpoint_url() == "http://127.0.0.1:8000/mcp"
    # Self-hosted remote behind TLS: https accepted.
    monkeypatch.setenv(ENV_ENDPOINT, "https://prowler.example.invalid:9/mcp")
    assert arm.endpoint_url() == "https://prowler.example.invalid:9/mcp"
    # Plain http off-loopback: refused.
    monkeypatch.setenv(ENV_ENDPOINT, "http://prowler.example.invalid/")
    assert arm.endpoint_url() is None
    # The loopback name (not literal): refused - names can rebind.
    monkeypatch.setenv(ENV_ENDPOINT, "http://localhost:8000/mcp")
    assert arm.endpoint_url() is None


# --- invoke ---------------------------------------------------------------


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
    result = _arm(session).invoke(_spec(), "prowler_trigger_scan", {})
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
            "prowler_hub_list_checks": {
                "content": [
                    {"type": "text", "text": "api_key=abc123"},
                    {"type": "text", "text": " check: s3 public read"},
                ],
                "isError": False,
            }
        },
    )
    result = _arm(session).invoke(_spec(), "prowler_hub_list_checks", {})
    assert result.ok is True
    text = result.output["data"]
    # Shared redaction is keyword-level (same contract as the burp arm):
    # the credential keyword is masked in any output text.
    assert "[redacted]" in text
    assert "api_key" not in text


# --- extension wiring -----------------------------------------------------


def test_default_extension_wires_prowler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Research tier: without an endpoint the arm fails closed as
    not-installed (install is gated by the endpoint env alone)."""
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
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
