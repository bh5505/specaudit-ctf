"""CLI invoke/run_range emit execution-result.v1, not the pre-v1 shapes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from extension.__main__ import main as invoke_main
from extension.contract import Result
from extension.encode import encode_range_document
from extension.envelopes import RESULT_SCHEMA_ID, accept_pair, parse_execution_result
from extension.invoke_profiles import INVOKE_PROFILES, PACKAGE_VERSION
from extension.range import run_range
from extension.range.__main__ import main as range_main
from tests.test_range_lifecycle import apply_no_curated_tools

ROOT = Path(__file__).resolve().parents[1]
RESULT_SCHEMA_PATH = ROOT / "extension" / "schema" / "execution-result.v1.schema.json"
MANIFESTS = ROOT / "tests" / "goldens" / "capability-manifest"
PREV1_INVOKE_KEYS = frozenset({"ok", "arm_id", "action", "output", "error"})
RANGE_LIFECYCLE_V2 = "range.lifecycle.v2"


def _schema() -> dict[str, Any]:
    payload = json.loads(RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _stdout_json(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert isinstance(payload, dict)
    return payload


def _assert_execution_result(payload: dict[str, Any], *, known_ids: Any = None) -> Any:
    assert payload["schema"] == RESULT_SCHEMA_ID
    assert payload["schema_version"] == 1
    assert payload["schema"] != RANGE_LIFECYCLE_V2
    for key in PREV1_INVOKE_KEYS:
        assert key not in payload
    assert "fixtures" not in payload
    jsonschema.validate(instance=payload, schema=_schema())
    parsed = parse_execution_result(payload, known_ids=known_ids)
    assert parsed.schema_ok is True
    assert parsed.result is not None
    assert parsed.status == payload["status"]
    assert parsed.status in {"complete", "degraded", "failed"}
    return parsed


@pytest.fixture
def no_curated_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    apply_no_curated_tools(monkeypatch)


def test_list_stays_catalog_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert invoke_main(["list"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    assert payload
    assert "id" in payload[0]
    assert payload[0].get("schema") != RESULT_SCHEMA_ID


def test_describe_stays_catalog_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert invoke_main(["describe", "checkov"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["id"] == "checkov"
    assert payload.get("schema") != RESULT_SCHEMA_ID
    assert "status" not in payload


def test_invoke_unknown_id_emits_failed_envelope_not_prev1(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = invoke_main(["invoke", "no-such-arm", "ping"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["capability_id"] == "no-such-arm.ping"
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert "unknown-capability" in parsed.reasons
    assert code == 2


def test_invoke_held_emits_failed_envelope(capsys: pytest.CaptureFixture[str]) -> None:
    """A still-held arm (semgrep-mcp) fails closed end-to-end; burp-mcp
    is admitted now and covered by its own success-path tests."""
    code = invoke_main(["invoke", "metasploit-mcp", "list_tools"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["capability_id"] == "metasploit-mcp.list_tools"
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    # Unadmitted (no profile) + held tier: the honest envelope is the
    # unknown-capability failure with the held limitation named.
    assert "unknown-capability" in parsed.reasons
    assert any("held" in line for line in payload.get("limitations", ()))
    assert code == 2


def test_invoke_methodology_only_emits_failed_envelope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = invoke_main(["invoke", "vulnhunter", "extract"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["capability_id"] == "vulnhunter.extract"
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert "methodology-only" in parsed.reasons
    assert code == 2


def test_invoke_not_installed_emits_failed_envelope(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # zgrab2, not agent-wiz: agent-wiz.list_tools enumerates from the
    # measured bundle/catalog source and no longer requires a binary (see
    # test_agentwiz_list_tools_available_without_a_binary_or_path below).
    monkeypatch.setattr("extension.arms.zgrab2.arm.resolve_binary", lambda: None)
    code = invoke_main(["invoke", "zgrab2", "list_tools"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["capability_id"] == "zgrab2.list_tools"
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert code == 2
    assert parsed.status == "failed"
    assert "required-step-skipped" in parsed.reasons
    assert "capability-profile-mismatch" not in parsed.reasons


def test_agentwiz_list_tools_available_without_a_binary_or_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unmocked: real resolve_binary() with no AGENT_WIZ_BIN and no PATH."""
    monkeypatch.delenv("AGENT_WIZ_BIN", raising=False)
    monkeypatch.setenv("PATH", "")
    code = invoke_main(["invoke", "agent-wiz", "list_tools"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["capability_id"] == "agent-wiz.list_tools"
    assert payload["status"] == "complete"
    assert payload["transport_ok"] is True
    assert code == 0
    assert parsed.status == "complete"


def test_invoke_invalid_json_args_emits_failed_envelope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = invoke_main(["invoke", "agent-wiz", "list_tools", "not-json"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert code == 2
    assert parsed.status == "failed"
    assert any("invalid" in item.lower() for item in payload["limitations"])
    assert "capability-profile-mismatch" not in parsed.reasons


def test_invoke_success_uses_manifest_profile_and_default_parser_agrees(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = Result(
        ok=True,
        arm_id="agent-wiz",
        action="list_tools",
        output={"read_actions": ["extract", "visualize"]},
        error=None,
    )
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    code = invoke_main(["invoke", "agent-wiz", "list_tools", "{}"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["status"] == "complete"
    assert payload["transport_ok"] is True
    assert code == 0
    assert parsed.status == "complete"
    assert parsed.result.transport_ok is True
    assert parsed.result.artifacts
    assert payload["tool"] == {"name": "specaudit-ctf", "version": PACKAGE_VERSION}
    assert payload["scope"] == {
        "authorized": ["policy://extension/arms/agent-wiz"],
        "touched": ["policy://extension/arms/agent-wiz"],
    }
    assert payload["safety_class"] == "R0"
    assert payload["side_effects"] == ["local-read"]
    assert payload["cleanup"]["required"] is False
    assert "unknown-capability" not in parsed.reasons


def test_manifested_policy_read_does_not_spawn_upstream_binary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "extension.arms.agentwiz.arm.resolve_binary", lambda: "/fake/agent-wiz"
    )

    def forbidden_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("list_tools spawned the upstream binary")

    monkeypatch.setattr("extension.arms.agentwiz.arm.subprocess.run", forbidden_spawn)
    assert invoke_main(["invoke", "agent-wiz", "list_tools"]) == 0
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert parsed.status == "complete"
    assert payload["capability_id"] == "agent-wiz.list_tools"


def test_default_parser_rejects_profile_metadata_tampering(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = Result(
        ok=True,
        arm_id="agent-wiz",
        action="list_tools",
        output={"read_actions": ["extract", "visualize"]},
        error=None,
    )
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    assert invoke_main(["invoke", "agent-wiz", "list_tools"]) == 0
    payload = _stdout_json(capsys)
    payload["scope"]["authorized"] = ["policy://extension/arms/other"]
    parsed = parse_execution_result(payload)
    assert parsed.status == "failed"
    assert "capability-profile-mismatch" in parsed.reasons


@pytest.mark.parametrize(
    "coverage",
    [
        {
            "attempted": [],
            "complete": [],
            "skipped": [],
            "unsupported": [],
            "failed": [],
            "required": [],
        },
        {
            "attempted": ["fixture.local-read"],
            "complete": ["fixture.local-read"],
            "skipped": [],
            "unsupported": [],
            "failed": [],
            "required": ["fixture.local-read"],
        },
    ],
    ids=("empty", "foreign-capability"),
)
def test_default_parser_binds_complete_coverage_to_profile_capability(
    coverage: dict[str, list[str]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = Result(
        ok=True,
        arm_id="agent-wiz",
        action="list_tools",
        output={"read_actions": ["extract", "visualize"]},
        error=None,
    )
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    assert invoke_main(["invoke", "agent-wiz", "list_tools"]) == 0
    payload = _stdout_json(capsys)
    payload["coverage"] = coverage
    parsed = parse_execution_result(payload)
    assert parsed.status == "failed"
    assert "capability-profile-mismatch" in parsed.reasons


def test_invoke_transport_ok_exit_zero_can_be_non_complete(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = Result(
        ok=True, arm_id="agent-wiz", action="list_tools", output=None, error=None
    )
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    code = invoke_main(["invoke", "agent-wiz", "list_tools", "{}"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert code == 0
    assert payload["transport_ok"] is True
    assert payload["status"] == "failed"
    assert parsed.status == "failed"
    assert "unowned-evidence" in parsed.reasons


def test_invoke_arm_error_emits_failed_envelope_exit_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = Result(
        ok=False,
        arm_id="agent-wiz",
        action="list_tools",
        output=None,
        error="scanner failed",
    )
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    code = invoke_main(["invoke", "agent-wiz", "list_tools"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is True
    assert code == 1
    assert parsed.status == "failed"
    assert "required-step-failed" in parsed.reasons
    assert "capability-profile-mismatch" not in parsed.reasons


def test_unmanifested_dispatch_is_refused_before_extension_invoke(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[tuple[str, str]] = []

    def forbidden_invoke(self: Any, arm_id: str, action: str, args: Any = None) -> Any:
        calls.append((arm_id, action))
        raise AssertionError("unmanifested action reached Extension.invoke")

    monkeypatch.setattr("extension.__main__.Extension.invoke", forbidden_invoke)
    # sniper.scan is the standing deliberately-unadmitted example
    # (doc-20 deferral); each prior example graduated with admission.
    code = invoke_main(
        ["invoke", "sniper", "scan", '{"target":"10.10.0.5"}']
    )
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert calls == []
    assert code == 2
    assert payload["capability_id"] == "sniper.scan"
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert payload["side_effects"] == ["none"]
    assert payload["scope"]["touched"] == []
    assert "unknown-capability" in parsed.reasons


def test_manifest_profiles_carry_honest_class_truth() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert PACKAGE_VERSION == project["project"]["version"]
    assert INVOKE_PROFILES
    dispatch_class = {
        "nmap.scan",
        "zaproxy.ascan_scan",
        "zaproxy.spider_scan",
        "zgrab2.scan",
        "wapiti.scan",
        "zdns.lookup",
        "pyrit.scan",
        "routersploit.run",
        "osmedeus.scan",
        "page-fetch.fetch",
        "commix.scan",
        "semgrep-mcp.semgrep_scan",
    }
    for capability_id, profile in INVOKE_PROFILES.items():
        assert capability_id == f"{profile.arm_id}.{profile.action}"
        assert profile.cleanup_required is False
        assert profile.max_spend is None
        if capability_id in dispatch_class:
            # 2026-09-01 dispatch admission: R1, declared side effects,
            # default-off, not synthetic-only, approval + RoE named.
            assert profile.safety_class == "R1"
            assert profile.side_effects
            assert profile.default_off is True
            assert profile.synthetic_only is False
            assert profile.approval_ref and profile.roe_ref
        elif profile.arm_id == "burp-mcp":
            # MCP read admission: R0 local-read (loopback-confined),
            # default-off, not synthetic-only once the endpoint is set.
            assert profile.safety_class == "R0"
            assert profile.side_effects == ("local-read",)
            assert profile.default_off is True
            assert profile.synthetic_only is False
        elif profile.arm_id in ("google-mcp-security", "prowler-mcp"):
            # Remote-read admission: R1 network-egress lookup, the
            # endpoint env is the operator's arming decision.
            assert profile.safety_class == "R1"
            assert profile.side_effects == ("network-egress",)
            assert profile.default_off is True
            assert profile.synthetic_only is False
            assert profile.approval_ref in (
                "operator://endpoint/GTI_MCP_ENDPOINT",
                "operator://endpoint/PROWLER_MCP_ENDPOINT",
            )
        else:
            assert profile.action == "list_tools"
            assert profile.safety_class == "R0"
            assert profile.side_effects == ("local-read",)


def test_module_invoke_cli_emits_v1_subprocess() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "extension", "invoke", "no-such-arm", "ping"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    payload = json.loads(proc.stdout)
    parsed = _assert_execution_result(payload)
    assert parsed.status == "failed"
    assert proc.returncode == 2


def test_range_cli_emits_execution_result_not_lifecycle_v2(
    no_curated_tools: None, capsys: pytest.CaptureFixture[str]
) -> None:
    inner = run_range()
    code = range_main([])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert inner["schema"] == RANGE_LIFECYCLE_V2
    assert inner["ok"] is False
    assert inner["status"] == "degraded"
    assert payload["capability_id"] == "fixture.range-observe"
    assert payload["status"] == "degraded"
    assert payload["status"] != "complete"
    assert parsed.status == "degraded"
    assert code == 1


def test_range_cli_inner_ok_is_not_outer_status(
    no_curated_tools: None, capsys: pytest.CaptureFixture[str]
) -> None:
    inner = run_range(arm_ids=())
    code = range_main(["--seed", "123"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert inner["ok"] is True
    assert inner["status"] == "complete"
    # Default CLI auto-discovers arms; it must not promote inner ok to outer complete.
    assert "ok" not in payload
    assert payload["status"] == parsed.status
    if inner["ok"] and payload["status"] == "complete":
        pytest.fail("auto-discover CLI used inner lifecycle ok as outer complete")
    assert payload["status"] == "degraded"
    assert parsed.status != "complete"
    assert code == 1


def test_range_module_cli_subprocess_emits_v1() -> None:
    env = os.environ.copy()
    env.pop("BURP_MCP_ENDPOINT", None)
    env["PATH"] = str(Path(sys.executable).parent)
    proc = subprocess.run(
        [sys.executable, "-m", "extension.range", "--seed", "123"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=15,
    )
    payload = json.loads(proc.stdout)
    parsed = _assert_execution_result(payload)
    assert payload["schema"] != RANGE_LIFECYCLE_V2
    assert parsed.status != "complete"
    assert proc.returncode != 0


def test_range_complete_encoder_pairs_with_manifest() -> None:
    inner = run_range(arm_ids=())
    assert inner["ok"] is True
    payload = encode_range_document(
        inner,
        started_at="2026-08-25T12:00:00Z",
        finished_at="2026-08-25T12:00:00Z",
    )
    parsed = _assert_execution_result(payload)
    assert parsed.status == "complete"
    assert "ok" not in payload
    pair = accept_pair(MANIFESTS / "range-observe.json", payload)
    assert pair.accepted is True
    assert pair.status == "complete"


def test_range_encoder_spends_one_step_under_freeze_budget(
    no_curated_tools: None,
) -> None:
    inner = run_range()
    assert len(inner["coverage"]["attempted"]) == 27
    payload = encode_range_document(
        inner,
        started_at="2026-08-25T12:00:00Z",
        finished_at="2026-08-25T12:00:00Z",
    )
    parsed = _assert_execution_result(payload)
    assert payload["budget"]["reserved"]["max_tool_steps"] == 16
    assert payload["budget"]["spent"]["tool_steps"] == 1
    assert payload["status"] == "degraded"
    assert parsed.status == "degraded"
    assert "budget-breach" not in parsed.reasons


def test_encode_range_ignores_inner_compatibility_ok() -> None:
    inner = dict(run_range(arm_ids=()))
    inner["ok"] = True
    inner["status"] = "failed"
    payload = encode_range_document(
        inner,
        started_at="2026-08-25T12:00:00Z",
        finished_at="2026-08-25T12:00:00Z",
    )
    parsed = _assert_execution_result(payload)
    assert "ok" not in payload
    assert payload["status"] == "failed"
    assert parsed.status == "failed"


def test_run_range_without_runner_is_a_typed_failed_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sealed bundle ships no extension/range/*: that must be an
    evaluated non-success envelope on both transports, never a traceback."""
    from extension import dispatch as dispatch_mod
    from extension.contract import Extension

    def _unavailable() -> tuple[type[Exception], object]:
        raise ImportError("extension.range.runner is not in this runtime")

    monkeypatch.setattr(dispatch_mod, "_load_range_runner", _unavailable)
    outcome = dispatch_mod.dispatch_range(Extension(), arm_ids=[])
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert "range runner unavailable" in (outcome.stderr_line or "")
    assert outcome.exit_code == 1
    assert outcome.contract_error is None
