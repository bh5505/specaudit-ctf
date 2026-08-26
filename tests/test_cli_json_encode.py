"""CLI invoke/run_range emit execution-result.v1, not the pre-v1 shapes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from extension.__main__ import main as invoke_main
from extension.contract import Result
from extension.encode import encode_range_document
from extension.envelopes import (
    KNOWN_CAPABILITY_IDS,
    RESULT_SCHEMA_ID,
    accept_pair,
    parse_execution_result,
)
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
    code = invoke_main(["invoke", "burp-mcp", "list_tools"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["capability_id"] == "burp-mcp.list_tools"
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert "held" in parsed.reasons
    assert code == 2
    pair = accept_pair(MANIFESTS / "held.json", payload)
    assert pair.status == "failed"
    assert "held" in pair.reasons


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
    monkeypatch.setattr("extension.arms.checkov.arm.resolve_binary", lambda: None)
    code = invoke_main(["invoke", "checkov", "scan"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(
        payload, known_ids=(*KNOWN_CAPABILITY_IDS, "checkov.scan")
    )
    assert payload["capability_id"] == "checkov.scan"
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert code == 2
    assert parsed.status == "failed"


def test_invoke_invalid_json_args_emits_failed_envelope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = invoke_main(["invoke", "checkov", "scan", "not-json"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(
        payload, known_ids=(*KNOWN_CAPABILITY_IDS, "checkov.scan")
    )
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert code == 2
    assert parsed.status == "failed"
    assert any("invalid" in item.lower() for item in payload["limitations"])


def test_invoke_success_emits_v1_exit_zero_is_not_complete(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = Result(
        ok=True, arm_id="checkov", action="scan", output={"findings": []}, error=None
    )
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    code = invoke_main(["invoke", "checkov", "scan", "{}"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(
        payload, known_ids=(*KNOWN_CAPABILITY_IDS, "checkov.scan")
    )
    assert payload["status"] == "complete"
    assert payload["transport_ok"] is True
    assert code == 0
    assert parsed.status == "complete"
    assert parsed.result.transport_ok is True
    assert parsed.result.artifacts
    default = parse_execution_result(payload)
    assert default.status == "failed"
    assert "unknown-capability" in default.reasons


def test_invoke_transport_ok_exit_zero_can_be_non_complete(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = Result(ok=True, arm_id="checkov", action="scan", output=None, error=None)
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    code = invoke_main(["invoke", "checkov", "scan", "{}"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(
        payload, known_ids=(*KNOWN_CAPABILITY_IDS, "checkov.scan")
    )
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
        arm_id="checkov",
        action="scan",
        output=None,
        error="scanner failed",
    )
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    code = invoke_main(["invoke", "checkov", "scan"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(
        payload, known_ids=(*KNOWN_CAPABILITY_IDS, "checkov.scan")
    )
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is True
    assert code == 1
    assert parsed.status == "failed"


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
    assert len(inner["coverage"]["attempted"]) == 26
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
