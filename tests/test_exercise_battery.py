"""The default CTF battery composes five arm calls and reports their outcomes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exercise.__main__ import main as exercise_main
from exercise.battery import BATTERY_PRESET, TARGET_ENV
from exercise.runner import run_exercise
from extension.contract import Result
from extension.dispatch import DispatchOutcome


@pytest.fixture(autouse=True)
def _missing_binaries(monkeypatch: pytest.MonkeyPatch) -> None:
    for arm_id in ("CHECKOV", "SEMGREP", "WAPITI", "NMAP"):
        monkeypatch.setenv(f"{arm_id}_BIN", f"/nonexistent/{arm_id.lower()}")
    monkeypatch.delenv(TARGET_ENV, raising=False)


def _outcome(arm_id: str, action: str, ok: bool = True) -> DispatchOutcome:
    result = Result(ok, arm_id, action, {"tested": True} if ok else None,
                    None if ok else "command failed")
    return DispatchOutcome(result.to_dict(), 0 if ok else 1)


def test_preset_has_visible_targets_and_real_demo_rules() -> None:
    assert [(member.arm_id, member.action) for member in BATTERY_PRESET] == [
        ("checkov", "scan"), ("semgrep-mcp", "semgrep_scan"),
        ("attack-stix-data", "technique"), ("wapiti", "scan"),
        ("nmap", "scan"),
    ]
    _, semgrep, stix, wapiti, nmap = BATTERY_PRESET
    import yaml
    rules = yaml.safe_load(semgrep.args["config"])["rules"]
    assert {rule["id"] for rule in rules} == {
        "demo-terraform-s3-public-read", "demo-terraform-iam-wildcard-action"
    }
    bundle = json.loads(Path(stix.args["bundle"]).read_text(encoding="utf-8"))
    assert any(ref.get("external_id") == stix.args["id"]
               for obj in bundle["objects"] if obj.get("type") == "attack-pattern"
               for ref in obj.get("external_references", []))
    assert wapiti.args == {"url": "http://{target}:8080/"}
    assert nmap.args == {"target": "{target}"}
    assert wapiti.target_env == nmap.target_env == TARGET_ENV


def test_missing_binaries_or_target_skip_and_degrade() -> None:
    document = run_exercise(battery=True)
    assert [row["status"] for row in document["battery"]] == [
        "skipped", "skipped", "complete", "skipped", "skipped"
    ]
    assert TARGET_ENV in document["battery"][3]["reason"]
    assert document["status"] == "degraded"


def test_supplied_target_is_passed_to_arms(monkeypatch: pytest.MonkeyPatch) -> None:
    import exercise.runner as runner
    seen: dict[str, dict] = {}

    def fake_dispatch(_extension, *, arm_id, action, args=None, **_):
        seen[arm_id] = dict(args or {})
        return _outcome(arm_id, action)

    monkeypatch.setattr(runner, "dispatch_invoke", fake_dispatch)
    monkeypatch.setenv(TARGET_ENV, "192.0.2.9")
    document = run_exercise(battery=True)
    assert seen["wapiti"] == {"url": "http://192.0.2.9:8080/"}
    assert seen["nmap"] == {"target": "192.0.2.9"}
    assert document["status"] == "complete"


def test_command_failure_fails_battery(monkeypatch: pytest.MonkeyPatch) -> None:
    import exercise.runner as runner

    def fake_dispatch(_extension, *, arm_id, action, args=None, **_):
        return _outcome(arm_id, action, ok=arm_id != "nmap")

    monkeypatch.setattr(runner, "dispatch_invoke", fake_dispatch)
    monkeypatch.setenv(TARGET_ENV, "192.0.2.9")
    document = run_exercise(battery=True)
    assert document["battery"][4]["status"] == "failed"
    assert document["status"] == "failed"


def test_battery_report_is_deterministic() -> None:
    assert run_exercise(battery=True) == run_exercise(battery=True)


def test_cli_battery_flag_reports_skips(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    code = exercise_main(["--battery", "--out", str(out)])
    assert code == 1
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "degraded"
    assert len(report["battery"]) == 5
