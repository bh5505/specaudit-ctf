"""The rehearsal battery: preset pin, skip/degrade semantics, fail-closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from exercise.__main__ import main as exercise_main
from exercise.battery import BATTERY_PRESET
from exercise.runner import run_exercise


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """No battery member can really run: pin absence deterministically."""
    monkeypatch.setenv("CHECKOV_BIN", "/nonexistent/checkov")
    monkeypatch.setenv("SEMGREP_BIN", "/nonexistent/semgrep")
    monkeypatch.delenv("SEMGREP_SCAN_ROOT", raising=False)
    monkeypatch.delenv("CHECKOV_SCAN_ROOT", raising=False)


def test_battery_preset_is_the_offline_pair() -> None:
    """Deliberate composition: exactly the contained/offline members.
    Target-facing arms are lab opt-in through --arms, never preset."""
    assert [(m.arm_id, m.action) for m in BATTERY_PRESET] == [
        ("checkov", "scan"),
        ("semgrep-mcp", "semgrep_scan"),
    ]
    checkov, semgrep = BATTERY_PRESET
    assert checkov.arming_env is None, "contained by construction: nothing to arm"
    assert semgrep.arming_env == "SEMGREP_SCAN_ROOT"
    # The inline pack must parse as real semgrep rules and carry the
    # planted-fixture detections (not just be a non-empty string).
    import yaml

    pack = yaml.safe_load(semgrep.args["config"])
    assert [rule["id"] for rule in pack["rules"]] == [
        "demo-terraform-s3-public-read",
        "demo-terraform-iam-wildcard-action",
    ]
    for rule in pack["rules"]:
        assert rule["languages"] == ["terraform"]
        assert rule["patterns"] and rule["message"] and rule["severity"]


def test_battery_unadmitted_member_is_a_programming_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Consult requirement: a preset member without an admitted profile
    raises at run time — it must never present as a perpetual skip.
    Patched at exercise.battery (the module _run_battery imports from)."""
    import exercise.battery as battery_module
    from exercise.battery import BatteryMember
    from exercise.runner import ExerciseError

    monkeypatch.setattr(
        battery_module,
        "BATTERY_PRESET",
        (
            BatteryMember(
                arm_id="checkov", action="scan", args={}, arming_env=None
            ),
            BatteryMember(
                arm_id="no-such-arm",
                action="scan",
                args={},
                arming_env="NO_SUCH_ENV",
            ),
        ),
        raising=True,
    )
    with pytest.raises(ExerciseError, match="not admitted"):
        run_exercise(battery=True)


def test_battery_unavailable_members_skip_and_degrade_the_run() -> None:
    document = run_exercise(battery=True)
    rows = document["battery"]
    assert [row["status"] for row in rows] == ["skipped", "skipped"]
    assert "SEMGREP_SCAN_ROOT is unset" in rows[1]["reason"]
    assert document["status"] == "degraded", "skips degrade, never fail"
    assert document["ok"] is False


def test_battery_unarmed_semgrep_skipped_but_arms_request_fails() -> None:
    """The dual mapping: designed-safe unavailability is a skip under
    the battery preset, while the same fully-armed-shape request (the
    inline pack, but SEMGREP_SCAN_ROOT unset) through --arms keeps the
    existing fail-closed rule."""
    battery_run = run_exercise(battery=True)
    assert battery_run["battery"][1]["status"] == "skipped"

    semgrep = BATTERY_PRESET[1]
    arms_run = run_exercise(
        arms=[
            {
                "arm_id": semgrep.arm_id,
                "action": semgrep.action,
                "args": dict(semgrep.args),
            }
        ]
    )
    assert arms_run["arms"][0]["status"] == "failed"
    assert arms_run["status"] == "failed"


def _complete_outcome(arm_id: str, action: str, output) -> "object":
    from extension.contract import Result
    from extension.dispatch import DispatchOutcome
    from extension.encode import encode_invoke_result, utc_now
    from extension.invoke_profiles import invoke_profile

    # utc_now, not datetime.isoformat: the envelope grammar pins the
    # exact timestamp format.
    envelope = encode_invoke_result(
        Result(ok=True, arm_id=arm_id, action=action, output=output, error=None),
        profile=invoke_profile(arm_id, action),
        started_at=utc_now(),
        finished_at=utc_now(),
    )
    return DispatchOutcome(envelope=envelope, exit_code=0, stderr_line=None)


def test_battery_member_that_runs_and_fails_fails_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import exercise.runner as runner_module
    from extension.contract import ExtensionError

    def fake_dispatch(extension, *, arm_id, action, args=None, **_):
        if arm_id == "checkov":
            return _complete_outcome(arm_id, action, {"passed": []})
        raise ExtensionError(f"{arm_id} exploded mid-scan")

    monkeypatch.setattr(runner_module, "dispatch_invoke", fake_dispatch)
    # Arm the semgrep member so it reaches dispatch and fails there —
    # a member that RUNS and fails fails the run (unarmed would skip).
    monkeypatch.setenv("SEMGREP_SCAN_ROOT", "/nonexistent-root-not-reached")
    document = run_exercise(battery=True)
    rows = document["battery"]
    assert rows[0]["status"] == "complete"
    assert rows[1]["status"] == "failed"
    assert "exploded" in rows[1]["reason"]
    assert document["status"] == "failed"
    assert document["ok"] is False


def test_battery_all_members_complete_passes_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import exercise.runner as runner_module

    def fake_dispatch(extension, *, arm_id, action, args=None, **_):
        return _complete_outcome(arm_id, action, {"ok": True})

    monkeypatch.setattr(runner_module, "dispatch_invoke", fake_dispatch)
    monkeypatch.setenv("SEMGREP_SCAN_ROOT", "/nonexistent-root-not-reached")
    document = run_exercise(battery=True)
    assert [row["status"] for row in document["battery"]] == ["complete", "complete"]
    assert document["status"] == "complete"
    assert document["ok"] is True


def test_battery_report_is_deterministic() -> None:
    first = run_exercise(battery=True)
    second = run_exercise(battery=True)
    assert first == second
    assert first["battery"] == second["battery"]


def test_minimal_report_carries_the_battery_key() -> None:
    document = run_exercise()
    assert document["battery"] == []
    assert document["status"] == "complete"


def test_cli_battery_flag_degrades_honestly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.json"
    code = exercise_main(["--battery", "--out", str(out)])
    assert code == 1
    payload = __import__("json").loads(out.read_text(encoding="utf-8"))
    assert [row["status"] for row in payload["battery"]] == ["skipped", "skipped"]
    assert payload["status"] == "degraded"
