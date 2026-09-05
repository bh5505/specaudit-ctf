"""Exercise runner: composition, fail-closed lanes, deterministic report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exercise.__main__ import main as exercise_main
from exercise.runner import SCHEMA_ID, ExerciseError, run_exercise

ROOT = Path(__file__).resolve().parents[1]
CHAIN_CONTRACT = (
    ROOT
    / "challenges"
    / "telecom-aws-06-chain-rehearsal"
    / "artifacts"
    / "expected-findings.json"
)


def _minimal() -> dict:
    return run_exercise()


def test_minimal_exercise_is_complete_and_deterministic() -> None:
    first = _minimal()
    second = _minimal()
    assert first == second, "the report must be deterministic per host"
    assert first["schema"] == SCHEMA_ID
    assert first["status"] == "complete"
    assert first["ok"] is True
    assert first["live_aws"] is False
    assert first["range"]["matched"] is True
    assert len(first["range"]["fixtures"]) == 10
    assert first["grading"] is None
    assert first["arms"] == []
    assert "exercise complete" in first["summary"]


def test_fixture_subset_and_unknown_rejection() -> None:
    document = run_exercise(fixtures=["tf_chain_ingress_role", "tf_iam_open"])
    # Reported in manifest order, narrowed to the requested subset.
    assert document["range"]["fixtures"] == ["tf_iam_open", "tf_chain_ingress_role"]
    assert document["range"]["ok"] is True
    assert len(document["range"]["chains"]) == 1
    with pytest.raises(ExerciseError, match="unknown fixtures"):
        run_exercise(fixtures=["tf_no_such_fixture"])


def test_grading_lane_pass_and_fail(tmp_path: Path) -> None:
    contract = json.loads(CHAIN_CONTRACT.read_text(encoding="utf-8"))
    perfect = tmp_path / "perfect.json"
    perfect.write_text(json.dumps(contract), encoding="utf-8")
    document = run_exercise(
        challenge="telecom-aws-06-chain-rehearsal",
        found_path=str(perfect),
        expected_path=str(CHAIN_CONTRACT),
    )
    assert document["grading"]["passed"] is True
    assert document["status"] == "complete"

    partial = dict(contract)
    partial["findings"] = contract["findings"][:2]
    partial["total"] = 2
    missing_two = tmp_path / "partial.json"
    missing_two.write_text(json.dumps(partial), encoding="utf-8")
    document = run_exercise(
        challenge="telecom-aws-06-chain-rehearsal",
        found_path=str(missing_two),
        expected_path=str(CHAIN_CONTRACT),
    )
    assert document["grading"]["passed"] is False
    assert document["status"] == "failed", "a failed grade is never degraded"
    assert document["ok"] is False

    with pytest.raises(ExerciseError, match="both the found document"):
        run_exercise(found_path=str(perfect))


def test_grading_schema_fault_is_recorded_not_raised(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{nope", encoding="utf-8")
    document = run_exercise(found_path=str(broken), expected_path=str(CHAIN_CONTRACT))
    assert document["status"] == "failed"
    assert document["grading"]["passed"] is False
    assert "error" in document["grading"]


def test_arms_lane_offline_success_and_refusal() -> None:
    document = run_exercise(
        arms=[
            {"arm_id": "agent-wiz", "action": "list_tools", "args": {}},
            {"arm_id": "no-such-arm", "action": "scan", "args": {}},
        ]
    )
    rows = document["arms"]
    assert rows[0]["status"] == "complete"
    assert rows[0]["capability_id"] == "agent-wiz.list_tools"
    assert rows[1]["status"] == "failed"
    assert document["status"] == "failed"


def test_head_lane_readiness_only() -> None:
    document = run_exercise(head="claude-code")
    assert document["head"]["ready"] is True
    assert document["head"]["status"] == "available"
    with pytest.raises(ExerciseError, match="unknown head"):
        run_exercise(head="no-such-head")


def test_cli_modes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "report.json"
    assert (
        exercise_main(["--challenge", "telecom-aws-06-chain-rehearsal", "--out", str(out)])
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert out.is_file()

    contract = json.loads(CHAIN_CONTRACT.read_text(encoding="utf-8"))
    empty = tmp_path / "empty.json"
    empty.write_text(
        json.dumps({"track": contract["track"], "total": 0, "findings": []}),
        encoding="utf-8",
    )
    code = exercise_main(
        [
            "--found",
            str(empty),
            "--expected",
            str(CHAIN_CONTRACT),
            "--out",
            str(tmp_path / "graded.json"),
        ]
    )
    assert code == 1
    graded = json.loads((tmp_path / "graded.json").read_text(encoding="utf-8"))
    assert graded["status"] == "failed"

    assert exercise_main(["--fixtures", "nope"]) == 2
    assert exercise_main(["--arms", "[not-json"]) == 2
