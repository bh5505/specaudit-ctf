"""The executed agent-head lane: fake-head personas, evidence gate, CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exercise import fake_head
from exercise.__main__ import main as exercise_main
from exercise.attempt import AttemptError, grade_attempt
from exercise.runner import ExerciseError, run_exercise
from extension import trace

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_02 = (
    ROOT / "challenges" / "telecom-aws-02-iam-s3-misconfig" / "artifacts" / "expected-findings.json"
)
CONTRACT_03 = (
    ROOT / "challenges" / "telecom-aws-03-iam-privesc" / "artifacts" / "expected-findings.json"
)
KEY_HEX = "ab" * 32


def _run_persona(persona: str, contract: Path, attempt_dir: Path) -> None:
    """Drive one persona with a test-owned key via the environment."""
    import os

    monkeyvars = {
        trace.ENV_TRACE: str(attempt_dir / "trace.ndjson"),
        trace.ENV_KEY: KEY_HEX,
        trace.ENV_ATTEMPT: "c0" * 32,
    }
    saved = {key: os.environ.pop(key, None) for key in monkeyvars}
    os.environ.update(monkeyvars)
    try:
        fake_head.run_attempt(persona, expected_path=contract, attempt_dir=attempt_dir)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_competent_persona_passes_with_genuine_tool_evidence(
    tmp_path: Path,
) -> None:
    attempt_dir = tmp_path / "attempt"
    _run_persona("competent", CONTRACT_02, attempt_dir)
    document = grade_attempt(attempt_dir, expected_path=CONTRACT_02, key_env=KEY_HEX)
    assert document["trace"]["chain_ok"] is True
    assert document["trace"]["tool_calls"] == 5
    assert document["passed"] is True, document["reason"]
    assert document["unverified"] == []
    assert len(document["verified"]) == 3
    assert document["touched_fixtures"], "run_range must cover the roster"


def test_competent_persona_is_contract_derived(tmp_path: Path) -> None:
    """A second challenge passes too: nothing about it is hard-coded."""
    attempt_dir = tmp_path / "attempt"
    _run_persona("competent", CONTRACT_03, attempt_dir)
    document = grade_attempt(attempt_dir, expected_path=CONTRACT_03, key_env=KEY_HEX)
    assert document["passed"] is True, document["reason"]
    assert len(document["verified"]) == 4


def test_blind_zero_persona_is_never_graded(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt"
    _run_persona("blind-zero", CONTRACT_02, attempt_dir)
    document = grade_attempt(attempt_dir, expected_path=CONTRACT_02, key_env=KEY_HEX)
    assert document["passed"] is False
    assert document["status"] == "failed"
    assert "no tool calls" in document["reason"]
    assert "grade" not in document, "a zero-call trace is never graded"


def test_blind_irrelevant_persona_fails_on_the_evidence_gate(
    tmp_path: Path,
) -> None:
    attempt_dir = tmp_path / "attempt"
    _run_persona("blind-irrelevant", CONTRACT_02, attempt_dir)
    document = grade_attempt(attempt_dir, expected_path=CONTRACT_02, key_env=KEY_HEX)
    assert document["grade"]["passed"] is True, "prose alone grades fine — that is the hole"
    assert document["passed"] is False
    keys = {row["finding_key"] for row in document["unverified"]}
    assert len(keys) == 3
    assert all("trace never touched" in row["reason"] for row in document["unverified"])
    assert document["verified"] == []


def test_truncated_attempt_fails_closed(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt"
    _run_persona("competent", CONTRACT_02, attempt_dir)
    trace_path = attempt_dir / "trace.ndjson"
    lines = trace_path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if '"close"' not in line]
    trace_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    document = grade_attempt(attempt_dir, expected_path=CONTRACT_02, key_env=KEY_HEX)
    assert document["passed"] is False
    assert document["trace"]["chain_ok"] is False


def test_attempt_without_key_is_a_usage_error(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt"
    _run_persona("competent", CONTRACT_02, attempt_dir)
    with pytest.raises(AttemptError, match="trace key"):
        grade_attempt(attempt_dir, expected_path=CONTRACT_02, key_env=None)


def test_every_contract_finding_parses_to_coverable_fixtures() -> None:
    """Drift alarm: a traces_to phrasing that names no fixture would
    fail honest agents — every shipped finding must stay parseable."""
    from exercise.attempt import fixtures_named
    from extension.trace import range_fixture_ids

    roster = range_fixture_ids()
    contracts = sorted((ROOT / "challenges").glob("*/artifacts/*expected*.json"))
    assert len(contracts) == 8, "the challenge library grew — keep this pin honest"
    for contract in contracts:
        document = json.loads(contract.read_text(encoding="utf-8"))
        for finding in document["findings"]:
            named = fixtures_named(finding["traces_to"], roster)
            assert named, f"{contract.name}:{finding['finding_key']} names no fixture"


def test_runner_executes_the_fake_head_and_passes(tmp_path: Path) -> None:
    document = run_exercise(
        challenge="telecom-aws-02-iam-s3-misconfig",
        head="fake",
        head_execute=True,
        attempt_dir=str(tmp_path / "attempt"),
        expected_path=str(CONTRACT_02),
    )
    lane = document["head"]
    assert lane["mode"] == "executed"
    assert lane["status"] == "passed"
    assert lane["passed"] is True
    assert lane["trace"]["chain_ok"] is True
    assert document["status"] == "complete"
    assert document["ok"] is True


def test_runner_executed_attempt_failure_fails_the_run(tmp_path: Path) -> None:
    """The blind persona through the full runner: failed, never degraded."""
    attempt_dir = tmp_path / "attempt"
    _run_persona("blind-irrelevant", CONTRACT_02, attempt_dir)
    document = run_exercise(
        challenge="telecom-aws-02-iam-s3-misconfig",
        attempt_dir=str(attempt_dir),
        expected_path=str(CONTRACT_02),
    )
    assert document["head"]["mode"] == "executed"
    assert document["head"]["status"] == "failed"
    assert document["status"] == "failed"
    assert document["ok"] is False


def test_runner_coupling_matrix() -> None:
    with pytest.raises(ExerciseError, match="never spawned by the runner"):
        run_exercise(head="claude-code", head_execute=True, attempt_dir="x", expected_path="y")
    with pytest.raises(ExerciseError, match="requires --attempt-dir"):
        run_exercise(head="fake", head_execute=True, expected_path="y")
    with pytest.raises(ExerciseError, match="requires --expected"):
        run_exercise(head="fake", head_execute=True, attempt_dir="x")
    with pytest.raises(ExerciseError, match="no launcher to probe"):
        run_exercise(head="fake")
    with pytest.raises(ExerciseError, match="requires --expected"):
        run_exercise(attempt_dir="x")


def test_cli_attempt_flags(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert exercise_main(["--head", "fake", "--head-execute"]) == 2
    assert exercise_main(["--head", "fake"]) == 2
    assert "no launcher to probe" in capsys.readouterr().err
    document = run_exercise(head="claude-code")
    assert document["head"]["mode"] == "readiness"

    out = tmp_path / "report.json"
    attempt_dir = tmp_path / "attempt"
    assert (
        exercise_main(
            [
                "--head-execute",
                "--head",
                "fake",
                "--attempt-dir",
                str(attempt_dir),
                "--expected",
                str(CONTRACT_02),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["head"]["passed"] is True
