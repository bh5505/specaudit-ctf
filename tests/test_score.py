"""Public scorer over execution-result.v1 envelopes — hermetic tests.

The two cardinal anti-rules are pinned by dedicated tests: transport
success is never a verdict, and a skipped/failed required arm is never
success.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from extension.envelopes import parse_execution_result
from score import Rubric, load_rubric, score_envelope, score_run
from score.rubric import RubricError
from score.scorer import GATE_NAMES, _GATE_REASONS

ROOT = Path(__file__).resolve().parent.parent
GOLDENS = ROOT / "tests" / "goldens" / "execution-result"


def _golden(name: str) -> Path:
    return GOLDENS / name


def _score_file(name: str, rubric: Rubric | None = None) -> dict:
    parsed = parse_execution_result(_golden(name))
    return score_envelope(parsed, rubric)


def test_complete_golden_passes_every_gate() -> None:
    entry = _score_file("complete-synthetic-readonly.json")
    assert entry["passed"] is True
    assert set(entry["gates"]) == set(GATE_NAMES)
    assert all(g["ok"] for g in entry["gates"].values())


def test_transport_success_is_never_a_verdict() -> None:
    # transport_ok=true but the claim is unowned: must fail, with the
    # evidence gate naming why; transport_ok is only echoed.
    entry = _score_file("transport-ok-unowned-failed.json")
    assert entry["transport_ok"] is True
    assert entry["passed"] is False
    assert entry["gates"]["owned_evidence"]["ok"] is False
    assert entry["gates"]["status_complete"]["ok"] is False


def test_required_arm_failure_is_never_success() -> None:
    entry = _score_file("required-arm-error-failed.json")
    assert entry["passed"] is False
    assert entry["gates"]["required_arms_complete"]["ok"] is False


def test_optional_arm_degraded_fails_by_default_and_waives_via_rubric() -> None:
    entry = _score_file("optional-unavailable-degraded.json")
    assert entry["status"] == "degraded"
    assert entry["passed"] is False
    assert entry["gates"]["limitations_empty"]["ok"] is False

    rubric = Rubric(
        name="waive",
        allowed_degraded=(entry["capability_id"],),
    )
    waived_entry = _score_file("optional-unavailable-degraded.json", rubric)
    assert waived_entry["passed"] is True
    assert waived_entry["status"] == "degraded"  # passes AS degraded
    assert {w["gate"] for w in waived_entry["waived"]} == {
        "limitations_empty",
        "status_complete",
    }


def test_waiver_never_rescues_a_failed_envelope() -> None:
    # required-arm failure: degraded waiver must not apply (failed, and
    # the failing gate is not waivable anyway).
    entry = _score_file(
        "required-arm-error-failed.json", Rubric(allowed_degraded=("x",))
    )
    assert entry["passed"] is False


def test_each_failure_golden_fails_its_named_gate() -> None:
    expectations = {
        "cleanup-unproven-failed.json": "cleanup_proven",
        "held-failed.json": "envelope_valid",
        "methodology-only-failed.json": "envelope_valid",
        "unknown-capability-failed.json": "envelope_valid",
        "unknown-schema-failed.json": "envelope_valid",
        "unknown-tier-failed.json": "limitations_empty",
    }
    for name, gate in expectations.items():
        entry = _score_file(name)
        assert entry["passed"] is False, name
        assert entry["gates"][gate]["ok"] is False, (name, gate)


def test_gate_reason_vocabulary_is_the_parser_s() -> None:
    # Gates import the parser's reason constants; every reason string a
    # gate can name must therefore exist in the parser's vocabulary.
    from extension import envelopes

    parser_reasons = {
        value
        for name, value in vars(envelopes).items()
        if name.startswith("REASON_") and isinstance(value, str)
    }
    for failing in _GATE_REASONS.values():
        for reason in failing:
            assert reason in parser_reasons, reason


def test_score_run_and_semantics(tmp_path: Path) -> None:
    good = tmp_path / "good.json"
    good.write_text(
        (_golden("complete-synthetic-readonly.json")).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    missing = tmp_path / "missing.json"

    document = score_run([good, bad, missing])
    assert document["passed"] is False
    assert document["scored_count"] == 3
    assert document["envelopes"][0]["passed"] is True
    assert document["envelopes"][1]["gates"]["envelope_valid"]["ok"] is False
    assert document["envelopes"][2]["gates"]["envelope_valid"]["ok"] is False
    assert all(g["ok"] for g in document["gates"].values()) is False

    only_good = score_run([good])
    assert only_good["passed"] is True

    # required_capabilities: absent id fails the run even if all
    # envelopes pass.
    with_required = score_run(
        [good], Rubric(required_capabilities=("fixture.local-read", "no.such"))
    )
    assert with_required["passed"] is False
    assert with_required["rubric"]["missing_required"] == ["no.such"]


def test_rubric_loader_is_strict(tmp_path: Path) -> None:
    ok = tmp_path / "ok.yaml"
    ok.write_text(
        "name: r\nrequired_capabilities: [fixture.local-read]\n", encoding="utf-8"
    )
    rubric = load_rubric(ok)
    assert rubric.name == "r"
    assert rubric.required_capabilities == ("fixture.local-read",)

    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    assert load_rubric(empty) == Rubric()

    bad_key = tmp_path / "bad_key.yaml"
    bad_key.write_text("name: r\nsurprise: 1\n", encoding="utf-8")
    with pytest.raises(RubricError, match="unknown keys"):
        load_rubric(bad_key)

    bad_type = tmp_path / "bad_type.yaml"
    bad_type.write_text("required_capabilities: 'oops'\n", encoding="utf-8")
    with pytest.raises(RubricError, match="list of non-empty strings"):
        load_rubric(bad_type)

    with pytest.raises(RubricError, match="unreadable"):
        load_rubric(tmp_path / "nope.yaml")


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "score", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_cli_exit_codes_and_document() -> None:
    good = str(_golden("complete-synthetic-readonly.json"))
    failed = str(_golden("required-arm-error-failed.json"))

    ok = _run_cli([good])
    assert ok.returncode == 0
    document = json.loads(ok.stdout)
    assert document["passed"] is True

    bad = _run_cli([good, failed])
    assert bad.returncode == 1
    document = json.loads(bad.stdout)  # valid document on failure too
    assert document["passed"] is False
    assert document["scored_count"] == 2

    missing = _run_cli([str(GOLDENS / "does-not-exist.json")])
    assert missing.returncode == 1
    assert json.loads(missing.stdout)["passed"] is False

    usage = _run_cli([])
    assert usage.returncode == 2
