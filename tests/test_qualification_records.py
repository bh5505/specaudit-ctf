"""Qualification records, calibration seeds, and the seed/human discriminator.

The records are validated three ways: against the closed Draft-07 schema,
against reality (every evidence_refs node id must name a test function that
exists in this checkout), and against the consult-mandated honesty rules
(per-pilot separation claims cite only tests that actually cover that pilot;
detect-01 asserts nothing). Seeds are validated through
challenges/qualification/loader.py, built into real evidence chains that
verify, and REFUSED as human calibration by is_human_calibration.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import date
from pathlib import Path
import re
import sys

import jsonschema
import pytest
import yaml

from evidence_chain import build_chain, verify_chain
from learning import agent_security_harness as ash
from learning import detection_validation as dv
from review_workpaper.__main__ import validate as validate_workpaper

REPO_ROOT = Path(__file__).resolve().parents[1]
QUAL = REPO_ROOT / "challenges" / "qualification"
RECORDS = QUAL / "records"
CALIBRATION = QUAL / "calibration"
SCHEMA_PATH = RECORDS / "qualification.v1.schema.json"
AS_OF = date(2026, 10, 13)

PILOTS = (
    "lab-review-01-threat-model",
    "lab-agent-01-tool-boundary",
    "lab-detect-01-technique-chain",
    "lab-k8s-01-rbac-path",
)

# Consult mandate: each pilot's separation claim cites ONLY the tests that
# actually cover it. The mediated block dispatches the review-01 key; the
# canary cases cover all four instructor key documents (review-01, k8s-01,
# agent-01 answers.json, detect-01 expected.json); detect-01's claim covers
# the instructor-controlled assessment variant, not the transparent
# self-study flow.
EXPECTED_SEPARATION = {
    "lab-review-01-threat-model": (
        "proven",
        frozenset({
            "tests/test_containment_instructor_plane.py::test_instructor_plane_enumerated",
            "tests/test_containment_instructor_plane.py::test_direct_read_of_instructor_material_is_typed_refused",
            "tests/test_containment_instructor_plane.py::test_reader_mediated_instructor_case_blocked_before_dispatch",
            "tests/test_containment_instructor_plane.py::test_instructor_key_challenges_are_not_preparable",
            "tests/test_containment_instructor_plane.py::test_canary_detector_fires_on_deliberate_leak",
        }),
    ),
    "lab-k8s-01-rbac-path": (
        "proven",
        frozenset({
            "tests/test_containment_instructor_plane.py::test_instructor_plane_enumerated",
            "tests/test_containment_instructor_plane.py::test_direct_read_of_instructor_material_is_typed_refused",
            "tests/test_containment_instructor_plane.py::test_instructor_key_challenges_are_not_preparable",
        }),
    ),
    "lab-agent-01-tool-boundary": (
        "proven",
        frozenset({
            "tests/test_agent_instructor_grading.py::test_grade_requires_the_instructor_key",
            "tests/test_agent_instructor_grading.py::test_key_shape_canary_and_scene_binding_are_enforced",
            "tests/test_containment_instructor_plane.py::test_instructor_plane_enumerated",
            "tests/test_containment_instructor_plane.py::test_direct_read_of_instructor_material_is_typed_refused",
            "tests/test_containment_instructor_plane.py::test_new_instructor_keys_are_canaried_and_refused",
        }),
    ),
    "lab-detect-01-technique-chain": (
        "proven",
        frozenset({
            "tests/test_detect_instructor_variant.py::test_assessment_grading_uses_the_instructor_key_only",
            "tests/test_detect_instructor_variant.py::test_assessment_key_and_case_bindings_are_enforced",
            "tests/test_detect_instructor_variant.py::test_assessment_packet_strips_the_verdict_gate_fields",
            "tests/test_containment_instructor_plane.py::test_instructor_plane_enumerated",
            "tests/test_containment_instructor_plane.py::test_direct_read_of_instructor_material_is_typed_refused",
            "tests/test_containment_instructor_plane.py::test_new_instructor_keys_are_canaried_and_refused",
        }),
    ),
}

RESET_REF = ("tests/test_containment_suite.py::"
             "test_rerun_determinism_and_ledger_retry_identity")


def _load_loader():
    # Loading a non-package module by path; never leave bytecode in the tree.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "qualification_loader", QUAL / "loader.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loader = _load_loader()


def _records() -> dict[str, dict]:
    out = {}
    for pilot in PILOTS:
        path = RECORDS / f"{pilot}.qualification.v1.yaml"
        assert path.is_file(), path
        out[pilot] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return out


def _seeds(pilot: str | None = None) -> list[Path]:
    pattern = f"{pilot}/*.json" if pilot else "*/*.json"
    return sorted(CALIBRATION.glob(pattern))


def _canonical(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=False).encode("utf-8")


def _digest(document) -> str:
    return "sha256:" + hashlib.sha256(_canonical(document)).hexdigest()


# --------------------------------------------------------------- records ---

def test_records_validate_against_closed_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft7Validator.check_schema(schema)
    for pilot, record in _records().items():
        jsonschema.Draft7Validator(schema).validate(record)


def test_record_lanes_are_assigned_unstaffed_operator_gated() -> None:
    for record in _records().values():
        lanes = [row["lane"] for row in record["review_lanes"]]
        assert lanes == ["technical", "safety-operator", "instructional"]
        for row in record["review_lanes"]:
            assert row["state"] == "assigned, unstaffed, wholly operator-gated"


def test_record_evidence_refs_resolve_to_real_test_functions() -> None:
    for record in _records().values():
        refs = (record["learner_context_separation"]["evidence_refs"]
                + record["reset"]["evidence_refs"])
        assert refs, record["id"]
        for ref in refs:
            match = re.fullmatch(r"tests/(test_[a-z0-9_]+\.py)::(test_[a-z0-9_]+)",
                                 ref)
            assert match, ref
            path = REPO_ROOT / "tests" / match.group(1)
            assert path.is_file(), ref
            assert re.search(rf"^def {match.group(2)}\(",
                             path.read_text(encoding="utf-8"), re.M), ref


def test_separation_claims_cite_only_tests_that_cover_each_pilot() -> None:
    for pilot, (state, expected_refs) in EXPECTED_SEPARATION.items():
        separation = _records()[pilot]["learner_context_separation"]
        assert separation["state"] == state, pilot
        assert set(separation["evidence_refs"]) == expected_refs, pilot
        if state == "not-asserted":
            assert "NOT asserted" in separation["notes"], pilot
            assert "instructor-controlled variant" in separation["notes"], pilot


def test_reset_gate_cites_containment_rerun_determinism_only() -> None:
    for record in _records().values():
        assert record["reset"]["state"] == "determinism-proven"
        assert record["reset"]["evidence_refs"] == [RESET_REF]


def test_calibration_and_dry_run_gates_are_open_everywhere() -> None:
    for record in _records().values():
        assert record["calibration"]["state"] == "fixtures-shipped-human-scoring-open"
        assert record["calibration"]["packet"] == (
            f"challenges/qualification/calibration/{record['pilot']}/")
        assert record["dry_run"]["state"] == "procedure-shipped-not-executed"
        assert record["dry_run"]["runbook"] == (
            "challenges/qualification/dry-run/runbook.md")
        assert Path(REPO_ROOT, record["dry_run"]["runbook"]).is_file()
        assert Path(REPO_ROOT, record["calibration"]["packet"]).is_dir()


def test_honest_limits_carry_the_mandated_notes() -> None:
    records = _records()
    for pilot, record in records.items():
        blob = " ".join(record["honest_limits"]).lower()
        assert "not a promotion signal" in blob, pilot
        assert "no human double-scoring has occurred" in blob, pilot
        assert "has never been executed" in blob, pilot
    agent_blob = " ".join(records["lab-agent-01-tool-boundary"]["honest_limits"])
    # The weak-key-delivery limit is retired: the module derives no answers.
    assert "grader logic and expected answers are readable" not in agent_blob.lower()
    assert "derives no expected rows" in agent_blob
    assert "learning/agent_security_harness.py" in agent_blob
    assert "instructor-canary-agent-01-answers" in agent_blob.lower()
    detect_blob = " ".join(records["lab-detect-01-technique-chain"]["honest_limits"]).lower()
    assert "transparent self-study retained unchanged" in detect_blob
    assert "assessment variant is instructor-controlled" in detect_blob
    assert "instructor-controlled variant is required before assessment use" \
        not in detect_blob


# ---------------------------------------------------------------- seeds ---

def test_seed_files_load_with_closed_shape_and_markers() -> None:
    counts = {}
    for pilot in PILOTS:
        paths = _seeds(pilot)
        counts[pilot] = len(paths)
        for path in paths:
            seed = loader.load_seed(path)
            assert seed["pilot"] == pilot
            assert seed["schema"] == loader.SEED_SCHEMA
            assert seed["adjudication"]["reviewer"] == "calibration-seed"
            assert seed["adjudication"]["adjusted_score"] is None
            assert seed["adjudication"]["decided_on"] == "2026-10-13"
            assert seed["note"] == (
                "author sample awaiting FIRST human double-scoring; "
                "not a rescoring loop")
    assert counts == {
        "lab-review-01-threat-model": 3,
        "lab-k8s-01-rbac-path": 3,
        "lab-agent-01-tool-boundary": 3,
        "lab-detect-01-technique-chain": 2,
    }


def test_seed_submission_digests_recompute_from_embedded_submissions() -> None:
    for path in _seeds():
        seed = loader.load_seed(path)
        sample = seed["anchored_sample"]
        assert sample["submission_digest"] == loader.submission_digest(
            sample["submission"])


def test_loader_refuses_tampered_seed(tmp_path: Path) -> None:
    seed = loader.load_seed(_seeds("lab-k8s-01-rbac-path")[0])
    tampered = json.loads(json.dumps(seed))
    tampered["anchored_sample"]["submission"]["subject"] = "changed"
    path = tmp_path / "seed.json"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(loader.SeedError) as excinfo:
        loader.load_seed(path)
    assert excinfo.value.reason == "submission-digest-mismatch"
    # A seed carrying a retained adjustment or a role reviewer is refused at
    # load time: the markers are mandatory, not advisory.
    for mutate, reason in (
        (lambda s: s["adjudication"].update(adjusted_score="8/10"),
         "seed-adjusted-score-must-be-null"),
        (lambda s: s["adjudication"].update(reviewer="operator"),
         "seed-reviewer-required"),
    ):
        broken = json.loads(json.dumps(seed))
        mutate(broken)
        broken["adjudication"]["decided_on"] = seed["adjudication"]["decided_on"]
        path.write_text(json.dumps(broken), encoding="utf-8")
        with pytest.raises(loader.SeedError) as excinfo:
            loader.load_seed(path)
        assert excinfo.value.reason == reason


def test_seed_chains_verify_but_are_never_human_calibration() -> None:
    for path in _seeds():
        seed = loader.load_seed(path)
        sample = seed["anchored_sample"]
        chain = build_chain(
            [{"digest": sample["submission_digest"],
              "locator": f"calibration/{seed['pilot']}/{path.name}",
              "custody_note": "operator-held calibration packet entry"}],
            [{"digest": sample["submission_digest"],
              "evidence_class": "declared"}],
            {"digest": _digest(sample["machine_check"]),
             "author_role": "analyst", "statement_count": 1},
            {**seed["adjudication"], "digest": _digest(seed["adjudication"])},
            {"digest": _digest(seed["note"]),
             "conclusion": "author sample; not calibrated review"},
        )
        # The chain is a VALID evidence-chain document...
        assert verify_chain(chain, as_of=AS_OF).ok, path
        # ...and the discriminator still refuses to count it as human
        # calibration, in either entry shape.
        assert loader.is_human_calibration(chain) is False
        assert loader.is_human_calibration(chain["adjudication"]) is False


def test_is_human_calibration_marker_mutants() -> None:
    human_scored = {"reviewer": "operator", "original_score": "7/10",
                    "adjusted_score": "8/10"}
    assert loader.is_human_calibration(human_scored) is True
    assert loader.is_human_calibration({"adjudication": human_scored}) is True
    # Every seed-shaped combination is refused; an unscored adjudication is
    # never counted either, so no single missing marker can smuggle a seed in.
    assert loader.is_human_calibration({"reviewer": "calibration-seed",
                                        "adjusted_score": None}) is False
    assert loader.is_human_calibration({"reviewer": "calibration-seed",
                                        "adjusted_score": "9/10"}) is False
    assert loader.is_human_calibration({"reviewer": "operator",
                                        "adjusted_score": None}) is False
    assert loader.is_human_calibration({}) is False
    assert loader.is_human_calibration(None) is False
    assert loader.is_human_calibration("operator") is False
    # And the loader rule matches the counting rule for every shipped seed.
    for path in _seeds():
        assert loader.is_human_calibration(
            loader.load_seed(path)["adjudication"]) is False


# ------------------------------------------- seeds validated as evidence ---

def _seed_machine_check(seed: dict) -> dict:
    return seed["anchored_sample"]["machine_check"]


def test_review_seeds_are_structurally_valid_against_the_real_packet() -> None:
    learner = (REPO_ROOT / "challenges" / "lab-review-01-threat-model" / "learner")
    manifest = json.loads((learner / "manifest.json").read_text(encoding="utf-8"))
    seeds = [loader.load_seed(path) for path in
             _seeds("lab-review-01-threat-model")]
    descriptions = " ".join(seed["anchored_sample"]["description"] for seed in seeds)
    # The unsupportable-all-clear anchor is present, and it is deliberately
    # structurally VALID: the failure mode it anchors is one only a human
    # reviewer can see.
    assert "unsupportable all-clear" in descriptions.lower()
    for seed in seeds:
        submission = seed["anchored_sample"]["submission"]
        assert submission["schema"] == "specaudit.review-workpaper.v1"
        errors = validate_workpaper(manifest, submission, learner)
        assert errors == [], (seed["seed_id"], errors)
        machine = _seed_machine_check(seed)
        assert machine["kind"] == "review-workpaper-structural"
        assert machine["expectation"] == {"structurally_valid": True}


def test_agent_seeds_grade_to_their_expected_profile() -> None:
    seeds = [loader.load_seed(path) for path in
             _seeds("lab-agent-01-tool-boundary")]
    # Correctness grading is instructor-held: the key is an operator-side
    # artifact loaded from the challenge's instructor directory.
    key = json.loads((REPO_ROOT / "challenges" / "lab-agent-01-tool-boundary" /
                      "instructor" / "answers.json").read_text(encoding="utf-8"))
    profiles = []
    for seed in seeds:
        submission = seed["anchored_sample"]["submission"]
        assert submission["schema"] == ash.SUBMISSION_SCHEMA
        evidence = ash.trace(submission["attempt_id"])
        ash.verify_trace(evidence)  # binds the seed to the deterministic scene
        result = ash.grade(evidence, submission, key)
        machine = _seed_machine_check(seed)
        assert machine["kind"] == "agent-trace-grade"
        expected = machine["expectation"]
        assert result["passed"] is expected["passed"], seed["seed_id"]
        assert result["errors"] == expected["errors"], seed["seed_id"]
        profiles.append((result["passed"],
                         sum(len(row["incorrect_fields"])
                             for row in result["errors"])))
    assert profiles == [(True, 0), (False, 3), (False, 1)]


def test_detect_seeds_grade_exactly_and_touch_only_the_retest_stage() -> None:
    seeds = [loader.load_seed(path) for path in
             _seeds("lab-detect-01-technique-chain")]
    assert len(seeds) == 2
    packet = json.loads((REPO_ROOT / "learning" / "data" / "detection" /
                         "retest-failed.json").read_text(encoding="utf-8"))
    for seed in seeds:
        # Mandate: detect-01 ships calibration for the retest-effectiveness
        # stage ONLY.
        assert seed["rubric_dimensions_touched"] == [
            "retest occurrence versus retest outcome"]
        submission = seed["anchored_sample"]["submission"]
        assert submission["schema"] == "synthetic-detection-submission/v1"
        result = dv.grade(packet, submission)
        machine = _seed_machine_check(seed)
        assert machine["kind"] == "detection-grade"
        assert result == {"case_id": machine["expectation"]["case_id"],
                          "pass": machine["expectation"]["pass"],
                          "differences": machine["expectation"]["differences"]}
    graded = [dv.grade(packet, seed["anchored_sample"]["submission"])["pass"]
              for seed in seeds]
    assert graded == [True, False]
    wrong = dv.grade(packet, seeds[1]["anchored_sample"]["submission"])
    assert wrong["differences"] == {
        "retest_result": {"submitted": "effective", "expected": "ineffective"}}


def test_k8s_seed_references_resolve_in_the_shipped_fixture() -> None:
    fixture = REPO_ROOT / "k8s_path_evidence" / "fixture"
    capture_text = (fixture / "capture.json").read_text(encoding="utf-8")
    report_text = (fixture / "report.json").read_text(encoding="utf-8")
    for path in _seeds("lab-k8s-01-rbac-path"):
        seed = loader.load_seed(path)
        submission = seed["anchored_sample"]["submission"]
        # This pilot ships no machine submission schema: the honest machine
        # check is reference resolution against the real fixture rows.
        assert "no machine submission schema" in \
            seed["anchored_sample"]["submission_schema"]
        machine = _seed_machine_check(seed)
        assert machine["kind"] == "capture-reference"
        for ref in machine["expectation"]["ids"]:
            assert ref in capture_text or ref in report_text, (path, ref)
        cited = {row["case_id"] for row in submission["branch_assessments"]}
        assert cited <= {"blue-secret-read", "red-binding-create",
                         "red-secret-read-unknown"}
