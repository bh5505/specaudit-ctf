"""Causal tests for the promotion-qualification contract (U-GOV.e).

The criterion set is exactly candidate_admission.REQUIRED_ADMISSION_FIELDS
(imported by identity); the twelve frozen 2026-10-14 events are projected
onto it with fail-closed attestation states, and the zero-of-twelve
outcome is computed by the conjunction, never asserted: rights are
contradicted on every event (each frozen decision accepts
no-license-or-data-rights-clearance), the regression citation is partial
with outcome authorized-not-executed, and the remaining contract fields
are unevidenced — while a synthetic event with a synthetic executed-evidence
store under tmp_path qualifies, proving the conjunction is real and the
frozen twelve simply do not satisfy it.

The exact event roster, current rights boundaries, and the recorded R15/R38
refusals are preserved: every negative mutates an in-memory deepcopy only,
never a tracked file, and roster/drift negatives use the module's cheap
frozen-table cross-check, never a full checker revalidation. A tripwire
test asserts the tracked governance files are byte-identical from import
to end. The untouched register still validates complete, exercised by at
most one full validation in this file.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any

import pytest

import governance.qualification as qualification_mod
from candidate_admission import REQUIRED_ADMISSION_FIELDS
from extension.invoke_profiles import INVOKE_PROFILES
from governance.check import (
    V2_AUTHORIZED_PROMOTION_EVENTS,
    _sha256,
    load_coverage_inventory,
    load_register,
    load_register_v2,
    snapshot_invoke_profiles,
    validate_register_v2,
)
from governance.qualification import (
    NULL_EVIDENCE_STORE,
    QUALIFICATION_LIMITS,
    QUALIFICATION_VERSION,
    assess_event,
    assess_population,
)

FIXED_AS_OF = date(2026, 10, 14)
REPO_ROOT = Path(__file__).resolve().parents[1]
RIGHTS_NON_CLEARANCE = "no-license-or-data-rights-clearance"

TRACKED_QUALIFICATION_FILES = (
    REPO_ROOT / "governance" / "register.v2.yaml",
    REPO_ROOT / "governance" / "check.py",
    REPO_ROOT / "governance" / "schema" / "register.v1.schema.json",
    REPO_ROOT / "governance" / "schema" / "register.v2.schema.json",
    REPO_ROOT / "governance" / "schema" / "review-evidence.v1.schema.json",
    REPO_ROOT / "governance" / "schema" / "review-result.v1.schema.json",
    REPO_ROOT / "candidate_admission" / "admission.py",
    REPO_ROOT / "promotion_verifier" / "verifier.py",
)
TRACKED_BASELINE = {path: path.read_bytes() for path in TRACKED_QUALIFICATION_FILES}


@pytest.fixture(scope="module")
def v1_registry():
    return load_register()


@pytest.fixture(scope="module")
def v2_registry():
    return load_register_v2()


@pytest.fixture(scope="module")
def inventory():
    return snapshot_invoke_profiles(INVOKE_PROFILES)


@pytest.fixture(scope="module")
def coverage():
    return load_coverage_inventory()


@pytest.fixture(scope="module")
def population(v2_registry):
    return assess_population(
        v2_registry,
        NULL_EVIDENCE_STORE,
        as_of=FIXED_AS_OF,
        requirement="qualify",
    )


def _validate(document, inventory, coverage, v1_registry, *, require="complete"):
    return validate_register_v2(
        document, inventory, coverage, as_of=FIXED_AS_OF,
        scope="full-v2", require=require, baseline_registry=v1_registry,
    )


def _codes(report):
    return {issue.code for issue in report.issues if issue.category == "integrity"}


def _source(document, source_id):
    return next(row for row in document["sources"] if row["id"] == source_id)


def _event(document, source_id):
    return next(
        event for event in document["promotion_events"]
        if event["subject"] == f"source:{source_id}"
    )


def _attestations(qualification):
    return {item.criterion: item for item in qualification.criteria}


def _states(qualification):
    return {item.criterion: item.state for item in qualification.criteria}


def _canonical_digest(value: Any) -> str:
    canonical = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _synthetic_event() -> dict[str, Any]:
    """A synthetic admission-shaped event satisfying every field criterion.

    Fixture only: no such event exists in the register, the frozen roster
    refuses it at population scope, and it evidences no real operation.
    """

    event_id = "promotion-synthetic-admission"
    return {
        "id": event_id,
        "subject": "source:SYN-01",
        "from_status": "research",
        "to_status": "admitted",
        "decided_on": "2026-10-14",
        "reviewer": "synthetic-fixture",
        "implementation_revision": "f" * 40,
        "subject_digest": "sha256:" + "0" * 64,
        "contract_digest": "sha256:" + "0" * 64,
        "regression_case": "tests/test_gov_qualification.py",
        "verification_result": "passed",
        "exercised_path": "tests/test_gov_qualification.py",
        "supported_versions": ["tag v0.0.0 at " + "f" * 40 + " (synthetic)"],
        "source_revisions": ["f" * 40],
        "revision_hashes": ["sha256:" + "1" * 64],
        "limitations_accepted": ["synthetic-fixture-only"],
        "code_license": "MIT (synthetic fixture record)",
        "data_rights": "synthetic fixture only; no upstream data involved",
        "named_owner": "synthetic-owner",
        "data_classification": "synthetic-public",
        "action_surface": "synthetic-surface",
        "side_effects": [],
        "egress": "egress-denied-synthetic",
        "cost_behavior": "zero-cost-synthetic",
        "cleanup_semantics": "no-persistence-synthetic",
        "offline_tests": "tests/test_gov_qualification.py",
        "denied_egress_tests": "tests/test_gov_qualification.py",
        "provenance_semantics": "synthetic-provenance",
        "negative_cases": "tests/test_gov_qualification.py",
        "inconclusive_cases": "tests/test_gov_qualification.py",
        "promotion_evidence": [
            f"governance/reviews/executed/{event_id}.2026-10-14.json"
        ],
    }


def _qualifying_store(tmp_path: Path, event: dict[str, Any]) -> dict[str, Any]:
    """Executed-evidence records backed by real tmp files, one per criterion."""

    ref = event["promotion_evidence"][0]
    target = tmp_path / ref
    target.parent.mkdir(parents=True, exist_ok=True)
    data = b'{"executed": "synthetic fixture record"}\n'
    target.write_bytes(data)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    records = [
        {
            "criterion": criterion,
            "ref": ref,
            "outcome": "passed",
            "dated_on": "2026-10-14",
            "content_sha256": digest,
        }
        for criterion in (
            "regression_case", "side_effects", "egress",
            "named_owner", "code_license", "data_rights",
        )
    ]
    return {_canonical_digest(event): records}


# ---------------------------------------------------------------------------
# Real register: the frozen population and its computed outcome
# ---------------------------------------------------------------------------

def test_population_assesses_exactly_the_twelve_frozen_events(
    v2_registry, population
) -> None:
    assert len(v2_registry.document["promotion_events"]) == 12
    assert population.events_total == 12
    assert len(population.per_event) == 12
    assert population.roster_ok is True
    assert population.issues == ()
    assert population.integrity_ok is True
    assert population.register_sha256 == v2_registry.register_sha256
    assert population.document_sha256 == v2_registry.document_sha256
    assert population.requirement == "qualify"
    assert population.as_of == FIXED_AS_OF
    assert population.limitations == QUALIFICATION_LIMITS
    assert "zero-of-twelve" in QUALIFICATION_LIMITS[0]
    payload = population.as_dict()
    assert payload["version"] == QUALIFICATION_VERSION
    assert payload["counts"] == {
        "events_total": 12, "qualified_count": 0, "issues": 0,
    }


def test_every_event_digest_independently_binds_the_frozen_table(
    v2_registry, population
) -> None:
    for item in population.per_event:
        source_id = item.subject.split(":", 1)[1]
        event_id, frozen_digest = V2_AUTHORIZED_PROMOTION_EVENTS[source_id]
        event = _event(v2_registry.document, source_id)
        assert item.event_id == event_id
        # The test recomputes the canonical digest itself instead of
        # trusting the module's helper: three bindings must agree.
        assert _canonical_digest(event) == frozen_digest
        assert _sha256(event) == frozen_digest
        assert item.event_digest == frozen_digest
        assert item.digest_binds_frozen_table is True


def test_criteria_authority_is_required_admission_fields_by_identity() -> None:
    # The module imports the criterion set by identity: no copy, no
    # redefinition, and the item-3 emphasis names are a strict subset.
    assert qualification_mod.REQUIRED_ADMISSION_FIELDS is REQUIRED_ADMISSION_FIELDS
    emphasis = {"named_owner", "regression_case", "side_effects", "egress"}
    assert emphasis < set(REQUIRED_ADMISSION_FIELDS)
    for item in qualification_mod.EXECUTED_EVIDENCE_CRITERIA:
        assert item in REQUIRED_ADMISSION_FIELDS


def test_zero_events_qualify_is_computed_by_the_conjunction(population) -> None:
    assert population.qualified_count == 0
    assert population.qualified_count == sum(
        1 for item in population.per_event if item.qualifies
    )
    # The zero falls out: every event carries unmet criteria, so the
    # all-evidenced conjunction fails for each of the twelve.
    assert all(item.unmet for item in population.per_event)
    assert all(not item.qualifies for item in population.per_event)
    assert population.ok is False


def test_per_event_gaps_name_every_criterion(population) -> None:
    expected_unevidenced = set(REQUIRED_ADMISSION_FIELDS) - {
        "candidate_id", "pinned_revision",
        "regression_case", "revision_hashes",
        "code_license", "data_rights",
    }
    for item in population.per_event:
        states = _states(item)
        assert set(states) == set(REQUIRED_ADMISSION_FIELDS)
        assert item.unmet == tuple(
            criterion for criterion, state in states.items()
            if state != "evidenced"
        )
        assert len(item.unmet) == 17
        assert states["code_license"] == "contradicted"
        assert states["data_rights"] == "contradicted"
        assert states["regression_case"] == "partial"
        assert states["revision_hashes"] == "partial"
        assert states["candidate_id"] == "evidenced"
        assert states["pinned_revision"] == "evidenced"
        assert {c for c, s in states.items() if s == "unevidenced"} == (
            expected_unevidenced
        )
        attestations = _attestations(item)
        rights = attestations["data_rights"]
        assert RIGHTS_NON_CLEARANCE in rights.reason
        regression = attestations["regression_case"]
        assert regression.outcome == "authorized-not-executed"
        assert "never execution proof" in regression.reason
        revision_hashes = attestations["revision_hashes"]
        assert "source rows, not on the events" in revision_hashes.reason
        owner = attestations["named_owner"]
        assert "attribution, not ownership" in owner.reason
        promotion = attestations["promotion_evidence"]
        assert "self-reference satisfies nothing" in promotion.reason


def test_r01_r43_closest_pair_still_unqualified(population) -> None:
    by_subject = {item.subject: item for item in population.per_event}
    # The two admitted events are the nearest to qualification (their rows
    # pin re-derivable content digests), yet their own events carry the
    # same unmet profile as the rest: nothing on an event qualifies it.
    for source_id in ("R01", "R43"):
        item = by_subject[f"source:{source_id}"]
        assert item.to_status == "admitted"
        assert item.qualifies is False
        assert len(item.unmet) == 17
        states = _states(item)
        assert states["code_license"] == "contradicted"
        assert states["regression_case"] == "partial"
        assert _attestations(item)["regression_case"].outcome == (
            "authorized-not-executed"
        )


def test_r15_and_r38_refusals_are_untouched_by_any_event(v2_registry) -> None:
    subjects = {event["subject"] for event in v2_registry.document["promotion_events"]}
    assert "source:R15" not in subjects
    assert "source:R38" not in subjects
    for source_id in ("R15", "R38"):
        row = _source(v2_registry.document, source_id)
        assert row["status"] == "research"
        assert row["promotion_evidence"] == []
        assert "operator decision 2026-10-14" in row["data_rights"]
        assert "not adopted" in row["data_rights"] or "refused" in row["data_rights"]


# ---------------------------------------------------------------------------
# Plane independence and negatives (in-memory deepcopy only)
# ---------------------------------------------------------------------------

def test_module_and_runtime_subjects_are_refused_not_assessed() -> None:
    for subject in ("module:CYB-05", "runtime:nmap.scan"):
        event = {"id": "promotion-synthetic-plane", "subject": subject}
        item = assess_event(event, NULL_EVIDENCE_STORE)
        assert item.qualifies is False
        assert item.digest_binds_frozen_table is False
        attestation = _attestations(item)["candidate_id"]
        assert attestation.state == "unevidenced"
        assert "not on the source plane" in attestation.reason
        assert "never imply runtime or module admission" in attestation.reason


def test_thirteenth_event_refuses_the_population(v2_registry) -> None:
    document = copy.deepcopy(dict(v2_registry.document))
    clone = copy.deepcopy(_event(document, "R02"))
    clone["id"] = "promotion-r02-clone"
    document["promotion_events"].append(clone)
    mutated = replace(v2_registry, document=document)
    report = assess_population(
        mutated, NULL_EVIDENCE_STORE, as_of=FIXED_AS_OF, requirement="integrity"
    )
    assert report.roster_ok is False
    assert report.events_total == 13
    assert report.per_event == ()
    assert report.qualified_count == 0
    assert "qualification-roster-mismatch" in _codes(report)
    assert report.ok is False
    # The report binds the bytes on disk plus the assessed mapping, which
    # now differ: the mutation lives only in memory.
    assert report.register_sha256 == v2_registry.register_sha256
    assert report.document_sha256 != v2_registry.document_sha256


def test_event_digest_drift_refuses_the_population(v2_registry) -> None:
    document = copy.deepcopy(dict(v2_registry.document))
    _event(document, "R02")["reviewer"] = "another-reviewer"
    mutated = replace(v2_registry, document=document)
    for requirement in ("integrity", "qualify"):
        report = assess_population(
            mutated, NULL_EVIDENCE_STORE, as_of=FIXED_AS_OF,
            requirement=requirement,
        )
        assert report.roster_ok is False
        assert report.per_event == ()
        assert "qualification-event-digest-mismatch" in _codes(report)
        assert "qualification-roster-mismatch" not in _codes(report)
        assert report.ok is False


def test_snapshot_freezing_alone_satisfies_nothing(population) -> None:
    # Every event binds its frozen snapshot exactly, and every event still
    # fails the conjunction: fidelity to the recorded decisions is not
    # qualification evidence.
    assert all(
        item.digest_binds_frozen_table is True for item in population.per_event
    )
    assert all(not item.qualifies for item in population.per_event)


def test_dropping_rights_limitation_does_not_flip_rights(v2_registry) -> None:
    event = copy.deepcopy(_event(v2_registry.document, "R02"))
    event["limitations_accepted"].remove(RIGHTS_NON_CLEARANCE)
    item = assess_event(event, NULL_EVIDENCE_STORE)
    states = _states(item)
    # Without an affirmative executed clearance record, the rights criteria
    # fall back to unevidenced — never evidenced — so the event still fails.
    assert states["code_license"] == "unevidenced"
    assert states["data_rights"] == "unevidenced"
    assert "contradicted" not in set(states.values())
    assert item.qualifies is False
    assert {"code_license", "data_rights"} <= set(item.unmet)


def test_verification_result_is_never_resolved_as_a_reference(v2_registry) -> None:
    existing = REPO_ROOT / "governance" / "check.py"
    event = copy.deepcopy(_event(v2_registry.document, "R02"))
    event["verification_result"] = str(existing)
    records = [{
        "criterion": "regression_case",
        "ref": str(existing),
        "outcome": "passed",
        "dated_on": "2026-10-14",
        "content_sha256": "sha256:" + hashlib.sha256(existing.read_bytes()).hexdigest(),
    }]
    item = assess_event(event, {_canonical_digest(event): records})
    regression = _attestations(item)["regression_case"]
    # The ref names a real file with a matching digest, but it violates the
    # reserved executed-evidence convention, so it counts as nothing.
    assert regression.state == "partial"
    assert regression.outcome == "authorized-not-executed"
    assert item.qualifies is False


def test_assessment_before_the_decisions_fails_integrity(v2_registry) -> None:
    report = assess_population(
        v2_registry, NULL_EVIDENCE_STORE, as_of=date(2026, 10, 1),
        requirement="integrity",
    )
    assert "qualification-decision-in-future" in _codes(report)
    assert report.integrity_ok is False
    assert report.ok is False


# ---------------------------------------------------------------------------
# Positive control entirely under tmp_path
# ---------------------------------------------------------------------------

def test_synthetic_qualifying_event_qualifies_under_tmp_store(tmp_path) -> None:
    event = _synthetic_event()
    store = _qualifying_store(tmp_path, event)
    item = assess_event(event, store, repo_root=tmp_path)
    assert item.qualifies is True
    assert item.unmet == ()
    assert all(
        attestation.state == "evidenced" for attestation in item.criteria
    )
    for criterion in qualification_mod.EXECUTED_EVIDENCE_CRITERIA:
        assert _attestations(item)[criterion].outcome == "passed"
    assert item.digest_binds_frozen_table is False
    # The population would still refuse the synthetic event: the frozen
    # roster admits exactly the twelve historical events.
    assert item.event_id not in {
        event_id for event_id, _digest in V2_AUTHORIZED_PROMOTION_EVENTS.values()
    }


def test_synthetic_store_negatives_fail_closed(tmp_path) -> None:
    event = _synthetic_event()
    digest = _canonical_digest(event)
    assert assess_event(
        event, NULL_EVIDENCE_STORE, repo_root=tmp_path
    ).qualifies is False

    failed = [
        dict(record, outcome="failed")
        for record in _qualifying_store(tmp_path, event)[digest]
    ]
    assert assess_event(
        event, {digest: failed}, repo_root=tmp_path
    ).qualifies is False

    mismatched = [
        dict(record, content_sha256="sha256:" + "0" * 64)
        for record in _qualifying_store(tmp_path, event)[digest]
    ]
    assert assess_event(
        event, {digest: mismatched}, repo_root=tmp_path
    ).qualifies is False


# ---------------------------------------------------------------------------
# Integrity of the untouched inputs and the CLI contract
# ---------------------------------------------------------------------------

def test_untouched_register_validates_complete(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    # The single full validation in this file: qualification is strictly
    # additive and the untouched register still validates complete.
    report = _validate(
        v2_registry, inventory, coverage, v1_registry, require="complete"
    )
    assert report.ok, sorted(_codes(report))


def test_cli_exit_semantics() -> None:
    from governance.qualification import main

    assert main(["check", "--as-of", "2026-10-14", "--format", "json"]) == 0
    assert main(
        ["check", "--as-of", "2026-10-14", "--format", "json", "--require", "qualify"]
    ) == 1
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--as-of", "not-a-date", "--format", "json"])
    assert excinfo.value.code == 2
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--as-of", "2026-10-14", "--require", "bogus"])
    assert excinfo.value.code == 2


def test_shared_worktree_tracked_files_untouched() -> None:
    """Tripwire: qualification tests must not touch tracked governance files."""

    for path, baseline in TRACKED_BASELINE.items():
        assert path.read_bytes() == baseline, f"tracked file modified: {path}"
