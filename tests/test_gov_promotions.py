"""Causal tests for the 2026-10-14 operator-authorized source promotions."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import yaml

from extension.invoke_profiles import INVOKE_PROFILES
from governance.check import (
    V2_AUTHORIZED_PROMOTIONS,
    V2_AUTHORIZED_PROMOTION_EVENTS,
    V2_AUTHORIZATION_DOC,
    load_coverage_inventory,
    load_register,
    load_register_v2,
    snapshot_invoke_profiles,
    validate_register_v2,
)

FIXED_AS_OF = date(2026, 10, 14)
REPO_ROOT = Path(__file__).resolve().parents[1]


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


def _validate(document, inventory, coverage, v1_registry, *, require="complete"):
    return validate_register_v2(
        document, inventory, coverage, as_of=FIXED_AS_OF,
        scope="full-v2", require=require, baseline_registry=v1_registry,
    )


def _codes(report):
    return {issue.code for issue in report.issues if issue.category == "integrity"}


def _source(document, source_id):
    return next(row for row in document["sources"] if row["id"] == source_id)


def test_all_three_requirements_pass_with_promotions(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    for requirement in ("integrity", "current", "complete"):
        report = _validate(
            v2_registry, inventory, coverage, v1_registry, require=requirement
        )
        assert report.ok, (requirement, sorted(_codes(report)))


def test_exactly_twelve_promotions_with_bound_events(v2_registry) -> None:
    document = v2_registry.document
    promoted = {
        row["id"] for row in document["sources"]
        if row["status"] in ("selected", "admitted")
    }
    assert promoted == set(V2_AUTHORIZED_PROMOTIONS)
    assert len(document["promotion_events"]) == len(V2_AUTHORIZED_PROMOTIONS)
    for event in document["promotion_events"]:
        row = _source(document, event["subject"].split(":", 1)[1])
        assert row["promotion_evidence"] == [event["id"]]
        assert event["reviewer"] == "repository-operator"
        assert event["decided_on"] == "2026-10-14"
    admitted = {
        row["id"] for row in document["sources"] if row["status"] == "admitted"
    }
    assert admitted == {"R01", "R43"}


def test_r15_and_r38_stay_research_with_refusal_decisions(v2_registry) -> None:
    for source_id in ("R15", "R38"):
        row = _source(v2_registry.document, source_id)
        assert row["status"] == "research"
        assert row["promotion_evidence"] == []
        assert "operator decision 2026-10-14" in row["data_rights"]
        assert "not adopted" in row["data_rights"] or "refused" in row["data_rights"]


def test_open_facts_survive_inside_decision_text(v2_registry) -> None:
    # The decisions authorize narrow uses; unresolved upstream facts stay
    # literally present rather than being papered over.
    r01 = _source(v2_registry.document, "R01")
    assert "remain OPEN" in r01["data_rights"]
    r43 = _source(v2_registry.document, "R43")
    assert "claimed-not-deposited" in r43["code_license"]
    assert "remain OPEN" in r43["data_rights"]


def test_missing_authorization_heading_fails_the_anchor(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    # Sabotage: rewrite the authorization document without the R01 heading.
    # The real file is swapped and always restored.
    original = REPO_ROOT / V2_AUTHORIZATION_DOC
    saved = original.read_bytes()
    sabotaged = saved.decode("utf-8").replace(
        "### R01 vulnify admitted", "### R01 vulnify (heading removed)"
    ).encode("utf-8")
    original.write_bytes(sabotaged)
    try:
        document = copy.deepcopy(dict(v2_registry.document))
        report = _validate(document, inventory, coverage, v1_registry)
        assert not report.integrity_ok
        assert any(
            issue.code in {"evidence-anchor-missing", "invalid-evidence-ref"}
            for issue in report.issues
        )
    finally:
        original.write_bytes(saved)


def test_promotion_field_drift_outside_the_mask_breaks_fidelity(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    # A promoted row may change ONLY the sanctioned fields: drift in an
    # unsanctioned field (name) still fails the v1-baseline copy fidelity.
    document = copy.deepcopy(dict(v2_registry.document))
    _source(document, "R01")["name"] = "vulnify-renamed"
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "v1-baseline-copy-mismatch" in _codes(report)


def test_promotion_evidence_removal_breaks_coverage(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = copy.deepcopy(dict(v2_registry.document))
    _source(document, "R17")["promotion_evidence"] = []
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "promotion-evidence-missing" in _codes(report)
    assert "promotion-anchor-coverage-mismatch" in _codes(report)


def test_anchor_table_matches_authorization_document(
    v2_registry,
) -> None:
    # Every anchor's authorization heading exists in the shipped document.
    text = (REPO_ROOT / V2_AUTHORIZATION_DOC).read_text(encoding="utf-8")
    import re

    headings = {
        line.removeprefix("### ").strip()
        for line in text.splitlines()
        if line.startswith("### ")
    }
    slug = lambda h: re.sub(r"[^a-z0-9 -]", "", h.lower()).replace(" ", "-")
    slugs = {slug(h) for h in headings}
    for anchor in V2_AUTHORIZED_PROMOTIONS.values():
        anchor_slug = anchor["authorization_anchor"].rsplit("#", 1)[1]
        assert anchor_slug in slugs, anchor_slug


def test_v1_checker_still_refuses_the_v1_register(
    v1_registry, inventory, coverage
) -> None:
    # The v1 register and its rules are untouched by the promotions: the v1
    # file still holds research rows and still refuses promotions.
    document = v1_registry.document
    assert all(row["status"] == "research" for row in document["sources"])
    assert document["promotion_events"] == []


def test_runtime_and_module_promotions_still_refused(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = copy.deepcopy(dict(v2_registry.document))
    _module = next(m for m in document["modules"] if m["id"] == "CYB-05")
    _module["status"] = "shipped"
    _runtime = next(r for r in document["runtime"] if r["capability_id"] == "nmap.scan")
    _runtime["promotion_evidence"] = ["promotion-nmap-hack"]
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "module-shipped-refused" in _codes(report)
    assert "promotion-verifier-unimplemented" in _codes(report)


EXPECTED_SELECTED_TEST_PATH = {
    "R02": "tests/test_arm_batch8.py",
    "R03": "tests/test_arm_batch7.py",
    "R08": "tests/test_arm_batch8.py",
    "R17": "tests/test_arm_batch8.py",
    "R25": "tests/test_arm_batch8.py",
    "R33": "tests/test_arm_batch7.py",
    "R34": "tests/test_arm_batch7.py",
    "R35": "tests/test_arm_batch7.py",
    "R36": "tests/test_arm_batch8.py",
    "R42": "tests/test_arm_batch7.py",
}


def _event(document, source_id):
    return next(
        e for e in document["promotion_events"]
        if e["subject"] == f"source:{source_id}"
    )


def test_complete_event_snapshots_bind_the_exact_historical_population(v2_registry) -> None:
    expected_ids = {
        "R01": "promotion-r01-admission",
        "R02": "promotion-r02-selection",
        "R03": "promotion-r03-selection",
        "R08": "promotion-r08-selection",
        "R17": "promotion-r17-selection",
        "R25": "promotion-r25-selection",
        "R33": "promotion-r33-selection",
        "R34": "promotion-r34-selection",
        "R35": "promotion-r35-selection",
        "R36": "promotion-r36-selection",
        "R42": "promotion-r42-selection",
        "R43": "promotion-r43-admission",
    }
    assert set(V2_AUTHORIZED_PROMOTION_EVENTS) == set(expected_ids)
    assert set(V2_AUTHORIZED_PROMOTIONS) == set(expected_ids)
    assert len(v2_registry.document["promotion_events"]) == len(expected_ids)
    for source_id, expected_id in expected_ids.items():
        event = _event(v2_registry.document, source_id)
        event_id, frozen_digest = V2_AUTHORIZED_PROMOTION_EVENTS[source_id]
        assert event_id == event["id"] == expected_id
        assert _source(v2_registry.document, source_id)["promotion_evidence"] == [expected_id]
        canonical = json.dumps(
            event, allow_nan=False, ensure_ascii=True, separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        assert "sha256:" + hashlib.sha256(canonical).hexdigest() == frozen_digest


@pytest.mark.parametrize("source_id", [
    "R01", "R02", "R03", "R08", "R17", "R25",
    "R33", "R34", "R35", "R36", "R42", "R43",
])
@pytest.mark.parametrize(("field", "replacement"), [
    ("from_status", "experimental"),
    ("verification_result", "pass"),
    ("supported_versions", ["unverified-version"]),
    ("source_revisions", ["f" * 40]),
])
def test_previously_unchecked_event_fields_fail_for_every_source(
    v2_registry, inventory, coverage, v1_registry, source_id, field, replacement
) -> None:
    # Each mutation is schema-valid and changes only this event field. The
    # complete literal snapshot supplies the authority, never the input row.
    document = copy.deepcopy(dict(v2_registry.document))
    _event(document, source_id)[field] = copy.deepcopy(replacement)
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "promotion-event-snapshot-mismatch" in _codes(report)


@pytest.mark.parametrize(("field", "replacement"), [
    ("id", "promotion-r02-renamed"),
    ("subject", "source:R43"),
    ("to_status", "admitted"),
    ("decided_on", "2026-10-15"),
    ("reviewer", "another-reviewer"),
    ("implementation_revision", "f" * 40),
    ("subject_digest", "sha256:" + "0" * 64),
    ("contract_digest", "sha256:" + "0" * 64),
    ("regression_case", "tests/test_arm_batch7.py"),
    ("exercised_path", "tests/test_arm_batch7.py"),
    ("limitations_accepted", ["unreviewed-limitation"]),
])
def test_remaining_event_fields_are_also_frozen(
    v2_registry, inventory, coverage, v1_registry, field, replacement
) -> None:
    # Together with the four-field full-population matrix, this exercises
    # every field in the closed promotion-event schema independently.
    document = copy.deepcopy(dict(v2_registry.document))
    _event(document, "R02")[field] = replacement
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    expected = (
        "promotion-event-roster-mismatch" if field == "id"
        else "promotion-event-snapshot-mismatch"
    )
    assert expected in _codes(report)


def test_event_list_and_object_key_reordering_preserve_fidelity(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = copy.deepcopy(dict(v2_registry.document))
    document["promotion_events"] = [
        dict(reversed(list(event.items())))
        for event in reversed(document["promotion_events"])
    ]
    report = _validate(document, inventory, coverage, v1_registry)
    assert report.ok, sorted(_codes(report))


def test_arrays_inside_historical_events_preserve_their_recorded_order(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = copy.deepcopy(dict(v2_registry.document))
    _event(document, "R02")["limitations_accepted"].reverse()
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "promotion-event-snapshot-mismatch" in _codes(report)


@pytest.mark.parametrize("source_id", ["R01", "R02"])
@pytest.mark.parametrize("scenario", [
    "cloned-event", "duplicate-event-id", "duplicate-reference", "missing-event",
    "missing-reference", "renamed-event", "cross-source-reference",
    "unreferenced-extra-event",
])
def test_event_identity_and_reference_cardinality_fail_closed(
    v2_registry, inventory, coverage, v1_registry, source_id, scenario
) -> None:
    document = copy.deepcopy(dict(v2_registry.document))
    event = _event(document, source_id)
    row = _source(document, source_id)
    original_id = event["id"]
    if scenario == "cloned-event":
        clone = copy.deepcopy(event)
        clone["id"] = original_id + "-clone"
        document["promotion_events"].append(clone)
        row["promotion_evidence"].append(clone["id"])
        expected_codes = {"promotion-event-roster-mismatch", "promotion-reference-mismatch"}
    elif scenario == "duplicate-event-id":
        document["promotion_events"].append(copy.deepcopy(event))
        expected_codes = {"promotion-event-roster-mismatch", "duplicate-id"}
    elif scenario == "duplicate-reference":
        row["promotion_evidence"].append(original_id)
        expected_codes = {"promotion-reference-mismatch"}
    elif scenario == "missing-event":
        document["promotion_events"].remove(event)
        expected_codes = {"promotion-event-roster-mismatch", "unknown-promotion-evidence"}
    elif scenario == "missing-reference":
        row["promotion_evidence"] = []
        expected_codes = {"promotion-reference-mismatch", "promotion-evidence-missing"}
    elif scenario == "renamed-event":
        event["id"] = original_id + "-replacement"
        row["promotion_evidence"] = [event["id"]]
        expected_codes = {"promotion-event-roster-mismatch", "promotion-reference-mismatch"}
    elif scenario == "cross-source-reference":
        other_id = "R43" if source_id == "R01" else "R03"
        other = _source(document, other_id)
        row["promotion_evidence"], other["promotion_evidence"] = (
            other["promotion_evidence"], row["promotion_evidence"]
        )
        expected_codes = {"promotion-reference-mismatch", "promotion-subject-mismatch"}
    else:
        clone = copy.deepcopy(event)
        clone["id"] = original_id + "-orphan"
        document["promotion_events"].append(clone)
        expected_codes = {"promotion-event-roster-mismatch", "orphan-promotion-evidence"}
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert expected_codes <= _codes(report)


def test_row_and_event_coediting_cannot_redefine_the_historical_snapshot(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    from governance.check import _governance_subject_digest, _source_contract_digest

    document = copy.deepcopy(dict(v2_registry.document))
    row = _source(document, "R02")
    row["selected_revision"] += " with unreviewed scope expansion"
    event = _event(document, "R02")
    event["subject_digest"] = _governance_subject_digest(row)
    event["contract_digest"] = _source_contract_digest(row)
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "promotion-event-snapshot-mismatch" in _codes(report)
    assert "promotion-subject-digest-mismatch" not in _codes(report)
    assert "promotion-contract-digest-mismatch" not in _codes(report)


def test_selected_citations_resolve_to_source_relevant_files(v2_registry) -> None:
    # Full-population check against the frozen anchor table: every selected
    # event cites its source-relevant batch file in BOTH fields, and each
    # file exists. Existence is citation resolvability only, not execution.
    assert set(EXPECTED_SELECTED_TEST_PATH) == {
        sid for sid, anchor in V2_AUTHORIZED_PROMOTIONS.items()
        if anchor["to_status"] == "selected"
    }
    for source_id, expected in EXPECTED_SELECTED_TEST_PATH.items():
        anchor = V2_AUTHORIZED_PROMOTIONS[source_id]
        assert anchor["regression_case"] == expected
        assert anchor["exercised_path"] == expected
        event = _event(v2_registry.document, source_id)
        assert event["regression_case"] == expected
        assert event["exercised_path"] == expected
        assert (REPO_ROOT / expected).is_file()
    # The corrected citation must not reintroduce the missing file.
    raw = (REPO_ROOT / "governance" / "register.v2.yaml").read_text()
    assert "test_synthetic_readers" not in raw
    # Admitted-slice regressions stay valid and unchanged.
    assert V2_AUTHORIZED_PROMOTIONS["R01"]["regression_case"] == "tests/test_vulnify_lookup.py"
    assert V2_AUTHORIZED_PROMOTIONS["R43"]["regression_case"] == "tests/test_reader_evidence.py"
    assert _event(v2_registry.document, "R01")["regression_case"] == "tests/test_vulnify_lookup.py"
    assert _event(v2_registry.document, "R43")["regression_case"] == "tests/test_reader_evidence.py"


def test_event_only_regression_drift_fails_anchor(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    # Unrelated-source mapping: R02's anchor is batch8; pointing its event
    # alone at batch7 (a real file for other sources) must fail the anchor.
    document = copy.deepcopy(dict(v2_registry.document))
    _event(document, "R02")["regression_case"] = "tests/test_arm_batch7.py"
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "promotion-anchor-mismatch" in _codes(report)
    # batch7 exists, so the existence guard alone passes here.
    assert "invalid-regression-ref" not in _codes(report)


def test_exercised_path_only_drift_fails_anchor(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = copy.deepcopy(dict(v2_registry.document))
    _event(document, "R02")["exercised_path"] = "tests/test_arm_batch7.py"
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "promotion-anchor-mismatch" in _codes(report)
    assert "invalid-exercised-path-ref" not in _codes(report)


def test_matching_nonexistent_anchor_and_event_fails_existence_guard(
    v2_registry, inventory, coverage, v1_registry, monkeypatch
) -> None:
    # Same nonexistent path in BOTH anchor and event: the string comparison
    # passes, so only the new existence guard can fail.
    import governance.check as gov_check

    bad = "tests/test_no_such_regression_probe.py"
    assert not (REPO_ROOT / bad).exists()
    patched = copy.deepcopy(dict(V2_AUTHORIZED_PROMOTIONS))
    patched["R02"] = dict(patched["R02"])
    patched["R02"]["regression_case"] = bad
    patched["R02"]["exercised_path"] = bad
    monkeypatch.setattr(gov_check, "V2_AUTHORIZED_PROMOTIONS", patched)
    document = copy.deepcopy(dict(v2_registry.document))
    _event(document, "R02")["regression_case"] = bad
    _event(document, "R02")["exercised_path"] = bad
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    codes = _codes(report)
    assert "promotion-anchor-mismatch" not in codes
    assert "invalid-regression-ref" in codes
    assert "invalid-exercised-path-ref" in codes


@pytest.mark.parametrize("bad", [
    "/abs/tests/test_arm_batch7.py",
    "tests/../governance/check.py",
    "tests",
    "governance/check.py",
    "tests/test_arm_batch7.py::",
    "tests/test_arm_batch7.py::NonexistentTestNode",
    "tests//test_arm_batch7.py",
    "tests/./test_arm_batch7.py",
])
def test_bounded_test_refs_reject_escape_and_nonfiles(
    v2_registry, inventory, coverage, v1_registry, monkeypatch, bad
) -> None:
    import governance.check as gov_check

    patched = copy.deepcopy(dict(V2_AUTHORIZED_PROMOTIONS))
    patched["R03"] = dict(patched["R03"])
    patched["R03"]["regression_case"] = bad
    patched["R03"]["exercised_path"] = bad
    monkeypatch.setattr(gov_check, "V2_AUTHORIZED_PROMOTIONS", patched)
    document = copy.deepcopy(dict(v2_registry.document))
    _event(document, "R03")["regression_case"] = bad
    _event(document, "R03")["exercised_path"] = bad
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    codes = _codes(report)
    assert "promotion-anchor-mismatch" not in codes
    assert ("invalid-regression-ref" in codes
            or "invalid-exercised-path-ref" in codes)


def test_symlink_escape_fails_existence_guard(
    v2_registry, inventory, coverage, v1_registry, monkeypatch, tmp_path
) -> None:
    import governance.check as gov_check

    outside = tmp_path / "outside_test.py"
    outside.write_text("# Synthetic artifact outside the repository.\n")
    with TemporaryDirectory(prefix=".ugova-", dir=REPO_ROOT / "tests") as probe:
        link = Path(probe) / "escape.py"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"host cannot create the synthetic symlink: {exc}")
        bad = link.relative_to(REPO_ROOT).as_posix()
        patched = copy.deepcopy(dict(V2_AUTHORIZED_PROMOTIONS))
        patched["R03"] = dict(patched["R03"])
        patched["R03"]["regression_case"] = bad
        patched["R03"]["exercised_path"] = bad
        monkeypatch.setattr(gov_check, "V2_AUTHORIZED_PROMOTIONS", patched)
        document = copy.deepcopy(dict(v2_registry.document))
        _event(document, "R03")["regression_case"] = bad
        _event(document, "R03")["exercised_path"] = bad
        report = _validate(document, inventory, coverage, v1_registry)
        assert not report.integrity_ok
        codes = _codes(report)
        assert "invalid-regression-ref" in codes
        assert "invalid-exercised-path-ref" in codes
