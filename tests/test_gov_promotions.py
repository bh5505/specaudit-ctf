"""Causal tests for the 2026-10-14 operator-authorized source promotions."""

from __future__ import annotations

import copy
from datetime import date
from pathlib import Path

import pytest
import yaml

from extension.invoke_profiles import INVOKE_PROFILES
from governance.check import (
    V2_AUTHORIZED_PROMOTIONS,
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
