"""Causal tests for the additive governance register v2 layer.

The tests intentionally mutate one invariant at a time.  The shipped v2
register validates clean, and each mutation must fail for its own reason:
copy fidelity against the frozen v1 baseline, frozen rosters, attributed
currentness with per-trigger checks, refused promotion paths, tier
authority, and the closed schema.  Mutations happen on in-memory copies;
the v1 baseline register, the profile snapshot, and the coverage snapshot
are each read from disk once per module.
"""

from __future__ import annotations

import copy
import json
from datetime import date, timedelta
from typing import Any

import pytest
import yaml

from extension.invoke_profiles import INVOKE_PROFILES
from governance.check import (
    DEFAULT_REGISTER_PATH,
    DEFAULT_REGISTER_V2_PATH,
    V2_SCOPE_ID,
    V2_BASELINE_IMPLEMENTATION_REVISION,
    RegisterLoadError,
    Registry,
    load_coverage_inventory,
    load_register,
    load_register_v2,
    main,
    snapshot_invoke_profiles,
    validate_register_v2,
)

FIXED_AS_OF = date(2026, 10, 13)
V2_REPORT_SCHEMA = "specaudit.ctf.governance.validation-report.v2"
V1_REPORT_SCHEMA = "specaudit.ctf.governance.validation-report.v1"
V2_ERROR_SCHEMA = "specaudit.ctf.governance.validation-error.v1"
REQUIREMENTS = ("integrity", "current", "complete")

# A schema-shaped promotion event: v2 must refuse it as unverifiable
# instead of letting record status travel without a promotion path.
WELL_FORMED_PROMOTION_EVENT = {
    "id": "promotion-test-probe",
    "subject": "source:R01",
    "from_status": "research",
    "to_status": "selected",
    "decided_on": "2026-10-13",
    "reviewer": "specaudit-ctf-maintainers",
    "implementation_revision": V2_BASELINE_IMPLEMENTATION_REVISION,
    "subject_digest": "sha256:" + "0" * 64,
    "contract_digest": "sha256:" + "0" * 64,
    "regression_case": "tests/test_governance_v2.py::test_promotion_paths_stay_refused",
    "verification_result": "pass",
    "exercised_path": "synthetic",
    "supported_versions": ["current-checkout-contract"],
    "source_revisions": [],
    "limitations_accepted": ["test-probe-only"],
}


@pytest.fixture(scope="module")
def v1_registry() -> Registry:
    return load_register()


@pytest.fixture(scope="module")
def v2_registry() -> Registry:
    return load_register_v2()


@pytest.fixture(scope="module")
def inventory():
    return snapshot_invoke_profiles(INVOKE_PROFILES)


@pytest.fixture(scope="module")
def coverage():
    return load_coverage_inventory()


def _copy_document(registry: Registry) -> dict[str, Any]:
    return copy.deepcopy(dict(registry.document))


def _module(document: dict[str, Any], module_id: str) -> dict[str, Any]:
    return next(row for row in document["modules"] if row["id"] == module_id)


def _source(document: dict[str, Any], source_id: str) -> dict[str, Any]:
    return next(row for row in document["sources"] if row["id"] == source_id)


def _runtime(document: dict[str, Any], capability_id: str) -> dict[str, Any]:
    return next(
        row for row in document["runtime"] if row["capability_id"] == capability_id
    )


def _validate(
    document,
    inventory,
    coverage,
    baseline_registry,
    *,
    require="complete",
):
    return validate_register_v2(
        document,
        inventory,
        coverage,
        as_of=FIXED_AS_OF,
        scope=V2_SCOPE_ID,
        require=require,
        baseline_registry=baseline_registry,
    )


def _codes(report, *, category: str | None = None) -> set[str]:
    return {
        issue.code
        for issue in report.issues
        if category is None or issue.category == category
    }


def _paths(report, code: str) -> set[str]:
    return {issue.path for issue in report.issues if issue.code == code}


def _cli_args(*options: str) -> list[str]:
    return ["check", *options, "--as-of", "2026-10-13", "--format", "json"]


def test_v2_shipped_register_passes_all_three_requirements(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    report = None
    for requirement in REQUIREMENTS:
        report = _validate(
            v2_registry, inventory, coverage, v1_registry, require=requirement
        )
        assert report.ok
        assert report.integrity_ok
        assert report.current_ok
        assert report.complete_ok

    payload = report.as_dict()
    assert payload["schema"] == V2_REPORT_SCHEMA
    assert payload["currentness_basis"] == "attributed-review-and-rederived-checks"
    counts = payload["counts"]
    assert counts["sources"] == 109
    assert counts["modules"] == 29
    assert counts["governed_runtime_records"] == 227
    assert counts["inventory_capabilities"] == 227


@pytest.mark.parametrize("requirement", REQUIREMENTS)
def test_v2_cli_passes_each_requirement_and_reports_v2_schema(capsys, requirement) -> None:
    argv = _cli_args(
        "--register-version", "2", "--scope", "full-v2", "--require", requirement
    )
    exit_code = main(argv)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert payload["schema"] == V2_REPORT_SCHEMA
    assert payload["requirement"] == requirement
    assert payload["ok"] is True
    assert payload["currentness_basis"] == "attributed-review-and-rederived-checks"


def test_v1_default_cli_is_unchanged(capsys) -> None:
    exit_code = main(["check", "--as-of", "2026-10-13"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 1
    assert payload["schema"] == V1_REPORT_SCHEMA
    assert payload["requested_scope"] == "full"
    partial = [i for i in payload["issues"] if i["code"] == "repository-partial"]
    assert partial
    assert partial[0]["category"] == "completeness"


def test_version_mismatch_fails_closed(capsys) -> None:
    exit_code = main(
        _cli_args(
            "--register-version", "2", "--scope", "full-v2",
            "--require", "integrity", "--register", str(DEFAULT_REGISTER_PATH),
        )
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert json.loads(captured.err)["schema"] == V2_ERROR_SCHEMA

    exit_code = main(
        _cli_args("--require", "integrity", "--register", str(DEFAULT_REGISTER_V2_PATH))
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert json.loads(captured.err)["schema"] == V2_ERROR_SCHEMA


def test_v1_loader_rejects_v2_document_and_vice_versa() -> None:
    with pytest.raises(RegisterLoadError):
        load_register(DEFAULT_REGISTER_V2_PATH)
    with pytest.raises(RegisterLoadError):
        load_register_v2(DEFAULT_REGISTER_PATH)


def test_pr97_source_row_perturbation_fails_copy_fidelity(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = _copy_document(v2_registry)
    _source(document, "R01")["url"] = "https://example.com/perturbed"

    report = _validate(document, inventory, coverage, v1_registry)

    assert not report.complete_ok
    assert "v1-baseline-copy-mismatch" in _codes(report, category="integrity")
    assert _paths(report, "v1-baseline-copy-mismatch") == {"source:R01"}


def test_pr97_runtime_row_perturbation_fails_copy_fidelity(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = _copy_document(v2_registry)
    known_limitations = _runtime(document, "numasec.finding")["known_limitations"]
    known_limitations.append("perturbed-limitation-not-in-contract")

    report = _validate(document, inventory, coverage, v1_registry)

    assert not report.complete_ok
    assert "v1-baseline-copy-mismatch" in _codes(report, category="integrity")
    assert _paths(report, "v1-baseline-copy-mismatch") == {"runtime:numasec.finding"}


def test_cyb05_module_row_perturbation_fails_copy_fidelity(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = _copy_document(v2_registry)
    _module(document, "CYB-05")["outcomes"].append("perturbed-outcome-not-in-v1")

    report = _validate(document, inventory, coverage, v1_registry)

    assert not report.complete_ok
    assert "v1-baseline-copy-mismatch" in _codes(report, category="integrity")
    assert _paths(report, "v1-baseline-copy-mismatch") == {"module:CYB-05"}


@pytest.mark.parametrize(
    ("kind", "victim_id", "expected_code"),
    [
        ("module", "TEL-05", "v2-module-roster-mismatch"),
        ("source", "SP-07", "v2-source-roster-mismatch"),
        ("runtime", "nmap.scan", "v2-runtime-roster-mismatch"),
    ],
)
def test_roster_mutations_fail(
    v2_registry, inventory, coverage, v1_registry, kind, victim_id, expected_code
) -> None:
    document = _copy_document(v2_registry)
    key = {"module": "modules", "source": "sources", "runtime": "runtime"}[kind]
    id_field = "capability_id" if kind == "runtime" else "id"
    document[key] = [row for row in document[key] if row[id_field] != victim_id]

    report = _validate(document, inventory, coverage, v1_registry)

    assert not report.integrity_ok
    assert not report.complete_ok
    assert expected_code in _codes(report, category="integrity")


def test_currentness_mutations(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    # (a) Removing every trigger check is a currentness gap, not an
    # integrity failure: the review claim itself is still well-formed.
    document = _copy_document(v2_registry)
    del _runtime(document, "nmap.scan")["currentness"]["trigger_checks"]
    report = _validate(document, inventory, coverage, v1_registry)
    assert report.integrity_ok
    assert not report.current_ok
    assert "trigger-check-missing" in _codes(report, category="currentness")

    # (b) A trigger check via an unknown method is an integrity failure.
    document = _copy_document(v2_registry)
    _runtime(document, "nmap.scan")["currentness"]["trigger_checks"][0][
        "checked_via"
    ] = "vibes"
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "trigger-check-method-unknown" in _codes(report, category="integrity")

    # (c) Evidence anchors must exist inside the cited evidence document.
    document = _copy_document(v2_registry)
    _source(document, "R01")["currentness"]["trigger_checks"][0]["evidence_ref"] = (
        "docs/governance/source-verification-2026-10-13.md#no-such-heading"
    )
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "evidence-anchor-missing" in _codes(report, category="integrity")

    # (d) A row without a completed review is a currentness gap.
    document = _copy_document(v2_registry)
    _source(document, "SP-01")["currentness"]["reviewed_on"] = None
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.current_ok
    assert "unreviewed" in _codes(report, category="currentness")


def test_cadence_window_binding(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = _copy_document(v2_registry)
    currentness = _source(document, "SP-01")["currentness"]
    reviewed_on = date.fromisoformat(currentness["reviewed_on"])
    drifted = (date.fromisoformat(currentness["review_due_on"]) + timedelta(days=1)).isoformat()
    currentness["review_due_on"] = drifted
    assert (date.fromisoformat(drifted) - reviewed_on).days != 90

    report = _validate(document, inventory, coverage, v1_registry)

    assert not report.integrity_ok
    assert "cadence-window-mismatch" in _codes(report, category="integrity")


def test_missing_queue_is_a_completeness_gap(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = _copy_document(v2_registry)
    del document["currentness_queue"]

    report = _validate(document, inventory, coverage, v1_registry)

    assert not report.complete_ok
    assert "currentness-queue-missing" in _codes(report, category="completeness")


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda d: d["promotion_events"].append(dict(WELL_FORMED_PROMOTION_EVENT)),
            "promotion-verifier-unimplemented",
        ),
        (
            lambda d: _source(d, "R04").__setitem__("status", "selected"),
            "source-selection-refused",
        ),
        (
            lambda d: _source(d, "R01").__setitem__("status", "selected"),
            "promotion-anchor-mismatch",
        ),
        (
            lambda d: _source(d, "R01")["rights"].__setitem__(
                "permitted_uses", ["reference-link-only"]),
            "promotion-anchor-mismatch",
        ),
        (
            lambda d: _source(d, "R43")["content_digests"].clear(),
            "promotion-anchor-mismatch",
        ),
        (
            lambda d: d["promotion_events"][0].__setitem__(
                "decided_on", "2026-10-15"),
            "promotion-anchor-mismatch",
        ),
        (
            lambda d: d["promotion_events"][0].__setitem__(
                "reviewer", "someone-else"),
            "promotion-anchor-mismatch",
        ),
        (
            lambda d: _module(d, "CYB-05").__setitem__("status", "shipped"),
            "module-shipped-refused",
        ),
        (
            lambda d: _runtime(d, "nmap.scan").__setitem__(
                "promotion_evidence",
                ["docs/governance/source-verification-2026-10-13.md"
                 "#runtime-reconciliation-review"],
            ),
            "promotion-verifier-unimplemented",
        ),
    ],
)
def test_promotion_paths_stay_refused(
    v2_registry, inventory, coverage, v1_registry, mutate, expected_code
) -> None:
    document = _copy_document(v2_registry)
    mutate(document)

    report = _validate(document, inventory, coverage, v1_registry)

    assert not report.integrity_ok
    assert expected_code in _codes(report, category="integrity")


def test_tier_authority_is_the_live_profile(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    # The live profile tier wins: a register note cannot re-tier a row.
    document = _copy_document(v2_registry)
    _runtime(document, "agent-wiz.list_tools")["support_tier"] = "research"
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "runtime-tier-mismatch" in _codes(report, category="integrity")

    # A maintained row without supported_versions is an integrity failure.
    document = _copy_document(v2_registry)
    _runtime(document, "agent-wiz.list_tools")["supported_versions"] = []
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "maintained-without-supported-versions" in _codes(report, category="integrity")


def test_tier_provenance_is_inert_for_outcomes(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = _copy_document(v2_registry)
    assert any(row.get("tier_provenance") is not None for row in document["runtime"])
    for row in document["runtime"]:
        row["tier_provenance"] = None

    report = _validate(document, inventory, coverage, v1_registry)

    assert report.ok
    assert report.integrity_ok
    assert report.current_ok
    assert report.complete_ok


def test_tier_provenance_shape_is_still_validated(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = _copy_document(v2_registry)
    provenance = _runtime(document, "agent-wiz.list_tools")["tier_provenance"]
    assert provenance is not None
    provenance["evidence_ref"] = "extension/README.md#no-such-heading"
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "evidence-anchor-missing" in _codes(report, category="integrity")

    document = _copy_document(v2_registry)
    _runtime(document, "agent-wiz.list_tools")["tier_provenance"]["decided_on"] = (
        "2030-01-01"
    )
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "tier-provenance-in-future" in _codes(report, category="integrity")


def test_v2_contract_template_drift_fails(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = _copy_document(v2_registry)
    contract = next(
        row for row in document["contract_templates"] if row["id"] == "read-local-v1"
    )
    contract["timeout_ms"] = contract["timeout_ms"] + 1

    report = _validate(document, inventory, coverage, v1_registry)

    assert not report.integrity_ok
    assert "v2-contract-template-mismatch" in _codes(report, category="integrity")
    assert "contract_template:read-local-v1" in _paths(
        report, "v2-contract-template-mismatch"
    )


def test_baseline_revision_drift_fails(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    # A non-PR97 row must keep the governed-as-of baseline revision.
    document = _copy_document(v2_registry)
    _runtime(document, "nmap.scan")["implementation_revision"] = "f" * 40
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "v2-baseline-revision-mismatch" in _codes(report, category="integrity")

    # A PR97 row must keep the frozen v1 merge revision instead.
    document = _copy_document(v2_registry)
    _runtime(document, "numasec.finding")["implementation_revision"] = "e" * 40
    report = _validate(document, inventory, coverage, v1_registry)
    assert not report.integrity_ok
    assert "runtime-implementation-revision-mismatch" in _codes(report, category="integrity")


def test_depends_on_drift_fails(
    v2_registry, inventory, coverage, v1_registry
) -> None:
    document = _copy_document(v2_registry)
    document["relationships"] = [
        row for row in document["relationships"] if row["id"] != "tel03-depends-on"
    ]

    report = _validate(document, inventory, coverage, v1_registry)

    assert not report.integrity_ok
    assert "v2-relationship-roster-mismatch" in _codes(report, category="integrity")
    assert "v2-depends-on-mismatch" in _codes(report, category="integrity")
    assert "module:TEL-03" in _paths(report, "v2-depends-on-mismatch")


def test_schema_rejects_unknown_row_field(tmp_path, v2_registry) -> None:
    document = _copy_document(v2_registry)
    _source(document, "R01")["unreviewed_field"] = "not-in-the-closed-schema"
    path = tmp_path / "register.v2.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(RegisterLoadError):
        load_register_v2(path)
