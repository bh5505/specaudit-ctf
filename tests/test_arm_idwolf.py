"""Curated idwolf arm: bounded offline reader over IDWolf analyzer exports.

Exercises the exact ok/exit mapping for complete/partial/unknown/invalid
reports, source_kind filtering, stable ordering, exact (run_id, finding_id)
lookup, the default-view projection (no detail/object_dn/tenant_id), and
the fail-closed refusals for malformed, duplicated, and oversized input.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extension.contract import (
    ArmSpec,
    Catalog,
    CatalogEntry,
    Extension,
)
from extension.dispatch import dispatch_invoke
from extension.arms.idwolf import ARM_ID, IdwolfArm
from extension.arms.idwolf.arm import ReportError, parse_report_bytes, render_producer_output_bytes
from extension.arms.idwolf.policy import (
    MAX_LINE_BYTES,
    MAX_RECORDS,
    demo_report_paths,
    limit_refusal,
    report_refusal,
)

DATA = Path(__file__).resolve().parent.parent / "extension" / "arms" / "idwolf" / "data"
AD_REPORT = DATA / "demo-idwolf-ad.jsonl"
ENTRA_REPORT = DATA / "demo-idwolf-entra.jsonl"
PARTIAL_REPORT = DATA / "demo-idwolf-partial.jsonl"

RUN_AD = "ad.demo.invalid-20261023090000"
RUN_ENTRA = "Synthetic_Labs-20261023093000"
RUN_PARTIAL = "ad.demo.invalid-20261023110000"
TENANT_ID = "00000000-0000-0000-0000-0000000000aa"

# Upstream-derived ids: sha256("check|object")[:16] over the fixture objects.
KERBEROASTABLE_ID = "7d044af7cbcd9670"
KRBGTGT_ID = "138cdeacb06d7ccd"


# --- Harness ------------------------------------------------------------

def _spec() -> ArmSpec:
    return ArmSpec(id=ARM_ID, protocols=("cli",), notes="test arm")


def _ext() -> Extension:
    entry = CatalogEntry(id=ARM_ID, kind="arm", protocols=("cli",), notes="test arm row")
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: IdwolfArm()})


def _invoke(action: str, args: dict):
    return IdwolfArm().invoke(_spec(), action, args)


def _dispatch(action: str, args: dict | None):
    return dispatch_invoke(_ext(), arm_id=ARM_ID, action=action, args=args)


def _write(path: Path, text: str) -> Path:
    path.write_bytes(text.encode("utf-8"))
    return path


def _finding_row(**overrides) -> dict:
    row = {
        "time": "2026-10-23T09:00:00.0000000Z",
        "event_type": "finding",
        "run_id": RUN_AD,
        "tool": "IDWolf",
        "tool_version": "1.2",
        "source_kind": "ad",
        "domain": "ad.demo.invalid",
        "severity": "High",
        "severity_score": 3,
        "check": "privileged_kerberoastable",
        "title": "Privileged account holds an SPN",
        "category": "Kerberos",
        "object": "svc-demo-account",
        "object_type": "user",
        "object_dn": "CN=svc-demo-account,OU=ServiceAccounts,DC=ad,DC=demo,DC=invalid",
        "detail": "Member of a privileged group and holds an SPN.",
        "mitre": "T1558.003",
        "controls": ["NIS2 21(2)(i)", "ISO27001 A.8.5"],
        "finding_id": KERBEROASTABLE_ID,
        "status": None,
    }
    row.update(overrides)
    return row


def _summary_row(**overrides) -> dict:
    row = {
        "time": "2026-10-23T09:00:00.0000000Z",
        "event_type": "summary",
        "run_id": RUN_AD,
        "tool": "IDWolf",
        "tool_version": "1.2",
        "source_kind": "ad",
        "domain": "ad.demo.invalid",
        "score": 62,
        "grade": "C",
        "score_reliable": True,
        "coverage_pct": 100,
        "findings": 1,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "accepted": 0,
        "new": None,
        "resolved": None,
        "not_evaluated": 0,
        "not_evaluated_checks": [],
    }
    row.update(overrides)
    return row


def _jsonl(rows: list[dict]) -> str:
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)


# --- Fixtures are parseable and list_tools makes no coverage claim ------

def test_shipped_demo_reports_exist_and_are_referenced() -> None:
    for path in demo_report_paths():
        assert path.is_file()
    listed = _invoke("list_tools", {})
    assert listed.ok is True
    assert listed.output["demo_reports"] == [str(path) for path in demo_report_paths()]
    assert "summary" in listed.output["actions"]
    # Interface listing only: no coverage/status claim anywhere in the output.
    assert "status" not in listed.output
    assert any("makes no claim about source coverage" in c for c in listed.output["caveats"])


def test_list_tools_refuses_arguments() -> None:
    outcome = _dispatch("list_tools", {"report": "x.jsonl"})
    assert outcome.exit_code == 1
    assert outcome.document["ok"] is False
    assert outcome.document["output"] is None


def test_unknown_action_is_refused() -> None:
    outcome = _dispatch("collect", {"report": str(AD_REPORT)})
    assert outcome.exit_code == 1
    assert "not on the allowlist" in outcome.document["error"]


# --- Exact ok/exit mapping for complete/partial/unknown/invalid ---------

@pytest.mark.parametrize(
    "report_path,expected_status,expected_ok,expected_exit",
    [
        (AD_REPORT, "complete", True, 0),
        (ENTRA_REPORT, "complete", True, 0),
        (PARTIAL_REPORT, "partial", False, 1),
    ],
)
def test_data_action_status_mapping(
    report_path: Path, expected_status: str, expected_ok: bool, expected_exit: int
) -> None:
    cases = [
        ("summary", {"report": str(report_path)}),
        ("list_findings", {"report": str(report_path)}),
    ]
    if report_path is not ENTRA_REPORT:
        # 138cdeacb06d7ccd = krbtgt_password_age|svc-krbtgt-demo, present in
        # both the complete AD report and the partial run's export.
        run_id = RUN_PARTIAL if report_path is PARTIAL_REPORT else RUN_AD
        cases.append(
            (
                "finding",
                {"report": str(report_path), "run_id": run_id, "finding_id": KRBGTGT_ID},
            )
        )
    for action, args in cases:
        result = _invoke(action, args)
        assert result.ok is expected_ok, (action, report_path)
        assert result.output["status"] == expected_status, (action, report_path)
        outcome = _dispatch(action, args)
        assert outcome.exit_code == expected_exit
        assert outcome.document["ok"] is expected_ok
        assert outcome.document["output"]["status"] == expected_status


def test_partial_report_carries_bounded_evidence_with_offending_fields() -> None:
    result = _invoke("summary", {"report": str(PARTIAL_REPORT)})
    assert result.ok is False
    assert result.output["status"] == "partial"
    assert result.error == "analyzer reported incomplete evaluation coverage"
    evidence = result.output["evidence"]
    assert evidence and evidence[0]["run_id"] == RUN_PARTIAL
    assert evidence[0]["coverage_pct"] == 60
    assert evidence[0]["not_evaluated"] == 3
    assert evidence[0]["not_evaluated_checks"]
    # The projected payload stays available alongside the degraded status.
    assert result.output["runs"][0]["run_status"] == "partial"


def test_missing_summary_row_maps_to_unknown(tmp_path: Path) -> None:
    report = _write(tmp_path / "no-summary.jsonl", _jsonl([_finding_row()]))
    for action, args in (
        ("summary", {"report": str(report)}),
        ("list_findings", {"report": str(report)}),
    ):
        result = _invoke(action, args)
        assert result.ok is False
        assert result.output["status"] == "unknown"
        assert result.error == "report is missing the summary row for at least one run"
        assert result.output["evidence"]
        assert result.output["evidence"][0]["summary_present"] is False
    outcome = _dispatch("summary", {"report": str(report)})
    assert outcome.exit_code == 1
    assert outcome.document["output"]["status"] == "unknown"


def test_invalid_report_is_a_plain_failure_without_status(tmp_path: Path) -> None:
    report = _write(tmp_path / "broken.jsonl", "{not json\n")
    outcome = _dispatch("summary", {"report": str(report)})
    assert outcome.exit_code == 1
    document = outcome.document
    assert document["ok"] is False
    assert document["output"] is None
    assert "not valid JSON" in document["error"]
    assert "status" not in document


# --- Arm-class invoke and dispatch parity -------------------------------

@pytest.mark.parametrize(
    "action,args",
    [
        ("list_tools", {}),
        ("summary", {"report": str(AD_REPORT)}),
        ("summary", {"report": str(PARTIAL_REPORT)}),
        ("list_findings", {"report": str(AD_REPORT), "severity": "High"}),
        (
            "finding",
            {"report": str(AD_REPORT), "run_id": RUN_AD, "finding_id": KRBGTGT_ID},
        ),
        ("summary", {"report": "http://example.invalid/report.jsonl"}),
    ],
)
def test_arm_class_and_dispatch_parity(action: str, args: dict) -> None:
    direct = _invoke(action, args)
    outcome = _dispatch(action, args)
    assert outcome.document == direct.to_dict()
    assert outcome.exit_code == (0 if direct.ok else 1)


# --- Source kinds: filtering, mixed files, and identity refusals --------

@pytest.fixture(scope="module")
def combined_report(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """AD and Entra rows in one file; distinct run_ids make this valid."""
    combined = tmp_path_factory.mktemp("combined") / "combined.jsonl"
    combined.write_bytes(AD_REPORT.read_bytes() + ENTRA_REPORT.read_bytes())
    return combined


def test_mixed_source_kinds_with_distinct_run_ids_are_allowed(combined_report: Path) -> None:
    result = _invoke("summary", {"report": str(combined_report)})
    assert result.ok is True
    assert result.output["status"] == "complete"
    assert result.output["run_count"] == 2
    kinds = sorted(run["source_kind"] for run in result.output["runs"])
    assert kinds == ["ad", "entra"]


def test_source_kind_filter(combined_report: Path) -> None:
    ad = _invoke("list_findings", {"report": str(combined_report), "source_kind": "ad"})
    entra = _invoke("list_findings", {"report": str(combined_report), "source_kind": "entra"})
    assert ad.ok is True and entra.ok is True
    assert {row["source_kind"] for row in ad.output["findings"]} == {"ad"}
    assert {row["source_kind"] for row in entra.output["findings"]} == {"entra"}
    assert ad.output["findings"] and entra.output["findings"]
    # Entra listing rows never carry tenant_id.
    assert all("tenant_id" not in row for row in entra.output["findings"])


def test_mixed_identity_inside_one_run_is_refused(tmp_path: Path) -> None:
    # One run_id whose rows disagree on source_kind/domain/tenant_id: the
    # rows cannot be one run of one export, so the parse is refused.
    row = _finding_row(source_kind="entra", domain="Synthetic Labs", tenant_id=TENANT_ID)
    summary = _summary_row()
    assert row["run_id"] == summary["run_id"]
    report = _write(tmp_path / "mixed.jsonl", _jsonl([row, summary]))
    outcome = _dispatch("summary", {"report": str(report)})
    assert outcome.exit_code == 1
    assert outcome.document["output"] is None
    assert "source_kind, domain, tenant_id, or tool_version" in outcome.document["error"]


def test_tenant_id_rules_per_source_kind(tmp_path: Path) -> None:
    ad_with_tenant = _finding_row(tenant_id=TENANT_ID)
    report = _write(tmp_path / "ad-tenant.jsonl", _jsonl([ad_with_tenant, _summary_row()]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "tenant_id on an ad row" in result.error

    entra_without_tenant = _finding_row(
        run_id=RUN_ENTRA, source_kind="entra", domain="Synthetic Labs"
    )
    report = _write(tmp_path / "entra-no-tenant.jsonl", _jsonl([entra_without_tenant]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "missing tenant_id on an entra row" in result.error


# --- Ordering, filters, and listing shape -------------------------------

def test_stable_listing_order(combined_report: Path) -> None:
    result = _invoke("list_findings", {"report": str(combined_report)})
    assert result.ok is True
    assert result.output["capped"] is False
    rows = result.output["findings"]
    keys = [
        (row["domain"], -row["severity_score"], row["check"], row["finding_id"])
        for row in rows
    ]
    assert keys == sorted(keys)
    # severity_score desc within the same domain: the first row is that
    # domain's highest severity.
    first_domain = rows[0]["domain"]
    domain_rows = [row for row in rows if row["domain"] == first_domain]
    assert domain_rows[0]["severity_score"] == max(
        row["severity_score"] for row in domain_rows
    )


def test_severity_filter_and_limit(combined_report: Path) -> None:
    result = _invoke(
        "list_findings", {"report": str(combined_report), "severity": "Critical"}
    )
    assert result.ok is True
    assert {row["severity"] for row in result.output["findings"]} == {"Critical"}

    limited = _invoke("list_findings", {"report": str(combined_report), "limit": 2})
    assert limited.output["count"] == 2
    assert limited.output["returned"] == 2
    assert limited.output["total"] > 2
    assert limited.output["capped"] is True


def test_invalid_filters_are_refused() -> None:
    result = _invoke(
        "list_findings", {"report": str(AD_REPORT), "severity": "SEV1"}
    )
    assert result.ok is False
    assert "args.severity" in result.error
    assert isinstance(limit_refusal(0), str)
    assert limit_refusal(None) == 200


def test_resolved_rows_are_listed_distinctly() -> None:
    result = _invoke("list_findings", {"report": str(AD_REPORT)})
    assert result.ok is True
    resolved = [row for row in result.output["findings"] if row["event_type"] == "resolved"]
    assert len(resolved) == 1
    row = resolved[0]
    assert row["status"] == "resolved"
    # Resolved rows carry the reduced upstream field set; the default view
    # never adds detail or object_dn.
    assert "detail" not in row and "object_dn" not in row and "category" not in row
    summary = _invoke("summary", {"report": str(AD_REPORT)}).output
    run = next(r for r in summary["runs"] if r["run_id"] == RUN_AD)
    assert run["resolved_rows"] == 1
    assert run["resolved"] == 1


# --- Exact identity lookup ----------------------------------------------

def test_exact_finding_lookup_on_ad() -> None:
    row = _finding_row()
    result = _invoke(
        "finding",
        {"report": str(AD_REPORT), "run_id": RUN_AD, "finding_id": row["finding_id"]},
    )
    assert result.ok is True
    assert result.output["finding"]["finding_id"] == row["finding_id"]
    assert result.output["status"] == "complete"


def test_exact_finding_lookup_on_entra_returns_tenant_id() -> None:
    rows = [
        json.loads(line)
        for line in ENTRA_REPORT.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    target = next(row for row in rows if row["event_type"] == "finding")
    result = _invoke(
        "finding",
        {
            "report": str(ENTRA_REPORT),
            "run_id": RUN_ENTRA,
            "finding_id": target["finding_id"],
        },
    )
    assert result.ok is True
    assert result.output["finding"]["tenant_id"] == TENANT_ID
    assert result.output["finding"]["detail"]  # full documented projection


def test_exact_finding_lookup_miss_is_a_plain_failure() -> None:
    outcome = _dispatch(
        "finding",
        {"report": str(AD_REPORT), "run_id": RUN_AD, "finding_id": "0" * 16},
    )
    assert outcome.exit_code == 1
    assert outcome.document["output"] is None
    assert "not found in run" in outcome.document["error"]
    outcome = _dispatch(
        "finding",
        {"report": str(AD_REPORT), "run_id": "nope-1", "finding_id": "0" * 16},
    )
    assert outcome.exit_code == 1
    outcome = _dispatch("finding", {"report": str(AD_REPORT), "run_id": RUN_AD})
    assert outcome.exit_code == 1
    assert "args.finding_id" in outcome.document["error"]


def test_finding_id_is_stable_across_runs() -> None:
    """The same check+object keeps its id in the partial run's export."""
    ad_row = next(
        json.loads(line)
        for line in AD_REPORT.read_text(encoding="utf-8").splitlines()
        if '"event_type":"finding"' in line and "krbtgt_password_age" in line
    )
    partial_row = next(
        json.loads(line)
        for line in PARTIAL_REPORT.read_text(encoding="utf-8").splitlines()
        if '"event_type":"finding"' in line
    )
    assert ad_row["finding_id"] == partial_row["finding_id"]


# --- Default views and leak tests ----------------------------------------

def test_tenant_id_absent_from_all_default_views(combined_report: Path) -> None:
    for action, args in (
        ("summary", {"report": str(combined_report)}),
        ("list_findings", {"report": str(combined_report)}),
        (
            "list_findings",
            {"report": str(combined_report), "source_kind": "entra"},
        ),
    ):
        rendered = render_producer_output_bytes(_invoke(action, args).output)
        assert b"tenant_id" not in rendered
        assert TENANT_ID.encode("utf-8") not in rendered


def test_secret_shaped_values_never_reach_the_error_channel(tmp_path: Path) -> None:
    secret = "Sup3rSecret-demo-token-value"
    row = _finding_row(detail=f"Observed credential material: {secret}")
    duplicate = _finding_row(detail=f"Observed credential material: {secret}")
    report = _write(tmp_path / "secret.jsonl", _jsonl([row, duplicate]))
    outcome = _dispatch("summary", {"report": str(report)})
    assert outcome.exit_code == 1
    assert outcome.document["output"] is None
    assert secret not in outcome.document["error"]

    # Default listing views omit detail entirely; the exact finding action
    # is the documented full-row projection.
    result = _invoke("list_findings", {"report": str(AD_REPORT)})
    assert secret.encode("utf-8") not in render_producer_output_bytes(result.output)

    # A malformed line carrying the secret fails without echoing it.
    broken = _write(tmp_path / "broken-secret.jsonl", f'{{"detail":"{secret}"\n')
    outcome = _dispatch("list_findings", {"report": str(broken)})
    assert outcome.exit_code == 1
    assert secret not in outcome.document["error"]


def test_score_unreliable_alone_is_not_partial(tmp_path: Path) -> None:
    summary = _summary_row(score_reliable=False)
    report = _write(tmp_path / "unreliable.jsonl", _jsonl([_finding_row(), summary]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is True
    assert result.output["status"] == "complete"
    assert result.output["runs"][0]["score_reliable"] is False


def test_accepted_count_is_surfaced() -> None:
    result = _invoke("summary", {"report": str(AD_REPORT)})
    run = next(r for r in result.output["runs"] if r["run_id"] == RUN_AD)
    assert run["accepted"] == 1
    assert run["coverage_pct"] == 100
    assert run["run_status"] == "complete"


# --- Fail-closed refusals ------------------------------------------------

def test_duplicate_finding_identity_is_refused(tmp_path: Path) -> None:
    row = _finding_row()
    report = _write(tmp_path / "dupe.jsonl", _jsonl([row, _summary_row(), dict(row)]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert result.output is None
    assert "repeats a finding identity" in result.error


def test_duplicate_summary_row_is_refused(tmp_path: Path) -> None:
    summary = _summary_row()
    report = _write(tmp_path / "dupe-summary.jsonl", _jsonl([_finding_row(), summary, dict(summary)]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "repeats the one summary row" in result.error


def test_duplicate_json_keys_are_refused(tmp_path: Path) -> None:
    report = _write(
        tmp_path / "dupe-keys.jsonl",
        '{"run_id":"r1","run_id":"r2","event_type":"summary"}\n',
    )
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "duplicate mapping key" in result.error


def test_invalid_utf8_is_refused(tmp_path: Path) -> None:
    report = tmp_path / "bad-utf8.jsonl"
    report.write_bytes(b'{"run_id":"\xff\xfe"}\n')
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "not valid UTF-8" in result.error


def test_unknown_tool_is_refused(tmp_path: Path) -> None:
    row = _finding_row(tool="NotIDWolf")
    report = _write(tmp_path / "tool.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "not the IDWolf analyzer export schema" in result.error


@pytest.mark.parametrize("version", ["", "1.2 beta", "v/1", None, 1.2])
def test_unknown_or_missing_tool_version_is_refused(tmp_path: Path, version) -> None:
    row = _finding_row(tool_version=version)
    report = _write(tmp_path / "version.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "tool_version" in result.error


@pytest.mark.parametrize(
    "event_type,extra",
    [
        ("resolved", {"detail": "resolved rows carry no detail"}),
        ("summary", {"domain": 5}),
    ],
)
def test_row_schema_refusals(tmp_path: Path, event_type: str, extra: dict) -> None:
    if event_type == "resolved":
        row = {
            "time": "2026-10-23T09:00:00.0000000Z",
            "event_type": "resolved",
            "run_id": RUN_AD,
            "tool": "IDWolf",
            "tool_version": "1.2",
            "source_kind": "ad",
            "domain": "ad.demo.invalid",
            "severity": "Low",
            "severity_score": 1,
            "check": "ldap_signing_not_enforced",
            "title": "LDAP signing not enforced",
            "object": "dc-demo-01",
            "finding_id": "d58770e1dde47e3d",
            "status": "resolved",
        }
        row.update(extra)
        rows = [row]
    else:
        rows = [_finding_row(), _summary_row(**extra)]
    report = _write(tmp_path / "schema.jsonl", _jsonl(rows))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert result.output is None


def test_status_scale_and_score_consistency_refusals(tmp_path: Path) -> None:
    row = _finding_row(status="resolved")
    report = _write(tmp_path / "status.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "must be null, new, or persisting" in result.error

    row = _finding_row(severity_score=5)
    report = _write(tmp_path / "score.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "severity scale" in result.error

    summary = _summary_row(coverage_pct=101)
    report = _write(tmp_path / "coverage.jsonl", _jsonl([_finding_row(), summary]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "coverage_pct" in result.error


def test_url_and_suffix_and_missing_paths_are_refused(tmp_path: Path) -> None:
    for bad in (
        "http://example.invalid/report.jsonl",
        "https://example.invalid/report.jsonl",
        "file:///C:/nope.jsonl",
    ):
        result = _invoke("summary", {"report": bad})
        assert result.ok is False
        assert "not a URL" in result.error
    plain = tmp_path / "report.txt"
    plain.write_text("{}", encoding="utf-8")
    result = _invoke("summary", {"report": str(plain)})
    assert result.ok is False
    assert ".jsonl" in result.error
    result = _invoke("summary", {"report": str(tmp_path / "missing.jsonl")})
    assert result.ok is False
    assert "not an existing file" in result.error
    assert isinstance(report_refusal(None)[1], str)


def test_file_line_and_record_caps(tmp_path: Path) -> None:
    # Line cap: one oversized line inside a small file.
    padded = '{"pad":"' + "a" * (MAX_LINE_BYTES) + '"}\n'
    report = _write(tmp_path / "long-line.jsonl", padded)
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "line cap" in result.error

    # Record cap: more than MAX_RECORDS lines.
    report = _write(tmp_path / "many.jsonl", "{}\n" * (MAX_RECORDS + 1))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "record cap" in result.error

    # File cap: the path pre-check refuses before reading.
    big = tmp_path / "big.jsonl"
    with big.open("wb") as handle:
        handle.write(b"{}\n" * 3)
        handle.truncate(8 * 1024 * 1024 + 1)
    path, refusal = report_refusal(str(big))
    assert path is None and refusal is not None and "byte read cap" in refusal


def test_empty_report_is_refused(tmp_path: Path) -> None:
    report = _write(tmp_path / "empty.jsonl", "\n\n")
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "no records" in result.error


def test_parse_error_values_stay_out_of_error_messages(tmp_path: Path) -> None:
    # Row-value errors reference record numbers only, never field values.
    valid = _jsonl([_finding_row()]).encode("utf-8")
    with pytest.raises(ReportError, match="record 1"):
        parse_report_bytes(valid + b'{"event_type":"nope"}\n')
    with pytest.raises(ReportError, match="repeats a finding identity"):
        parse_report_bytes(valid + valid)
