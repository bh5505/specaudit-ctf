"""Curated hostbadger arm: bounded offline reader over HostBadger exports.

Exercises the exact ok/exit mapping for complete/partial/unknown/invalid
reports, severity filtering, stable ordering, exact (run_id, finding_id)
lookup, the default-view projection (no object/detail/os free text), the
edr null-vs-empty distinction, and the fail-closed refusals for
malformed, duplicated, and oversized input.
"""

from __future__ import annotations

import hashlib
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
from extension.arms.hostbadger import ARM_ID, HostbadgerArm
from extension.arms.hostbadger.arm import (
    ReportError,
    parse_report_bytes,
    render_producer_output_bytes,
)
from extension.arms.hostbadger.policy import (
    MAX_LINE_BYTES,
    MAX_RECORDS,
    demo_report_paths,
    limit_refusal,
    report_refusal,
)

DATA = Path(__file__).resolve().parent.parent / "extension" / "arms" / "hostbadger" / "data"
DEMO_REPORT = DATA / "demo-hostbadger-report.jsonl"

HOST_WKS = "HB-WKS-01"
HOST_DC = "HB-DC-02"
RUN_WKS = "HB-WKS-01-20261023090000"
RUN_DC = "HB-DC-02-20261023093000"

SECRET = "DemoOnly-NotReal-token-7Q3"

# Upstream-derived ids: sha256 of the lowercased "check|host|object".
LDAP_SIGNING_ID = "ccac3de043f91266"
CREDENTIAL_GUARD_ID = "cf8f53a85b2ae9ab"


def _finding_id(check: str, host: str, obj: str) -> str:
    return hashlib.sha256(f"{check}|{host}|{obj}".lower().encode()).hexdigest()[:16]


# --- Harness ------------------------------------------------------------

def _spec() -> ArmSpec:
    return ArmSpec(id=ARM_ID, protocols=("cli",), notes="test arm")


def _ext() -> Extension:
    entry = CatalogEntry(id=ARM_ID, kind="arm", protocols=("cli",), notes="test arm row")
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: HostbadgerArm()})


def _invoke(action: str, args: dict):
    return HostbadgerArm().invoke(_spec(), action, args)


def _dispatch(action: str, args: dict | None):
    return dispatch_invoke(_ext(), arm_id=ARM_ID, action=action, args=args)


def _write(path: Path, text: str) -> Path:
    path.write_bytes(text.encode("utf-8"))
    return path


def _jsonl(rows: list[dict]) -> str:
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)


def _finding_row(**overrides) -> dict:
    row = {
        "time": "2026-10-23T09:30:00.0000000Z",
        "event_type": "finding",
        "run_id": RUN_DC,
        "tool": "HostBadger",
        "tool_version": "2.0",
        "host": HOST_DC,
        "host_role": "dc",
        "severity": "High",
        "severity_score": 3,
        "check": "credential_guard_off",
        "title": "Credential Guard is not running",
        "category": "Credential Protection",
        "object": "Credential Guard",
        "detail": "Virtualization-based security is not running (synthetic demo value).",
        "mitre": "T1562.001",
        "cis": "",
        "cis_benchmark": None,
        "found": "off",
        "expected": "enabled",
        "fix_available": True,
        "finding_id": CREDENTIAL_GUARD_ID,
        "status": None,
        "attacks": None,
    }
    row.update(overrides)
    return row


def _resolved_row(**overrides) -> dict:
    row = {
        "time": "2026-10-23T09:00:00.0000000Z",
        "event_type": "resolved",
        "run_id": RUN_WKS,
        "tool": "HostBadger",
        "tool_version": "2.0",
        "host": HOST_WKS,
        "host_role": "workstation",
        "severity": "Low",
        "severity_score": 1,
        "check": "local_admin_member",
        "title": "Service account holds local administrator rights",
        "object": "svc-demo-admin",
        "finding_id": _finding_id("local_admin_member", HOST_WKS, "svc-demo-admin"),
        "status": "resolved",
    }
    row.update(overrides)
    return row


def _summary_row(host: str = HOST_DC, **overrides) -> dict:
    run_id = RUN_DC if host == HOST_DC else RUN_WKS
    role = "dc" if host == HOST_DC else "workstation"
    row = {
        "time": "2026-10-23T09:30:00.0000000Z" if host == HOST_DC else "2026-10-23T09:00:00.0000000Z",
        "event_type": "host_summary",
        "run_id": run_id,
        "tool": "HostBadger",
        "tool_version": "2.0",
        "host": host,
        "host_role": role,
        "score": 41,
        "grade": "D",
        "os": "Synthetic Windows Server 2022 demo build 20348",
        "findings": 1,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "not_evaluated": 0,
        "not_evaluated_checks": [],
        "policy_disabled_checks": [],
        "collected_as_system": True,
        "edr": [],
    }
    row.update(overrides)
    return row


def _complete_report_rows() -> list[dict]:
    """One finding plus its host_summary: a provably complete mini export."""
    return [_finding_row(), _summary_row()]


# --- Fixtures are parseable and list_tools makes no coverage claim ------

def test_shipped_demo_report_exists_and_is_referenced() -> None:
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
    outcome = _dispatch("collect", {"report": str(DEMO_REPORT)})
    assert outcome.exit_code == 1
    assert "not on the allowlist" in outcome.document["error"]


# --- Exact ok/exit mapping for complete/partial/unknown/invalid ---------

def test_demo_report_is_partial_with_per_host_split() -> None:
    for action, args in (
        ("summary", {"report": str(DEMO_REPORT)}),
        ("list_findings", {"report": str(DEMO_REPORT)}),
    ):
        result = _invoke(action, args)
        assert result.ok is False
        assert result.output["status"] == "partial"
        outcome = _dispatch(action, args)
        assert outcome.exit_code == 1
        assert outcome.document["ok"] is False
        assert outcome.document["output"]["status"] == "partial"
        # The projected payload stays available alongside the degraded status.
        assert outcome.document["output"]["findings" if action == "list_findings" else "hosts"]


def test_complete_report_maps_to_ok_true(tmp_path: Path) -> None:
    report = _write(tmp_path / "complete.jsonl", _jsonl(_complete_report_rows()))
    for action, args in (
        ("summary", {"report": str(report)}),
        ("list_findings", {"report": str(report)}),
        (
            "finding",
            {"report": str(report), "run_id": RUN_DC, "finding_id": CREDENTIAL_GUARD_ID},
        ),
    ):
        result = _invoke(action, args)
        assert result.ok is True, (action, result.error)
        assert result.output["status"] == "complete"
        assert result.output["reason"] is None
        assert result.output["evidence"] == []
        outcome = _dispatch(action, args)
        assert outcome.exit_code == 0
        assert outcome.document["output"]["status"] == "complete"


def test_demo_summary_carries_bounded_evidence_and_clean_host() -> None:
    result = _invoke("summary", {"report": str(DEMO_REPORT)})
    assert result.ok is False
    assert result.output["status"] == "partial"
    assert result.error == "analyzer reported checks it did not evaluate"
    evidence = result.output["evidence"]
    assert evidence and evidence[0]["kind"] == "unevaluated_checks"
    assert evidence[0]["host"] == HOST_DC
    assert evidence[0]["not_evaluated"] == 2
    assert evidence[0]["not_evaluated_checks"] == [
        "defender_tamper_off",
        "bitlocker_os_volume_off",
    ]
    hosts = {entry["host"]: entry for entry in result.output["hosts"]}
    # policy_disabled_checks never forces partial: the clean host stays
    # complete despite its non-empty policy_disabled_checks.
    assert hosts[HOST_WKS]["host_status"] == "complete"
    assert hosts[HOST_WKS]["policy_disabled_checks"] == ["stig_defender"]
    assert hosts[HOST_DC]["host_status"] == "partial"
    assert result.output["host_count"] == 2


def test_missing_host_summary_maps_to_partial(tmp_path: Path) -> None:
    rows = [_finding_row()]
    report = _write(tmp_path / "no-summary.jsonl", _jsonl(rows))
    for action, args in (
        ("summary", {"report": str(report)}),
        ("list_findings", {"report": str(report)}),
    ):
        result = _invoke(action, args)
        assert result.ok is False
        assert result.output["status"] == "partial"
        assert result.error == "hosts with rows carry no host_summary row"
        kinds = [entry["kind"] for entry in result.output["evidence"]]
        assert "missing_host_summary" in kinds
        entry = next(e for e in result.output["evidence"] if e["kind"] == "missing_host_summary")
        assert entry["host"] == HOST_DC
    outcome = _dispatch("summary", {"report": str(report)})
    assert outcome.exit_code == 1
    assert outcome.document["output"]["status"] == "partial"


@pytest.mark.parametrize(
    "truncate",
    ["no_newline", "row_after_summary"],
)
def test_truncated_export_maps_to_unknown(tmp_path: Path, truncate: str) -> None:
    if truncate == "no_newline":
        text = _jsonl(_complete_report_rows()).rstrip("\n")
        report = _write(tmp_path / "cut.jsonl", text)
    else:
        # A second, distinct finding appended after the last host_summary
        # row: the upstream serializer writes all observations before the
        # summaries, so this is only possible in a truncated or spliced
        # export.
        extra = _finding_row(
            check="audit_policy_gaps",
            object="Advanced audit policy",
            detail="Kerberos Authentication Service subcategory not audited.",
            severity="Medium",
            severity_score=2,
            finding_id=_finding_id("audit_policy_gaps", HOST_DC, "Advanced audit policy"),
        )
        report = _write(
            tmp_path / "spliced.jsonl",
            _jsonl(_complete_report_rows() + [extra]),
        )
    for action, args in (
        ("summary", {"report": str(report)}),
        ("list_findings", {"report": str(report)}),
    ):
        result = _invoke(action, args)
        assert result.ok is False, (action, truncate)
        assert result.output["status"] == "unknown"
        assert (
            result.error == "export appears truncated mid-file; completeness cannot be proven"
        )
        kinds = [entry["kind"] for entry in result.output["evidence"]]
        assert "truncated_export" in kinds
    outcome = _dispatch("summary", {"report": str(report)})
    assert outcome.exit_code == 1
    assert outcome.document["output"]["status"] == "unknown"


def test_truncation_with_proven_gaps_stays_partial(tmp_path: Path) -> None:
    # Proven positive gaps win over a truncation signal: the report is
    # known-partial regardless of what an unwritten tail would have added.
    rows = [
        _finding_row(),
        _summary_row(not_evaluated=1, not_evaluated_checks=["defender_tamper_off"]),
    ]
    report = _write(tmp_path / "gap-and-cut.jsonl", _jsonl(rows).rstrip("\n"))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert result.output["status"] == "partial"
    kinds = [entry["kind"] for entry in result.output["evidence"]]
    assert "unevaluated_checks" in kinds
    assert "truncated_export" in kinds


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
        ("summary", {"report": str(DEMO_REPORT)}),
        ("list_findings", {"report": str(DEMO_REPORT), "severity": "Critical"}),
        (
            "finding",
            {"report": str(DEMO_REPORT), "run_id": RUN_DC, "finding_id": LDAP_SIGNING_ID},
        ),
        ("summary", {"report": "http://example.invalid/report.jsonl"}),
    ],
)
def test_arm_class_and_dispatch_parity(action: str, args: dict) -> None:
    direct = _invoke(action, args)
    outcome = _dispatch(action, args)
    assert outcome.document == direct.to_dict()
    assert outcome.exit_code == (0 if direct.ok else 1)


# --- Summary contents and the three-way check distinction ----------------

def test_summary_preserves_identity_and_upstream_counts() -> None:
    result = _invoke("summary", {"report": str(DEMO_REPORT)})
    assert result.output["host_count"] == 2
    dc = next(h for h in result.output["hosts"] if h["host"] == HOST_DC)
    assert dc["run_id"] == RUN_DC
    assert dc["host_role"] == "dc"
    assert dc["tool_version"] == "2.0"
    assert dc["score"] == 41
    assert dc["grade"] == "D"
    assert dc["findings"] == 3
    assert dc["critical"] == 1 and dc["high"] == 1 and dc["medium"] == 1 and dc["low"] == 0
    assert dc["collected_as_system"] is True
    assert dc["acn_unmet"] == ["37.1"]
    assert dc["acn_not_judged"] == ["39.2"]
    assert result.output["source"]["kind"] == "operator-file"


def test_three_way_check_distinction_is_preserved(tmp_path: Path) -> None:
    # passed: absent from rows and from not_evaluated_checks; not
    # evaluated: named in not_evaluated_checks; absent: no signal at all.
    result = _invoke("summary", {"report": str(DEMO_REPORT)})
    dc = next(h for h in result.output["hosts"] if h["host"] == HOST_DC)
    assert dc["not_evaluated_checks"] == [
        "defender_tamper_off",
        "bitlocker_os_volume_off",
    ]
    assert dc["findings"] == 3
    # ldap_server_signing_off produced a row; credential_guard_off too.
    listing = _invoke("list_findings", {"report": str(DEMO_REPORT)})
    checks = {row["check"] for row in listing.output["findings"]}
    assert "ldap_server_signing_off" in checks
    # A passed check (e.g. spooler_on_dc, never run on a workstation here)
    # appears nowhere: not a row, not not_evaluated.
    assert "spooler_on_dc" not in checks
    assert "spooler_on_dc" not in dc["not_evaluated_checks"]
    # Only a summary row's not_evaluated_checks ever reports not evaluated.
    unevaluated = set(dc["not_evaluated_checks"])
    assert not (unevaluated & checks)


def test_edr_null_and_empty_list_are_distinct(tmp_path: Path) -> None:
    # Shipped demo: HB-DC-02 edr null (services not collected), and a
    # synthesized host_summary with [] (collected, none found).
    result = _invoke("summary", {"report": str(DEMO_REPORT)})
    hosts = {entry["host"]: entry for entry in result.output["hosts"]}
    assert hosts[HOST_DC]["edr"] is None
    assert hosts[HOST_WKS]["edr"] == ["DemoEdr Agent:running"]

    empty = _write(tmp_path / "edr-empty.jsonl", _jsonl(_complete_report_rows()))
    empty_result = _invoke("summary", {"report": str(empty)})
    assert empty_result.ok is True
    assert empty_result.output["hosts"][0]["edr"] == []

    # A single-element EDR list written as a scalar string (upstream JSON
    # writer collapse) normalizes to a list.
    scalar = _write(
        tmp_path / "edr-scalar.jsonl",
        _jsonl([_finding_row(), _summary_row(edr="DemoEdr Agent:running")]),
    )
    scalar_result = _invoke("summary", {"report": str(scalar)})
    assert scalar_result.output["hosts"][0]["edr"] == ["DemoEdr Agent:running"]


# --- Ordering, filters, and listing shape -------------------------------

def test_stable_listing_order() -> None:
    result = _invoke("list_findings", {"report": str(DEMO_REPORT)})
    assert result.ok is False  # demo is partial; payload still projected
    rows = result.output["findings"]
    keys = [
        (row["host"], -row["severity_score"], row["check"], row["finding_id"])
        for row in rows
    ]
    assert keys == sorted(keys)
    # severity_score desc within the same host: the first row is that
    # host's highest severity.
    first_host = rows[0]["host"]
    host_rows = [row for row in rows if row["host"] == first_host]
    assert host_rows[0]["severity_score"] == max(
        row["severity_score"] for row in host_rows
    )


def test_severity_filter_and_capped_listing() -> None:
    result = _invoke(
        "list_findings", {"report": str(DEMO_REPORT), "severity": "Critical"}
    )
    assert {row["severity"] for row in result.output["findings"]} == {"Critical"}
    assert result.output["capped"] is False

    limited = _invoke("list_findings", {"report": str(DEMO_REPORT), "limit": 2})
    assert limited.output["count"] == 2
    assert limited.output["returned"] == 2
    assert limited.output["total"] > 2
    assert limited.output["capped"] is True


def test_invalid_filters_are_refused() -> None:
    result = _invoke(
        "list_findings", {"report": str(DEMO_REPORT), "severity": "SEV1"}
    )
    assert result.ok is False
    assert "args.severity" in result.error
    assert isinstance(limit_refusal(0), str)
    assert limit_refusal(None) == 200


def test_resolved_rows_are_listed_distinctly() -> None:
    result = _invoke("list_findings", {"report": str(DEMO_REPORT)})
    resolved = [
        row for row in result.output["findings"] if row["event_type"] == "resolved"
    ]
    assert len(resolved) == 1
    row = resolved[0]
    assert row["status"] == "resolved"
    assert row["host"] == HOST_WKS
    # Resolved rows carry the reduced upstream field set; the default view
    # never adds object, detail, or category.
    assert "detail" not in row and "category" not in row and "object" not in row
    summary = _invoke("summary", {"report": str(DEMO_REPORT)}).output
    host = next(h for h in summary["hosts"] if h["host"] == HOST_WKS)
    assert host["resolved_rows"] == 1
    assert host["finding_rows"] == 1
    assert host["findings"] == 1


# --- Exact identity lookup ----------------------------------------------

def test_exact_finding_lookup_returns_full_row() -> None:
    result = _invoke(
        "finding",
        {"report": str(DEMO_REPORT), "run_id": RUN_DC, "finding_id": LDAP_SIGNING_ID},
    )
    assert result.ok is False  # demo is partial; exact row still returned
    assert result.output["status"] == "partial"
    row = result.output["finding"]
    assert row["finding_id"] == LDAP_SIGNING_ID
    assert row["run_id"] == RUN_DC
    assert row["host"] == HOST_DC
    # Full documented projection: the only place these fields are returned.
    for key in ("object", "detail", "found", "expected", "attacks"):
        assert key in row
    assert row["found"] == "not set (negotiate)"


def test_exact_resolved_row_lookup() -> None:
    resolved_id = _finding_id("local_admin_member", HOST_WKS, "svc-demo-admin")
    result = _invoke(
        "finding",
        {"report": str(DEMO_REPORT), "run_id": RUN_WKS, "finding_id": resolved_id},
    )
    assert result.output["finding"]["event_type"] == "resolved"
    assert result.output["finding"]["status"] == "resolved"
    assert "detail" not in result.output["finding"]


def test_exact_finding_lookup_miss_is_a_plain_failure() -> None:
    outcome = _dispatch(
        "finding",
        {"report": str(DEMO_REPORT), "run_id": RUN_DC, "finding_id": "0" * 16},
    )
    assert outcome.exit_code == 1
    assert outcome.document["output"] is None
    assert "not found in run" in outcome.document["error"]
    outcome = _dispatch(
        "finding",
        {"report": str(DEMO_REPORT), "run_id": "nope-1", "finding_id": "0" * 16},
    )
    assert outcome.exit_code == 1
    outcome = _dispatch("finding", {"report": str(DEMO_REPORT), "run_id": RUN_DC})
    assert outcome.exit_code == 1
    assert "args.finding_id" in outcome.document["error"]


def test_finding_id_is_stable_for_same_check_host_object(tmp_path: Path) -> None:
    # The demo row and a synthesized row for the same check|host|object
    # carry the same upstream-derived id.
    assert _finding_row()["finding_id"] == CREDENTIAL_GUARD_ID
    assert DEMO_REPORT.read_text(encoding="utf-8").count(CREDENTIAL_GUARD_ID) == 1


# --- Default views and leak tests ----------------------------------------

def test_sensitive_fields_absent_from_all_default_views() -> None:
    for action, args in (
        ("summary", {"report": str(DEMO_REPORT)}),
        ("list_findings", {"report": str(DEMO_REPORT)}),
        ("list_findings", {"report": str(DEMO_REPORT), "severity": "Medium"}),
    ):
        rendered = render_producer_output_bytes(_invoke(action, args).output)
        # Free-text host evidence never appears in default views: neither
        # the field names nor the demo's secret-shaped value.
        for key in (b'"object"', b'"detail"', b'"os"', b'"found"', b'"expected"', b'"attacks"'):
            assert key not in rendered, (action, key)
        assert SECRET.encode("utf-8") not in rendered
        # The host_summary os text is validated but never projected.
        assert b"Synthetic Windows Server" not in rendered


def test_exact_finding_lookup_is_the_only_full_projection() -> None:
    rendered = render_producer_output_bytes(
        _invoke(
            "finding",
            {"report": str(DEMO_REPORT), "run_id": RUN_DC, "finding_id": LDAP_SIGNING_ID},
        ).output
    )
    assert b'"detail"' in rendered and b'"attacks"' in rendered


def test_secret_shaped_values_never_reach_the_error_channel(tmp_path: Path) -> None:
    detail = f"Observed credential material: {SECRET}"
    row = _finding_row(detail=detail)
    report = _write(tmp_path / "secret.jsonl", _jsonl([row, dict(row)]))
    outcome = _dispatch("summary", {"report": str(report)})
    assert outcome.exit_code == 1
    assert outcome.document["output"] is None
    assert "repeats a finding identity" in outcome.document["error"]
    assert SECRET not in outcome.document["error"]

    # Default listing views omit detail entirely; the exact finding action
    # is the documented full-row projection.
    result = _invoke("list_findings", {"report": str(DEMO_REPORT)})
    assert SECRET.encode("utf-8") not in render_producer_output_bytes(result.output)

    # A malformed line carrying the secret fails without echoing it.
    broken = _write(tmp_path / "broken-secret.jsonl", f'{{"detail":"{SECRET}"\n')
    outcome = _dispatch("list_findings", {"report": str(broken)})
    assert outcome.exit_code == 1
    assert SECRET not in outcome.document["error"]


# --- Fail-closed refusals ------------------------------------------------

def test_duplicate_finding_identity_is_refused(tmp_path: Path) -> None:
    row = _finding_row()
    report = _write(tmp_path / "dupe.jsonl", _jsonl([row, _summary_row(), dict(row)]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert result.output is None
    assert "repeats a finding identity" in result.error


def test_duplicate_host_summary_is_refused(tmp_path: Path) -> None:
    summary = _summary_row()
    report = _write(
        tmp_path / "dupe-summary.jsonl", _jsonl([_finding_row(), summary, dict(summary)])
    )
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "repeats the one host_summary row" in result.error


def test_duplicate_json_keys_are_refused(tmp_path: Path) -> None:
    report = _write(
        tmp_path / "dupe-keys.jsonl",
        '{"run_id":"r1","run_id":"r2","event_type":"host_summary"}\n',
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
    row = _finding_row(tool="NotHostBadger")
    report = _write(tmp_path / "tool.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "not the HostBadger analyzer export schema" in result.error


@pytest.mark.parametrize("version", ["", "1.2 beta", "v/1", None, 1.2, "3.0"])
def test_unknown_or_missing_tool_version_is_refused(tmp_path: Path, version) -> None:
    row = _finding_row(tool_version=version)
    report = _write(tmp_path / "version.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "tool_version" in result.error


def test_unknown_event_type_is_refused(tmp_path: Path) -> None:
    report = _write(tmp_path / "event.jsonl", '{"event_type":"nope"}\n')
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "not finding, resolved, or host_summary" in result.error


def test_summary_optional_keys_are_host_summary_only(tmp_path: Path) -> None:
    row = _finding_row(e8_levels={"patch_os": 1})
    report = _write(tmp_path / "finding-e8.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert result.output is None
    assert "unknown fields for a finding row" in result.error


@pytest.mark.parametrize(
    "event_type,extra",
    [
        ("resolved", {"detail": "resolved rows carry no detail"}),
        ("resolved", {"attacks": "resolved rows carry no attacks"}),
        ("finding", {"fix_available": "yes"}),
        ("host_summary", {"collected_as_system": "yes"}),
        ("host_summary", {"edr": 5}),
        ("host_summary", {"not_evaluated_checks": "defender_tamper_off"}),
        ("host_summary", {"e8_levels": {"patch_os": "high"}}),
    ],
)
def test_row_schema_refusals(tmp_path: Path, event_type: str, extra: dict) -> None:
    if event_type == "resolved":
        row = _resolved_row(**extra)
        rows = [row]
    elif event_type == "finding":
        rows = [_finding_row(**extra)]
    else:
        rows = [_finding_row(), _summary_row(**extra)]
    report = _write(tmp_path / "schema.jsonl", _jsonl(rows))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert result.output is None


def test_status_scale_and_severity_consistency_refusals(tmp_path: Path) -> None:
    row = _finding_row(status="resolved")
    report = _write(tmp_path / "status.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "must be null, new, or persisting" in result.error

    resolved = _resolved_row(status=None)
    report = _write(tmp_path / "resolved-status.jsonl", _jsonl([resolved]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "must be 'resolved' on a resolved row" in result.error

    row = _finding_row(severity_score=5)
    report = _write(tmp_path / "score.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "severity scale" in result.error

    row = _finding_row(host_role="printer")
    report = _write(tmp_path / "role.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "host_role" in result.error

    row = _finding_row(finding_id="NOTHEX")
    report = _write(tmp_path / "fid.jsonl", _jsonl([row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "finding_id" in result.error


def test_host_run_identity_is_enforced(tmp_path: Path) -> None:
    # One host whose rows disagree on run_id: the rows cannot be one run.
    row = _finding_row(run_id="HB-DC-02-20261023099999")
    report = _write(
        tmp_path / "mixed-run.jsonl", _jsonl([_finding_row(), row, _summary_row()])
    )
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert result.output is None
    assert "changes run_id, host_role, or tool_version" in result.error

    # One run_id reused for a second host: upstream derives run_id from the
    # host name, so this cannot be one export.
    row = _finding_row(host=HOST_WKS, host_role="workstation")
    report = _write(
        tmp_path / "mixed-host.jsonl", _jsonl([_finding_row(), row])
    )
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "reuses a run_id for a second host" in result.error

    # A report mixing tool_version values is refused.
    row = _finding_row(tool_version="2.1")
    report = _write(tmp_path / "mixed-version.jsonl", _jsonl([_finding_row(), row]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is False
    assert "tool_version" in result.error


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


def test_parse_error_values_stay_out_of_error_messages() -> None:
    # Row-value errors reference record numbers only, never field values.
    valid = _jsonl([_finding_row()]).encode("utf-8")
    with pytest.raises(ReportError, match="record 1"):
        parse_report_bytes(valid + b'{"event_type":"nope"}\n')
    with pytest.raises(ReportError, match="repeats a finding identity"):
        parse_report_bytes(valid + valid)
    with pytest.raises(ReportError, match="not valid UTF-8"):
        parse_report_bytes(valid + b'{"host":"\xff\xfe"}\n')


def test_report_with_only_summaries_is_complete(tmp_path: Path) -> None:
    # A host where every check passed or was policy-disabled: zero finding
    # rows, a summary row with not_evaluated=0.  A clean parse is a clean
    # report, never a claim that the host is secure.
    report = _write(tmp_path / "clean.jsonl", _jsonl([_summary_row(host=HOST_WKS, findings=0, high=0)]))
    result = _invoke("summary", {"report": str(report)})
    assert result.ok is True
    assert result.output["status"] == "complete"
    assert result.output["hosts"][0]["finding_rows"] == 0
    listing = _invoke("list_findings", {"report": str(report)})
    assert listing.output["total"] == 0
    assert listing.output["capped"] is False
    assert listing.output["findings"] == []
