"""Curated hostbadger arm: bounded offline reader for HostBadger JSONL exports.

The arm reads a caller-supplied local ``.jsonl`` export of the upstream
analyzer in-process.  It never invokes the collector, PowerShell, the
remediation path, online enrichment, or any AI summary.  Row schema and
completeness semantics follow the upstream serializer at the
campaign-pinned revision: ``finding`` and ``resolved`` rows (resolved rows
carry a reduced field set) plus ONE ``host_summary`` row per host.

Status model for data actions (summary, list_findings, finding): a report
is ``complete`` only when every host that appears in any row has its
``host_summary`` row, its finding and severity counts match the exported
finding rows, and every summary reports full evaluation
(``not_evaluated == 0`` and empty ``not_evaluated_checks``). A count mismatch
means the export cannot prove its reported contents (``unknown``). A summary
reporting unevaluated checks is a proven gap (``partial``); a host with
rows but no summary is a proven gap too (``partial``, evidence names the
hosts); a truncated export (a finding/resolved row after the last
``host_summary`` row, or a file that does not end with a newline) cannot
prove completeness either way (``unknown``), because a truncated export is
only a prefix and its missing summaries cannot be told apart from rows
that were never written — proven positive gaps still win, since they make
the report partial regardless of what a tail would have added.
``policy_disabled_checks`` records organization policy, not a coverage
gap, and never makes a report partial by itself.  ``edr: null`` means EDR
services were not collected (distinct from an empty list) and is surfaced
without changing coverage.  Complete reports return ``ok=true``; partial
and unknown reports return ``ok=false`` with ``output.status``, a reason,
and bounded evidence (CLI exit 1 / MCP ``isError=true``) while still
carrying the projected payload.  Invalid input is a plain failure with a
redacted bounded error and no status object.

Projection: default views (summary hosts, list_findings rows) omit the
free-text ``object``, ``detail``, ``os``, ``found``, ``expected``, and
``attacks`` fields, which carry host evidence; the exact ``finding``
action returns the full documented row.  Parse errors reference record
numbers and field names only, never row values, so secret-shaped fixture
values cannot leak into the error channel.  Finding ids are stable
upstream: the first 16 hex digits of SHA-256 over
``check|host|object`` lowercased.

The shipped demo fixture under ``data/`` is fully synthetic (CTF-owned
hosts, checks, and values) and is a reader demo, not a graded challenge;
a successful parse never attests that a host is secure.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..mcp_client import redact
from ..strict_data import (
    MAX_INTEGER_BITS,
    StrictDataError,
    strict_json_loads,
)
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    CAVEATS,
    INPUT_HINT,
    KNOWN_TOOL,
    KNOWN_TOOL_VERSIONS,
    LIST_ACTIONS,
    MAX_EVIDENCE_HOSTS,
    MAX_FINDINGS,
    MAX_LINE_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RECORDS,
    MAX_REPORT_BYTES,
    SEVERITIES,
    args_refusal,
    demo_report_paths,
    limit_refusal,
    report_refusal,
)

_MAX_TEXT = 4_096
_SEVERITY_SCORE = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
_FINDING_STATUSES = (None, "new", "persisting")
# 16 lowercase hex digits: upstream derives them as the first 8 SHA-256
# bytes of the lowercased "check|host|object", stable across runs for the
# same check on the same host and object.
_FINDING_ID_CHARS = 16
_SCORE_BOUND = 10_000

_BASE_KEYS = frozenset(
    {"time", "event_type", "run_id", "tool", "tool_version", "host", "host_role"}
)
_FINDING_ROW_KEYS = frozenset(
    {
        "severity",
        "severity_score",
        "check",
        "title",
        "category",
        "object",
        "detail",
        "mitre",
        "cis",
        "cis_benchmark",
        "found",
        "expected",
        "fix_available",
        "finding_id",
        "status",
        "attacks",
    }
)
# Upstream writes resolved rows with a reduced field set: no category,
# detail, mitre, cis, cis_benchmark, found, expected, fix_available, or
# attacks.
_RESOLVED_ROW_KEYS = frozenset(
    {"severity", "severity_score", "check", "title", "object", "finding_id", "status"}
)
_SUMMARY_REQUIRED_KEYS = frozenset(
    {
        "score",
        "grade",
        "os",
        "findings",
        "critical",
        "high",
        "medium",
        "low",
        "not_evaluated",
        "not_evaluated_checks",
        "policy_disabled_checks",
        "collected_as_system",
        "edr",
    }
)
_SUMMARY_OPTIONAL_KEYS = frozenset(
    {"e8_levels", "e8_capped", "acn_unmet", "acn_not_judged"}
)

# Default-view projection: identity and verdict fields only.  object,
# detail, os, found, expected, and attacks are never projected here; the
# exact finding action is the only action that returns them.
_LISTING_KEYS = (
    "time",
    "event_type",
    "run_id",
    "host",
    "host_role",
    "severity",
    "severity_score",
    "check",
    "title",
    "category",
    "mitre",
    "cis",
    "cis_benchmark",
    "fix_available",
    "finding_id",
    "status",
)


class ReportError(ValueError):
    """The report is malformed or outside the closed reader contract."""


class HostbadgerArm:
    """Bounded in-process reader over local HostBadger analyzer exports."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(self, spec: ArmSpec, action: str, args: Mapping[str, Any]) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return _fail(
                spec,
                action,
                f"action {action!r} is not on the allowlist "
                "(offline reads over local HostBadger analyzer exports only; "
                "there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, refusal = report_refusal(payload.get("report"))
        if refusal:
            return _fail(spec, action, refusal)
        assert path is not None
        try:
            report, source, provenance = _load_report(path)
        except ReportError as exc:
            return _fail(spec, action, str(exc))
        except Exception:
            return _fail(spec, action, "report could not be parsed safely")

        status, reason, evidence = _overall_status(report)
        if action == "summary":
            document: dict[str, Any] = {
                "hosts": [_project_host(host) for host in _sorted_hosts(report)],
                "host_count": report["host_count"],
            }
        elif action == "list_findings":
            document = self._listing_document(payload, report)
            if "error" in document:
                return _fail(spec, action, document["error"])
        else:
            row = _find_reported_row(report, payload)
            if row is None:
                # Caller-supplied identity echoed back; _fail redacts it.
                run_id = payload["run_id"].strip()
                finding_id = payload["finding_id"].strip()
                return _fail(
                    spec,
                    action,
                    f"finding {finding_id!r} not found in run {run_id!r} of this report",
                )
            # Exact lookup projection: the full row including object,
            # detail, found, expected, and attacks.  This is the only
            # action that returns those fields.
            document = {"finding": dict(row)}
        return _data_result(
            spec, action, document, status, reason, evidence, source, provenance
        )

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        if payload:
            return _fail(spec, action, "list_tools takes no caller arguments")
        return _ok(
            spec,
            action,
            {
                "actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "arg_keys": {key: sorted(values) for key, values in ARG_KEYS.items()},
                "caps": {
                    "max_report_bytes": MAX_REPORT_BYTES,
                    "max_line_bytes": MAX_LINE_BYTES,
                    "max_records": MAX_RECORDS,
                    "max_findings_per_listing": MAX_FINDINGS,
                    "max_output_chars": MAX_OUTPUT_CHARS,
                },
                "caveats": list(CAVEATS),
                "demo_reports": [str(path) for path in demo_report_paths()],
                "input_hint": INPUT_HINT,
            },
        )

    def _listing_document(self, payload: dict, report: dict[str, Any]) -> dict[str, Any]:
        limit = limit_refusal(payload.get("limit"))
        if isinstance(limit, str):
            return {"error": limit}
        severity = _opt_query(payload.get("severity"))
        rows = [
            row
            for row in _sorted_rows(report)
            if severity is None or row["severity"] == severity
        ]
        page = rows[:limit]
        return {
            "findings": [_project_row(row) for row in page],
            "count": len(page),
            "total": len(rows),
            "returned": len(page),
            "capped": len(page) < len(rows),
        }


def _load_report(path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Read once and delegate strict parsing to the byte API."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise ReportError("could not read report") from exc
    if len(raw) > MAX_REPORT_BYTES:
        raise ReportError(f"report exceeds the {MAX_REPORT_BYTES} byte read cap")
    return parse_report_bytes(raw)


def parse_report_bytes(raw: bytes) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Parse exact report bytes without I/O; shared by the arm and verifiers."""
    if type(raw) is not bytes:
        raise ReportError("report bytes must be immutable bytes")
    if len(raw) > MAX_REPORT_BYTES:
        raise ReportError(f"report exceeds the {MAX_REPORT_BYTES} byte read cap")

    records: list[Any] = []
    ends_with_newline = raw.endswith(b"\n")
    for line_number, line in enumerate(raw.split(b"\n"), 1):
        line = line.rstrip(b"\r")
        if not line.strip():
            continue
        if len(line) > MAX_LINE_BYTES:
            raise ReportError(
                f"report line {line_number} exceeds the {MAX_LINE_BYTES} byte line cap"
            )
        if len(records) >= MAX_RECORDS:
            raise ReportError(f"report exceeds the {MAX_RECORDS} record cap")
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReportError(f"report line {line_number} is not valid UTF-8") from exc
        try:
            record = strict_json_loads(text)
        except StrictDataError as exc:
            raise ReportError(f"report line {line_number}: {exc}") from exc
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise ReportError(f"report line {line_number} is not valid JSON") from exc
        records.append(record)
    if not records:
        raise ReportError("report contained no records")

    hosts: dict[str, dict[str, Any]] = {}
    host_run: dict[str, str] = {}
    run_host: dict[str, str] = {}
    identities: set[tuple[str, str, str]] = set()
    tool_version: str | None = None
    last_summary_index: int | None = None
    last_observation_index: int | None = None
    for index, record in enumerate(records):
        row = _validate_row(record, index)
        host = _bind_host(hosts, host_run, run_host, row, index)
        if tool_version is None:
            tool_version = row["tool_version"]
        event_type = row["event_type"]
        if event_type == "host_summary":
            if host["summary"] is not None:
                raise ReportError(
                    f"report record {index} repeats the one host_summary row "
                    "allowed for its host"
                )
            host["summary"] = row
            last_summary_index = index
        else:
            identity = (row["run_id"], row["host"], row["finding_id"])
            if identity in identities:
                raise ReportError(
                    f"report record {index} repeats a finding identity already "
                    "present in this report"
                )
            identities.add(identity)
            host["findings" if event_type == "finding" else "resolved"].append(row)
            last_observation_index = index

    for host in hosts.values():
        host["findings"].sort(key=_order_key)
        host["resolved"].sort(key=_order_key)
    report = {
        "hosts": hosts,
        "host_count": len(hosts),
        "tool_version": tool_version or "",
        # Truncation signals: upstream terminates every row with a newline
        # and writes all finding/resolved rows before the host_summary rows,
        # so a missing trailing newline or an observation after the last
        # summary means the export is a prefix of the real one.
        "ends_with_newline": ends_with_newline,
        "rows_after_last_host_summary": (
            last_observation_index is not None
            and last_summary_index is not None
            and last_observation_index > last_summary_index
        ),
    }
    canonical = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    provenance = {
        "snapshot_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "normalization": {
            "records_sha256": f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        },
    }
    return report, _source(raw), provenance


def _validate_row(raw: Any, index: int) -> dict[str, Any]:
    label = f"report record {index}"
    if not isinstance(raw, dict):
        raise ReportError(f"{label} is not a JSON object")
    if any(not isinstance(key, str) for key in raw):
        raise ReportError(f"{label} field names must be strings")

    event_type = raw.get("event_type")
    if event_type not in ("finding", "resolved", "host_summary"):
        raise ReportError(
            f"{label}.event_type is not finding, resolved, or host_summary"
        )
    if raw.get("tool") != KNOWN_TOOL:
        raise ReportError(f"{label}.tool is not the HostBadger analyzer export schema")
    version = _version(raw.get("tool_version"), f"{label}.tool_version")
    row: dict[str, Any] = {
        "time": _time(raw.get("time"), f"{label}.time"),
        "event_type": event_type,
        "run_id": _text(raw.get("run_id"), f"{label}.run_id"),
        "tool": KNOWN_TOOL,
        "tool_version": version,
        "host": _text(raw.get("host"), f"{label}.host"),
        "host_role": _host_role(raw.get("host_role"), f"{label}.host_role"),
    }

    if event_type == "finding":
        required = _FINDING_ROW_KEYS
    elif event_type == "resolved":
        required = _RESOLVED_ROW_KEYS
    else:
        required = _SUMMARY_REQUIRED_KEYS
    allowed = _BASE_KEYS | required
    if event_type == "host_summary":
        # Only a host_summary row may carry the optional e8/acn keys.
        allowed |= _SUMMARY_OPTIONAL_KEYS
    extra = sorted(set(raw) - allowed)
    if extra:
        raise ReportError(
            f"{label} has unknown fields for a {event_type} row: {', '.join(extra)}"
        )
    missing = sorted(required - set(raw))
    if missing:
        raise ReportError(f"{label} is missing fields: {', '.join(missing)}")

    if event_type in ("finding", "resolved"):
        row.update(
            severity=_severity(raw["severity"], f"{label}.severity"),
            severity_score=_severity_score(
                raw["severity_score"], raw["severity"], f"{label}.severity_score"
            ),
            check=_text(raw["check"], f"{label}.check"),
            title=_text(raw["title"], f"{label}.title"),
            object=_any_text(raw["object"], f"{label}.object"),
            finding_id=_finding_id(raw["finding_id"], f"{label}.finding_id"),
            status=_status(raw["status"], event_type, f"{label}.status"),
        )
    if event_type == "finding":
        row.update(
            category=_text(raw["category"], f"{label}.category"),
            detail=_any_text(raw["detail"], f"{label}.detail"),
            mitre=_any_text(raw["mitre"], f"{label}.mitre"),
            cis=_any_text(raw["cis"], f"{label}.cis"),
            cis_benchmark=_nullable_text(
                raw["cis_benchmark"], f"{label}.cis_benchmark"
            ),
            found=_nullable_text(raw["found"], f"{label}.found"),
            expected=_nullable_text(raw["expected"], f"{label}.expected"),
            fix_available=_bool(raw["fix_available"], f"{label}.fix_available"),
            attacks=_nullable_text(raw["attacks"], f"{label}.attacks"),
        )
    if event_type == "host_summary":
        row.update(
            score=_bounded_int(raw["score"], 0, _SCORE_BOUND, f"{label}.score"),
            grade=_text(raw["grade"], f"{label}.grade"),
            # Free-text OS evidence: validated and bounded, never projected.
            os=_any_text(raw["os"], f"{label}.os"),
            findings=_bounded_int(raw["findings"], 0, MAX_RECORDS, f"{label}.findings"),
            critical=_bounded_int(raw["critical"], 0, MAX_RECORDS, f"{label}.critical"),
            high=_bounded_int(raw["high"], 0, MAX_RECORDS, f"{label}.high"),
            medium=_bounded_int(raw["medium"], 0, MAX_RECORDS, f"{label}.medium"),
            low=_bounded_int(raw["low"], 0, MAX_RECORDS, f"{label}.low"),
            not_evaluated=_bounded_int(
                raw["not_evaluated"], 0, MAX_RECORDS, f"{label}.not_evaluated"
            ),
            not_evaluated_checks=_str_list(
                raw["not_evaluated_checks"], f"{label}.not_evaluated_checks"
            ),
            policy_disabled_checks=_str_list(
                raw["policy_disabled_checks"], f"{label}.policy_disabled_checks"
            ),
            collected_as_system=_bool(
                raw["collected_as_system"], f"{label}.collected_as_system"
            ),
            # null means EDR services were not collected; upstream's JSON
            # writer collapses a single-element list to a scalar string, so
            # both forms are accepted and normalized to a list.
            edr=_edr(raw["edr"], f"{label}.edr"),
        )
        if "e8_levels" in raw:
            row["e8_levels"] = _e8_levels(raw["e8_levels"], f"{label}.e8_levels")
        if "e8_capped" in raw:
            row["e8_capped"] = _str_list(raw["e8_capped"], f"{label}.e8_capped")
        for key in ("acn_unmet", "acn_not_judged"):
            if key in raw:
                row[key] = _str_list(raw[key], f"{label}.{key}")
    return row


def _bind_host(
    hosts: dict[str, dict[str, Any]],
    host_run: dict[str, str],
    run_host: dict[str, str],
    row: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    """Bind a row to its host, refusing rows that cannot be one export.

    Upstream derives run_id from the host name and collects each host in
    exactly one run, so a host whose run_id changes, or a run_id that
    changes host or role, means the rows are not one export.
    """
    host = hosts.get(row["host"])
    identity = (row["host_role"], row["tool_version"])
    if host is None:
        known_run = run_host.get(row["run_id"])
        if known_run is not None and known_run != row["host"]:
            raise ReportError(
                f"report record {index} reuses a run_id for a second host"
            )
        run_host[row["run_id"]] = row["host"]
        host_run[row["host"]] = row["run_id"]
        return hosts.setdefault(
            row["host"],
            {
                "host": row["host"],
                "run_id": row["run_id"],
                "host_role": row["host_role"],
                "tool_version": row["tool_version"],
                "time": row["time"],
                "identity": identity,
                "summary": None,
                "findings": [],
                "resolved": [],
            },
        )
    if host["identity"] != identity or host_run[row["host"]] != row["run_id"]:
        raise ReportError(
            f"report record {index} changes run_id, host_role, or tool_version "
            "inside a single host's rows"
        )
    return host


def _host_coverage(host: dict[str, Any]) -> str:
    """Classify one host from its own summary row (complete/partial/unknown)."""
    summary = host["summary"]
    if summary is None:
        return "unknown"
    gaps = summary["not_evaluated"] > 0 or bool(summary["not_evaluated_checks"])
    if gaps:
        return "partial"
    return "unknown" if _finding_count_mismatch(host) else "complete"


def _finding_count_mismatch(host: dict[str, Any]) -> dict[str, dict[str, int]] | None:
    """Compare the upstream summary to the rows it serialized for this host.

    The pinned HostBadger JSONL writer counts current findings, excluding
    resolved rows, both in total and by severity. A missing row must not
    turn its positive summary into a clean, complete finding list.
    """
    summary = host["summary"]
    if summary is None:
        return None
    observed = {"findings": len(host["findings"])}
    for severity in SEVERITIES:
        observed[severity.lower()] = sum(
            row["severity"] == severity for row in host["findings"]
        )
    declared = {key: summary[key] for key in observed}
    return {"declared": declared, "observed": observed} if observed != declared else None


def _overall_status(report: dict[str, Any]) -> tuple[str, str | None, list[dict[str, Any]]]:
    """Classify the report from its hosts' summary rows and truncation signals.

    See the module docstring for the exact predicate.  Proven positive gaps
    (unevaluated checks, or a host with rows but no summary in an export
    that shows no truncation signal) make the report partial.  A truncated
    export is only a prefix, so it cannot prove completeness and maps to
    unknown unless a positive gap is already proven.  policy_disabled_checks
    and edr null are surfaced on the host projection but never contribute
    to partial.
    """
    truncated = (
        not report["ends_with_newline"] or report["rows_after_last_host_summary"]
    )
    evidence: list[dict[str, Any]] = []
    overflow = 0
    gaps = False
    count_mismatch = False
    for host in _sorted_hosts(report):
        host_status = _host_coverage(host)
        if host_status == "complete":
            continue
        entry: dict[str, Any]
        if host_status == "partial":
            gaps = True
            summary = host["summary"]
            entry = {
                "kind": "unevaluated_checks",
                "host": host["host"],
                "run_id": host["run_id"],
                "not_evaluated": summary["not_evaluated"],
                "not_evaluated_checks": list(summary["not_evaluated_checks"]),
            }
            mismatch = _finding_count_mismatch(host)
            if mismatch:
                entry["finding_counts"] = mismatch
        elif host["summary"] is not None:
            count_mismatch = True
            entry = {
                "kind": "summary_count_mismatch",
                "host": host["host"],
                "run_id": host["run_id"],
                "finding_counts": _finding_count_mismatch(host),
            }
        else:
            # A missing summary is only a proven gap when the export shows
            # no truncation signal; under truncation the host's tail may
            # simply never have been written.
            entry = {
                "kind": "missing_host_summary",
                "host": host["host"],
                "run_id": host["run_id"],
                "finding_rows": len(host["findings"]),
                "resolved_rows": len(host["resolved"]),
            }
        if len(evidence) < MAX_EVIDENCE_HOSTS:
            evidence.append(entry)
        else:
            overflow += 1
    if truncated:
        evidence.append(
            {
                "kind": "truncated_export",
                "trailing_newline": report["ends_with_newline"],
                "rows_after_last_host_summary": report[
                    "rows_after_last_host_summary"
                ],
            }
        )
    if overflow:
        evidence.append(
            {
                "evidence_truncated": True,
                "unshown_hosts": overflow,
            }
        )
    if not evidence:
        return "complete", None, []
    if gaps:
        return "partial", "analyzer reported checks it did not evaluate", evidence
    if truncated:
        return (
            "unknown",
            "export appears truncated mid-file; completeness cannot be proven",
            evidence,
        )
    if count_mismatch:
        return "unknown", "summary finding counts do not match report rows", evidence
    return "partial", "hosts with rows carry no host_summary row", evidence


def _sorted_hosts(report: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(report["hosts"].values(), key=lambda host: host["host"])


def _sorted_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for host in report["hosts"].values():
        rows.extend(host["findings"])
        rows.extend(host["resolved"])
    rows.sort(key=_order_key)
    return rows


def _order_key(row: dict[str, Any]) -> tuple:
    # Stable ordering: host, severity_score desc, check, finding_id; the
    # trailing keys only break ties across runs sharing a finding id.
    return (
        row["host"],
        -row["severity_score"],
        row["check"],
        row["finding_id"],
        row["run_id"],
        row["event_type"],
    )


def _find_reported_row(report: dict[str, Any], payload: dict) -> dict[str, Any] | None:
    """Exact (run_id, finding_id) lookup across a host's finding/resolved rows."""
    for host in report["hosts"].values():
        if host["run_id"] != payload["run_id"].strip():
            continue
        for row in host["findings"]:
            if row["finding_id"] == payload["finding_id"].strip():
                return row
        for row in host["resolved"]:
            if row["finding_id"] == payload["finding_id"].strip():
                return row
    return None


def _project_host(host: dict[str, Any]) -> dict[str, Any]:
    summary = host["summary"]
    row: dict[str, Any] = {
        "host": host["host"],
        "run_id": host["run_id"],
        "host_role": host["host_role"],
        "tool_version": host["tool_version"],
        "time": host["time"],
        "finding_rows": len(host["findings"]),
        "resolved_rows": len(host["resolved"]),
        "host_status": _host_coverage(host),
    }
    if summary is None:
        return row
    for key in (
        "score",
        "grade",
        "findings",
        "critical",
        "high",
        "medium",
        "low",
        "not_evaluated",
        "not_evaluated_checks",
        "policy_disabled_checks",
        "collected_as_system",
        "edr",
    ):
        row[key] = summary[key]
    for key in ("e8_levels", "e8_capped", "acn_unmet", "acn_not_judged"):
        if key in summary:
            row[key] = summary[key]
    return row


def _project_row(row: dict[str, Any]) -> dict[str, Any]:
    projected = {key: row[key] for key in _LISTING_KEYS if key in row}
    return projected


def _source(raw: bytes) -> dict[str, Any]:
    return {
        "kind": "operator-file",
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _time(value: Any, label: str) -> str:
    text = _text(value, label)
    try:
        datetime.fromisoformat(text)
    except ValueError as exc:
        raise ReportError(f"{label} is not an ISO 8601 timestamp") from exc
    return text


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or value not in KNOWN_TOOL_VERSIONS:
        raise ReportError(f"{label} is missing or not a supported analyzer version")
    return value


def _severity(value: Any, label: str) -> str:
    if value not in SEVERITIES:
        raise ReportError(f"{label} is not one of {', '.join(SEVERITIES)}")
    return value


def _severity_score(value: Any, severity: str, label: str) -> int:
    expected = _SEVERITY_SCORE[severity]
    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
        raise ReportError(f"{label} does not match the upstream severity scale")
    return value


def _host_role(value: Any, label: str) -> str:
    if value not in ("dc", "server", "workstation"):
        raise ReportError(f"{label} is not one of dc, server, workstation")
    return value


def _status(value: Any, event_type: str, label: str) -> str | None:
    if event_type == "resolved":
        if value != "resolved":
            raise ReportError(f"{label} must be 'resolved' on a resolved row")
        return value
    if value not in _FINDING_STATUSES:
        raise ReportError(f"{label} must be null, new, or persisting on a finding row")
    return value


def _finding_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _FINDING_ID_CHARS
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ReportError(f"{label} must be a {_FINDING_ID_CHARS}-hex finding id")
    return value


def _bounded_int(value: Any, low: int, high: int, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < low
        or value > high
        or value.bit_length() > MAX_INTEGER_BITS
    ):
        raise ReportError(f"{label} must be an integer from {low} to {high}")
    return value


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ReportError(f"{label} must be a boolean")
    return value


def _edr(value: Any, label: str) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return [_text(value, label)]
    return _str_list(value, label)


def _e8_levels(value: Any, label: str) -> dict[str, int | None] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ReportError(f"{label} must be a mapping with string keys or null")
    output: dict[str, int | None] = {}
    for key, item in value.items():
        name = _text(key, f"{label} key")
        if item is None:
            output[name] = None
        else:
            output[name] = _bounded_int(item, 0, _SCORE_BOUND, f"{label}.{name}")
    return output


def _str_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ReportError(f"{label} must be a list")
    return [_text(item, f"{label}[{i}]") for i, item in enumerate(value)]


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise ReportError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 and char != "\t" for char in value):
        raise ReportError(f"{label} contains control characters")
    return value


def _any_text(value: Any, label: str) -> str:
    """Like _text but allows an empty string (upstream writes empty values)."""
    if not isinstance(value, str) or len(value) > _MAX_TEXT:
        raise ReportError(f"{label} must be a bounded string")
    if any(ord(char) < 0x20 and char != "\t" for char in value):
        raise ReportError(f"{label} contains control characters")
    return value


def _nullable_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _any_text(value, label)


def _opt_query(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def render_producer_output_bytes(output: Any) -> bytes:
    """Render the exact UTF-8 form used by this arm's output size gate."""
    return json.dumps(
        output, sort_keys=True, ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _output_refusal(output: Any) -> str | None:
    try:
        size = len(render_producer_output_bytes(output))
    except (TypeError, ValueError, OverflowError) as exc:
        return f"result could not be encoded: {exc}"
    if size > MAX_OUTPUT_CHARS:
        return f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; narrow the lookup"
    return None


def _data_result(
    spec: ArmSpec,
    action: str,
    document: dict[str, Any],
    status: str,
    reason: str | None,
    evidence: list[dict[str, Any]],
    source: dict[str, Any],
    provenance: dict[str, Any],
) -> Result:
    """Wrap a data-action payload with the report's coverage status.

    Complete reports return ok=true.  Partial and unknown reports keep the
    projected payload in output for the caller but return ok=false with the
    reason as error, mapping to CLI exit 1 and MCP isError=true.  Invalid
    input never reaches here: it is a plain failure with no status object.
    """
    output = dict(document)
    output["status"] = status
    output["reason"] = reason
    output["evidence"] = evidence
    output["source"] = source
    output["provenance"] = provenance
    refusal = _output_refusal(output)
    if refusal:
        return _fail(spec, action, refusal)
    if status == "complete":
        return Result(True, spec.id, action, output, None)
    return Result(False, spec.id, action, output, redact(str(reason))[:MAX_OUTPUT_CHARS])


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    refusal = _output_refusal(output)
    if refusal:
        return _fail(spec, action, refusal)
    return Result(True, spec.id, action, output, None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(False, spec.id, action, None, redact(str(error))[:MAX_OUTPUT_CHARS])
