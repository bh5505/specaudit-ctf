"""Curated idwolf arm: bounded offline reader for IDWolf analyzer JSONL exports.

The arm reads a caller-supplied local ``.jsonl`` export of the upstream
analyzer in-process.  It never invokes the AD/Entra collectors, password
quality path, AI summary, or any wrapper.  Row schema and completeness
semantics follow the upstream serializer at the campaign-pinned revision:
``finding`` and ``resolved`` rows (resolved rows carry a reduced field set)
plus ONE ``summary`` row per run.

Status model for data actions (summary, list_findings, finding): a report is
``complete`` only when every run has its summary row, its finding and
severity counts match the exported finding rows, and the analyzer reported
full evaluation (``coverage_pct == 100``, ``not_evaluated == 0``, empty
``not_evaluated_checks``). A count mismatch or missing summary means the
export cannot prove completeness (``unknown``); any reported coverage gap is
``partial``.  Complete reports return ``ok=true``; partial and unknown
reports return ``ok=false`` with ``output.status``, a reason, and bounded
evidence (CLI exit 1 / MCP ``isError=true``), while still carrying the
projected payload.  ``score_reliable=false`` is surfaced on the run
projection but never makes a run partial: it qualifies the analyzer's
score, not its coverage.  Invalid input is a plain failure with a
redacted bounded error and no status object.

Projection: default views (summary runs, list_findings rows) omit
``detail``, ``object_dn``, and ``tenant_id``; the exact ``finding`` action
returns the full documented row.  Parse errors reference record numbers
and field names only, never row values, so secret-shaped fixture values
cannot leak into the error channel.
"""

from __future__ import annotations

import hashlib
import json
import re
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
    KNOWN_TOOL_VERSIONS,
    LIST_ACTIONS,
    MAX_EVIDENCE_RUNS,
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
# 16 lowercase hex digits: upstream derives them as the first 8 SHA-256 bytes
# of "check|object", stable across runs for the same check on the same object.
_FINDING_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_SCORE_BOUND = 10_000

_BASE_KEYS = frozenset(
    {"time", "event_type", "run_id", "tool", "tool_version", "source_kind", "domain"}
)
_TENANT_KEY = frozenset({"tenant_id"})
_FINDING_ROW_KEYS = frozenset(
    {
        "severity",
        "severity_score",
        "check",
        "title",
        "category",
        "object",
        "object_type",
        "object_dn",
        "detail",
        "mitre",
        "controls",
        "finding_id",
        "status",
    }
)
# Upstream writes resolved rows with a reduced field set: no category,
# object_type, object_dn, detail, mitre, or controls.
_RESOLVED_ROW_KEYS = frozenset(
    {"severity", "severity_score", "check", "title", "object", "finding_id", "status"}
)
_SUMMARY_ROW_KEYS = frozenset(
    {
        "score",
        "grade",
        "score_reliable",
        "coverage_pct",
        "findings",
        "critical",
        "high",
        "medium",
        "low",
        "accepted",
        "new",
        "resolved",
        "not_evaluated",
        "not_evaluated_checks",
    }
)

# Default-view projection: identity and verdict fields only.  detail,
# object_dn, tenant_id, and controls are never projected here; the exact
# finding action is the only action that returns them.
_LISTING_KEYS = (
    "time",
    "event_type",
    "run_id",
    "source_kind",
    "domain",
    "severity",
    "severity_score",
    "check",
    "title",
    "category",
    "object",
    "finding_id",
    "status",
)


class ReportError(ValueError):
    """The report is malformed or outside the closed reader contract."""


class IdwolfArm:
    """Bounded in-process reader over local IDWolf analyzer exports."""

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
                "(offline reads over local IDWolf analyzer exports only; "
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
                "runs": [_project_run(run) for run in _sorted_runs(report)],
                "run_count": report["run_count"],
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
            # Exact lookup projection: the full row including detail,
            # object_dn, controls, and tenant_id on Entra rows.  This is the
            # only action that returns those fields.
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
        source_kind = _opt_query(payload.get("source_kind"))
        rows = [
            row
            for row in _sorted_rows(report)
            if (severity is None or row["severity"] == severity)
            and (source_kind is None or row["source_kind"] == source_kind)
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

    runs: dict[str, dict[str, Any]] = {}
    identities: set[tuple[str, str]] = set()
    for index, record in enumerate(records):
        row = _validate_row(record, index)
        run = _bind_run(runs, row, index)
        event_type = row["event_type"]
        if event_type == "summary":
            if run["summary"] is not None:
                raise ReportError(
                    f"report record {index} repeats the one summary row allowed for its run"
                )
            run["summary"] = row
        else:
            identity = (row["run_id"], row["finding_id"])
            if identity in identities:
                raise ReportError(
                    f"report record {index} repeats a finding identity already "
                    "present in this report"
                )
            identities.add(identity)
            run["findings" if event_type == "finding" else "resolved"].append(row)

    for run in runs.values():
        run["findings"].sort(key=_order_key)
        run["resolved"].sort(key=_order_key)
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
    return (
        {"runs": runs, "run_count": len(runs)},
        _source(raw),
        provenance,
    )


def _validate_row(raw: Any, index: int) -> dict[str, Any]:
    label = f"report record {index}"
    if not isinstance(raw, dict):
        raise ReportError(f"{label} is not a JSON object")
    if any(not isinstance(key, str) for key in raw):
        raise ReportError(f"{label} field names must be strings")

    event_type = raw.get("event_type")
    if event_type not in ("finding", "resolved", "summary"):
        raise ReportError(f"{label}.event_type is not finding, resolved, or summary")
    source_kind = raw.get("source_kind")
    if source_kind not in ("ad", "entra"):
        raise ReportError(f"{label}.source_kind is not ad or entra")
    if raw.get("tool") != "IDWolf":
        raise ReportError(f"{label}.tool is not the IDWolf analyzer export schema")
    version = _version(raw.get("tool_version"), f"{label}.tool_version")
    row: dict[str, Any] = {
        "time": _time(raw.get("time"), f"{label}.time"),
        "event_type": event_type,
        "run_id": _text(raw.get("run_id"), f"{label}.run_id"),
        "tool": "IDWolf",
        "tool_version": version,
        "source_kind": source_kind,
        "domain": _text(raw.get("domain"), f"{label}.domain"),
    }
    if "tenant_id" in raw:
        if source_kind != "entra":
            raise ReportError(f"{label} carries tenant_id on an ad row")
        row["tenant_id"] = _text(raw["tenant_id"], f"{label}.tenant_id")
    elif source_kind == "entra":
        raise ReportError(f"{label} is missing tenant_id on an entra row")

    if event_type == "finding":
        required = _FINDING_ROW_KEYS
    elif event_type == "resolved":
        required = _RESOLVED_ROW_KEYS
    else:
        required = _SUMMARY_ROW_KEYS
    extra = sorted(set(raw) - _BASE_KEYS - _TENANT_KEY - required)
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
            object=_text(raw["object"], f"{label}.object"),
            finding_id=_finding_id(raw["finding_id"], f"{label}.finding_id"),
            status=_status(raw["status"], event_type, f"{label}.status"),
        )
    if event_type == "finding":
        row.update(
            category=_text(raw["category"], f"{label}.category"),
            object_type=_text(raw["object_type"], f"{label}.object_type"),
            object_dn=_any_text(raw["object_dn"], f"{label}.object_dn"),
            detail=_text(raw["detail"], f"{label}.detail"),
            mitre=_any_text(raw["mitre"], f"{label}.mitre"),
            controls=_controls(raw["controls"], f"{label}.controls"),
        )
    if event_type == "summary":
        row.update(
            score=_bounded_int(raw["score"], 0, _SCORE_BOUND, f"{label}.score"),
            grade=_text(raw["grade"], f"{label}.grade"),
            score_reliable=_bool(raw["score_reliable"], f"{label}.score_reliable"),
            coverage_pct=_coverage(raw["coverage_pct"], f"{label}.coverage_pct"),
            findings=_bounded_int(raw["findings"], 0, MAX_RECORDS, f"{label}.findings"),
            critical=_bounded_int(raw["critical"], 0, MAX_RECORDS, f"{label}.critical"),
            high=_bounded_int(raw["high"], 0, MAX_RECORDS, f"{label}.high"),
            medium=_bounded_int(raw["medium"], 0, MAX_RECORDS, f"{label}.medium"),
            low=_bounded_int(raw["low"], 0, MAX_RECORDS, f"{label}.low"),
            accepted=_bounded_int(raw["accepted"], 0, MAX_RECORDS, f"{label}.accepted"),
            new=_nullable_count(raw.get("new"), f"{label}.new"),
            resolved=_nullable_count(raw.get("resolved"), f"{label}.resolved"),
            not_evaluated=_bounded_int(
                raw["not_evaluated"], 0, MAX_RECORDS, f"{label}.not_evaluated"
            ),
            not_evaluated_checks=_controls(
                raw["not_evaluated_checks"], f"{label}.not_evaluated_checks"
            ),
        )
    return row


def _bind_run(runs: dict[str, dict[str, Any]], row: dict[str, Any], index: int) -> dict[str, Any]:
    """Bind a row to its run, refusing mixed source identity inside one run."""
    run = runs.get(row["run_id"])
    identity = (
        row["source_kind"],
        row["domain"],
        row.get("tenant_id"),
        row["tool_version"],
    )
    if run is None:
        return runs.setdefault(
            row["run_id"],
            {
                "run_id": row["run_id"],
                "tool_version": row["tool_version"],
                "time": row["time"],
                "identity": identity,
                "summary": None,
                "findings": [],
                "resolved": [],
            },
        )
    if run["identity"] != identity:
        # Upstream never mixes source_kind, domain, tenant_id, or tool
        # version inside one run; a mix means the rows are not one export.
        raise ReportError(
            f"report record {index} changes source_kind, domain, tenant_id, or "
            "tool_version inside a single run"
        )
    return run


def _run_coverage(run: dict[str, Any]) -> str:
    """Classify one run from its own summary row (complete/partial/unknown)."""
    summary = run["summary"]
    if summary is None:
        return "unknown"
    gaps = (
        summary["coverage_pct"] != 100
        or summary["not_evaluated"] > 0
        or bool(summary["not_evaluated_checks"])
    )
    if gaps:
        return "partial"
    return "unknown" if _finding_count_mismatch(run) else "complete"


def _finding_count_mismatch(run: dict[str, Any]) -> dict[str, dict[str, int]] | None:
    """Compare the upstream summary with the current findings it exported.

    The pinned IDWolf JSONL writer derives both total and severity counts
    from its Findings array; resolved comparison rows are separate.
    """
    summary = run["summary"]
    if summary is None:
        return None
    observed = {"findings": len(run["findings"])}
    for severity in SEVERITIES:
        observed[severity.lower()] = sum(
            row["severity"] == severity for row in run["findings"]
        )
    declared = {key: summary[key] for key in observed}
    return {"declared": declared, "observed": observed} if observed != declared else None


def _overall_status(report: dict[str, Any]) -> tuple[str, str | None, list[dict[str, Any]]]:
    """Classify the report from its runs' summary rows.

    See the module docstring for the exact predicate.  score_reliable=false
    is surfaced on the run projection but never contributes to partial:
    it qualifies the analyzer's score, not its evaluation coverage.
    """
    incomplete: list[tuple[str, str]] = []
    evidence: list[dict[str, Any]] = []
    count_mismatch = False
    for run in _sorted_runs(report):
        run_status = _run_coverage(run)
        if run_status == "complete":
            continue
        incomplete.append((run["run_id"], run_status))
        if run_status == "unknown":
            if run["summary"] is None:
                entry: dict[str, Any] = {
                    "run_id": run["run_id"],
                    "run_status": "unknown",
                    "summary_present": False,
                    "finding_rows": len(run["findings"]),
                    "resolved_rows": len(run["resolved"]),
                }
            else:
                count_mismatch = True
                entry = {
                    "run_id": run["run_id"],
                    "run_status": "unknown",
                    "kind": "summary_count_mismatch",
                    "finding_counts": _finding_count_mismatch(run),
                }
        else:
            summary = run["summary"]
            entry = {
                "run_id": run["run_id"],
                "run_status": "partial",
                "coverage_pct": summary["coverage_pct"],
                "not_evaluated": summary["not_evaluated"],
                "not_evaluated_checks": list(summary["not_evaluated_checks"]),
            }
            mismatch = _finding_count_mismatch(run)
            if mismatch:
                entry["finding_counts"] = mismatch
        if len(evidence) < MAX_EVIDENCE_RUNS:
            evidence.append(entry)
    if not incomplete:
        return "complete", None, []
    if len(incomplete) > MAX_EVIDENCE_RUNS:
        evidence.append(
            {"evidence_truncated": True, "unshown_runs": len(incomplete) - len(evidence)}
        )
    if any(status == "unknown" for _, status in incomplete):
        if count_mismatch:
            return "unknown", "summary finding counts do not match report rows", evidence
        return "unknown", "report is missing the summary row for at least one run", evidence
    return "partial", "analyzer reported incomplete evaluation coverage", evidence


def _sorted_runs(report: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(report["runs"].values(), key=lambda run: (run["identity"][1], run["run_id"]))


def _sorted_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in report["runs"].values():
        rows.extend(run["findings"])
        rows.extend(run["resolved"])
    rows.sort(key=_order_key)
    return rows


def _order_key(row: dict[str, Any]) -> tuple:
    # Stable ordering: domain, severity_score desc, check, finding_id; the
    # trailing keys only break ties across runs sharing a finding id.
    return (
        row["domain"],
        -row["severity_score"],
        row["check"],
        row["finding_id"],
        row["run_id"],
        row["event_type"],
    )


def _find_identity(run: dict[str, Any], finding_id: str) -> dict[str, Any] | None:
    for row in run["findings"]:
        if row["finding_id"] == finding_id:
            return row
    for row in run["resolved"]:
        if row["finding_id"] == finding_id:
            return row
    return None


def _find_reported_row(report: dict[str, Any], payload: dict) -> dict[str, Any] | None:
    """Exact (run_id, finding_id) lookup across a run's finding/resolved rows."""
    run = report["runs"].get(payload["run_id"].strip())
    if run is None:
        return None
    return _find_identity(run, payload["finding_id"].strip())


def _project_run(run: dict[str, Any]) -> dict[str, Any]:
    summary = run["summary"]
    row: dict[str, Any] = {
        "run_id": run["run_id"],
        "source_kind": run["identity"][0],
        "domain": run["identity"][1],
        "tool_version": run["tool_version"],
        "time": run["time"],
        "finding_rows": len(run["findings"]),
        "resolved_rows": len(run["resolved"]),
        "run_status": _run_coverage(run),
    }
    if summary is None:
        return row
    for key in (
        "score",
        "grade",
        "score_reliable",
        "coverage_pct",
        "findings",
        "critical",
        "high",
        "medium",
        "low",
        "accepted",
        "new",
        "resolved",
        "not_evaluated",
        "not_evaluated_checks",
    ):
        row[key] = summary[key]
    return row


def _project_row(row: dict[str, Any]) -> dict[str, Any]:
    projected = {key: row[key] for key in _LISTING_KEYS if key in row}
    for key in ("object_type", "mitre"):
        if key in row:
            projected[key] = row[key]
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


def _status(value: Any, event_type: str, label: str) -> str | None:
    if event_type == "resolved":
        if value != "resolved":
            raise ReportError(f"{label} must be 'resolved' on a resolved row")
        return value
    if value not in _FINDING_STATUSES:
        raise ReportError(f"{label} must be null, new, or persisting on a finding row")
    return value


def _finding_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _FINDING_ID_RE.fullmatch(value):
        raise ReportError(f"{label} must be a 16-hex finding id")
    return value


def _coverage(value: Any, label: str) -> int | float:
    # Strict JSON decoding already refuses non-finite numbers.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"{label} must be a number from 0 to 100")
    if not 0 <= value <= 100:
        raise ReportError(f"{label} must be a number from 0 to 100")
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


def _nullable_count(value: Any, label: str) -> int | None:
    if value is None:
        return None
    return _bounded_int(value, 0, MAX_RECORDS, label)


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ReportError(f"{label} must be a boolean")
    return value


def _controls(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ReportError(f"{label} must be a list")
    return [_text(item, f"{label}[{i}]") for i, item in enumerate(value)]


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise ReportError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 and char not in "\t" for char in value):
        raise ReportError(f"{label} contains control characters")
    return value


def _any_text(value: Any, label: str) -> str:
    """Like _text but allows an empty string (upstream writes empty DNs)."""
    if not isinstance(value, str) or len(value) > _MAX_TEXT:
        raise ReportError(f"{label} must be a bounded string")
    if any(ord(char) < 0x20 and char not in "\t" for char in value):
        raise ReportError(f"{label} contains control characters")
    return value


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
