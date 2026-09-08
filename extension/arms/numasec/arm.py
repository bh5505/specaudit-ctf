"""Curated numasec arm: strict, structurally attributed lifecycle reads."""

from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..mcp_client import redact
from ..strict_data import StrictDataError, strict_json_loads
from .policy import (
    ALLOWED_ACTIONS,
    ALLOWED_STATUSES,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_LEDGER_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    ledger_refusal,
    limit_refusal,
)

_FINDING_KEYS = frozenset({"finding_id", "title", "status", "severity", "transitions"})
_TRANSITION_KEYS = frozenset({"from", "to", "actor", "reason", "ts"})
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "informational"})
_TRANSITIONS = {
    "new": frozenset({"open", "rejected", "false-positive"}),
    "open": frozenset({"verified", "resolved", "rejected", "accepted-risk", "false-positive"}),
    "verified": frozenset({"open", "resolved", "rejected", "accepted-risk", "false-positive"}),
    "resolved": frozenset({"closed", "reopened"}),
    "closed": frozenset({"reopened"}),
    "reopened": frozenset({"open", "verified", "resolved", "rejected", "accepted-risk", "false-positive"}),
    "rejected": frozenset({"reopened"}),
    "accepted-risk": frozenset({"reopened"}),
    "false-positive": frozenset({"reopened"}),
}
_MAX_TEXT = 16_384
_MAX_RECORDS = 50_000


class _LedgerError(ValueError):
    """The ledger violates the closed lifecycle contract."""


class NumasecArm:
    """Read a validated lifecycle whose status is derived from its history."""

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
                spec, action,
                f"action {action!r} is not on the allowlist "
                "(offline finding lifecycle reads over a local ledger only; there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, refusal = ledger_refusal(payload.get("ledger"))
        if refusal:
            return _fail(spec, action, refusal)
        assert path is not None
        try:
            findings, source = _load_ledger(path)
        except _LedgerError as exc:
            return _fail(spec, action, redact(str(exc)))

        finding_id = _optional_query(payload.get("finding_id"))
        if action == "finding":
            match = _find(findings, finding_id)
            if match is None:
                return _fail(spec, action, f"finding_id {finding_id!r} not found in this ledger")
            return _ok(spec, action, {"finding": _project_finding(match), "source": source})

        if action == "list_findings":
            limit, refusal = limit_refusal(payload.get("limit"))
            if refusal:
                return _fail(spec, action, refusal)
            assert limit is not None
            status = _optional_query(payload.get("status"))
            matches = [item for item in findings if status is None or item["status"] == status]
            rows = [_project_summary(item) for item in matches[:limit]]
            return _ok(
                spec, action,
                {
                    "findings": rows,
                    "total": len(matches),
                    "unfiltered_total": len(findings),
                    "returned": len(rows),
                    "capped": len(rows) < len(matches),
                    "source": source,
                },
            )

        match = _find(findings, finding_id)
        if match is None:
            return _fail(spec, action, f"finding_id {finding_id!r} not found in this ledger")
        transitions = [_project_transition(item) for item in match["transitions"]]
        rows = transitions[:MAX_RESULTS]
        return _ok(
            spec, action,
            {
                "finding_id": match["finding_id"],
                "status": match["status"],
                "transitions": rows,
                "total": len(transitions),
                "returned": len(rows),
                "capped": len(rows) < len(transitions),
                "source": source,
            },
        )

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        if payload:
            return _fail(spec, action, "list_tools takes no caller arguments")
        return _ok(
            spec, action,
            {
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": {key: sorted(values) for key, values in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
        )


def _load_ledger(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = _read_bounded(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _LedgerError("ledger is not strict UTF-8") from exc
    if not text.strip():
        raise _LedgerError("ledger is empty")
    try:
        if path.suffix.lower() == ".json":
            data = strict_json_loads(text)
            if isinstance(data, list):
                rows = data
            elif isinstance(data, dict) and set(data) == {"findings"} and isinstance(data["findings"], list):
                rows = data["findings"]
            else:
                raise _LedgerError("JSON ledger must be an array or an object containing only a findings array")
        else:
            rows = _parse_jsonl(text)
    except _LedgerError:
        raise
    except StrictDataError as exc:
        raise _LedgerError(str(exc)) from exc
    except Exception as exc:
        raise _LedgerError(f"invalid {path.suffix.lower().lstrip('.')} ledger") from exc
    if len(rows) > _MAX_RECORDS:
        raise _LedgerError(f"ledger exceeds the {_MAX_RECORDS} record cap")
    return _validate_findings(rows), _source(raw)


def _parse_jsonl(text: str) -> list[Any]:
    rows: list[Any] = []
    for line_number, line in enumerate(io.StringIO(text), 1):
        if not line.strip():
            raise _LedgerError(f"ledger line {line_number} is blank")
        if len(rows) >= _MAX_RECORDS:
            raise _LedgerError(f"ledger exceeds the {_MAX_RECORDS} record cap")
        try:
            rows.append(strict_json_loads(line))
        except StrictDataError as exc:
            raise _LedgerError(f"ledger line {line_number}: {exc}") from exc
        except Exception as exc:
            raise _LedgerError(f"ledger line {line_number} is not valid JSON") from exc
    if not rows:
        raise _LedgerError("ledger contains no records")
    return rows


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_LEDGER_BYTES + 1)
    except OSError as exc:
        raise _LedgerError("could not read ledger") from exc
    if len(raw) > MAX_LEDGER_BYTES:
        raise _LedgerError(f"ledger exceeds the {MAX_LEDGER_BYTES} byte read cap")
    return raw


def _validate_findings(rows: list[Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        label = f"finding entry {index}"
        if not isinstance(raw, dict):
            raise _LedgerError(f"{label} is not a mapping")
        if any(not isinstance(key, str) for key in raw):
            raise _LedgerError(f"{label} field names must be strings")
        extra = sorted(set(raw) - _FINDING_KEYS)
        missing = sorted(_FINDING_KEYS - set(raw))
        if extra:
            raise _LedgerError(f"{label} has unknown fields: {', '.join(extra)}")
        if missing:
            raise _LedgerError(f"{label} is missing fields: {', '.join(missing)}")
        finding_id = _text(raw["finding_id"], f"{label}.finding_id")
        if finding_id in seen:
            raise _LedgerError(f"duplicate finding_id: {finding_id}")
        seen.add(finding_id)
        severity = _text(raw["severity"], f"{label}.severity").casefold()
        if severity not in _SEVERITIES:
            raise _LedgerError(f"{label}.severity is not recognized")
        declared_status = _status(raw["status"], f"{label}.status")
        transitions_raw = raw["transitions"]
        if not isinstance(transitions_raw, list) or len(transitions_raw) > _MAX_RECORDS:
            raise _LedgerError(f"{label}.transitions must be a bounded list")
        transitions, derived_status = _validate_transitions(transitions_raw, label)
        if declared_status != derived_status:
            raise _LedgerError(
                f"{label}.status {declared_status!r} does not match derived status {derived_status!r}"
            )
        findings.append(
            {
                "finding_id": finding_id,
                "title": _text(raw["title"], f"{label}.title"),
                "severity": severity,
                "status": derived_status,
                "transitions": transitions,
            }
        )
    return findings


def _validate_transitions(rows: list[Any], finding_label: str) -> tuple[list[dict[str, str]], str]:
    transitions: list[dict[str, str]] = []
    current = "new"
    previous_timestamp: datetime | None = None
    for index, raw in enumerate(rows):
        label = f"{finding_label}.transitions[{index}]"
        if not isinstance(raw, dict):
            raise _LedgerError(f"{label} is not a mapping")
        if any(not isinstance(key, str) for key in raw):
            raise _LedgerError(f"{label} field names must be strings")
        extra = sorted(set(raw) - _TRANSITION_KEYS)
        missing = sorted(_TRANSITION_KEYS - set(raw))
        if extra:
            raise _LedgerError(f"{label} has unknown fields: {', '.join(extra)}")
        if missing:
            raise _LedgerError(f"{label} is missing fields: {', '.join(missing)}")
        from_status = _status(raw["from"], f"{label}.from")
        to_status = _status(raw["to"], f"{label}.to")
        if from_status != current:
            raise _LedgerError(f"{label}.from breaks lifecycle continuity; expected {current!r}")
        if to_status not in _TRANSITIONS[from_status]:
            raise _LedgerError(f"{label} has disallowed transition {from_status!r} -> {to_status!r}")
        actor = _text(raw["actor"], f"{label}.actor")
        reason = _text(raw["reason"], f"{label}.reason")
        timestamp, parsed_timestamp = _timestamp(raw["ts"], f"{label}.ts")
        if previous_timestamp is not None and parsed_timestamp <= previous_timestamp:
            raise _LedgerError(f"{label}.ts must be later than the preceding transition")
        transitions.append(
            {"from": from_status, "to": to_status, "actor": actor, "reason": reason, "ts": timestamp}
        )
        current = to_status
        previous_timestamp = parsed_timestamp
    return transitions, current


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    text = _text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _LedgerError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise _LedgerError(f"{label} must include a timezone")
    return text, parsed


def _status(value: Any, label: str) -> str:
    status = _text(value, label)
    if status not in ALLOWED_STATUSES:
        raise _LedgerError(f"{label} is not a recognized finding status")
    return status


def _find(findings: list[dict[str, Any]], finding_id: str | None) -> dict[str, Any] | None:
    return next((item for item in findings if item["finding_id"] == finding_id), None)


def _project_transition(item: Mapping[str, str]) -> dict[str, str]:
    return {key: item[key] for key in ("from", "to", "actor", "reason", "ts")}


def _project_finding(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": item["finding_id"],
        "title": item["title"],
        "severity": item["severity"],
        "status": item["status"],
        "transitions": [_project_transition(value) for value in item["transitions"]],
    }


def _project_summary(item: Mapping[str, Any]) -> dict[str, str]:
    return {
        "finding_id": item["finding_id"],
        "title": item["title"],
        "severity": item["severity"],
        "status": item["status"],
    }


def _source(raw: bytes) -> dict[str, Any]:
    return {"kind": "operator-file", "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise _LedgerError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
        raise _LedgerError(f"{label} contains control characters")
    return value.strip()


def _optional_query(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        size = len(json.dumps(output, sort_keys=True, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        return _fail(spec, action, f"result could not be encoded: {exc}")
    if size > MAX_OUTPUT_CHARS:
        return _fail(spec, action, f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; narrow the lookup")
    return Result(True, spec.id, action, output, None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(False, spec.id, action, None, redact(str(error))[:MAX_OUTPUT_CHARS])
