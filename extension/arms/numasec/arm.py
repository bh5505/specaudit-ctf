"""Curated numasec arm: finding lifecycle reads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..mcp_client import redact
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    ledger_refusal,
    limit_refusal,
)


class NumasecArm:
    """Specialized transport for catalog id numasec.

    First-party in-process read arm: a stdlib finding lifecycle reader
    with no subprocess and no endpoint.  ``installed`` reports handler
    presence only — the corpus is per-invoke caller data (args.ledger),
    the same contract as every other file-consuming arm.

    Status changes are attributable and reversible.  No model-only
    status change creates a verified finding.  Every transition records
    an actor and a reason.
    """

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(offline finding lifecycle reads over a local ledger only; "
                "there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        path, ledger_refused = ledger_refusal(payload.get("ledger"))
        if ledger_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=ledger_refused,
            )
        try:
            records = _load_ledger(path)
        except Exception as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if isinstance(records, str):
            # refusal string from _load_ledger
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=records,
            )
        if action == "finding":
            return self._finding(spec, payload, records)
        if action == "list_findings":
            return self._list_findings(spec, payload, records)
        # action == "list_transitions"
        return self._list_transitions(spec, payload, records)

    # ------------------------------------------------------------------
    # action handlers
    # ------------------------------------------------------------------

    def _finding(
        self,
        spec: ArmSpec,
        payload: dict,
        records: list[dict],
    ) -> Result:
        """Return a single finding with its full status history."""
        finding_id = _opt_str(payload.get("finding_id"))
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if rec.get("finding_id") == finding_id:
                text = json.dumps(rec, sort_keys=True)
                if len(text) > MAX_OUTPUT_CHARS:
                    return Result(
                        ok=False,
                        arm_id=spec.id,
                        action="finding",
                        output=None,
                        error=(
                            f"result exceeds the {MAX_OUTPUT_CHARS} character "
                            "output cap; the finding record is too large"
                        ),
                    )
                return _ok_result(spec, "finding", rec)
        return Result(
            ok=False,
            arm_id=spec.id,
            action="finding",
            output=None,
            error=f"finding_id {finding_id!r} not found in this ledger",
        )

    def _list_findings(
        self,
        spec: ArmSpec,
        payload: dict,
        records: list[dict],
    ) -> Result:
        """Return a summary list of findings, optionally filtered by status."""
        limit, lrefusal = limit_refusal(payload.get("limit"))
        if lrefusal:
            return Result(
                ok=False,
                arm_id=spec.id,
                action="list_findings",
                output=None,
                error=lrefusal,
            )
        status_filter = _opt_str(payload.get("status"))
        summary: list[dict] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            current_status = rec.get("status", "")
            if status_filter and current_status != status_filter:
                continue
            summary.append(
                {
                    "finding_id": rec.get("finding_id", ""),
                    "title": rec.get("title", ""),
                    "severity": rec.get("severity", ""),
                    "status": current_status,
                    "actor": rec.get("actor", ""),
                }
            )
            if len(summary) >= limit:
                break
        return _ok_result(spec, "list_findings", summary)

    def _list_transitions(
        self,
        spec: ArmSpec,
        payload: dict,
        records: list[dict],
    ) -> Result:
        """Return the status change history for a specific finding."""
        finding_id = _opt_str(payload.get("finding_id"))
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if rec.get("finding_id") == finding_id:
                transitions = rec.get("transitions", [])
                if not isinstance(transitions, list):
                    return Result(
                        ok=False,
                        arm_id=spec.id,
                        action="list_transitions",
                        output=None,
                        error=(
                            f"finding {finding_id!r} has a malformed "
                            "transitions field (expected a list)"
                        ),
                    )
                # Validate that every transition has actor and reason.
                for i, t in enumerate(transitions):
                    if not isinstance(t, dict):
                        return Result(
                            ok=False,
                            arm_id=spec.id,
                            action="list_transitions",
                            output=None,
                            error=(
                                f"transition {i} for finding {finding_id!r} "
                                "is not a JSON object"
                            ),
                        )
                    if not t.get("actor") or not t.get("reason"):
                        return Result(
                            ok=False,
                            arm_id=spec.id,
                            action="list_transitions",
                            output=None,
                            error=(
                                f"transition {i} for finding {finding_id!r} "
                                "is missing actor or reason — every status "
                                "change must be attributable"
                            ),
                        )
                text = json.dumps(transitions, sort_keys=True)
                if len(text) > MAX_OUTPUT_CHARS:
                    return Result(
                        ok=False,
                        arm_id=spec.id,
                        action="list_transitions",
                        output=None,
                        error=(
                            f"transitions for finding {finding_id!r} exceed "
                            f"the {MAX_OUTPUT_CHARS} character output cap"
                        ),
                    )
                return _ok_result(
                    spec,
                    "list_transitions",
                    {"finding_id": finding_id, "transitions": transitions},
                )
        return Result(
            ok=False,
            arm_id=spec.id,
            action="list_transitions",
            output=None,
            error=f"finding_id {finding_id!r} not found in this ledger",
        )

    def _list_tools(
        self, spec: ArmSpec, action: str, payload: dict
    ) -> Result:
        if payload:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="list_tools takes no caller arguments",
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": {key: sorted(vals) for key, vals in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )


# ------------------------------------------------------------------
# ledger loader
# ------------------------------------------------------------------

def _load_ledger(path: Path) -> list[dict] | str:
    """Load a local finding lifecycle ledger.

    Handles JSON arrays and JSONL (one JSON object per line).
    Returns a list of dicts on success, or a refusal string on error.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"args.ledger could not be read: {exc}"
    text = raw.strip()
    if not text:
        return "args.ledger is empty"

    # Try JSON array first.
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return f"args.ledger is not valid JSON: {exc}"
        if not isinstance(data, list):
            return "args.ledger top-level value must be a JSON array or JSONL"
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                return f"args.ledger record {i} is not a JSON object"
        return data

    # Fall back to JSONL: one JSON object per line.
    records: list[dict] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return f"args.ledger line {lineno} is not valid JSON: {exc}"
        if not isinstance(obj, dict):
            return f"args.ledger line {lineno} is not a JSON object"
        records.append(obj)
    if not records:
        return "args.ledger contained no parseable records"
    return records


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()


def _ok_result(spec: ArmSpec, action: str, output: Any) -> Result:
    text = json.dumps(output, sort_keys=True)
    if len(text) > MAX_OUTPUT_CHARS:
        return Result(
            ok=False,
            arm_id=spec.id,
            action=action,
            output=None,
            error=(
                f"result exceeds the {MAX_OUTPUT_CHARS} character output "
                "cap; narrow the lookup"
            ),
        )
    return Result(
        ok=True,
        arm_id=spec.id,
        action=action,
        output=output,
        error=None,
    )
