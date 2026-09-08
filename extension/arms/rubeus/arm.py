"""Curated rubeus arm: deweaponized AD telemetry reads."""

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
    args_refusal,
    limit_refusal,
    telemetry_refusal,
)


class RubeusArm:
    """Specialized transport for catalog id rubeus.

    First-party in-process read arm: a stdlib reader over a local
    deweaponized AD telemetry JSON file with no subprocess and no
    endpoint.  ``installed`` reports handler presence only — the
    telemetry file is per-invoke caller data (args.telemetry_file),
    the same contract as every other file-consuming arm.

    No real Kerberos tickets, NTLM hashes, or secrets are present in
    the telemetry data.  Legitimate administration is not automatically
    classified as compromise.
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
                error=(
                    f"action {action!r} is not on the allowlist "
                    "(offline reads over a local deweaponized AD telemetry "
                    "file only; there is no dispatch tier)"
                ),
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
        path, file_refused = telemetry_refusal(payload.get("telemetry_file"))
        if file_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=file_refused,
            )
        assert path is not None  # noqa: S101 — guarded by file_refused
        try:
            events = _load_telemetry(path)
        except _TelemetryError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if action == "telemetry":
            return self._telemetry(spec, payload, events)
        if action == "list_telemetry":
            return self._list_telemetry(spec, payload, events)
        # action == "list_indicators"
        return self._list_indicators(spec, payload, events)

    # -- action handlers --------------------------------------------------

    def _telemetry(
        self, spec: ArmSpec, payload: dict, events: list[dict]
    ) -> Result:
        """Return the full record for a single event by event_id."""
        event_id = str(payload["event_id"]).strip()
        match = _find_event(events, event_id)
        if match is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action="telemetry",
                output=None,
                error=f"event_id {event_id!r} not found in this telemetry file",
            )
        text = json.dumps(match, sort_keys=True, default=str)
        if len(text) > MAX_OUTPUT_CHARS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action="telemetry",
                output=None,
                error=(
                    f"result exceeds the {MAX_OUTPUT_CHARS} character "
                    "output cap; narrow the lookup"
                ),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action="telemetry",
            output=match,
            error=None,
        )

    def _list_telemetry(
        self, spec: ArmSpec, payload: dict, events: list[dict]
    ) -> Result:
        """Return a summary list of events, optionally filtered by category."""
        raw_limit = limit_refusal(payload.get("limit"))
        if isinstance(raw_limit, str):
            return Result(
                ok=False,
                arm_id=spec.id,
                action="list_telemetry",
                output=None,
                error=raw_limit,
            )
        limit = raw_limit
        category = payload.get("category")
        if category is not None:
            if not isinstance(category, str) or not category.strip():
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action="list_telemetry",
                    output=None,
                    error="args.category must be a non-empty string",
                )
            category = category.strip().lower()
            filtered = [
                e for e in events
                if str(e.get("category", "")).strip().lower() == category
            ]
        else:
            filtered = events
        summaries: list[dict[str, Any]] = []
        for event in filtered[:limit]:
            summaries.append(
                {
                    "event_id": event.get("event_id", ""),
                    "category": event.get("category", ""),
                    "description": event.get("description", ""),
                    "severity": event.get("severity", ""),
                }
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action="list_telemetry",
            output={
                "count": len(summaries),
                "total": len(filtered),
                "unfiltered_total": len(events),
                "events": summaries,
            },
            error=None,
        )

    def _list_indicators(
        self, spec: ArmSpec, payload: dict, events: list[dict]
    ) -> Result:
        """List unique indicator types without real values."""
        indicator_type = payload.get("indicator_type")
        if indicator_type is not None:
            if not isinstance(indicator_type, str) or not indicator_type.strip():
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action="list_indicators",
                    output=None,
                    error="args.indicator_type must be a non-empty string",
                )
            indicator_type = indicator_type.strip().lower()

        seen: dict[str, int] = {}
        for event in events:
            indicators = event.get("indicators")
            if not isinstance(indicators, list):
                continue
            for ind in indicators:
                if not isinstance(ind, dict):
                    continue
                itype = str(ind.get("type", "")).strip()
                if not itype:
                    continue
                if indicator_type is not None and itype.lower() != indicator_type:
                    continue
                # Never emit real values — only the type and count
                seen[itype] = seen.get(itype, 0) + 1

        result_list = sorted(
            [{"type": t, "count": c} for t, c in seen.items()],
            key=lambda r: (-r["count"], r["type"]),
        )
        return Result(
            ok=True,
            arm_id=spec.id,
            action="list_indicators",
            output={
                "indicator_types": len(result_list),
                "indicators": result_list,
                "note": (
                    "indicator values are intentionally omitted — "
                    "no real tickets, hashes, or secrets are distributed"
                ),
            },
            error=None,
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
                "arg_keys": {
                    key: sorted(vals) for key, vals in ARG_KEYS.items()
                },
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )


# -- telemetry loading ---------------------------------------------------


class _TelemetryError(Exception):
    """Raised when the telemetry file cannot be loaded."""


def _load_telemetry(path: Path) -> list[dict]:
    """Load deweaponized AD telemetry from a local JSON file.

    Accepted shapes:
    - A JSON file containing a top-level array of event dicts.
    - A JSON file containing an object with an ``events`` key whose
      value is a list.
    - A JSONL (newline-delimited JSON) file where each line is one
      event dict.

    Returns the list of event dicts, or raises ``_TelemetryError``.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise _TelemetryError(f"could not read telemetry file: {exc}") from exc

    text = raw_bytes.decode("utf-8", errors="replace")

    # --- Try JSON array / object first ---
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Fall through to JSONL
        data = None

    if data is not None:
        if isinstance(data, list):
            return _validate_list(data)
        if isinstance(data, dict):
            events = data.get("events")
            if isinstance(events, list):
                return _validate_list(events)
        raise _TelemetryError(
            "JSON telemetry must be an array of events or a mapping "
            "with an 'events' key"
        )

    # --- JSONL fallback ---
    events: list[dict] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except (json.JSONDecodeError, ValueError) as exc:
            raise _TelemetryError(
                f"invalid JSON on line {line_no}: {exc}"
            ) from exc
        if not isinstance(item, dict):
            raise _TelemetryError(
                f"telemetry line {line_no} is not a mapping "
                f"(got {type(item).__name__})"
            )
        events.append(item)
    if not events:
        raise _TelemetryError("telemetry file contains no events")
    return events


def _validate_list(data: list) -> list[dict]:
    """Ensure every element in the telemetry list is a dict."""
    out: list[dict] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise _TelemetryError(
                f"telemetry entry {idx} is not a mapping "
                f"(got {type(item).__name__})"
            )
        out.append(item)
    return out


# -- helpers --------------------------------------------------------------


def _find_event(events: list[dict], event_id: str) -> dict | None:
    """Exact-match search by event_id (first match wins)."""
    for event in events:
        if str(event.get("event_id", "")).strip() == event_id:
            return event
    return None
