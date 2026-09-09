"""Curated rubeus arm: strict reads over deweaponized AD telemetry."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any, Mapping

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..mcp_client import redact
from ..strict_data import StrictDataError, strict_json_loads
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    MAX_TELEMETRY_BYTES,
    args_refusal,
    limit_refusal,
    telemetry_refusal,
)

_EVENT_KEYS = frozenset({"event_id", "category", "description", "severity", "indicators"})
_INDICATOR_KEYS = frozenset({"type", "value"})
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "informational"})
_REDACTED_VALUES = frozenset({"[REDACTED]", "<REDACTED>", "REDACTED"})
_MAX_TEXT = 16_384
_MAX_RECORDS = 50_000


class _TelemetryError(ValueError):
    """Telemetry is malformed or contains non-deweaponized values."""


class RubeusArm:
    """Read-only telemetry lookup that never emits indicator values."""

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
                "(offline reads over a local deweaponized AD telemetry file only; there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, refusal = telemetry_refusal(payload.get("telemetry_file"))
        if refusal:
            return _fail(spec, action, refusal)
        assert path is not None
        try:
            events, source = _load_telemetry(path)
        except _TelemetryError as exc:
            return _fail(spec, action, redact(str(exc)))
        except Exception:
            return _fail(spec, action, "invoke failed")

        if action == "telemetry":
            event_id = payload["event_id"].strip()
            match = next((item for item in events if item["event_id"] == event_id), None)
            if match is None:
                return _fail(spec, action, f"event_id {event_id!r} not found in this telemetry file")
            return _ok(spec, action, {"telemetry": _project_event(match), "source": source})

        if action == "list_telemetry":
            limit = limit_refusal(payload.get("limit"))
            if isinstance(limit, str):
                return _fail(spec, action, limit)
            category = _optional_query(payload.get("category"))
            matches = [
                item for item in events
                if category is None or item["category"].casefold() == category.casefold()
            ]
            rows = [_project_summary(item) for item in matches[:limit]]
            return _ok(
                spec, action,
                {
                    "events": rows,
                    "count": len(rows),
                    "total": len(matches),
                    "unfiltered_total": len(events),
                    "returned": len(rows),
                    "capped": len(rows) < len(matches),
                    "source": source,
                },
            )

        indicator_type = _optional_query(payload.get("indicator_type"))
        counts: dict[str, int] = {}
        all_types: set[str] = set()
        for event in events:
            for indicator in event["indicators"]:
                value = indicator["type"]
                all_types.add(value)
                if indicator_type is None or value.casefold() == indicator_type.casefold():
                    counts[value] = counts.get(value, 0) + 1
        all_rows = sorted(
            ({"type": key, "count": value} for key, value in counts.items()),
            key=lambda item: (-item["count"], item["type"].casefold()),
        )
        rows = all_rows[:MAX_RESULTS]
        return _ok(
            spec, action,
            {
                "indicators": rows,
                "indicator_types": len(rows),
                "total": len(all_rows),
                "unfiltered_total": len(all_types),
                "returned": len(rows),
                "capped": len(rows) < len(all_rows),
                "source": source,
                "note": "indicator values are intentionally omitted",
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


def _load_telemetry(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read once and delegate strict telemetry parsing to the byte API."""
    raw = _read_bounded(path)
    events, source, _provenance = parse_telemetry_bytes(
        raw, format=path.suffix.lower().lstrip(".")
    )
    return events, source


def parse_telemetry_bytes(
    raw: bytes, *, format: str
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Parse exact telemetry bytes without I/O and bind normalized events."""
    if type(raw) is not bytes:
        raise _TelemetryError("telemetry bytes must be immutable bytes")
    if type(format) is not str:
        raise _TelemetryError("telemetry format is not supported")
    if len(raw) > MAX_TELEMETRY_BYTES:
        raise _TelemetryError(
            f"telemetry exceeds the {MAX_TELEMETRY_BYTES} byte read cap"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _TelemetryError("telemetry is not strict UTF-8") from exc
    if not text.strip():
        raise _TelemetryError("telemetry file is empty")
    if format not in {"json", "jsonl"}:
        raise _TelemetryError("telemetry format is not supported")
    try:
        if format == "json":
            data = strict_json_loads(text)
            if isinstance(data, list):
                rows = data
            elif isinstance(data, dict) and set(data) == {"events"} and isinstance(data["events"], list):
                rows = data["events"]
            else:
                raise _TelemetryError("JSON telemetry must be an array or an object containing only an events array")
        else:
            rows = _parse_jsonl(text)
    except _TelemetryError:
        raise
    except StrictDataError as exc:
        raise _TelemetryError(str(exc)) from exc
    except Exception as exc:
        raise _TelemetryError(f"invalid {format} telemetry") from exc
    if len(rows) > _MAX_RECORDS:
        raise _TelemetryError(f"telemetry exceeds the {_MAX_RECORDS} record cap")
    events = _validate_events(rows)
    canonical = json.dumps(
        events,
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
    return events, _source(raw), provenance


def _parse_jsonl(text: str) -> list[Any]:
    rows: list[Any] = []
    for line_number, line in enumerate(io.StringIO(text), 1):
        if not line.strip():
            raise _TelemetryError(f"telemetry line {line_number} is blank")
        if len(rows) >= _MAX_RECORDS:
            raise _TelemetryError(f"telemetry exceeds the {_MAX_RECORDS} event cap")
        try:
            rows.append(strict_json_loads(line))
        except StrictDataError as exc:
            raise _TelemetryError(f"telemetry line {line_number}: {exc}") from exc
        except Exception as exc:
            raise _TelemetryError(f"telemetry line {line_number} is not valid JSON") from exc
    if not rows:
        raise _TelemetryError("telemetry contains no events")
    return rows


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_TELEMETRY_BYTES + 1)
    except OSError as exc:
        raise _TelemetryError("could not read telemetry") from exc
    if len(raw) > MAX_TELEMETRY_BYTES:
        raise _TelemetryError(f"telemetry exceeds the {MAX_TELEMETRY_BYTES} byte read cap")
    return raw


def _validate_events(rows: list[Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        label = f"telemetry entry {index}"
        if not isinstance(raw, dict):
            raise _TelemetryError(f"{label} is not a mapping")
        if any(not isinstance(key, str) for key in raw):
            raise _TelemetryError(f"{label} field names must be strings")
        extra = sorted(set(raw) - _EVENT_KEYS)
        missing = sorted(_EVENT_KEYS - set(raw))
        if extra:
            raise _TelemetryError(f"{label} has unknown fields: {', '.join(extra)}")
        if missing:
            raise _TelemetryError(f"{label} is missing fields: {', '.join(missing)}")
        event_id = _text(raw["event_id"], f"{label}.event_id")
        if event_id in seen:
            raise _TelemetryError(f"duplicate event_id: {event_id}")
        seen.add(event_id)
        severity = _text(raw["severity"], f"{label}.severity").casefold()
        if severity not in _SEVERITIES:
            raise _TelemetryError(f"{label}.severity is not recognized")
        indicators_raw = raw["indicators"]
        if not isinstance(indicators_raw, list) or len(indicators_raw) > _MAX_RECORDS:
            raise _TelemetryError(f"{label}.indicators must be a bounded list")
        events.append(
            {
                "event_id": event_id,
                "category": _text(raw["category"], f"{label}.category"),
                "description": _text(raw["description"], f"{label}.description"),
                "severity": severity,
                "indicators": [
                    _validate_indicator(item, f"{label}.indicators[{item_index}]")
                    for item_index, item in enumerate(indicators_raw)
                ],
            }
        )
    return events


def _validate_indicator(raw: Any, label: str) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise _TelemetryError(f"{label} is not a mapping")
    if any(not isinstance(key, str) for key in raw):
        raise _TelemetryError(f"{label} field names must be strings")
    extra = sorted(set(raw) - _INDICATOR_KEYS)
    missing = sorted(_INDICATOR_KEYS - set(raw))
    if extra:
        raise _TelemetryError(f"{label} has unknown fields: {', '.join(extra)}")
    if missing:
        raise _TelemetryError(f"{label} is missing fields: {', '.join(missing)}")
    value = _text(raw["value"], f"{label}.value")
    if value not in _REDACTED_VALUES:
        raise _TelemetryError(f"{label}.value must contain an explicit redaction sentinel")
    return {"type": _text(raw["type"], f"{label}.type")}


def _project_event(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_id": item["event_id"],
        "category": item["category"],
        "description": item["description"],
        "severity": item["severity"],
        "indicators": [{"type": value["type"]} for value in item["indicators"]],
    }


def _project_summary(item: Mapping[str, Any]) -> dict[str, str]:
    return {
        "event_id": item["event_id"],
        "category": item["category"],
        "description": item["description"],
        "severity": item["severity"],
    }


def _source(raw: bytes) -> dict[str, Any]:
    return {"kind": "operator-file", "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise _TelemetryError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
        raise _TelemetryError(f"{label} contains control characters")
    return value.strip()


def _optional_query(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def render_producer_output_bytes(output: Any) -> bytes:
    """Render the exact UTF-8 form used by this arm's output size gate."""
    return json.dumps(
        output, sort_keys=True, ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        size = len(render_producer_output_bytes(output))
    except (TypeError, ValueError, OverflowError) as exc:
        return _fail(spec, action, f"result could not be encoded: {exc}")
    if size > MAX_OUTPUT_CHARS:
        return _fail(spec, action, f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; narrow the lookup")
    return Result(True, spec.id, action, output, None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(False, spec.id, action, None, redact(str(error))[:MAX_OUTPUT_CHARS])
