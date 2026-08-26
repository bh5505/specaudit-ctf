"""Thin execution-result.v1 encoder. envelopes.parse_execution_result owns status."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .contract import (
    NotAnArmError,
    NotCuratedError,
    NotHeldError,
    NotInstalledError,
    Result,
    UnknownIdError,
)
from .envelopes import (
    KNOWN_CAPABILITY_IDS,
    RESULT_SCHEMA_ID,
    SCHEMA_VERSION,
    STATUS_COMPLETE,
    STATUS_DEGRADED,
    STATUS_FAILED,
    _CAPABILITY_ID_RE,
    parse_execution_result,
)

RANGE_CAPABILITY_ID = "fixture.range-observe"
RANGE_TOOL = {"name": "fixture-range", "version": "1.0.0"}
INVOKE_SCOPE = ("file:///extension/range/tf_s3_public_access",)
RANGE_SCOPE = (
    "file:///extension/range/tf_s3_public_access",
    "file:///extension/range/tf_iam_open",
)
_RANGE_SCOPE_BY_FIXTURE = {
    "tf_s3_public_access": "file:///extension/range/tf_s3_public_access",
    "tf_iam_open": "file:///extension/range/tf_iam_open",
}
ROE_REF = "roe:synthetic-range"
_INVOKE_RESERVED = {
    "timeout_ms": 30000,
    "max_output_bytes": 1048576,
    "max_tool_steps": 8,
    "max_spend": None,
}
_RANGE_RESERVED = {
    "timeout_ms": 60000,
    "max_output_bytes": 1048576,
    "max_tool_steps": 64,
    "max_spend": None,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def encode_invoke_result(
    result: Result,
    *,
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    """Encode a completed transport Result. Caller exit code stays Result.ok."""
    cap = _capability_id(result.arm_id, result.action)
    blob = _canonical_bytes(result.output)
    if result.ok:
        claimed = STATUS_COMPLETE
        coverage = _coverage(attempted=(cap,), complete=(cap,), required=(cap,))
        artifacts = [_artifact(blob, kind="scan-report")]
        limitations: tuple[str, ...] = ()
    else:
        claimed = STATUS_FAILED
        coverage = _coverage(attempted=(cap,), failed=(cap,), required=(cap,))
        artifacts = [_artifact(blob, kind="scan-report")] if result.output not in (None, "") else []
        limitations = ("required arm failed",)
    candidate = _envelope(
        capability_id=cap,
        tool=_tool(result.arm_id),
        authorized=INVOKE_SCOPE,
        touched=INVOKE_SCOPE,
        side_effects=("local-read",),
        reserved=_INVOKE_RESERVED,
        started_at=started_at,
        finished_at=finished_at,
        status=claimed,
        transport_ok=True,
        artifacts=artifacts,
        coverage=coverage,
        limitations=limitations,
        output_bytes=len(blob),
        tool_steps=1,
    )
    return _admit(candidate, extra_known=(cap,))


def encode_invoke_failure(
    exc: BaseException,
    *,
    arm_id: str,
    action: str,
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    """Encode a fail-closed invoke that never produced a transport Result."""
    cap = _capability_id(arm_id, action)
    extra: tuple[str, ...] = () if isinstance(exc, UnknownIdError) else (cap,)
    attempted: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    required: tuple[str, ...] = ()
    if isinstance(exc, UnknownIdError):
        limitations = ("unknown capability",)
    elif isinstance(exc, NotHeldError):
        unsupported = (cap,)
        limitations = ("held capability is never invocable",)
    elif isinstance(exc, NotAnArmError) and exc.kind == "methodology-only":
        unsupported = (cap,)
        limitations = ("methodology-only is never invocable",)
    elif isinstance(exc, NotInstalledError):
        attempted = (cap,)
        skipped = (cap,)
        required = (cap,)
        limitations = ("arm is not installed",)
    elif isinstance(exc, NotCuratedError):
        unsupported = (cap,)
        required = (cap,)
        limitations = ("arm is not curated",)
    elif isinstance(exc, NotAnArmError):
        unsupported = (cap,)
        required = (cap,)
        limitations = (f"{arm_id} is {exc.kind}, not an arm",)
    elif _is_invalid_args(exc):
        extra = (cap,)
        limitations = ("invalid JSON arguments",)
    else:
        attempted = (cap,)
        failed = (cap,)
        required = (cap,)
        limitations = ("invoke failed",)
    candidate = _envelope(
        capability_id=cap,
        tool=_tool(arm_id),
        authorized=INVOKE_SCOPE,
        touched=(),
        side_effects=("none",),
        reserved=_INVOKE_RESERVED,
        started_at=started_at,
        finished_at=finished_at,
        status=STATUS_FAILED,
        transport_ok=False,
        artifacts=[],
        coverage=_coverage(
            attempted=attempted,
            skipped=skipped,
            unsupported=unsupported,
            failed=failed,
            required=required,
        ),
        limitations=limitations,
        output_bytes=0,
        tool_steps=0,
    )
    return _admit(candidate, extra_known=extra)


def encode_range_document(
    document: Mapping[str, Any],
    *,
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    """Wrap range.lifecycle.v2 as coverage input. Inner ok is not outer status."""
    claimed = document.get("status")
    if claimed not in {STATUS_COMPLETE, STATUS_DEGRADED, STATUS_FAILED}:
        claimed = STATUS_FAILED
    inner = document.get("coverage") if isinstance(document.get("coverage"), dict) else {}
    attempted = _str_tuple(inner.get("attempted"))
    complete = _str_tuple(inner.get("complete"))
    skipped = _str_tuple(inner.get("skipped"))
    failed = _str_tuple(inner.get("error"))
    limitations: list[str] = []
    if skipped:
        limitations.append("optional arm is not installed")
    if failed:
        limitations.append("arm status=error")
    if claimed == STATUS_FAILED and not limitations:
        limitations.append("range lifecycle did not complete")
    blob = _canonical_bytes(dict(document))
    candidate = _envelope(
        capability_id=RANGE_CAPABILITY_ID,
        tool=RANGE_TOOL,
        authorized=RANGE_SCOPE,
        touched=_range_touched(document),
        side_effects=("local-read",),
        reserved=_RANGE_RESERVED,
        started_at=started_at,
        finished_at=finished_at,
        status=claimed,
        transport_ok=True,
        artifacts=[_artifact(blob, kind="range-report")],
        coverage=_coverage(
            attempted=attempted,
            complete=complete,
            skipped=skipped,
            failed=failed,
        ),
        limitations=tuple(limitations),
        output_bytes=len(blob),
        tool_steps=max(1, len(attempted)),
    )
    return _admit(candidate)


def encode_range_failure(
    exc: BaseException,
    *,
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    candidate = _envelope(
        capability_id=RANGE_CAPABILITY_ID,
        tool=RANGE_TOOL,
        authorized=RANGE_SCOPE,
        touched=(),
        side_effects=("none",),
        reserved=_RANGE_RESERVED,
        started_at=started_at,
        finished_at=finished_at,
        status=STATUS_FAILED,
        transport_ok=False,
        artifacts=[],
        coverage=_coverage(),
        limitations=("range run failed",),
        output_bytes=0,
        tool_steps=0,
    )
    return _admit(candidate)


def _admit(
    candidate: Mapping[str, Any], *, extra_known: Sequence[str] = ()
) -> dict[str, Any]:
    known = tuple(dict.fromkeys([*KNOWN_CAPABILITY_IDS, *extra_known]))
    parsed = parse_execution_result(candidate, known_ids=known)
    if parsed.result is not None:
        return parsed.result.to_dict()
    payload = dict(candidate)
    payload["status"] = STATUS_FAILED
    return payload


def _envelope(
    *,
    capability_id: str,
    tool: Mapping[str, str],
    authorized: Sequence[str],
    touched: Sequence[str],
    side_effects: Sequence[str],
    reserved: Mapping[str, Any],
    started_at: str,
    finished_at: str,
    status: str,
    transport_ok: bool,
    artifacts: Sequence[Mapping[str, str]],
    coverage: Mapping[str, list[str]],
    limitations: Sequence[str],
    output_bytes: int,
    tool_steps: int,
) -> dict[str, Any]:
    finished = finished_at if finished_at >= started_at else started_at
    return {
        "schema": RESULT_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "capability_id": capability_id,
        "tool": {"name": tool["name"], "version": tool["version"]},
        "scope": {
            "authorized": list(authorized),
            "touched": list(dict.fromkeys(touched)),
        },
        "safety_class": "R0",
        "side_effects": list(side_effects),
        "approval_ref": None,
        "roe_ref": ROE_REF,
        "budget": {
            "reserved": {
                "timeout_ms": reserved["timeout_ms"],
                "max_output_bytes": reserved["max_output_bytes"],
                "max_tool_steps": reserved["max_tool_steps"],
                "max_spend": reserved["max_spend"],
            },
            "spent": {
                "elapsed_ms": _elapsed_ms(started_at, finished),
                "output_bytes": max(output_bytes, 0),
                "tool_steps": max(tool_steps, 0),
                "spend": 0,
            },
        },
        "started_at": started_at,
        "finished_at": finished,
        "status": status,
        "transport_ok": transport_ok,
        "artifacts": [dict(item) for item in artifacts],
        "coverage": dict(coverage),
        "cleanup": {"required": False, "proof_digest": None, "residual": False},
        "limitations": list(dict.fromkeys(item for item in limitations if item)),
    }


def _coverage(
    *,
    attempted: Sequence[str] = (),
    complete: Sequence[str] = (),
    skipped: Sequence[str] = (),
    unsupported: Sequence[str] = (),
    failed: Sequence[str] = (),
    required: Sequence[str] = (),
) -> dict[str, list[str]]:
    return {
        "attempted": _unique(attempted),
        "complete": _unique(complete),
        "skipped": _unique(skipped),
        "unsupported": _unique(unsupported),
        "failed": _unique(failed),
        "required": _unique(required),
    }


def _artifact(blob: bytes, *, kind: str) -> dict[str, str]:
    return {
        "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
        "kind": kind,
        "redaction": "credentials-stripped",
    }


def _capability_id(arm_id: str, action: str) -> str:
    candidate = f"{arm_id}.{action}"
    if _CAPABILITY_ID_RE.match(candidate):
        return candidate
    return "unknown.capability"


def _tool(arm_id: str) -> dict[str, str]:
    name = arm_id if isinstance(arm_id, str) and arm_id else "unknown"
    return {"name": name, "version": "0.0.0"}


def _range_touched(document: Mapping[str, Any]) -> tuple[str, ...]:
    fixtures = document.get("fixtures")
    if not isinstance(fixtures, list):
        return RANGE_SCOPE
    touched: list[str] = []
    for row in fixtures:
        if not isinstance(row, dict):
            continue
        uri = _RANGE_SCOPE_BY_FIXTURE.get(str(row.get("id") or ""))
        if uri:
            touched.append(uri)
    return tuple(dict.fromkeys(touched)) or RANGE_SCOPE


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _elapsed_ms(started_at: str, finished_at: str) -> int:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        start = datetime.strptime(started_at, fmt)
        finish = datetime.strptime(finished_at, fmt)
    except ValueError:
        return 0
    delta = int((finish - start).total_seconds() * 1000)
    return max(delta, 0)


def _is_invalid_args(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "invalid json" in text or "json arguments" in text


def _str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item)


def _unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(item for item in values if item))
