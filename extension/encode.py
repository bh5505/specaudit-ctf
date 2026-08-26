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
    UnmanifestedCapabilityError,
    UnknownIdError,
)
from .envelopes import (
    RESULT_SCHEMA_ID,
    SCHEMA_VERSION,
    STATUS_COMPLETE,
    STATUS_DEGRADED,
    STATUS_FAILED,
    _CAPABILITY_ID_RE,
    parse_execution_result,
)
from .invoke_profiles import InvokeProfile, PACKAGE_NAME, PACKAGE_VERSION

RANGE_CAPABILITY_ID = "fixture.range-observe"
RANGE_TOOL = {"name": "fixture-range", "version": "1.0.0"}
RANGE_SCOPE = (
    "file:///extension/range/tf_s3_public_access",
    "file:///extension/range/tf_iam_open",
)
_RANGE_SCOPE_BY_FIXTURE = {
    "tf_s3_public_access": "file:///extension/range/tf_s3_public_access",
    "tf_iam_open": "file:///extension/range/tf_iam_open",
}
ROE_REF = "roe:synthetic-range"
_REFUSED_SCOPE = ("urn:specaudit-ctf:refused-before-dispatch",)
_REFUSED_RESERVED = {
    "timeout_ms": 30000,
    "max_output_bytes": 1048576,
    "max_tool_steps": 8,
    "max_spend": None,
}
# Match range-observe freeze reserved. Spent steps are this one capability.
_RANGE_RESERVED = {
    "timeout_ms": 60000,
    "max_output_bytes": 1048576,
    "max_tool_steps": 16,
    "max_spend": None,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def encode_invoke_result(
    result: Result,
    *,
    profile: InvokeProfile,
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    """Encode one admitted result using its authoritative action profile."""
    cap = profile.capability_id
    blob = _canonical_bytes(result.output)
    owned = result.output not in (None, "")
    identity_matches = (
        result.arm_id == profile.arm_id and result.action == profile.action
    )
    artifacts = (
        [_artifact(blob, kind="policy-report")] if owned and identity_matches else []
    )
    if result.ok and identity_matches:
        claimed = STATUS_COMPLETE
        coverage = _coverage(attempted=(cap,), complete=(cap,), required=(cap,))
        limitations: tuple[str, ...] = ()
    elif not identity_matches:
        claimed = STATUS_FAILED
        coverage = _coverage(attempted=(cap,), failed=(cap,), required=(cap,))
        limitations = ("arm result identity did not match admitted capability",)
    else:
        claimed = STATUS_FAILED
        coverage = _coverage(attempted=(cap,), failed=(cap,), required=(cap,))
        limitations = ("required arm failed",)
    candidate = _envelope(
        capability_id=cap,
        tool={"name": profile.tool_name, "version": profile.tool_version},
        authorized=profile.authorized_scope,
        touched=profile.touched_scope,
        safety_class=profile.safety_class,
        side_effects=profile.side_effects,
        reserved=_profile_reserved(profile),
        started_at=started_at,
        finished_at=finished_at,
        status=claimed,
        transport_ok=True,
        artifacts=artifacts,
        coverage=coverage,
        limitations=limitations,
        output_bytes=len(blob),
        tool_steps=1,
        cleanup_required=profile.cleanup_required,
        approval_ref=profile.approval_ref,
        roe_ref=profile.roe_ref,
    )
    return _admit(candidate)


def encode_invoke_failure(
    exc: BaseException,
    *,
    arm_id: str,
    action: str,
    profile: InvokeProfile | None,
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    """Encode a fail-closed invoke that never produced a transport Result."""
    cap = _capability_id(arm_id, action)
    if profile is not None:
        cap = profile.capability_id
    attempted: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    required: tuple[str, ...] = ()
    if isinstance(exc, (UnknownIdError, UnmanifestedCapabilityError)):
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
        limitations = ("invalid JSON arguments",)
    else:
        attempted = (cap,)
        failed = (cap,)
        required = (cap,)
        limitations = ("invoke failed",)
    candidate = _envelope(
        capability_id=cap,
        tool=_failure_tool(profile),
        authorized=(profile.authorized_scope if profile else _REFUSED_SCOPE),
        touched=(),
        safety_class=(profile.safety_class if profile else "R0"),
        side_effects=("none",),
        reserved=(
            _profile_reserved(profile) if profile is not None else _REFUSED_RESERVED
        ),
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
        cleanup_required=(profile.cleanup_required if profile else False),
        approval_ref=(profile.approval_ref if profile else None),
        roe_ref=(profile.roe_ref if profile else None),
    )
    return _admit(candidate)


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
        safety_class="R0",
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
        tool_steps=1,
        cleanup_required=False,
        approval_ref=None,
        roe_ref=ROE_REF,
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
        safety_class="R0",
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
        cleanup_required=False,
        approval_ref=None,
        roe_ref=ROE_REF,
    )
    return _admit(candidate)


def _admit(candidate: Mapping[str, Any]) -> dict[str, Any]:
    parsed = parse_execution_result(candidate)
    if parsed.result is None:
        raise ValueError("internal execution-result encoder produced an invalid envelope")
    payload = parsed.result.to_dict()
    reparsed = parse_execution_result(payload)
    if reparsed.result is None or reparsed.status != payload["status"]:
        raise ValueError("execution-result parser did not agree with encoded status")
    return payload


def _envelope(
    *,
    capability_id: str,
    tool: Mapping[str, str],
    authorized: Sequence[str],
    touched: Sequence[str],
    safety_class: str,
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
    cleanup_required: bool,
    approval_ref: str | None,
    roe_ref: str | None,
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
        "safety_class": safety_class,
        "side_effects": list(side_effects),
        "approval_ref": approval_ref,
        "roe_ref": roe_ref,
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
        "cleanup": {
            "required": cleanup_required,
            "proof_digest": None,
            "residual": False,
        },
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


def _profile_reserved(profile: InvokeProfile) -> dict[str, Any]:
    return {
        "timeout_ms": profile.timeout_ms,
        "max_output_bytes": profile.max_output_bytes,
        "max_tool_steps": profile.max_tool_steps,
        "max_spend": profile.max_spend,
    }


def _failure_tool(profile: InvokeProfile | None) -> dict[str, str]:
    if profile is not None:
        return {"name": profile.tool_name, "version": profile.tool_version}
    return {"name": PACKAGE_NAME, "version": PACKAGE_VERSION}


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
