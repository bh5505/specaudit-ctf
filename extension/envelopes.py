"""Fail-closed parse/validate for CTF capability-manifest and execution-result v1.

CLI JSON and stdio MCP are encodings of this typed contract. This module does
not spawn arms, open sockets, or rewrite live invoke / run_range output.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

MANIFEST_SCHEMA_ID = "specaudit.ctf.capability.manifest.v1"
RESULT_SCHEMA_ID = "specaudit.ctf.execution-result.v1"
SCHEMA_VERSION = 1

STATUS_COMPLETE = "complete"
STATUS_DEGRADED = "degraded"
STATUS_FAILED = "failed"
ALLOWED_STATUSES = (STATUS_COMPLETE, STATUS_DEGRADED, STATUS_FAILED)

TIER_RESEARCH = "research"
TIER_EXPERIMENTAL = "experimental"
TIER_MAINTAINED = "maintained"
TIER_HELD = "held"
ALLOWED_TIERS = frozenset(
    {TIER_RESEARCH, TIER_EXPERIMENTAL, TIER_MAINTAINED, TIER_HELD}
)

KIND_ARM = "arm"
KIND_HEAD = "head"
KIND_RANGE = "range"
KIND_METHODOLOGY_ONLY = "methodology-only"
ALLOWED_KINDS = frozenset(
    {KIND_ARM, KIND_HEAD, KIND_RANGE, KIND_METHODOLOGY_ONLY}
)
DISPATCHABLE_KINDS = frozenset({KIND_ARM, KIND_RANGE})

ALLOWED_PROTOCOLS = frozenset({"cli-json", "mcp-stdio"})
ALLOWED_SAFETY = frozenset({"R0", "R1", "R2", "R3"})
ALLOWED_SIDE_EFFECTS = frozenset(
    {
        "none",
        "local-read",
        "local-write",
        "subprocess",
        "network-egress",
        "cloud-read",
        "cloud-mutate",
    }
)
READ_TIER_EFFECTS = frozenset({"none", "local-read"})
BLANKET_SCOPE = frozenset({"*", "0.0.0.0/0", "::/0"})
CLEANUP_PROOFS = frozenset({"none", "artifact-digest"})

REASON_UNKNOWN_SCHEMA = "unknown-schema"
REASON_UNKNOWN_CAPABILITY = "unknown-capability"
REASON_UNKNOWN_TIER = "unknown-tier"
REASON_METHODOLOGY_ONLY = "methodology-only"
REASON_HELD = "held"
REASON_REQUIRED_FAILED = "required-step-failed"
REASON_REQUIRED_SKIPPED = "required-step-skipped"
REASON_UNOWNED_EVIDENCE = "unowned-evidence"
REASON_CLEANUP_UNPROVEN = "cleanup-unproven"
REASON_OPTIONAL_LIMITATION = "optional-limitation"
REASON_BUDGET_BREACH = "budget-breach"
REASON_BLANKET_SCOPE = "blanket-scope"
REASON_MISSING_APPROVAL = "missing-approval"
REASON_INVALID_JSON = "invalid-json"
REASON_INVALID_ENVELOPE = "invalid-envelope"

_FAILED_REASONS = frozenset(
    {
        REASON_UNKNOWN_SCHEMA,
        REASON_UNKNOWN_CAPABILITY,
        REASON_UNKNOWN_TIER,
        REASON_METHODOLOGY_ONLY,
        REASON_HELD,
        REASON_REQUIRED_FAILED,
        REASON_REQUIRED_SKIPPED,
        REASON_UNOWNED_EVIDENCE,
        REASON_CLEANUP_UNPROVEN,
        REASON_BUDGET_BREACH,
        REASON_BLANKET_SCOPE,
        REASON_MISSING_APPROVAL,
        REASON_INVALID_JSON,
        REASON_INVALID_ENVELOPE,
    }
)

# Synthetic packet-1 freeze. Survey catalog rows are not automatically
# invocable; methodology-only and held ids are known so they fail closed
# without being confused with an unknown id.
METHODOLOGY_ONLY_IDS = frozenset({"vulnhunter.extract"})
HELD_IDS = frozenset({"burp-mcp.list_tools"})
KNOWN_CAPABILITY_IDS = frozenset(
    {
        "fixture.local-read",
        "fixture.range-observe",
        "fixture.cleanup-write",
        *METHODOLOGY_ONLY_IDS,
        *HELD_IDS,
    }
)

_CAPABILITY_ID_RE = re.compile(
    r"^[a-z][a-z0-9]*(-[a-z0-9]+)*(\.[a-z][a-z0-9_]*(-[a-z0-9_]+)*)+$"
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_ATTEMPT_ID_RE = re.compile(r"^attempt-[0-9a-f]{64}$")

_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "capability_id",
        "tier",
        "kind",
        "tool",
        "protocols",
        "safety_class",
        "side_effects",
        "default_off",
        "synthetic_only",
        "authorized_scope",
        "approval_ref",
        "roe_ref",
        "budget",
        "cleanup",
        "redaction",
    }
)
_RESULT_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "capability_id",
        "tool",
        "attempt_id",
        "scope",
        "safety_class",
        "side_effects",
        "approval_ref",
        "roe_ref",
        "budget",
        "started_at",
        "finished_at",
        "status",
        "transport_ok",
        "artifacts",
        "coverage",
        "cleanup",
        "limitations",
    }
)
_STATUS_RANK = {
    STATUS_FAILED: 0,
    STATUS_DEGRADED: 1,
    STATUS_COMPLETE: 2,
}

JsonSource = Path | str | Mapping[str, Any]
Dispatcher = Callable[["CapabilityManifest"], Any]


class EnvelopeError(Exception):
    """Fail-closed envelope error (malformed source when raising is required)."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "version": self.version}
        if self.digest is not None:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True)
class BudgetLimit:
    timeout_ms: int
    max_output_bytes: int
    max_tool_steps: int
    max_spend: float | int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timeout_ms": self.timeout_ms,
            "max_output_bytes": self.max_output_bytes,
            "max_tool_steps": self.max_tool_steps,
            "max_spend": self.max_spend,
        }


@dataclass(frozen=True)
class CleanupPolicy:
    required: bool
    proof: str

    def to_dict(self) -> dict[str, Any]:
        return {"required": self.required, "proof": self.proof}


@dataclass(frozen=True)
class RedactionPolicy:
    fields: tuple[str, ...]
    env: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"fields": list(self.fields), "env": list(self.env)}


@dataclass(frozen=True)
class CapabilityManifest:
    schema: str
    schema_version: int
    capability_id: str
    tier: str
    kind: str
    tool: ToolSpec
    protocols: tuple[str, ...]
    safety_class: str
    side_effects: tuple[str, ...]
    default_off: bool
    synthetic_only: bool
    authorized_scope: tuple[str, ...]
    approval_ref: str | None
    roe_ref: str | None
    budget: BudgetLimit
    cleanup: CleanupPolicy
    redaction: RedactionPolicy

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "capability_id": self.capability_id,
            "tier": self.tier,
            "kind": self.kind,
            "tool": self.tool.to_dict(),
            "protocols": list(self.protocols),
            "safety_class": self.safety_class,
            "side_effects": list(self.side_effects),
            "default_off": self.default_off,
            "synthetic_only": self.synthetic_only,
            "authorized_scope": list(self.authorized_scope),
            "approval_ref": self.approval_ref,
            "roe_ref": self.roe_ref,
            "budget": self.budget.to_dict(),
            "cleanup": self.cleanup.to_dict(),
            "redaction": self.redaction.to_dict(),
        }


@dataclass(frozen=True)
class ScopeSpec:
    authorized: tuple[str, ...]
    touched: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorized": list(self.authorized),
            "touched": list(self.touched),
        }


@dataclass(frozen=True)
class SpentBudget:
    elapsed_ms: int
    output_bytes: int
    tool_steps: int
    spend: float | int

    def to_dict(self) -> dict[str, Any]:
        return {
            "elapsed_ms": self.elapsed_ms,
            "output_bytes": self.output_bytes,
            "tool_steps": self.tool_steps,
            "spend": self.spend,
        }


@dataclass(frozen=True)
class ResultBudget:
    reserved: BudgetLimit
    spent: SpentBudget

    def to_dict(self) -> dict[str, Any]:
        return {
            "reserved": self.reserved.to_dict(),
            "spent": self.spent.to_dict(),
        }


@dataclass(frozen=True)
class ArtifactSpec:
    digest: str
    kind: str
    redaction: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "kind": self.kind,
            "redaction": self.redaction,
        }


@dataclass(frozen=True)
class Coverage:
    attempted: tuple[str, ...]
    complete: tuple[str, ...]
    skipped: tuple[str, ...]
    unsupported: tuple[str, ...]
    failed: tuple[str, ...]
    required: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempted": list(self.attempted),
            "complete": list(self.complete),
            "skipped": list(self.skipped),
            "unsupported": list(self.unsupported),
            "failed": list(self.failed),
            "required": list(self.required),
        }


@dataclass(frozen=True)
class CleanupResult:
    required: bool
    proof_digest: str | None
    residual: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "proof_digest": self.proof_digest,
            "residual": self.residual,
        }


@dataclass(frozen=True)
class ExecutionResult:
    schema: str
    schema_version: int
    capability_id: str
    tool: ToolSpec
    scope: ScopeSpec
    safety_class: str
    side_effects: tuple[str, ...]
    approval_ref: str | None
    roe_ref: str | None
    budget: ResultBudget
    started_at: str
    finished_at: str
    status: str
    transport_ok: bool
    artifacts: tuple[ArtifactSpec, ...]
    coverage: Coverage
    cleanup: CleanupResult
    limitations: tuple[str, ...]
    attempt_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "capability_id": self.capability_id,
            "tool": self.tool.to_dict(),
        }
        if self.attempt_id is not None:
            payload["attempt_id"] = self.attempt_id
        payload.update(
            {
                "scope": self.scope.to_dict(),
                "safety_class": self.safety_class,
                "side_effects": list(self.side_effects),
                "approval_ref": self.approval_ref,
                "roe_ref": self.roe_ref,
                "budget": self.budget.to_dict(),
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "status": self.status,
                "transport_ok": self.transport_ok,
                "artifacts": [item.to_dict() for item in self.artifacts],
                "coverage": self.coverage.to_dict(),
                "cleanup": self.cleanup.to_dict(),
                "limitations": list(self.limitations),
            }
        )
        return payload


@dataclass(frozen=True)
class ManifestParse:
    schema_ok: bool
    dispatch_allowed: bool
    reasons: tuple[str, ...]
    manifest: CapabilityManifest | None


@dataclass(frozen=True)
class ResultParse:
    schema_ok: bool
    status: str
    reasons: tuple[str, ...]
    result: ExecutionResult | None


def parse_capability_manifest(
    source: JsonSource,
    *,
    known_ids: Sequence[str] | None = None,
) -> ManifestParse:
    """Parse a capability manifest. Never dispatches."""
    payload, load_reasons = _read_mapping(source)
    if payload is None:
        return ManifestParse(
            schema_ok=False,
            dispatch_allowed=False,
            reasons=_unique(load_reasons),
            manifest=None,
        )
    known = frozenset(known_ids) if known_ids is not None else KNOWN_CAPABILITY_IDS
    struct_reasons = _validate_manifest_structure(payload)
    schema_ok = not struct_reasons
    gate_reasons = list(struct_reasons)
    capability_id = payload.get("capability_id")
    kind = payload.get("kind")
    tier = payload.get("tier")
    if isinstance(capability_id, str) and capability_id not in known:
        gate_reasons.append(REASON_UNKNOWN_CAPABILITY)
    if kind == KIND_METHODOLOGY_ONLY or (
        isinstance(capability_id, str) and capability_id in METHODOLOGY_ONLY_IDS
    ):
        gate_reasons.append(REASON_METHODOLOGY_ONLY)
    if tier == TIER_HELD or (
        isinstance(capability_id, str) and capability_id in HELD_IDS
    ):
        gate_reasons.append(REASON_HELD)
    dispatch_allowed = (
        schema_ok
        and isinstance(capability_id, str)
        and capability_id in known
        and kind in DISPATCHABLE_KINDS
        and tier in ALLOWED_TIERS
        and tier != TIER_HELD
        and kind != KIND_METHODOLOGY_ONLY
        and REASON_BLANKET_SCOPE not in gate_reasons
    )
    manifest = _build_manifest(payload) if schema_ok else None
    return ManifestParse(
        schema_ok=schema_ok,
        dispatch_allowed=dispatch_allowed,
        reasons=_unique(gate_reasons),
        manifest=manifest,
    )


def parse_execution_result(
    source: JsonSource,
    *,
    known_ids: Sequence[str] | None = None,
) -> ResultParse:
    """Parse an execution-result envelope. Never dispatches."""
    payload, load_reasons = _read_mapping(source)
    if payload is None:
        return ResultParse(
            schema_ok=False,
            status=STATUS_FAILED,
            reasons=_unique(load_reasons),
            result=None,
        )
    known = frozenset(known_ids) if known_ids is not None else KNOWN_CAPABILITY_IDS
    struct_reasons = _validate_result_structure(payload)
    schema_ok = not struct_reasons
    reasons = list(struct_reasons)
    capability_id = payload.get("capability_id")
    if isinstance(capability_id, str):
        if capability_id not in known:
            reasons.append(REASON_UNKNOWN_CAPABILITY)
        if capability_id in METHODOLOGY_ONLY_IDS:
            reasons.append(REASON_METHODOLOGY_ONLY)
        if capability_id in HELD_IDS:
            reasons.append(REASON_HELD)
    reasons.extend(_semantic_result_reasons(payload))
    reasons = list(_unique(reasons))
    derived = _derive_status(reasons, payload)
    claimed = payload.get("status") if isinstance(payload.get("status"), str) else None
    status = _clamp_status(claimed, derived)
    result = _build_result(payload, status=status) if schema_ok else None
    return ResultParse(
        schema_ok=schema_ok,
        status=status,
        reasons=tuple(reasons),
        result=result,
    )


def gate_dispatch(
    source: JsonSource,
    dispatcher: Dispatcher | None = None,
    *,
    known_ids: Sequence[str] | None = None,
) -> ManifestParse:
    """Admit a manifest for invoke. Dispatcher runs only when dispatch is allowed."""
    parsed = parse_capability_manifest(source, known_ids=known_ids)
    if parsed.dispatch_allowed and dispatcher is not None and parsed.manifest is not None:
        dispatcher(parsed.manifest)
    return parsed


def _read_mapping(
    source: JsonSource,
) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    if isinstance(source, Mapping):
        return dict(source), ()
    if isinstance(source, Path):
        try:
            text = source.read_text(encoding="utf-8")
        except OSError:
            return None, (REASON_INVALID_ENVELOPE,)
        return _loads_object(text)
    if isinstance(source, str):
        return _loads_object(source)
    return None, (REASON_INVALID_ENVELOPE,)


def _loads_object(text: str) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None, (REASON_INVALID_JSON,)
    if not isinstance(data, dict):
        return None, (REASON_INVALID_ENVELOPE,)
    return data, ()


def _validate_manifest_structure(payload: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    extra = set(payload) - _MANIFEST_KEYS
    if extra:
        reasons.append(REASON_INVALID_ENVELOPE)
    if payload.get("schema") != MANIFEST_SCHEMA_ID or not _is_int(
        payload.get("schema_version")
    ) or payload.get("schema_version") != SCHEMA_VERSION:
        reasons.append(REASON_UNKNOWN_SCHEMA)
    capability_id = payload.get("capability_id")
    if not isinstance(capability_id, str) or not _CAPABILITY_ID_RE.match(capability_id):
        reasons.append(REASON_INVALID_ENVELOPE)
    tier = payload.get("tier")
    if not isinstance(tier, str) or tier not in ALLOWED_TIERS:
        reasons.append(REASON_UNKNOWN_TIER)
    kind = payload.get("kind")
    if kind not in ALLOWED_KINDS:
        reasons.append(REASON_INVALID_ENVELOPE)
    reasons.extend(_validate_tool(payload.get("tool")))
    reasons.extend(_validate_str_enum_list(payload.get("protocols"), ALLOWED_PROTOCOLS))
    if payload.get("safety_class") not in ALLOWED_SAFETY:
        reasons.append(REASON_INVALID_ENVELOPE)
    reasons.extend(_validate_side_effects(payload.get("side_effects")))
    if not isinstance(payload.get("default_off"), bool) or not isinstance(
        payload.get("synthetic_only"), bool
    ):
        reasons.append(REASON_INVALID_ENVELOPE)
    reasons.extend(_validate_scope_list(payload.get("authorized_scope"), min_items=1))
    reasons.extend(_validate_optional_ref(payload.get("approval_ref")))
    reasons.extend(_validate_optional_ref(payload.get("roe_ref")))
    reasons.extend(_validate_budget_limit(payload.get("budget")))
    cleanup = payload.get("cleanup")
    if not isinstance(cleanup, dict):
        reasons.append(REASON_INVALID_ENVELOPE)
    else:
        if set(cleanup) - {"required", "proof"}:
            reasons.append(REASON_INVALID_ENVELOPE)
        if not isinstance(cleanup.get("required"), bool):
            reasons.append(REASON_INVALID_ENVELOPE)
        if cleanup.get("proof") not in CLEANUP_PROOFS:
            reasons.append(REASON_INVALID_ENVELOPE)
    reasons.extend(_validate_redaction(payload.get("redaction")))
    return reasons


def _validate_result_structure(payload: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    extra = set(payload) - _RESULT_KEYS
    if extra:
        reasons.append(REASON_INVALID_ENVELOPE)
    if payload.get("schema") != RESULT_SCHEMA_ID or not _is_int(
        payload.get("schema_version")
    ) or payload.get("schema_version") != SCHEMA_VERSION:
        reasons.append(REASON_UNKNOWN_SCHEMA)
    capability_id = payload.get("capability_id")
    if not isinstance(capability_id, str) or not _CAPABILITY_ID_RE.match(capability_id):
        reasons.append(REASON_INVALID_ENVELOPE)
    reasons.extend(_validate_tool(payload.get("tool")))
    if "attempt_id" in payload:
        attempt_id = payload.get("attempt_id")
        if not isinstance(attempt_id, str) or not _ATTEMPT_ID_RE.match(attempt_id):
            reasons.append(REASON_INVALID_ENVELOPE)
    scope = payload.get("scope")
    if not isinstance(scope, dict) or set(scope) - {"authorized", "touched"}:
        reasons.append(REASON_INVALID_ENVELOPE)
    else:
        reasons.extend(_validate_scope_list(scope.get("authorized"), min_items=1))
        reasons.extend(_validate_scope_list(scope.get("touched"), min_items=0))
    if payload.get("safety_class") not in ALLOWED_SAFETY:
        reasons.append(REASON_INVALID_ENVELOPE)
    reasons.extend(_validate_side_effects(payload.get("side_effects")))
    reasons.extend(_validate_optional_ref(payload.get("approval_ref")))
    reasons.extend(_validate_optional_ref(payload.get("roe_ref")))
    budget = payload.get("budget")
    if not isinstance(budget, dict) or set(budget) - {"reserved", "spent"}:
        reasons.append(REASON_INVALID_ENVELOPE)
    else:
        reasons.extend(_validate_budget_limit(budget.get("reserved")))
        reasons.extend(_validate_spent(budget.get("spent")))
    started = payload.get("started_at")
    finished = payload.get("finished_at")
    if not isinstance(started, str) or not _TIMESTAMP_RE.match(started):
        reasons.append(REASON_INVALID_ENVELOPE)
    if not isinstance(finished, str) or not _TIMESTAMP_RE.match(finished):
        reasons.append(REASON_INVALID_ENVELOPE)
    if (
        isinstance(started, str)
        and isinstance(finished, str)
        and finished < started
    ):
        reasons.append(REASON_INVALID_ENVELOPE)
    if payload.get("status") not in ALLOWED_STATUSES:
        reasons.append(REASON_INVALID_ENVELOPE)
    if not isinstance(payload.get("transport_ok"), bool):
        reasons.append(REASON_INVALID_ENVELOPE)
    reasons.extend(_validate_artifacts(payload.get("artifacts")))
    reasons.extend(_validate_coverage(payload.get("coverage")))
    cleanup = payload.get("cleanup")
    if not isinstance(cleanup, dict) or set(cleanup) - {
        "required",
        "proof_digest",
        "residual",
    }:
        reasons.append(REASON_INVALID_ENVELOPE)
    else:
        if not isinstance(cleanup.get("required"), bool) or not isinstance(
            cleanup.get("residual"), bool
        ):
            reasons.append(REASON_INVALID_ENVELOPE)
        proof = cleanup.get("proof_digest")
        if proof is not None and (
            not isinstance(proof, str) or not _DIGEST_RE.match(proof)
        ):
            reasons.append(REASON_INVALID_ENVELOPE)
    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or any(
        not isinstance(item, str) or not item for item in limitations
    ):
        reasons.append(REASON_INVALID_ENVELOPE)
    return reasons


def _semantic_result_reasons(payload: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    coverage = payload.get("coverage") if isinstance(payload.get("coverage"), dict) else {}
    required = _str_tuple(coverage.get("required"))
    complete = _str_tuple(coverage.get("complete"))
    skipped = _str_tuple(coverage.get("skipped"))
    failed = _str_tuple(coverage.get("failed"))
    unsupported = _str_tuple(coverage.get("unsupported"))
    for item in required:
        if item in failed:
            reasons.append(REASON_REQUIRED_FAILED)
        elif item in skipped:
            reasons.append(REASON_REQUIRED_SKIPPED)
        elif item in unsupported:
            reasons.append(REASON_REQUIRED_FAILED)
        elif item not in complete:
            reasons.append(REASON_REQUIRED_FAILED)
    cleanup = payload.get("cleanup") if isinstance(payload.get("cleanup"), dict) else {}
    if cleanup.get("required") is True:
        proof = cleanup.get("proof_digest")
        if not isinstance(proof, str) or not _DIGEST_RE.match(proof):
            reasons.append(REASON_CLEANUP_UNPROVEN)
    artifacts = payload.get("artifacts")
    owned = isinstance(artifacts, list) and any(
        isinstance(item, dict)
        and isinstance(item.get("digest"), str)
        and _DIGEST_RE.match(item["digest"])
        for item in artifacts
    )
    claimed = payload.get("status")
    substantive = bool(complete) or claimed == STATUS_COMPLETE
    if substantive and not owned:
        reasons.append(REASON_UNOWNED_EVIDENCE)
    if _budget_breach(payload):
        reasons.append(REASON_BUDGET_BREACH)
    if _is_dispatch_class(payload) and _missing_approval(payload):
        reasons.append(REASON_MISSING_APPROVAL)
    scope = payload.get("scope") if isinstance(payload.get("scope"), dict) else {}
    for item in list(scope.get("authorized") or []) + list(scope.get("touched") or []):
        if item in BLANKET_SCOPE:
            reasons.append(REASON_BLANKET_SCOPE)
            break
    optional_gap = bool(
        (set(skipped) | set(unsupported) | set(failed)) - set(required)
    ) or (
        isinstance(payload.get("limitations"), list) and bool(payload.get("limitations"))
    )
    if optional_gap and not any(code in _FAILED_REASONS for code in reasons):
        # Stamped after failed reasons are known; derivation also inspects coverage.
        reasons.append(REASON_OPTIONAL_LIMITATION)
    return reasons


def _derive_status(reasons: Sequence[str], payload: Mapping[str, Any]) -> str:
    if any(code in _FAILED_REASONS for code in reasons):
        return STATUS_FAILED
    coverage = payload.get("coverage") if isinstance(payload.get("coverage"), dict) else {}
    skipped = _str_tuple(coverage.get("skipped"))
    unsupported = _str_tuple(coverage.get("unsupported"))
    failed = _str_tuple(coverage.get("failed"))
    limitations = payload.get("limitations")
    if (
        skipped
        or unsupported
        or failed
        or (isinstance(limitations, list) and limitations)
        or REASON_OPTIONAL_LIMITATION in reasons
    ):
        return STATUS_DEGRADED
    return STATUS_COMPLETE


def _clamp_status(claimed: str | None, derived: str) -> str:
    if claimed not in _STATUS_RANK:
        return STATUS_FAILED
    if _STATUS_RANK[derived] < _STATUS_RANK[claimed]:
        return derived
    return claimed


def _validate_tool(tool: Any) -> list[str]:
    if not isinstance(tool, dict):
        return [REASON_INVALID_ENVELOPE]
    allowed = {"name", "version", "digest"}
    if set(tool) - allowed or "name" not in tool or "version" not in tool:
        return [REASON_INVALID_ENVELOPE]
    if not isinstance(tool.get("name"), str) or not tool["name"]:
        return [REASON_INVALID_ENVELOPE]
    if not isinstance(tool.get("version"), str) or not tool["version"]:
        return [REASON_INVALID_ENVELOPE]
    if "digest" in tool:
        digest = tool.get("digest")
        if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
            return [REASON_INVALID_ENVELOPE]
    return []


def _validate_str_enum_list(value: Any, allowed: frozenset[str]) -> list[str]:
    if not isinstance(value, list) or not value:
        return [REASON_INVALID_ENVELOPE]
    if len(value) != len(set(value)):
        return [REASON_INVALID_ENVELOPE]
    for item in value:
        if not isinstance(item, str) or item not in allowed:
            return [REASON_INVALID_ENVELOPE]
    return []


def _validate_side_effects(value: Any) -> list[str]:
    reasons = _validate_str_enum_list(value, ALLOWED_SIDE_EFFECTS)
    if reasons:
        return reasons
    assert isinstance(value, list)
    if "none" in value and value != ["none"]:
        return [REASON_INVALID_ENVELOPE]
    return []


def _validate_scope_list(value: Any, *, min_items: int) -> list[str]:
    if not isinstance(value, list) or len(value) < min_items:
        return [REASON_INVALID_ENVELOPE]
    if len(value) != len(set(value)):
        return [REASON_INVALID_ENVELOPE]
    reasons: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            reasons.append(REASON_INVALID_ENVELOPE)
            continue
        if item in BLANKET_SCOPE:
            reasons.append(REASON_BLANKET_SCOPE)
    return reasons


def _validate_optional_ref(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, str) or not value:
        return [REASON_INVALID_ENVELOPE]
    return []


def _validate_budget_limit(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return [REASON_INVALID_ENVELOPE]
    required = {"timeout_ms", "max_output_bytes", "max_tool_steps", "max_spend"}
    if set(value) != required:
        return [REASON_INVALID_ENVELOPE]
    for key in ("timeout_ms", "max_output_bytes", "max_tool_steps"):
        if not _is_int(value.get(key)) or value[key] < 1:
            return [REASON_INVALID_ENVELOPE]
    spend = value.get("max_spend")
    if spend is not None and not (
        isinstance(spend, (int, float)) and not isinstance(spend, bool) and spend >= 0
    ):
        return [REASON_INVALID_ENVELOPE]
    return []


def _validate_spent(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return [REASON_INVALID_ENVELOPE]
    required = {"elapsed_ms", "output_bytes", "tool_steps", "spend"}
    if set(value) != required:
        return [REASON_INVALID_ENVELOPE]
    for key in ("elapsed_ms", "output_bytes", "tool_steps"):
        if not _is_int(value.get(key)) or value[key] < 0:
            return [REASON_INVALID_ENVELOPE]
    spend = value.get("spend")
    if not (
        isinstance(spend, (int, float)) and not isinstance(spend, bool) and spend >= 0
    ):
        return [REASON_INVALID_ENVELOPE]
    return []


def _validate_redaction(value: Any) -> list[str]:
    if not isinstance(value, dict) or set(value) != {"fields", "env"}:
        return [REASON_INVALID_ENVELOPE]
    for key in ("fields", "env"):
        items = value.get(key)
        if not isinstance(items, list) or len(items) != len(set(items)):
            return [REASON_INVALID_ENVELOPE]
        if any(not isinstance(item, str) or not item for item in items):
            return [REASON_INVALID_ENVELOPE]
    return []


def _validate_artifacts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return [REASON_INVALID_ENVELOPE]
    for item in value:
        if not isinstance(item, dict) or set(item) != {"digest", "kind", "redaction"}:
            return [REASON_INVALID_ENVELOPE]
        digest = item.get("digest")
        if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
            return [REASON_INVALID_ENVELOPE]
        if not isinstance(item.get("kind"), str) or not item["kind"]:
            return [REASON_INVALID_ENVELOPE]
        if not isinstance(item.get("redaction"), str) or not item["redaction"]:
            return [REASON_INVALID_ENVELOPE]
    return []


def _validate_coverage(value: Any) -> list[str]:
    required = {
        "attempted",
        "complete",
        "skipped",
        "unsupported",
        "failed",
        "required",
    }
    if not isinstance(value, dict) or set(value) != required:
        return [REASON_INVALID_ENVELOPE]
    for key in required:
        items = value.get(key)
        if not isinstance(items, list) or len(items) != len(set(items)):
            return [REASON_INVALID_ENVELOPE]
        if any(not isinstance(item, str) or not item for item in items):
            return [REASON_INVALID_ENVELOPE]
    return []


def _budget_breach(payload: Mapping[str, Any]) -> bool:
    budget = payload.get("budget")
    if not isinstance(budget, dict):
        return False
    reserved = budget.get("reserved")
    spent = budget.get("spent")
    if not isinstance(reserved, dict) or not isinstance(spent, dict):
        return False
    try:
        if spent["elapsed_ms"] > reserved["timeout_ms"]:
            return True
        if spent["output_bytes"] > reserved["max_output_bytes"]:
            return True
        if spent["tool_steps"] > reserved["max_tool_steps"]:
            return True
        ceiling = reserved.get("max_spend")
        if ceiling is not None and spent["spend"] > ceiling:
            return True
    except (KeyError, TypeError):
        return False
    return False


def _is_dispatch_class(payload: Mapping[str, Any]) -> bool:
    effects = payload.get("side_effects")
    if isinstance(effects, list) and any(
        item not in READ_TIER_EFFECTS for item in effects if isinstance(item, str)
    ):
        return True
    return payload.get("safety_class") in {"R2", "R3"}


def _missing_approval(payload: Mapping[str, Any]) -> bool:
    approval = payload.get("approval_ref")
    roe = payload.get("roe_ref")
    return not (isinstance(approval, str) and approval and isinstance(roe, str) and roe)


def _build_manifest(payload: Mapping[str, Any]) -> CapabilityManifest:
    tool = payload["tool"]
    cleanup = payload["cleanup"]
    redaction = payload["redaction"]
    budget = payload["budget"]
    return CapabilityManifest(
        schema=str(payload["schema"]),
        schema_version=int(payload["schema_version"]),
        capability_id=str(payload["capability_id"]),
        tier=str(payload["tier"]),
        kind=str(payload["kind"]),
        tool=ToolSpec(
            name=str(tool["name"]),
            version=str(tool["version"]),
            digest=tool.get("digest") if isinstance(tool.get("digest"), str) else None,
        ),
        protocols=tuple(str(item) for item in payload["protocols"]),
        safety_class=str(payload["safety_class"]),
        side_effects=tuple(str(item) for item in payload["side_effects"]),
        default_off=bool(payload["default_off"]),
        synthetic_only=bool(payload["synthetic_only"]),
        authorized_scope=tuple(str(item) for item in payload["authorized_scope"]),
        approval_ref=_opt_str(payload.get("approval_ref")),
        roe_ref=_opt_str(payload.get("roe_ref")),
        budget=BudgetLimit(
            timeout_ms=int(budget["timeout_ms"]),
            max_output_bytes=int(budget["max_output_bytes"]),
            max_tool_steps=int(budget["max_tool_steps"]),
            max_spend=budget.get("max_spend"),
        ),
        cleanup=CleanupPolicy(
            required=bool(cleanup["required"]),
            proof=str(cleanup["proof"]),
        ),
        redaction=RedactionPolicy(
            fields=tuple(str(item) for item in redaction["fields"]),
            env=tuple(str(item) for item in redaction["env"]),
        ),
    )


def _build_result(payload: Mapping[str, Any], *, status: str) -> ExecutionResult:
    tool = payload["tool"]
    scope = payload["scope"]
    budget = payload["budget"]
    reserved = budget["reserved"]
    spent = budget["spent"]
    coverage = payload["coverage"]
    cleanup = payload["cleanup"]
    artifacts = tuple(
        ArtifactSpec(
            digest=str(item["digest"]),
            kind=str(item["kind"]),
            redaction=str(item["redaction"]),
        )
        for item in payload["artifacts"]
    )
    return ExecutionResult(
        schema=str(payload["schema"]),
        schema_version=int(payload["schema_version"]),
        capability_id=str(payload["capability_id"]),
        tool=ToolSpec(
            name=str(tool["name"]),
            version=str(tool["version"]),
            digest=tool.get("digest") if isinstance(tool.get("digest"), str) else None,
        ),
        attempt_id=_opt_str(payload.get("attempt_id")),
        scope=ScopeSpec(
            authorized=tuple(str(item) for item in scope["authorized"]),
            touched=tuple(str(item) for item in scope["touched"]),
        ),
        safety_class=str(payload["safety_class"]),
        side_effects=tuple(str(item) for item in payload["side_effects"]),
        approval_ref=_opt_str(payload.get("approval_ref")),
        roe_ref=_opt_str(payload.get("roe_ref")),
        budget=ResultBudget(
            reserved=BudgetLimit(
                timeout_ms=int(reserved["timeout_ms"]),
                max_output_bytes=int(reserved["max_output_bytes"]),
                max_tool_steps=int(reserved["max_tool_steps"]),
                max_spend=reserved.get("max_spend"),
            ),
            spent=SpentBudget(
                elapsed_ms=int(spent["elapsed_ms"]),
                output_bytes=int(spent["output_bytes"]),
                tool_steps=int(spent["tool_steps"]),
                spend=spent["spend"],
            ),
        ),
        started_at=str(payload["started_at"]),
        finished_at=str(payload["finished_at"]),
        status=status,
        transport_ok=bool(payload["transport_ok"]),
        artifacts=artifacts,
        coverage=Coverage(
            attempted=_str_tuple(coverage.get("attempted")),
            complete=_str_tuple(coverage.get("complete")),
            skipped=_str_tuple(coverage.get("skipped")),
            unsupported=_str_tuple(coverage.get("unsupported")),
            failed=_str_tuple(coverage.get("failed")),
            required=_str_tuple(coverage.get("required")),
        ),
        cleanup=CleanupResult(
            required=bool(cleanup["required"]),
            proof_digest=_opt_str(cleanup.get("proof_digest")),
            residual=bool(cleanup["residual"]),
        ),
        limitations=tuple(str(item) for item in payload["limitations"]),
    )


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
