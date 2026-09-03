"""Gate projection over parsed execution-result envelopes.

Every gate is a thin predicate over ``parse_execution_result`` output
(the repository's own parser owns the semantics; this module imports
its reason constants so a parser rename breaks this package at import
time instead of silently detaching a gate). The single verdict site
never reads ``transport_ok``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from extension.envelopes import (
    REASON_BLANKET_SCOPE,
    REASON_BUDGET_BREACH,
    REASON_CAPABILITY_MISMATCH,
    REASON_CLEANUP_POLICY,
    REASON_CLEANUP_UNPROVEN,
    REASON_COVERAGE_INCONSISTENT,
    REASON_HELD,
    REASON_INVALID_ENVELOPE,
    REASON_INVALID_JSON,
    REASON_METHODOLOGY_ONLY,
    REASON_MISSING_APPROVAL,
    REASON_OPTIONAL_LIMITATION,
    REASON_PROFILE_MISMATCH,
    REASON_REQUIRED_FAILED,
    REASON_REQUIRED_SKIPPED,
    REASON_SCOPE_OVERFLOW,
    REASON_UNOWNED_EVIDENCE,
    REASON_UNKNOWN_CAPABILITY,
    REASON_UNKNOWN_SCHEMA,
    REASON_UNKNOWN_TIER,
    STATUS_COMPLETE,
    STATUS_DEGRADED,
    ResultParse,
    parse_execution_result,
)

from .rubric import Rubric

# Structural reasons that make the envelope itself invalid to score.
_STRUCTURAL_REASONS = frozenset(
    {
        REASON_UNKNOWN_SCHEMA,
        REASON_INVALID_JSON,
        REASON_INVALID_ENVELOPE,
        REASON_UNKNOWN_CAPABILITY,
        REASON_UNKNOWN_TIER,
        REASON_METHODOLOGY_ONLY,
        REASON_HELD,
        REASON_COVERAGE_INCONSISTENT,
        REASON_CAPABILITY_MISMATCH,
        REASON_PROFILE_MISMATCH,
    }
)

# gate name -> parser reasons that fail it
_GATE_REASONS: dict[str, frozenset[str]] = {
    "envelope_valid": frozenset(_STRUCTURAL_REASONS),
    "status_complete": frozenset(),  # judged on the parsed status below
    "required_arms_complete": frozenset(
        {REASON_REQUIRED_FAILED, REASON_REQUIRED_SKIPPED}
    ),
    "owned_evidence": frozenset({REASON_UNOWNED_EVIDENCE}),
    "limitations_empty": frozenset({REASON_OPTIONAL_LIMITATION}),
    "cleanup_proven": frozenset({REASON_CLEANUP_UNPROVEN, REASON_CLEANUP_POLICY}),
    "budget_respected": frozenset({REASON_BUDGET_BREACH}),
    "scope_contained": frozenset({REASON_SCOPE_OVERFLOW, REASON_BLANKET_SCOPE}),
    "approval_present": frozenset({REASON_MISSING_APPROVAL}),
}

GATE_NAMES = tuple(_GATE_REASONS)

# The only gates a rubric may waive, and only together, only for
# envelopes the rubric explicitly allows to be degraded. Waiving the
# status gate is what makes the waiver meaningful: an allowed-degraded
# envelope passes as degraded, never as anything better, and every
# other gate (required arms, evidence, cleanup, budget, scope,
# approval) stays strict.
_WAIVABLE_GATES = ("limitations_empty", "status_complete")


def score_envelope(
    parsed: ResultParse, rubric: Rubric | None = None
) -> dict[str, Any]:
    """Score one parsed envelope into a per-envelope entry."""
    rubric = rubric or Rubric()
    capability_id = parsed.result.capability_id if parsed.result else None
    reasons = frozenset(parsed.reasons)
    gates: dict[str, dict[str, Any]] = {}
    for gate, failing in _GATE_REASONS.items():
        if gate == "status_complete":
            ok = parsed.schema_ok and parsed.status == STATUS_COMPLETE
            detail = (
                f"parsed status is {parsed.status!r}"
                if parsed.schema_ok
                else "envelope did not parse; status forced failed"
            )
        else:
            hit = sorted(reasons & failing)
            ok = not hit
            detail = "; ".join(hit) if hit else "ok"
        gates[gate] = {"ok": ok, "detail": detail}

    waived: list[dict[str, str]] = []
    if (
        capability_id is not None
        and capability_id in rubric.allowed_degraded
        and parsed.status == STATUS_DEGRADED
        and parsed.schema_ok
    ):
        for gate in _WAIVABLE_GATES:
            if not gates[gate]["ok"]:
                gates[gate].update(
                    ok=True, detail="waived by rubric (degraded envelope)"
                )
                waived.append(
                    {
                        "capability_id": capability_id,
                        "gate": gate,
                        "reason": "rubric allowed_degraded",
                    }
                )

    # Single verdict site: transport_ok is deliberately NOT read here —
    # it is echo-only (see the entry below). Flipping it must never
    # change `passed`; two regression tests pin that.
    passed = all(g["ok"] for g in gates.values())

    entry: dict[str, Any] = {
        "capability_id": capability_id,
        "status": parsed.status,
        # informational only — never a verdict input
        "transport_ok": parsed.result.transport_ok if parsed.result else None,
        "attempt_id": parsed.result.attempt_id if parsed.result else None,
        "passed": passed,
        "gates": gates,
    }
    if waived:
        entry["waived"] = waived
    return entry


def score_run(
    files: list[Path], rubric: Rubric | None = None
) -> dict[str, Any]:
    """Score every named envelope file; the run passes iff each does."""
    rubric = rubric or Rubric()
    entries: list[dict[str, Any]] = []
    for path in files:
        parsed = parse_execution_result(Path(path))
        entry = score_envelope(parsed, rubric)
        entry = {"path": str(path), **entry}
        entries.append(entry)

    aggregate: dict[str, dict[str, Any]] = {}
    for gate in GATE_NAMES:
        ok = all(e["gates"][gate]["ok"] for e in entries)
        aggregate[gate] = {"ok": ok}

    missing_required: list[str] = []
    seen = {
        e["capability_id"] for e in entries if e["capability_id"] is not None
    }
    for required in rubric.required_capabilities:
        if required not in seen:
            missing_required.append(required)

    passed = bool(entries) and all(e["passed"] for e in entries) and not missing_required
    document: dict[str, Any] = {
        "schema": "specaudit.ctf.score.v1",
        "passed": passed,
        "scored_count": len(entries),
        "gates": aggregate,
        "envelopes": entries,
        "rubric": {
            "name": rubric.name,
            "required_capabilities": list(rubric.required_capabilities),
            "allowed_degraded": list(rubric.allowed_degraded),
            "missing_required": missing_required,
            "waived": [w for e in entries for w in e.get("waived", [])],
        },
    }
    return document


def verdict(document: Mapping[str, Any]) -> int:
    """Exit code for a score document: 0 passed, else 1."""
    return 0 if document.get("passed") is True else 1
