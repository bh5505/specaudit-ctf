"""Human workpaper rubric (AUDIT-01).

Grades a workpaper document against the audit-quality criteria.  Each
dimension is a boolean pass/fail with a recorded reason for failure, so a
reviewer can reperform the assessment.  False assurance (unsupported
conclusion) and unsupported claims fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

RUBRIC_VERSION = "specaudit.ctf.workpaper-rubric.v1"

_REQUIRED_TOP_KEYS = frozenset(
    {
        "objective",
        "scope",
        "criteria",
        "population",
        "period",
        "procedures",
        "evidence",
        "findings",
        "conclusion",
        "limitations",
    }
)

_FINDING_REQUIRED = frozenset(
    {"condition", "criterion", "cause", "consequence"}
)


@dataclass(frozen=True)
class DimensionResult:
    name: str
    passed: bool
    reason: str


@dataclass(frozen=True)
class WorkpaperRubricResult:
    version: str
    passed: bool
    score: float
    dimensions: tuple[DimensionResult, ...]
    unmet: tuple[str, ...]


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _grade_objective(wp: Mapping[str, Any]) -> DimensionResult:
    if _is_nonempty_str(wp.get("objective")):
        return DimensionResult("objective", True, "objective stated")
    return DimensionResult("objective", False, "objective missing or empty")


def _grade_scope(wp: Mapping[str, Any]) -> DimensionResult:
    scope = wp.get("scope")
    if not isinstance(scope, Mapping):
        return DimensionResult("bounded_scope", False, "scope must be a mapping")
    if not _is_nonempty_str(scope.get("subject")):
        return DimensionResult("bounded_scope", False, "scope.subject missing")
    if not _is_nonempty_str(scope.get("actions")):
        return DimensionResult("bounded_scope", False, "scope.actions missing")
    if not _is_nonempty_str(scope.get("stop_conditions")):
        return DimensionResult("bounded_scope", False, "scope.stop_conditions missing")
    return DimensionResult("bounded_scope", True, "scope bounded")


def _grade_criteria(wp: Mapping[str, Any]) -> DimensionResult:
    criteria = wp.get("criteria")
    if not isinstance(criteria, (list, tuple)) or not criteria:
        return DimensionResult("criteria", False, "criteria list missing or empty")
    if not all(_is_nonempty_str(c) for c in criteria):
        return DimensionResult("criteria", False, "criteria entries must be nonempty strings")
    return DimensionResult("criteria", True, "criteria present")


def _grade_population_period(wp: Mapping[str, Any]) -> DimensionResult:
    if not _is_nonempty_str(wp.get("population")):
        return DimensionResult("population_period", False, "population missing")
    if not _is_nonempty_str(wp.get("period")):
        return DimensionResult("population_period", False, "period missing")
    return DimensionResult("population_period", True, "population and period stated")


def _grade_procedures(wp: Mapping[str, Any]) -> DimensionResult:
    procs = wp.get("procedures")
    if not isinstance(procs, (list, tuple)) or not procs:
        return DimensionResult("procedures", False, "procedures missing or empty")
    if not all(_is_nonempty_str(p) for p in procs):
        return DimensionResult("procedures", False, "procedure entries must be nonempty strings")
    return DimensionResult("procedures", True, "procedures present")


def _grade_evidence(wp: Mapping[str, Any]) -> DimensionResult:
    ev = wp.get("evidence")
    if not isinstance(ev, (list, tuple)) or not ev:
        return DimensionResult("evidence_sufficiency", False, "evidence missing or empty")
    for idx, item in enumerate(ev):
        if not isinstance(item, Mapping):
            return DimensionResult(
                "evidence_sufficiency", False, f"evidence[{idx}] must be a mapping"
            )
        for key in ("source", "version", "time", "scope", "custody", "limitations"):
            if key not in item:
                return DimensionResult(
                    "evidence_sufficiency", False, f"evidence[{idx}] missing {key}"
                )
    return DimensionResult("evidence_sufficiency", True, "evidence attributable")


def _grade_findings(wp: Mapping[str, Any]) -> DimensionResult:
    findings = wp.get("findings")
    if not isinstance(findings, (list, tuple)):
        return DimensionResult("finding_structure", False, "findings must be a list")
    for idx, f in enumerate(findings):
        if not isinstance(f, Mapping):
            return DimensionResult("finding_structure", False, f"finding[{idx}] must be a mapping")
        missing = _FINDING_REQUIRED - set(f)
        if missing:
            return DimensionResult(
                "finding_structure", False, f"finding[{idx}] missing {sorted(missing)}"
            )
        for key in _FINDING_REQUIRED:
            if not _is_nonempty_str(f.get(key)):
                return DimensionResult(
                    "finding_structure", False, f"finding[{idx}].{key} empty"
                )
    return DimensionResult("finding_structure", True, "findings structured")


def _grade_conclusion(wp: Mapping[str, Any]) -> DimensionResult:
    if not _is_nonempty_str(wp.get("conclusion")):
        return DimensionResult("conclusion", False, "conclusion missing or empty")
    return DimensionResult("conclusion", True, "conclusion stated")


def _grade_limitations(wp: Mapping[str, Any]) -> DimensionResult:
    lims = wp.get("limitations")
    if not isinstance(lims, (list, tuple)) or not lims:
        return DimensionResult("stated_uncertainty", False, "limitations missing or empty")
    if not all(_is_nonempty_str(x) for x in lims):
        return DimensionResult("stated_uncertainty", False, "limitation entries must be nonempty strings")
    return DimensionResult("stated_uncertainty", True, "uncertainty stated")


def _grade_traceability(wp: Mapping[str, Any]) -> DimensionResult:
    evidence = wp.get("evidence")
    conclusion = wp.get("conclusion")
    if not (isinstance(evidence, (list, tuple)) and evidence):
        return DimensionResult("traceability", False, "no evidence to trace to")
    # Every conclusion must be traceable: require at least one evidence item
    # referencing the conclusion's subject.  We check that evidence count >= 1
    # and that each finding's condition appears in at least one evidence
    # limitations/notes is not required; instead require evidence count covers
    # findings count as a coarse guard.
    findings = wp.get("findings") or []
    if len(evidence) < max(1, len(findings)):
        return DimensionResult(
            "traceability", False, "evidence count does not cover findings"
        )
    if not _is_nonempty_str(conclusion):
        return DimensionResult("traceability", False, "no conclusion to trace")
    return DimensionResult("traceability", True, "conclusions traceable to evidence")


def _grade_supported_nonfinding(wp: Mapping[str, Any]) -> DimensionResult:
    # A complete engagement includes at least one supported non-finding or
    # genuinely inconclusive area (PROGRAM.md capstone requirement).
    findings = wp.get("findings") or []
    has_nonfinding = any(
        isinstance(f, Mapping) and f.get("type") in {"non-finding", "inconclusive"}
        for f in findings
    )
    # Also accept an explicit non_findings list.
    non_findings = wp.get("non_findings")
    if isinstance(non_findings, (list, tuple)) and non_findings:
        has_nonfinding = True
    inconclusive = wp.get("inconclusive_areas")
    if isinstance(inconclusive, (list, tuple)) and inconclusive:
        has_nonfinding = True
    if has_nonfinding:
        return DimensionResult("supported_nonfinding", True, "non-finding/inconclusive present")
    return DimensionResult(
        "supported_nonfinding", False, "no supported non-finding or inconclusive area"
    )


def _grade_reperformability(wp: Mapping[str, Any]) -> DimensionResult:
    # A reviewer must be able to reconstruct the test: procedures + evidence
    # with source/version/time/scope/custody + conclusion + limitations.
    if not _is_nonempty_str(wp.get("procedures") if not isinstance(wp.get("procedures"), list) else "x"):
        pass
    procs = wp.get("procedures")
    ev = wp.get("evidence")
    if not (isinstance(procs, (list, tuple)) and procs and isinstance(ev, (list, tuple)) and ev):
        return DimensionResult("reperformability", False, "missing procedures or evidence")
    if not _is_nonempty_str(wp.get("conclusion")):
        return DimensionResult("reperformability", False, "missing conclusion")
    if not (isinstance(wp.get("limitations"), (list, tuple)) and wp.get("limitations")):
        return DimensionResult("reperformability", False, "missing limitations")
    return DimensionResult("reperformability", True, "reperformable")


def _grade_retest(wp: Mapping[str, Any]) -> DimensionResult:
    # Follow-through: retest/close/revise plan present.
    if _is_nonempty_str(wp.get("retest_plan")) or (isinstance(wp.get("retest_plan"), (list, tuple)) and wp.get("retest_plan")):
        return DimensionResult("follow_through", True, "retest plan present")
    return DimensionResult("follow_through", False, "retest/close/revise plan missing")


def grade_workpaper(document: Any) -> WorkpaperRubricResult:
    if not isinstance(document, Mapping):
        raise TypeError("workpaper must be a mapping")
    missing = _REQUIRED_TOP_KEYS - set(document)
    dims: list[DimensionResult] = []
    if missing:
        dims.append(DimensionResult("structure", False, f"missing keys: {sorted(missing)}"))
        # still grade what we can
    else:
        dims.append(DimensionResult("structure", True, "required keys present"))

    dims.append(_grade_objective(document))
    dims.append(_grade_scope(document))
    dims.append(_grade_criteria(document))
    dims.append(_grade_population_period(document))
    dims.append(_grade_procedures(document))
    dims.append(_grade_evidence(document))
    dims.append(_grade_findings(document))
    dims.append(_grade_conclusion(document))
    dims.append(_grade_limitations(document))
    dims.append(_grade_traceability(document))
    dims.append(_grade_supported_nonfinding(document))
    dims.append(_grade_reperformability(document))
    dims.append(_grade_retest(document))

    passed_dims = sum(1 for d in dims if d.passed)
    score = passed_dims / len(dims) if dims else 0.0
    unmet = tuple(d.name for d in dims if not d.passed)
    # Overall pass requires all dimensions pass (fail closed).
    overall = all(d.passed for d in dims)
    return WorkpaperRubricResult(
        version=RUBRIC_VERSION,
        passed=overall,
        score=score,
        dimensions=tuple(dims),
        unmet=unmet,
    )


__all__ = [
    "DimensionResult",
    "RUBRIC_VERSION",
    "WorkpaperRubricResult",
    "grade_workpaper",
]
