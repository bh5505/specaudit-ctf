"""Deterministic workpaper structure and declared human review (AUDIT-01).

``score`` and ``dimensions`` measure structure only, never evidence sufficiency
or prose truth. Evidence uses review_workpaper's ``id`` / ``sha256`` / ``kind``
and ``evidence_ids`` conventions. Every claim, finding, non-finding and
inconclusive area is an object with a unique id, explicit subject/population/
period and resolvable evidence_ids; conclusion text uses
``conclusion_evidence_ids`` and the workpaper's scope.subject/population/period.
Supported statements require observed evidence, without upgrading declarations.
Optional conclusion_status uses supported (default), rejected or unresolved;
an explicit unresolved conclusion can retain declared evidence without claiming
observed support.

Evidence requires nonempty source/version/time/scope/custody/limitations and
subject/population/period. Digests must be unique lowercase SHA-256 hex. Optional
``evidence_bytes`` maps evidence ids to retained bytes exactly; if supplied,
content digests are checked. Without it, digest binding is declared only.

``passed`` requires structural validity AND an explicit human_adjudication with
reviewer, rationale, ISO decided_on, document_digest, evidence_sufficient and
supportedness (the latter two exact booleans). document_digest is the returned
review_subject_digest: canonical JSON SHA-256 excluding human_adjudication.
Missing review is pending. Reviewer assertions are unauthenticated and do not
prove professional calibration, custody or semantic support. Machine and human
verdicts remain siblings; neither overrides the other. No I/O or truth oracle.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import json
import re
from typing import Any, Mapping

RUBRIC_VERSION = "specaudit.ctf.workpaper-rubric.v1"
_REQUIRED_TOP_KEYS = frozenset({
    "objective", "scope", "criteria", "population", "period", "procedures",
    "evidence", "findings", "conclusion", "limitations",
})
_FINDING_REQUIRED = frozenset({"condition", "criterion", "cause", "consequence"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


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
    structurally_valid: bool
    machine_verdict: str
    human_verdict: str
    human_review_required: bool
    review_subject_digest: str | None
    limitations: tuple[str, ...]


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _texts(value: Any) -> bool:
    return isinstance(value, (list, tuple)) and bool(value) and all(_text(x) for x in value)


def _dimension(name: str, errors: list[str], success: str) -> DimensionResult:
    return DimensionResult(name, not errors, "; ".join(errors) if errors else success)


def _evidence(wp: Mapping[str, Any], evidence_bytes: Mapping[str, bytes] | None):
    errors: list[str] = []
    index: dict[str, Mapping[str, Any]] = {}
    digests: set[str] = set()
    records = wp.get("evidence")
    if not isinstance(records, (list, tuple)) or not records:
        errors.append("evidence must be a nonempty list")
        records = []
    for i, record in enumerate(records):
        label = f"evidence[{i}]"
        if not isinstance(record, Mapping):
            errors.append(f"{label} must be an object")
            continue
        key = record.get("id")
        if not _text(key) or key in index:
            errors.append(f"{label}.id must be nonempty and unique")
        else:
            index[key] = record
        digest = record.get("sha256")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            errors.append(f"{label}.sha256 must be 64 lowercase hex")
        elif digest in digests:
            errors.append(f"{label}.sha256 must be unique")
        else:
            digests.add(digest)
        for field in ("source", "version", "time", "scope", "custody", "subject", "population", "period"):
            if not _text(record.get(field)):
                errors.append(f"{label}.{field} must be nonempty text")
        limits = record.get("limitations")
        if not (_text(limits) or _texts(limits)):
            errors.append(f"{label}.limitations must be nonempty text or text list")
        if not isinstance(record.get("kind"), str) or record["kind"] not in {"observed", "declared", "inferred"}:
            errors.append(f"{label}.kind must be observed, declared or inferred")
    if evidence_bytes is not None:
        if (not isinstance(evidence_bytes, Mapping)
                or any(not _text(k) or not isinstance(v, bytes) for k, v in evidence_bytes.items())):
            raise TypeError("evidence_bytes must map nonempty evidence ids to bytes")
        if set(evidence_bytes) != set(index):
            errors.append("evidence_bytes must match evidence ids exactly")
        for key, record in index.items():
            content = evidence_bytes.get(key)
            if content is not None and hashlib.sha256(content).hexdigest() != record.get("sha256"):
                errors.append(f"evidence {key!r}: content digest mismatch")
    return index, _dimension("evidence_sufficiency", errors, "attribution structure valid; human sufficiency unestablished")


def _references(record: Mapping[str, Any], label: str, evidence: Mapping[str, Mapping[str, Any]],
                errors: list[str], *, supported: bool = True) -> None:
    refs = record.get("evidence_ids")
    if not _texts(refs):
        errors.append(f"{label}.evidence_ids must be a nonempty text list")
        return
    if len(set(refs)) != len(refs):
        errors.append(f"{label}.evidence_ids contains duplicates")
    for ref in refs:
        if ref not in evidence:
            errors.append(f"{label}: unknown evidence {ref!r}")
            continue
        for field in ("subject", "population", "period"):
            if not _text(record.get(field)) or record[field] != evidence[ref].get(field):
                errors.append(f"{label}: {field} does not match evidence {ref!r}")
    if supported and not any(evidence.get(ref, {}).get("kind") == "observed" for ref in refs):
        errors.append(f"{label}: supported statement requires observed evidence")


def _statements(wp: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]]):
    trace_errors: list[str] = []
    finding_errors: list[str] = []
    nonfinding_errors: list[str] = []
    seen: set[str] = set()
    nonfinding_count = 0
    for group in ("claims", "findings", "non_findings", "inconclusive_areas"):
        records = wp.get(group, [])
        if not isinstance(records, (list, tuple)):
            trace_errors.append(f"{group} must be a list")
            if group == "findings":
                finding_errors.append("findings must be a list")
            elif group in {"non_findings", "inconclusive_areas"}:
                nonfinding_errors.append(f"{group} must be a list")
            continue
        for i, record in enumerate(records):
            label = f"{group}[{i}]"
            errors: list[str] = []
            if not isinstance(record, Mapping):
                errors.append(f"{label} must be an object")
            else:
                key = record.get("id")
                if not _text(key) or key in seen:
                    errors.append(f"{label}.id must be nonempty and unique across statements")
                else:
                    seen.add(key)
                kind = record.get("type", "finding") if group == "findings" else group
                if group == "findings" and (not isinstance(kind, str) or kind not in {"finding", "non-finding", "inconclusive"}):
                    errors.append(f"{label}.type invalid")
                if group == "findings" and kind == "finding":
                    for field in _FINDING_REQUIRED:
                        if not _text(record.get(field)):
                            errors.append(f"{label}.{field} must be nonempty text")
                elif not _text(record.get("statement")):
                    errors.append(f"{label}.statement must be nonempty text")
                supported = not isinstance(kind, str) or kind not in {"inconclusive", "inconclusive_areas"}
                if group == "claims":
                    status = record.get("status")
                    if not isinstance(status, str) or status not in {"supported", "rejected", "unresolved"}:
                        errors.append(f"{label}.status invalid")
                    supported = status == "supported"
                _references(record, label, evidence, errors, supported=supported)
                if group in {"non_findings", "inconclusive_areas"} or (isinstance(kind, str) and kind in {"non-finding", "inconclusive"}):
                    if not errors:
                        nonfinding_count += 1
            trace_errors.extend(errors)
            if group == "findings":
                finding_errors.extend(errors)
            if group in {"non_findings", "inconclusive_areas"}:
                nonfinding_errors.extend(errors)
    if not nonfinding_count:
        nonfinding_errors.append("no evidence-linked non-finding or inconclusive area")
    scope = wp.get("scope")
    conclusion_record = {
        "subject": scope.get("subject") if isinstance(scope, Mapping) else None,
        "population": wp.get("population"), "period": wp.get("period"),
        "evidence_ids": wp.get("conclusion_evidence_ids"),
    }
    conclusion_status = wp.get("conclusion_status", "supported")
    if not isinstance(conclusion_status, str) or conclusion_status not in {"supported", "rejected", "unresolved"}:
        trace_errors.append("conclusion_status must be supported, rejected or unresolved")
    _references(conclusion_record, "conclusion", evidence, trace_errors, supported=conclusion_status == "supported")
    return (
        _dimension("finding_structure", finding_errors, "finding structure valid"),
        _dimension("traceability", trace_errors, "explicit references resolve; semantic support unestablished"),
        _dimension("supported_nonfinding", nonfinding_errors, "non-finding/inconclusive references valid; human support unestablished"),
    )


def _review(wp: Mapping[str, Any], digest: str | None):
    review = wp.get("human_adjudication")
    if review is None:
        return "pending", "human_adjudication missing; human quality pending"
    if not isinstance(review, Mapping):
        return "invalid", "human_adjudication must be an object"
    for field in ("reviewer", "rationale", "decided_on"):
        if not _text(review.get(field)):
            return "invalid", f"human_adjudication.{field} must be nonempty text"
    try:
        decided_on = date.fromisoformat(review["decided_on"])
        if decided_on.isoformat() != review["decided_on"]:
            raise ValueError("noncanonical date")
    except ValueError:
        return "invalid", "human_adjudication.decided_on must be an ISO date"
    if digest is None or review.get("document_digest") != digest:
        return "invalid", "human_adjudication.document_digest does not bind this workpaper"
    for field in ("evidence_sufficient", "supportedness"):
        if type(review.get(field)) is not bool:
            return "invalid", f"human_adjudication.{field} must be a boolean"
    if not review["evidence_sufficient"] or not review["supportedness"]:
        return "fail", "reviewer adjudicated insufficient evidence or unsupported conclusions"
    return "pass", "declared reviewer pass; authentication and calibration unestablished"


def grade_workpaper(document: Any, *, evidence_bytes: Mapping[str, bytes] | None = None) -> WorkpaperRubricResult:
    """Return structural dimensions and a separate declared human verdict.

    Existing score/dimension names remain structural indicators. An overall
    pass records a bound caller-declared review, never a machine truth decision.
    Call once without review to obtain review_subject_digest, then retain the
    attributed review against that exact digest. A changed document needs review
    again. Supplying bytes checks content hashes, not authenticity or custody.
    """
    if not isinstance(document, Mapping):
        raise TypeError("workpaper must be a mapping")
    structure_errors = []
    missing = _REQUIRED_TOP_KEYS - set(document)
    if missing:
        structure_errors.append(f"missing keys: {sorted(missing)}")
    try:
        body = {k: v for k, v in document.items() if k != "human_adjudication"}
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=False).encode("utf-8")
        digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    except (TypeError, ValueError, UnicodeError):
        digest = None
        structure_errors.append("workpaper must be finite JSON data")
    scope = document.get("scope")
    scope_valid = isinstance(scope, Mapping) and all(_text(scope.get(k)) for k in ("subject", "actions", "stop_conditions"))
    evidence, evidence_result = _evidence(document, evidence_bytes)
    findings, traceability, nonfinding = _statements(document, evidence)
    dims = [
        _dimension("structure", structure_errors, "required keys and JSON structure valid"),
        DimensionResult("objective", _text(document.get("objective")), "objective must be nonempty text"),
        DimensionResult("bounded_scope", scope_valid, "scope requires subject, actions and stop_conditions"),
        DimensionResult("criteria", _texts(document.get("criteria")), "criteria must be nonempty text list"),
        DimensionResult("population_period", all(_text(document.get(k)) for k in ("population", "period")), "population and period must be nonempty text"),
        DimensionResult("procedures", _texts(document.get("procedures")), "procedures must be nonempty text list"),
        evidence_result, findings,
        DimensionResult("conclusion", _text(document.get("conclusion")), "conclusion must be nonempty text"),
        DimensionResult("stated_uncertainty", _texts(document.get("limitations")), "limitations must be nonempty text list"),
        traceability, nonfinding,
        DimensionResult("reperformability", evidence_result.passed and traceability.passed and _texts(document.get("procedures")) and _text(document.get("conclusion")) and _texts(document.get("limitations")), "reperformance inputs and references required; actual reperformance unestablished"),
        DimensionResult("follow_through", _text(document.get("retest_plan")) or _texts(document.get("retest_plan")), "retest/close/revise plan must be nonempty text or text list"),
    ]
    structurally_valid = all(d.passed for d in dims)
    human_verdict, review_reason = _review(document, digest)
    unmet = tuple(d.name for d in dims if not d.passed)
    if human_verdict != "pass":
        unmet += ("human_adjudication",)
    limitations = (
        "structural-checks-do-not-establish-evidence-sufficiency-or-semantic-supportedness",
        "reviewer-adjudication-is-caller-declared-unauthenticated-and-uncalibrated",
        "no-evidence-authenticity-custody-or-observation-promotion-established",
        "evidence-content-digests-checked" if evidence_bytes is not None else "evidence-content-not-checked-digests-declared-only",
        review_reason,
    )
    return WorkpaperRubricResult(
        version=RUBRIC_VERSION, passed=structurally_valid and human_verdict == "pass",
        score=sum(d.passed for d in dims) / len(dims), dimensions=tuple(dims), unmet=unmet,
        structurally_valid=structurally_valid,
        machine_verdict="structurally-valid" if structurally_valid else "structurally-invalid",
        human_verdict=human_verdict, human_review_required=human_verdict != "pass",
        review_subject_digest=digest, limitations=limitations,
    )


__all__ = ["DimensionResult", "RUBRIC_VERSION", "WorkpaperRubricResult", "grade_workpaper"]
