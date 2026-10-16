"""Attempt grading: captured server-side trace + claimed findings.

The head lane's evidence doctrine in one place. An attempt is a
directory holding ``trace.ndjson`` (written by the MCP server — our
process — while the agent worked) and ``found.json`` (the agent's
claimed findings, plain participant prose). Grading is fail-closed and
combines both:

1. the trace chain is verified against the attempt key; an unverified,
   truncated, or close-less trace fails the attempt — it is never
   graded;
2. a trace with zero ``tools/call`` records fails the attempt outright:
   there is nothing to grade, and a confident found document must never
   pass on prose alone;
3. ``score.grading.grade`` runs unmodified on the found-vs-expected
   pair (owned-evidence doctrine, misses/extras/invalid all fail);
4. every hit is then demoted to ``unverified`` unless the trace shows
   the agent actually touched the finding's fixtures through the
   server. The ONLY fixture-coverage source is a successful
   ``run_range`` and the fixture roster the server itself recorded
   from the packaged manifest — trusted handler evidence.
   ``list``/``describe``/``invoke`` grant none: reconnaissance moves
   no data, and invoke arguments are the agent's own strings, whose
   substrings could lexically walk any path without touching it.

The verdict passes only with ``grade().passed`` AND zero unverified
hits. This gate is deliberately a tripwire against claim-without-
evidence attempts, not proof of investigative depth: one successful
``run_range`` covers every fixture, and this module never claims more.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from extension.trace import (
    TraceVerification,
    TraceUnavailable,
    load_trace_key,
    range_fixture_ids,
    verify_trace,
)
from score.grading import (
    GradingError,
    LANE_FIXTURE_BACKED,
    grade,
    load_findings_document,
)

SCHEMA_ID = "specaudit.ctf.attempt.v1"

FOUND_NAME = "found.json"
TRACE_NAME = "trace.ndjson"
AGENT_TRACE_SCHEMA = "specaudit.ctf.agent-trace-assessment.v1"
AGENT_CLAIMS_SCHEMA = "specaudit.ctf.agent-trace-claims.v1"
_KNOWN_TOOLS = frozenset({"list", "describe", "invoke", "run_range"})
_CLAIM_OUTCOMES = frozenset({"succeeded", "failed", "denied"})
_MAX_CLAIMS = 128
_MAX_REPORTED_CALLS = 128


class AttemptError(ValueError):
    """The attempt cannot be graded (layout or key problems; exit 2)."""


def _observed_outcome(record: Mapping[str, Any]) -> str:
    """Classify only facts the server recorded, not requested arguments.

    A JSON-RPC invalid-params error is a refusal before tool execution;
    an internal JSON-RPC error might occur after side effects and remains
    unknown. A tool-level error is a failure; its bounded message cannot
    prove that nothing happened, so it is not called a denial. An incomplete
    or unexpected envelope cannot substantiate a success claim.
    """
    result = record.get("result")
    if not isinstance(result, Mapping):
        return "unknown"
    if result.get("isError") is None and result.get("rpc_error_code") == -32602:
        return "denied"
    if result.get("isError") is True:
        return "failed"
    if result.get("isError") is not False:
        return "unknown"
    status = result.get("envelope_status")
    if record.get("tool") in {"invoke", "run_range"}:
        return "succeeded" if status == "complete" else "unknown"
    return "succeeded" if status is None and record.get("tool") in _KNOWN_TOOLS else "unknown"


def analyze_agent_trace(
    trace_path: Path,
    *,
    key_env: str | None,
    submission: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess actual MCP behavior and optional agent-declared outcomes.

    The trusted operator supplies the server's HMAC key out of band. An
    attached submission is a declaration, never trace authority. Its
    trace_sha256 binds claims to the exact file and each seq identifies
    a server record. Only the verified, closed trace can supply observed
    outcomes; unbound, duplicate, missing, or unsupported claims are
    surfaced rather than silently credited. This is a bounded summary,
    not a reconstruction of redacted tool output or autonomous intent.
    """
    if not key_env or not key_env.strip():
        raise AttemptError("analyzing agent behavior requires the trace key on the operator side")
    try:
        key = load_trace_key(key_env)
    except TraceUnavailable as exc:
        raise AttemptError(str(exc)) from exc
    verification = verify_trace(Path(trace_path), key)
    return _assess_verified_trace(verification, submission)


def _assess_verified_trace(
    verification: TraceVerification, submission: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Build a bounded review from one authenticated trace snapshot."""
    report: dict[str, Any] = {
        "schema": AGENT_TRACE_SCHEMA,
        "kind": "agent",
        "status": "unverified",
        "trace": verification.as_dict(),
        "observed_calls": [],
        "claims": [],
    }
    if not verification.ok:
        return report
    # The digest belongs to the same bytes the verifier authenticated,
    # avoiding a second read across a mutable trace file.
    digest = verification.sha256
    report["trace_sha256"] = digest
    calls = [row for row in verification.records if row.get("type") == "call"]
    by_seq = {row["seq"]: row for row in calls}
    observed = []
    for row in calls[:_MAX_REPORTED_CALLS]:
        result = row.get("result")
        summary = result if isinstance(result, Mapping) else {}
        observed.append({
            "seq": row["seq"],
            "tool": row.get("tool"),
            "outcome": _observed_outcome(row),
            "envelope_status": summary.get("envelope_status"),
            "capability_id": summary.get("capability_id"),
            "error": summary.get("error"),
            "rpc_error_code": summary.get("rpc_error_code"),
            "unknown_tool": row.get("tool") not in _KNOWN_TOOLS,
        })
    report["observed_calls"] = observed
    report["omitted_calls"] = max(0, len(calls) - len(observed))
    report["status"] = "verified" if calls else "no_tool_calls"
    if submission is None:
        return report
    if (
        not isinstance(submission, Mapping)
        or submission.get("schema") != AGENT_CLAIMS_SCHEMA
        or set(submission) != {"schema", "trace_sha256", "claims"}
        or submission.get("trace_sha256") != digest
    ):
        report["claims_status"] = "unbound"
        return report
    claims = submission.get("claims")
    if not isinstance(claims, list) or not claims or len(claims) > _MAX_CLAIMS:
        report["claims_status"] = "invalid"
        return report
    seen: set[int] = set()
    assessed = []
    for claim in claims:
        if (
            not isinstance(claim, Mapping)
            or set(claim) not in (
                {"seq", "tool", "reported_outcome"},
                {"seq", "tool", "reported_outcome", "capability_id"},
            )
            or type(claim.get("seq")) is not int
            or not isinstance(claim.get("tool"), str)
            or not isinstance(claim.get("reported_outcome"), str)
            or claim["reported_outcome"] not in _CLAIM_OUTCOMES
            or ("capability_id" in claim and not isinstance(claim["capability_id"], str))
            or claim["seq"] in seen
        ):
            report["claims_status"] = "invalid"
            report["claims"] = []
            return report
        seen.add(claim["seq"])
        row = by_seq.get(claim["seq"])
        actual = _observed_outcome(row) if row else "unobserved"
        recorded_result = row.get("result") if row else None
        recorded_capability = recorded_result.get("capability_id") if isinstance(recorded_result, Mapping) else None
        match = (
            row is not None and row.get("tool") == claim["tool"]
            and actual == claim["reported_outcome"]
            and ("capability_id" not in claim or claim["capability_id"] == recorded_capability)
        )
        assessed.append({
            "seq": claim["seq"],
            "tool": claim["tool"],
            "reported_outcome": claim["reported_outcome"],
            "observed_outcome": actual,
            "observed_capability_id": recorded_capability,
            "assessment": "supported" if match else "unsupported",
        })
    report["claims"] = assessed
    report["claims_status"] = "supported" if all(row["assessment"] == "supported" for row in assessed) else "unsupported"
    return report


def load_attempt(attempt_dir: Path) -> tuple[Path, Path]:
    """Validate the attempt layout; return (trace_path, found_path)."""
    directory = Path(attempt_dir)
    if not directory.is_dir():
        raise AttemptError(f"attempt directory does not exist: {directory}")
    trace_path = directory / TRACE_NAME
    found_path = directory / FOUND_NAME
    if not trace_path.is_file():
        raise AttemptError(f"attempt has no {TRACE_NAME}: {directory}")
    if not found_path.is_file():
        raise AttemptError(f"attempt has no {FOUND_NAME}: {directory}")
    return trace_path, found_path


def fixtures_named(text: str, roster: tuple[str, ...]) -> list[str]:
    """Manifest fixture ids mentioned in a free-form traces_to string.

    The contracts phrase provenance heterogeneously (paths, bare ids,
    prose), so recognition is roster membership by substring against
    the shipped manifest ids. A string that names no roster fixture
    yields an empty list — which the coverage gate treats as
    uncovered (fail closed), never as vacuously covered.
    """
    return [fixture for fixture in roster if fixture in text]


def touched_fixtures(
    records: list[Mapping[str, Any]], roster: tuple[str, ...]
) -> set[str]:
    """Derive the fixture set the trace proves the agent touched.

    Coverage comes from TRUSTED HANDLER EVIDENCE only: a successful
    ``run_range`` and the fixture roster the server recorded for it
    (intersected with the current manifest). Everything else grants
    nothing — a failed run_range produced no ground truth, and invoke
    arguments are the agent's own strings whose substrings could name
    any path without the handler ever touching it.
    """
    touched: set[str] = set()
    for record in records:
        if record.get("type") != "call":
            continue
        result = record.get("result")
        if not isinstance(result, Mapping) or result.get("isError") is not False:
            continue
        if record.get("tool") == "run_range":
            recorded = result.get("fixture_ids")
            if isinstance(recorded, list) and recorded:
                touched.update(
                    fixture for fixture in recorded if fixture in roster
                )
    return touched


def grade_attempt(
    attempt_dir: Path,
    *,
    expected_path: Path,
    key_env: str | None,
    claims_path: Path | None = None,
) -> dict[str, Any]:
    """Verify the trace, grade the claims, demote unevidenced hits.

    ``key_env`` is the raw trace-key value from the grading side's
    environment (never stored in the attempt directory). Raises
    AttemptError for layout problems and GradingError for malformed
    documents, exactly like the standalone grading lane.
    """
    trace_path, found_path = load_attempt(attempt_dir)
    if not key_env or not key_env.strip():
        raise AttemptError(
            "verifying an attempt requires the trace key in "
            "SPECAUDIT_CTF_MCP_TRACE_KEY (it is never stored beside the trace)"
        )
    try:
        key = load_trace_key(key_env)
    except TraceUnavailable as exc:
        raise AttemptError(str(exc)) from exc

    document: dict[str, Any] = {
        "schema": SCHEMA_ID,
        "attempt_dir": str(attempt_dir),
        "passed": False,
    }
    verification = verify_trace(trace_path, key)
    document["trace"] = verification.as_dict()
    submission = None
    claims_unreadable = False
    if claims_path is not None:
        try:
            # Descriptor-bound, nonblocking, nofollow read; the strict
            # decoder rejects duplicate keys and non-JSON constants.
            # Keep the claims budget lower than the generic request cap.
            from learning.operator import _parse_json_document, _read_request_file

            raw = _read_request_file(Path(claims_path))
            if len(raw) > 65536:
                raise ValueError("agent claims exceed 64 KiB")
            submission = _parse_json_document(raw)
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
            claims_unreadable = True
    document["agent_trace"] = _assess_verified_trace(verification, submission)
    if claims_unreadable:
        document["agent_trace"]["claims_status"] = "invalid"
    if not verification.ok:
        document["status"] = "failed"
        document["reason"] = "trace failed verification; the attempt is not gradable"
        return document
    if verification.tool_calls == 0:
        document["status"] = "failed"
        document["reason"] = "no tool calls were recorded; nothing is gradable"
        return document

    try:
        found = load_findings_document(found_path, what="found findings")
        expected = load_findings_document(expected_path, what="expected contract")
    except GradingError as exc:
        document["status"] = "failed"
        document["reason"] = f"attempt documents unusable: {exc}"
        return document
    lane = expected.get("lane", LANE_FIXTURE_BACKED)
    if lane != LANE_FIXTURE_BACKED:
        document["status"] = "failed"
        document["reason"] = (
            f"{lane} contract: the attempt lane cannot grade it — its "
            "coverage doctrine verifies run_range fixture touches, which no "
            "non-fixture finding can honestly name; grade through the "
            "standalone found-vs-expected lane"
        )
        return document

    graded = grade(found, expected)
    roster = range_fixture_ids()
    touched = touched_fixtures(verification.records, roster)
    claimed = document["trace"]["tool_calls"]

    unverified: list[dict[str, str]] = []
    verified: list[str] = []
    findings_by_key = {
        row["finding_key"]: row
        for row in found.get("findings", [])
        if isinstance(row, dict)
    }
    for hit in graded.get("hits", []):
        row = findings_by_key.get(hit, {})
        named = fixtures_named(str(row.get("traces_to") or ""), roster)
        missing = sorted(set(named) - touched)
        if not named:
            unverified.append(
                {
                    "finding_key": hit,
                    "reason": (
                        "traces_to names no shipped fixture the trace could cover"
                    ),
                }
            )
        elif missing:
            unverified.append(
                {
                    "finding_key": hit,
                    "reason": "trace never touched: " + ", ".join(missing),
                }
            )
        else:
            verified.append(hit)

    document.update(
        {
            "status": "graded",
            "roster": list(roster),
            "touched_fixtures": sorted(touched),
            "tool_calls": claimed,
            "claimed": len(found.get("findings", [])),
            "verified": sorted(verified),
            "unverified": unverified,
            "grade": graded,
            "passed": graded.get("passed") is True and not unverified
            and (claims_path is None or document["agent_trace"].get("claims_status") == "supported"),
        }
    )
    if not document["passed"]:
        document["reason"] = (
            "claims lack tool evidence" if unverified else
            "agent claims conflict with or lack verified trace evidence"
            if claims_path is not None and document["agent_trace"].get("claims_status") != "supported"
            else "found-vs-expected grading failed"
        )
    return document
