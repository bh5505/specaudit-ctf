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
   server: a successful ``run_range`` covers the shipped fixture
   roster, a successful ``invoke`` covers fixtures named in its
   arguments, and ``list``/``describe`` reconnaissance covers nothing.

The verdict passes only with ``grade().passed`` AND zero unverified
hits. This gate is deliberately a tripwire against claim-without-
evidence attempts, not proof of investigative depth: one successful
``run_range`` covers every fixture, and this module never claims more.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from extension.trace import (
    TraceUnavailable,
    load_trace_key,
    range_fixture_ids,
    verify_trace,
)
from score.grading import GradingError, grade, load_findings_document

SCHEMA_ID = "specaudit.ctf.attempt.v1"

FOUND_NAME = "found.json"
TRACE_NAME = "trace.ndjson"


class AttemptError(ValueError):
    """The attempt cannot be graded (layout or key problems; exit 2)."""


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

    Only successful calls count (isError false): a failed run_range
    produced no ground truth, and a failed invoke moved no data.
    Reconnaissance tools touch nothing by definition.
    """
    touched: set[str] = set()
    for record in records:
        if record.get("type") != "call":
            continue
        result = record.get("result")
        if not isinstance(result, Mapping) or result.get("isError") is not False:
            continue
        tool = record.get("tool")
        if tool == "run_range":
            touched.update(roster)
        elif tool == "invoke":
            blob = json.dumps(record.get("args") or {}, sort_keys=True)
            touched.update(fixtures_named(blob, roster))
    return touched


def grade_attempt(
    attempt_dir: Path,
    *,
    expected_path: Path,
    key_env: str | None,
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
            "passed": graded.get("passed") is True and not unverified,
        }
    )
    if not document["passed"]:
        document["reason"] = (
            "claims lack tool evidence" if unverified else "found-vs-expected grading failed"
        )
    return document
