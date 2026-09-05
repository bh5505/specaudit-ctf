"""Challenge grading: found-vs-expected finding-set comparison.

Each challenge ships an expected-findings contract (the finding set a
correct auditor would defend, every entry tracing to a planted fixture
violation). A participant ships a found-findings document in the same
schema. The grader compares them strictly:

- a found finding counts only with owned evidence — non-empty
  ``traces_to``, ``control``, and ``rationale``; anything less is
  invalid and can never count as a hit;
- expected keys the participant did not ship are misses;
- found keys absent from the contract are extras;
- severity disagreements are surfaced as soft flags — calibration
  feedback, never a verdict input;
- partial coverage NEVER reads as all-clear: the verdict passes only
  with zero misses, zero extras, zero invalid rows, and a non-empty
  contract.

Schema notes: both documents are validated strictly (unknown keys are
rejected, the ``total`` field must equal the findings list length), so
a malformed deliverable is a usage error (exit 2), not a score.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

SCHEMA_ID = "specaudit.ctf.grade.v1"

_SEVERITIES = ("critical", "high", "medium", "low", "none")
_EVIDENCE_KEYS = ("control", "rationale", "traces_to")
_FINDING_KEYS = ("finding_key", "control", "severity", "rationale", "traces_to")


class GradingError(ValueError):
    """A found/expected document is malformed or unusable (exit 2)."""


def load_findings_document(path: Path, *, what: str) -> dict[str, Any]:
    """Strictly load and validate a findings document."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise GradingError(f"{what} unreadable: {path} ({exc})") from exc
    except json.JSONDecodeError as exc:
        raise GradingError(f"{what} is not valid JSON: {path}") from exc
    if not isinstance(raw, dict):
        raise GradingError(f"{what} must be a JSON object: {path}")
    allowed = {"track", "seed", "fixtures", "total", "findings", "stage", "stages"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise GradingError(f"{what} has unknown keys: {', '.join(unknown)}")
    track = raw.get("track")
    if not isinstance(track, str) or not track.strip():
        raise GradingError(f"{what} requires a non-empty track")
    findings = raw.get("findings")
    if not isinstance(findings, list):
        raise GradingError(f"{what} requires a findings list")
    seen_keys: set[str] = set()
    total = raw.get("total")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise GradingError(f"{what} requires a non-negative integer total")
    if total != len(findings):
        raise GradingError(
            f"{what} total ({total}) does not match findings count ({len(findings)})"
        )
    for row in findings:
        if not isinstance(row, dict):
            raise GradingError(f"{what} findings must be objects")
        unknown = sorted(set(row) - set(_FINDING_KEYS))
        if unknown:
            raise GradingError(
                f"{what} finding has unknown keys: {', '.join(unknown)}"
            )
        for key in _FINDING_KEYS:
            if not isinstance(row.get(key), str):
                raise GradingError(
                    f"{what} finding {key!r} must be a string"
                )
        if not row["finding_key"].strip():
            raise GradingError(f"{what} finding_key must be a non-empty string")
        if row["finding_key"] in seen_keys:
            raise GradingError(
                f"{what} has duplicate finding_key: {row['finding_key']}"
            )
        seen_keys.add(row["finding_key"])
        severity = str(row.get("severity"))
        if severity not in _SEVERITIES:
            raise GradingError(
                f"{what} finding severity must be one of {', '.join(_SEVERITIES)}"
            )
    return raw


def grade(found: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    """Compare one found-findings document against its contract."""
    expected_rows = list(expected["findings"])
    expected_keys: dict[str, dict[str, Any]] = {
        row["finding_key"]: row for row in expected_rows
    }
    hits: list[str] = []
    misses: list[str] = []
    extras: list[str] = []
    invalid: list[dict[str, str]] = []
    severity_mismatches: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in found["findings"]:
        key = row["finding_key"]
        if key in seen:
            invalid.append({"finding_key": key, "reason": "duplicate finding_key"})
            continue
        seen.add(key)
        contract = expected_keys.get(key)
        if contract is None:
            extras.append(key)
            continue
        evidence_gaps = [
            evidence for evidence in _EVIDENCE_KEYS if not str(row.get(evidence) or "").strip()
        ]
        if evidence_gaps:
            invalid.append(
                {
                    "finding_key": key,
                    "reason": "unowned evidence (missing: " + ", ".join(evidence_gaps) + ")",
                }
            )
            continue
        hits.append(key)
        if str(row.get("severity")) != str(contract.get("severity")):
            severity_mismatches.append(
                {
                    "finding_key": key,
                    "expected": str(contract.get("severity")),
                    "found": str(row.get("severity")),
                }
            )
    # A key counts as covered only by a valid hit: an evidence-less
    # claim or a duplicate is both an invalid row AND a miss — the
    # participant named the violation but never owned the evidence.
    misses = sorted(set(expected_keys) - set(hits))

    track_match = str(found.get("track")) == str(expected.get("track"))
    expected_total = len(expected_rows)
    passed = (
        track_match
        and expected_total > 0
        and not misses
        and not extras
        and not invalid
    )
    return {
        "schema": SCHEMA_ID,
        "track": expected.get("track"),
        "track_match": track_match,
        "expected_total": expected_total,
        "hits": sorted(hits),
        "misses": misses,
        "extras": extras,
        "invalid": invalid,
        "severity_mismatches": severity_mismatches,
        "score": (len(hits) / expected_total) if expected_total else 0.0,
        "passed": passed,
    }


def grade_files(found_path: Path, expected_path: Path) -> dict[str, Any]:
    """Load both documents and grade; raises GradingError on schema faults."""
    expected = load_findings_document(expected_path, what="expected contract")
    found = load_findings_document(found_path, what="found findings")
    return grade(found, expected)


def verdict(document: Mapping[str, Any]) -> int:
    """Exit code for a grade document: 0 passed, 1 graded-but-not-passed."""
    return 0 if document.get("passed") is True else 1
