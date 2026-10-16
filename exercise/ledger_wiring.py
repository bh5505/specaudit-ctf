"""Opt-in attempt-ledger wiring for the exercise runner (issue #90, unit 1).

``python -m exercise --ledger`` appends one attempt-ledger row per executed
lane after the run document is produced. The lane → row mapping lives here,
as one reviewable pure table (``map_outcome``), so the CLI stays thin and
the classification is auditable without running anything. Appending is
strictly additive: the run document, its lanes and its grading are read
only as classification evidence and are never changed, and without
``--ledger`` the CLI never touches this module's append path.

Honesty rules of the mapping:

- every executed lane gets a row — skips, refusals, timeouts, crashes and
  failed grades are never dropped from the denominator;
- a graded run whose verdict failed is a COMPLETED attempt with outcome
  ``graded-failed`` (wrong findings, not a refusal); only a refused grade
  (``score.failed-to-grade``) maps to the refusal class;
- the runner's arms/battery rows do not carry the envelope's refusal
  reasons (only ``status``/``envelope_status``), so an envelope-backed
  failure classifies as ``crash`` (unexpected failure) from the evidence
  the row actually holds; only the pre-dispatch contract error names a
  refusal;
- a skipped battery member is a refusal when its arming or target env is
  unset (not authorized on this host) and a setup-failure when the arm's
  binary is absent (launcher missing);
- the top-level run row is a completion with outcome ``run-failed`` unless
  some lane's failure classifies as timeout / crash / interruption /
  setup-failure, in which case that class propagates to the run row.

``detail_digest`` is sha256 over the canonical JSON of exactly the report
section the class was derived from; the section body never enters the
ledger. Attempt ids derive from the same digest, so re-running an
otherwise identical exercise is a legitimate ledger retry, never a new
attempt.

Fail-closed: attempt_ledger is imported lazily so a runtime without the
package fails the ledgered run loudly; a corrupt existing ledger aborts
before any append. No network, no subprocess, no clock reads.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

# Lanes of the attempt-ledger taxonomy used by this wiring: everything the
# exercise runner composes is a rehearsal; only the standalone grading lane
# is fixture-backed evidence.
LANE_REHEARSAL = "operator-rehearsal"
LANE_FIXTURE_BACKED = "fixture-backed"

# The runner's failed-to-grade marker (score lane refuses to grade).
_FAILED_TO_GRADE_SCHEMA = "score.failed-to-grade"

# "exceeded 300s" / "exceeded 900s timeout": both head timeout reasons.
_TIMEOUT = re.compile(r"exceeded \d+s")

# Failure classes that escalate the run-level row out of plain completion.
_ESCALATION_PRIORITY = ("timeout", "crash", "interruption", "setup-failure")


class LedgerWiringError(RuntimeError):
    """The --ledger wiring failed; the run must not pass as ledgered."""


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=False).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _detail(section: Mapping[str, Any]) -> tuple[str, str]:
    """Canonical section bytes → (detail_digest, attempt-id discriminator)."""
    raw = _canonical(section)
    return _digest(raw), hashlib.sha256(raw).hexdigest()[:16]


def _status_of(section: Mapping[str, Any]) -> object:
    status = section.get("status")
    if status is None or isinstance(status, str):
        return status
    return None


def _map_dispatch_row(row: Mapping[str, Any]) -> tuple[str, str]:
    """One arms-lane or battery-lane invocation row."""
    status = _status_of(row)
    reason = str(row.get("reason") or "")
    if status == "complete":
        return ("completion", "complete")
    if status == "degraded":
        return ("completion", "degraded")
    if status == "skipped":
        if reason == "battery: arm is not installed":
            return ("setup-failure", "not-installed")
        if "is unset; preset member skipped" in reason:
            return ("refusal", "skipped-unarmed")
        if "is unset; target-facing member skipped" in reason:
            return ("refusal", "skipped-no-target")
        return ("parse-failure", "unknown-skip-reason")
    if status == "failed":
        if reason == "arm request must be a mapping":
            return ("parse-failure", "invalid-request")
        if reason == "arm_id and action are required":
            return ("parse-failure", "invalid-request")
        if reason.startswith("pre-dispatch contract error"):
            return ("refusal", "refused")
        # Envelope-backed failure: the row holds no refusal reasons, so the
        # honest class from the recorded evidence is an unexpected failure.
        return ("crash", "invoke-failed")
    return ("parse-failure", "unknown-status")


def _map_head(lane: Mapping[str, Any]) -> tuple[str, str]:
    """The head lane: readiness probe or an executed/graded attempt."""
    mode = lane.get("mode")
    status = _status_of(lane)
    if mode == "readiness":
        if status == "available":
            return ("completion", "ready")
        if status == "skipped":
            return ("setup-failure", "launcher-missing")
        return ("parse-failure", "unknown-status")
    if mode != "executed":
        return ("parse-failure", "unknown-mode")
    if status == "passed":
        return ("completion", "attempt-passed")
    if status != "failed":
        return ("parse-failure", "unknown-status")
    reason = str(lane.get("reason") or "")
    low = reason.lower()
    # Order matters: the real-head timeout reason also says "killed", but
    # the timeout is the primary cause (the runner did the killing).
    if _TIMEOUT.search(low):
        return ("timeout", "head-timeout")
    if low.startswith("head spawn failed"):
        return ("setup-failure", "spawn-failed")
    if low.startswith("fake-head driver exited"):
        return ("crash", "driver-crashed")
    if "interrupted" in low or "stopped" in low:
        return ("interruption", "interrupted")
    if "killed" in low:
        return ("crash", "killed")
    if reason == "no tool calls were recorded; nothing is gradable":
        return ("abstention", "no-tool-calls")
    if reason == "trace failed verification; the attempt is not gradable":
        return ("parse-failure", "trace-unverified")
    if reason.startswith("attempt documents unusable"):
        return ("parse-failure", "documents-unusable")
    if "cannot grade it" in reason:
        return ("refusal", "refused")
    if (reason.startswith("attempt directory does not exist")
            or reason.startswith("attempt has no trace.ndjson")
            or reason.startswith("attempt has no found.json")):
        return ("setup-failure", "missing-attempt-layout")
    if reason.startswith("verifying an attempt requires the trace key"):
        return ("setup-failure", "missing-trace-key")
    if reason in (
        "claims lack tool evidence",
        "agent claims conflict with or lack verified trace evidence",
        "found-vs-expected grading failed",
    ):
        return ("completion", "graded-failed")
    spawn = lane.get("spawn")
    exit_code = spawn.get("exit_code") if isinstance(spawn, Mapping) else None
    if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0:
        return ("crash", "head-exited-nonzero")
    # The attempt ran and failed for a reason this mapping does not name:
    # still a completed attempt (the denominator keeps it), not a refusal.
    return ("completion", "attempt-failed")


def _map_range(lane: Mapping[str, Any]) -> tuple[str, str]:
    status = _status_of(lane)
    if status == "complete":
        return ("completion", "range-matched")
    if status == "degraded":
        return ("completion", "range-degraded")
    if status == "failed":
        return ("completion", "range-failed")
    return ("parse-failure", "unknown-status")


def _map_grade(lane: Mapping[str, Any]) -> tuple[str, str]:
    if not isinstance(lane, Mapping):
        return ("parse-failure", "malformed-section")
    if lane.get("schema") == _FAILED_TO_GRADE_SCHEMA:
        return ("refusal", "refused")
    if lane.get("passed") is True:
        return ("completion", "graded-passed")
    if lane.get("passed") is False:
        return ("completion", "graded-failed")
    return ("parse-failure", "unknown-status")


def _map_run(document: Mapping[str, Any]) -> tuple[str, str]:
    """The top-level run row: completion unless a lane's failure is better
    classified as timeout / crash / interruption / setup-failure."""
    status = _status_of(document)
    if status == "complete":
        return ("completion", "run-complete")
    if status == "degraded":
        return ("completion", "run-degraded")
    if status != "failed":
        return ("parse-failure", "unknown-status")
    best: tuple[int, str] | None = None
    for lane, _subject, section in _lane_sections(document):
        attempt_class, _ = map_outcome(lane, section)
        if attempt_class in _ESCALATION_PRIORITY:
            rank = _ESCALATION_PRIORITY.index(attempt_class)
            if best is None or rank < best[0]:
                best = (rank, attempt_class)
    if best is not None:
        return (best[1], "run-failed")
    return ("completion", "run-failed")


def map_outcome(lane: str, row_or_doc: Mapping[str, Any]) -> tuple[str, str]:
    """Pure mapping: one report section → its (attempt_class, outcome).

    ``lane`` names the report section: run | range | grade | arms |
    battery | head. Raises ValueError for an unknown lane (a wiring bug,
    never a data condition).
    """
    if lane == "run":
        return _map_run(row_or_doc)
    if lane == "range":
        return _map_range(row_or_doc)
    if lane == "grade":
        return _map_grade(row_or_doc)
    if lane in ("arms", "battery"):
        return _map_dispatch_row(row_or_doc)
    if lane == "head":
        return _map_head(row_or_doc)
    raise ValueError(f"unknown ledger lane: {lane}")


def _lane_sections(document: Mapping[str, Any]) -> list[tuple[str, str, Mapping[str, Any]]]:
    """(lane tag, subject, section) for every executed lane, in row order."""
    sections: list[tuple[str, str, Mapping[str, Any]]] = [
        ("range", "range", document["range"])
    ]
    grading = document.get("grading")
    if grading is not None:
        challenge = document.get("challenge")
        track = grading.get("track") if isinstance(grading, Mapping) else None
        name = challenge or (track if isinstance(track, str) and track else "unbound")
        sections.append(("grade", f"grade:{name}", grading))
    for row in document.get("arms") or ():
        sections.append(
            ("arms", f"arms:{row.get('arm_id')}:{row.get('action')}", row))
    for row in document.get("battery") or ():
        sections.append(("battery", f"battery:{row.get('arm_id')}", row))
    head = document.get("head")
    if head is not None:
        sections.append(
            ("head", "head:" + str(head.get("head") or "attempt"), head))
    return sections


def _sections(document: Mapping[str, Any]) -> list[tuple[str, str, Mapping[str, Any]]]:
    """All row sections: every lane, then the run summary row last."""
    return _lane_sections(document) + [("run", "run", document)]


def build_rows(document: Mapping[str, Any], *, assistance: str,
               recorded_at: datetime | str) -> list[dict[str, Any]]:
    """Pure: the ledger row content for every executed lane of one run.

    Row order: range, grade (when present), arms rows, battery rows, head
    lane, and the run summary row last. Each row's detail_digest covers
    exactly the section its classification was derived from.
    """
    rows: list[dict[str, Any]] = []
    for lane, subject, section in _sections(document):
        attempt_class, outcome = map_outcome(lane, section)
        detail_digest, discriminator = _detail(section)
        rows.append({
            "attempt_id": f"{lane}-{discriminator}",
            "lane": LANE_FIXTURE_BACKED if lane == "grade" else LANE_REHEARSAL,
            "subject": subject,
            "attempt_class": attempt_class,
            "outcome": outcome,
            "assistance": assistance,
            "detail_digest": detail_digest,
            "recorded_at": recorded_at,
        })
    return rows


def _read_ledger_rows(path: Path) -> list[dict]:
    """Read the JSON-lines ledger; a missing file starts an empty chain."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise LedgerWiringError(f"ledger unreadable: {exc}") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise LedgerWiringError(f"ledger is not utf-8: {exc}") from exc
    if text and not text.endswith("\n"):
        raise LedgerWiringError("ledger does not end with a newline")
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise LedgerWiringError(f"ledger line {number} is blank")
        try:
            row = json.loads(line, parse_constant=_no_constant)
        except ValueError as exc:
            raise LedgerWiringError(f"ledger line {number} is not JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise LedgerWiringError(f"ledger line {number} is not an object")
        rows.append(row)
    return rows


def _no_constant(value: str) -> None:
    raise ValueError(f"non-JSON constant {value}")


def _append_ledger_line(path: Path, row: dict) -> None:
    """Append one canonical line; refuse to extend a partial trailing line."""
    if path.exists() and path.stat().st_size > 0:
        with path.open("rb") as stream:
            stream.seek(-1, os.SEEK_END)
            if stream.read(1) != b"\n":
                raise LedgerWiringError("refusing to append after a partial line")
    line = json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False,
                      ensure_ascii=False) + "\n"
    with path.open("ab") as stream:
        stream.write(line.encode("utf-8"))


def append_document_rows(ledger: Path, document: Mapping[str, Any], *,
                         ledger_key: bytes | None = None,
                         assistance: str = "first-pass",
                         recorded_at: datetime | str | None = None) -> str:
    """Verify the existing chain, append every executed lane's rows.

    All rows are validated and chained in memory BEFORE any byte is
    written, so a taxonomy or chain refusal leaves the file untouched.
    Returns the new head digest. Raises LedgerWiringError on any ledger
    problem; the caller must fail the run closed (never exit as
    ledgered).
    """
    if recorded_at is None:
        raise LedgerWiringError("ledger rows require an explicit recording time")
    try:
        from attempt_ledger import LedgerError, append_row, verify_ledger
    except ImportError as exc:
        raise LedgerWiringError(f"attempt_ledger package unavailable: {exc}") from exc
    content = build_rows(document, assistance=assistance, recorded_at=recorded_at)
    rows = _read_ledger_rows(Path(ledger))
    check = verify_ledger(rows, hmac_key=ledger_key)
    if not check.ok:
        raise LedgerWiringError(
            f"existing ledger fails verification: {', '.join(check.reasons)}")
    existing_count = len(rows)
    try:
        for row in content:
            rows, _ = append_row(rows, row, hmac_key=ledger_key)
    except LedgerError as exc:
        raise LedgerWiringError(str(exc)) from exc
    try:
        for stored in rows[existing_count:]:
            _append_ledger_line(Path(ledger), stored)
    except OSError as exc:
        raise LedgerWiringError(f"ledger append failed: {exc}") from exc
    return rows[-1]["row_digest"]
