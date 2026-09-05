"""The exercise runner: one command composes a full rehearsal.

Composes the synthetic range, optional challenge grading, optional
standalone arm invocations (through the same admission path as the
CLI), and an optional agent-head readiness probe into one consolidated
run report (JSON). A new surface enters as a parallel module entry —
the four-subcommand CLI and four-tool MCP contracts are untouched.

Fail-closed doctrine: a lane that cannot run is recorded as skipped or
failed with a reason; a report never claims success it cannot prove.
``complete`` requires the range to have matched, the grading (when
supplied) to have passed, and every standalone arm invocation to have
succeeded. Anything less is ``degraded`` or ``failed``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.envelopes import parse_execution_result
from extension.range import run_range

SCHEMA_ID = "exercise.run.v1"
STATUS_COMPLETE = "complete"
STATUS_DEGRADED = "degraded"
STATUS_FAILED = "failed"
HEAD_IDS = ("claude-code", "codex-cli")
FAKE_HEAD = "fake"
HEAD_STATUS_PASSED = "passed"


class ExerciseError(Exception):
    """Fail-closed exercise composition error."""


def run_exercise(
    *,
    extension: Extension | None = None,
    challenge: str | None = None,
    fixtures: Sequence[str] | None = None,
    arms: Sequence[Mapping[str, Any]] | None = None,
    seed: int | None = None,
    found_path: str | None = None,
    expected_path: str | None = None,
    head: str | None = None,
    attempt_dir: str | None = None,
    head_execute: bool = False,
    trace_key: str | None = None,
) -> dict[str, Any]:
    """Compose the lanes and return the consolidated run report.

    Lanes:
    - range (required): the full synthetic lifecycle, ``arm_ids=()``
      so host-installed arms never gate the rehearsal; when
      ``fixtures`` is given the report narrows to those rows (the run
      itself always covers every shipped fixture).
    - grading (optional): requires both a found-findings document and
      the challenge's expected contract; a grading miss fails the run.
    - arms (optional): standalone invocations as
      ``[{"arm_id", "action", "args"}, ...]`` riding the same X2-PUB
      admission path as ``python -m extension invoke``; a failed arm
      row fails the run.
    - head (optional): readiness only for the shipped real-agent
      bundles — whether the named head's MCP launcher exists in this
      checkout. Attachment is an operator-driven step and is never
      simulated here. The lane executes only over an ``attempt_dir``:
      ``head_execute=True`` spawns the lane-internal fake head (never
      a real agent CLI — real heads run out-of-band, their attempts
      graded by passing ``attempt_dir`` afterwards), then the captured
      server-side trace + claimed findings grade through
      ``attempt.grade_attempt``. A failed executed attempt fails the
      run, like a failed grade.
    """
    ext = extension if extension is not None else Extension()

    if head_execute:
        if head != FAKE_HEAD:
            raise ExerciseError(
                "--head-execute only drives the lane-internal fake head; "
                "real agent CLIs are never spawned by the runner — run the "
                "agent out-of-band and grade its attempt with --attempt-dir"
            )
        if attempt_dir is None:
            raise ExerciseError("--head-execute requires --attempt-dir")
        if expected_path is None:
            raise ExerciseError("--head-execute requires --expected (the challenge contract)")
    elif head == FAKE_HEAD and attempt_dir is None:
        raise ExerciseError(
            "the fake head has no launcher to probe; it exists only under "
            "--head-execute, or grade an existing fake attempt with --attempt-dir"
        )
    if attempt_dir is not None and expected_path is None:
        raise ExerciseError("grading an attempt requires --expected (the challenge contract)")

    range_doc = run_range(extension=ext, seed=seed, arm_ids=())
    reported_rows = range_doc["fixtures"]
    if fixtures is not None:
        wanted = list(dict.fromkeys(fixtures))
        known = {row["id"] for row in reported_rows}
        unknown = [fixture_id for fixture_id in wanted if fixture_id not in known]
        if unknown:
            raise ExerciseError(f"unknown fixtures: {', '.join(unknown)}")
        reported_rows = [row for row in reported_rows if row["id"] in set(wanted)]
    range_matched = bool(reported_rows) and all(
        row["matched_expected"] is True for row in reported_rows
    )
    reported_status = (
        range_doc["status"] if fixtures is None else _subset_status(reported_rows)
    )
    range_lane = {
        "full_status": range_doc["status"],
        # A subset report narrows what is listed; it never upgrades a
        # failed full run.
        "status": reported_status if range_doc["ok"] is True else STATUS_FAILED,
        "ok": range_matched,
        "fixtures": [row["id"] for row in reported_rows],
        "matched": range_matched,
        "chains": [
            chain
            for row in reported_rows
            for chain in row.get("chains", [])
        ],
    }

    grading_lane: dict[str, Any] | None = None
    # The found/expected pairing is the STANDALONE grading lane's rule;
    # the attempt modes require --expected only (the found document
    # comes from the attempt directory).
    if (found_path is None) != (expected_path is None) and not (
        head_execute or attempt_dir is not None
    ):
        raise ExerciseError(
            "grading requires both the found document and the expected contract"
        )
    if found_path is not None:
        from score.grading import GradingError, grade_files

        try:
            grading_lane = grade_files(Path(found_path), Path(expected_path))  # type: ignore[arg-type]
        except GradingError as exc:
            grading_lane = {
                "schema": "score.failed-to-grade",
                "passed": False,
                "error": str(exc),
            }

    arms_lane: list[dict[str, Any]] = []
    for request in arms or ():
        if not isinstance(request, Mapping):
            arms_lane.append(
                {
                    "arm_id": "",
                    "action": "",
                    "status": STATUS_FAILED,
                    "reason": "arm request must be a mapping",
                }
            )
            continue
        arm_id = str(request.get("arm_id") or "")
        action = str(request.get("action") or "")
        args = request.get("args") or {}
        row: dict[str, Any] = {"arm_id": arm_id, "action": action}
        if not arm_id or not action:
            row.update(status=STATUS_FAILED, reason="arm_id and action are required")
            arms_lane.append(row)
            continue
        try:
            outcome = dispatch_invoke(ext, arm_id=arm_id, action=action, args=dict(args))
        except Exception as exc:  # noqa: BLE001 - recorded per arm, stay fail-closed
            row.update(status=STATUS_FAILED, reason=str(exc))
            arms_lane.append(row)
            continue
        if outcome.envelope is None:
            row.update(
                status=STATUS_FAILED,
                reason=(
                    "pre-dispatch contract error"
                    + (f": {outcome.stderr_line}" if outcome.stderr_line else "")
                ),
            )
            arms_lane.append(row)
            continue
        parsed = parse_execution_result(outcome.envelope)
        row.update(
            status=(
                STATUS_COMPLETE
                if parsed.schema_ok and parsed.status == "complete"
                else STATUS_DEGRADED
                if parsed.schema_ok and parsed.status == "degraded"
                else STATUS_FAILED
            ),
            capability_id=outcome.envelope.get("capability_id"),
            envelope_status=outcome.envelope.get("status"),
        )
        arms_lane.append(row)

    head_lane: dict[str, Any] | None = None
    attempt_executed = attempt_dir is not None
    if head_execute:
        head_lane = _execute_fake_head(
            attempt_dir=str(attempt_dir),  # type: ignore[arg-type]
            expected_path=str(expected_path),  # type: ignore[arg-type]
            trace_key=trace_key
            if trace_key is not None
            else os.environ.get("SPECAUDIT_CTF_MCP_TRACE_KEY"),
        )
    elif attempt_dir is not None:
        from exercise.attempt import AttemptError, grade_attempt

        key = (
            trace_key
            if trace_key is not None
            else os.environ.get("SPECAUDIT_CTF_MCP_TRACE_KEY")
        )
        try:
            document = grade_attempt(
                Path(attempt_dir),
                expected_path=Path(expected_path),  # type: ignore[arg-type]
                key_env=key,
            )
        except AttemptError as exc:
            document = {
                "schema": "specaudit.ctf.attempt.v1",
                "attempt_dir": attempt_dir,
                "status": "failed",
                "reason": str(exc),
                "passed": False,
            }
        head_lane = _attempt_lane(head=head, document=document)
    elif head is not None:
        if head not in HEAD_IDS:
            raise ExerciseError(f"unknown head: {head} (shipped: {', '.join(HEAD_IDS)})")
        launcher = (
            Path(__file__).resolve().parent.parent
            / "extension"
            / "heads"
            / head
            / "launch_mcp.py"
        )
        head_lane = {
            "head": head,
            "mode": "readiness",
            "launcher": str(launcher),
            "ready": launcher.is_file(),
            "status": "available" if launcher.is_file() else "skipped",
        }

    lanes_ok = [
        range_matched,
        # The full run must hold too: a subset report may narrow what is
        # listed, never what must have matched.
        range_doc["ok"] is True,
    ]
    if grading_lane is not None:
        lanes_ok.append(grading_lane.get("passed") is True)
    arm_failures = [row for row in arms_lane if row["status"] == STATUS_FAILED]
    lanes_ok.append(not arm_failures)
    if attempt_executed:
        lanes_ok.append(head_lane.get("passed") is True)  # type: ignore[union-attr]
    if all(lanes_ok):
        status = STATUS_COMPLETE
    elif arm_failures:
        # A requested arm invocation that failed fails the run.
        status = STATUS_FAILED
    elif not range_matched or range_doc["ok"] is not True:
        # The ground truth itself did not hold (reported subset or the
        # full run): nothing else matters.
        status = STATUS_FAILED
    elif grading_lane is not None and grading_lane.get("passed") is not True:
        # A graded challenge that did not pass is a failure, not a
        # degraded success: partial coverage never reads as all-clear.
        status = STATUS_FAILED
    elif attempt_executed and head_lane.get("passed") is not True:  # type: ignore[union-attr]
        # An executed head attempt that did not pass is a failure for
        # the same reason: claims without owned evidence never degrade
        # into a success.
        status = STATUS_FAILED
    else:
        status = STATUS_DEGRADED
    document = {
        "schema": SCHEMA_ID,
        "challenge": challenge,
        "seed": seed,
        "status": status,
        "ok": status == STATUS_COMPLETE,
        "live_aws": False,
        "range": range_lane,
        "grading": grading_lane,
        "arms": arms_lane,
        "head": head_lane,
    }
    document["summary"] = _summary(document)
    return document


def _subset_status(rows: Sequence[Mapping[str, Any]]) -> str:
    if rows and all(row["matched_expected"] is True for row in rows):
        return STATUS_COMPLETE
    return STATUS_FAILED


DRIVER_TIMEOUT_SECONDS = 300


def _execute_fake_head(
    *,
    attempt_dir: str,
    expected_path: str,
    trace_key: str | None,
) -> dict[str, Any]:
    """Spawn the lane-internal fake head, then grade its attempt.

    The runner mints the trace key and attempt id for the child (they
    travel by environment, never through the attempt directory), waits
    for the driver, and grades whatever the SERVER recorded — the
    driver's own summary is transport noise, not evidence.
    """
    from exercise.attempt import AttemptError, grade_attempt
    from extension.trace import mint_key

    directory = Path(attempt_dir)
    key = trace_key if trace_key and trace_key.strip() else mint_key()
    attempt_id = os.urandom(32).hex()
    child_env = dict(os.environ)
    child_env["SPECAUDIT_CTF_MCP_TRACE"] = str(directory / "trace.ndjson")
    child_env["SPECAUDIT_CTF_MCP_TRACE_KEY"] = key
    child_env["SPECAUDIT_CTF_MCP_TRACE_ATTEMPT"] = attempt_id
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "exercise.fake_head",
                "--persona",
                "competent",
                "--expected",
                expected_path,
                "--attempt-dir",
                attempt_dir,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=DRIVER_TIMEOUT_SECONDS,
            cwd=str(Path(__file__).resolve().parent.parent),
            env=child_env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _failed_attempt_lane(
            attempt_dir, f"fake-head driver exceeded {DRIVER_TIMEOUT_SECONDS}s"
        )
    if proc.returncode != 0:
        return _failed_attempt_lane(
            attempt_dir,
            f"fake-head driver exited {proc.returncode}: "
            + (proc.stderr or "").strip()[:400],
        )
    try:
        document = grade_attempt(
            directory,
            expected_path=Path(expected_path),
            key_env=key,
        )
    except AttemptError as exc:
        return _failed_attempt_lane(attempt_dir, str(exc))
    lane = dict(document)
    lane.update(
        {
            "head": FAKE_HEAD,
            "mode": "executed",
            "status": "passed" if document.get("passed") is True else STATUS_FAILED,
        }
    )
    return lane


def _attempt_lane(head: str | None, document: Mapping[str, Any]) -> dict[str, Any]:
    """Wrap a graded attempt document as the executed head-lane section."""
    lane = dict(document)
    lane["head"] = head
    lane["mode"] = "executed"
    lane["status"] = "passed" if document.get("passed") is True else STATUS_FAILED
    return lane


def _failed_attempt_lane(attempt_dir: str, reason: str) -> dict[str, Any]:
    return {
        "head": FAKE_HEAD,
        "mode": "executed",
        "attempt_dir": attempt_dir,
        "status": STATUS_FAILED,
        "passed": False,
        "reason": reason,
    }


def _summary(document: Mapping[str, Any]) -> str:
    parts = [f"exercise {document['status']}"]
    range_lane = document["range"]
    parts.append(
        f"range {range_lane['status']} ({len(range_lane['fixtures'])} fixtures)"
    )
    if document["grading"] is not None:
        grade = document["grading"]
        parts.append(f"grading {'passed' if grade.get('passed') else 'not passed'}")
        if "score" in grade:
            parts.append(f"score {grade['score']:.2f}")
    if document["arms"]:
        ok = sum(1 for row in document["arms"] if row["status"] == STATUS_COMPLETE)
        parts.append(f"arms {ok}/{len(document['arms'])}")
    if document["head"] is not None:
        parts.append(f"head {document['head']['status']}")
    return "; ".join(parts)
