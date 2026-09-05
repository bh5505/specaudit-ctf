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
      admission path as ``python -m extension invoke``; an arm that is
      not installed is recorded skipped.
    - head (optional): readiness only — whether the named agent head's
      MCP launcher ships in this checkout. Attachment is an
      operator-driven step and is never simulated here.
    """
    ext = extension if extension is not None else Extension()

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
    range_lane = {
        "status": range_doc["status"] if fixtures is None else _subset_status(reported_rows),
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
    if (found_path is None) != (expected_path is None):
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
            row.update(status=STATUS_FAILED, reason="pre-dispatch contract error")
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
    if head is not None:
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
            "launcher": str(launcher),
            "ready": launcher.is_file(),
            "status": "available" if launcher.is_file() else "skipped",
        }

    lanes_ok = [range_matched]
    if grading_lane is not None:
        lanes_ok.append(grading_lane.get("passed") is True)
    arm_failures = [row for row in arms_lane if row["status"] == STATUS_FAILED]
    lanes_ok.append(not arm_failures)
    if all(lanes_ok):
        status = STATUS_COMPLETE
    elif arm_failures:
        # A requested arm invocation that failed fails the run.
        status = STATUS_FAILED
    elif not range_matched:
        # The ground truth itself did not hold: nothing else matters.
        status = STATUS_FAILED
    elif grading_lane is not None and grading_lane.get("passed") is not True:
        # A graded challenge that did not pass is a failure, not a
        # degraded success: partial coverage never reads as all-clear.
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
