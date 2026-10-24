"""Compose range results, arm calls, challenge grading, and agent attempts.

The JSON report records each selected component's result. ``complete`` means
the range matched, grading passed when requested, and selected arms succeeded.
Unavailable optional components are reported as skipped.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.range import run_range

SCHEMA_ID = "exercise.run.v1"
STATUS_COMPLETE = "complete"
STATUS_DEGRADED = "degraded"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
HEAD_IDS = ("claude-code", "codex-cli", "qwen-code")
FAKE_HEAD = "fake"


class ExerciseError(Exception):
    """Invalid exercise request or composition failure."""


# An ok=false arm result degrades the run only when its output carries a
# validated honesty status from the closed degraded set AND structured,
# non-empty, bounded evidence. Anything else - error statuses, string or
# missing evidence, oversized evidence - stays failed: partial data must
# never silently read as all-clear, and transport errors never degrade.
_DEGRADED_ARM_STATUSES = frozenset({"partial", "degraded", "unknown"})
_MAX_ARM_EVIDENCE_ITEMS = 64
_OSV_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OSV_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_MAX_OSV_SOURCE_PAGES = 10


def _evidence_is_bounded(value: Any) -> bool:
    if isinstance(value, (str, bytes)) or not isinstance(value, (Mapping, Sequence)):
        return False
    return 0 < len(value) <= _MAX_ARM_EVIDENCE_ITEMS


def _arm_status(document: Mapping[str, Any]) -> str:
    if document.get("ok") is True:
        return STATUS_COMPLETE
    output = document.get("output")
    if (
        isinstance(output, Mapping)
        and output.get("status") in _DEGRADED_ARM_STATUSES
        and _evidence_is_bounded(output.get("evidence"))
    ):
        return STATUS_DEGRADED
    return STATUS_FAILED


def _result_projection(document: Mapping[str, Any]) -> dict[str, Any]:
    """A small, redacted source/completeness projection of a reader result.

    Only honesty fields survive: status and reason strings (already
    redacted by the arms), an evidence item count, and bounded source
    provenance. Raw evidence rows, identity material, file paths, and
    free-text detail never enter an exercise report.
    """
    output = document.get("output")
    if not isinstance(output, Mapping):
        return {}
    projection: dict[str, Any] = {}
    for key in ("status", "reason"):
        value = output.get(key)
        if isinstance(value, str) and value:
            projection[key] = value
    evidence = output.get("evidence")
    if _evidence_is_bounded(evidence):
        projection["evidence_items"] = len(evidence)
    source = output.get("source")
    if isinstance(source, Mapping) and isinstance(source.get("kind"), str):
        kept = {"kind": source["kind"]}
        if isinstance(source.get("sha256"), str):
            kept["sha256"] = source["sha256"]
        projection["source"] = kept
    elif isinstance(source, Mapping) and document.get("arm_id") == "osv":
        digest = source.get("sha256")
        if (
            isinstance(digest, str)
            and digest.startswith("sha256:")
            and _OSV_DIGEST_RE.fullmatch(digest[7:])
        ):
            kept = {"kind": "osv-snapshot", "sha256": digest}
            snapshot_time = source.get("snapshot_time")
            if isinstance(snapshot_time, str) and _OSV_TIME_RE.fullmatch(snapshot_time):
                kept["snapshot_time"] = snapshot_time
            projection["source"] = kept
        elif (
            source.get("host") == "https://api.osv.dev"
            and source.get("endpoint") == "/v1/query"
        ):
            kept = {
                "kind": "osv-live",
                "host": source["host"],
                "endpoint": source["endpoint"],
            }
            fetched_at = source.get("fetched_at")
            if isinstance(fetched_at, str) and _OSV_TIME_RE.fullmatch(fetched_at):
                kept["fetched_at"] = fetched_at
            pages = source.get("pages")
            if type(pages) is int and 0 <= pages <= _MAX_OSV_SOURCE_PAGES:
                kept["pages"] = pages
            outcomes = source.get("page_outcomes")
            if isinstance(outcomes, list) and len(outcomes) <= _MAX_OSV_SOURCE_PAGES:
                digests = []
                for entry in outcomes:
                    if not isinstance(entry, Mapping):
                        continue
                    request_digest = entry.get("request_sha256")
                    response_digest = entry.get("response_sha256")
                    if (
                        isinstance(request_digest, str)
                        and _OSV_DIGEST_RE.fullmatch(request_digest)
                        and isinstance(response_digest, str)
                        and _OSV_DIGEST_RE.fullmatch(response_digest)
                    ):
                        digests.append(
                            {
                                "request_sha256": request_digest,
                                "response_sha256": response_digest,
                            }
                        )
                kept["page_digests"] = digests
            projection["source"] = kept
    return projection


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
    agent_claims_path: str | None = None,
    head_execute: bool = False,
    trace_key: str | None = None,
    battery: bool = False,
    attempt_prompt: str | None = None,
) -> dict[str, Any]:
    """Compose the lanes and return the consolidated run report.

    Lanes:
    - range (required): the full synthetic lifecycle, ``arm_ids=()``;
      when
      ``fixtures`` is given the report narrows to those rows (the run
      itself always covers every shipped fixture).
    - grading (optional): requires both a found-findings document and
      the challenge's expected contract; a grading miss fails the run.
    - arms (optional): standalone invocations as
      ``[{"arm_id", "action", "args"}, ...]`` using the same handlers as
      ``python -m extension invoke``; a failed arm
      row fails the run.
    - battery (optional): the default rehearsal preset
      (``exercise/battery.py``) spanning the exercise domains — the
      checkov, semgrep inline rules, the ATT&CK demo-bundle lookup,
      wapiti, and nmap. The target-facing pair uses ``LAB_TARGET_HOST``.
      A member that is not installed or whose target env
      is unset is SKIPPED (the run degrades); a member that runs and fails fails the
      run. zgrab2 composes through ``arms`` in the lab instead (it
      needs a per-run module choice).
    - head (optional): readiness only for the shipped real-agent
      bundles — whether the named head's MCP launcher exists in this
      checkout. Attachment is an operator-driven step and is never
      simulated here. The lane executes only over an ``attempt_dir``:
      ``head_execute=True`` with the fake head spawns the
      lane-internal scripted client; with a REAL head id
      (``claude-code`` / ``codex-cli`` / ``qwen-code``) it spawns the named agent CLI
      headless with the standard CLI command or an optional command
      override (``EXERCISE_HEAD_*_CMD``), and an ``--attempt-prompt``.
      Either way the captured
      server-side trace + claimed findings grade through
      ``attempt.grade_attempt``. A failed executed attempt fails the
      run, like a failed grade.
    """
    ext = extension if extension is not None else Extension()
    prompt_facts: tuple[str, str, int] | None = None
    head_command: str | None = None

    if agent_claims_path is not None and attempt_dir is None:
        raise ExerciseError("--agent-claims requires --attempt-dir")

    if head_execute:
        if head == FAKE_HEAD:
            if attempt_prompt is not None:
                raise ExerciseError(
                    "--attempt-prompt belongs to real-head execution; the "
                    "fake head is scripted and takes no operator prompt"
                )
            if attempt_dir is None:
                raise ExerciseError("--head-execute requires --attempt-dir")
            if expected_path is None:
                raise ExerciseError("--head-execute requires --expected (the challenge contract)")
        elif head in HEAD_IDS:
            from .real_head import command_for, load_prompt, RealHeadError

            try:
                cmd = command_for(head)
            except RealHeadError as exc:
                # HEAD_IDS and the command map drifting apart would
                # otherwise escape as a traceback past the usage
                # boundary; unreachable today, pinned by construction.
                raise ExerciseError(str(exc)) from None
            head_command = cmd
            if attempt_prompt is None:
                raise ExerciseError(
                    f"--head-execute --head {head} requires --attempt-prompt "
                    "<file> (the operator-supplied attempt prompt)"
                )
            if attempt_dir is None:
                raise ExerciseError("--head-execute requires --attempt-dir")
            if expected_path is None:
                raise ExerciseError("--head-execute requires --expected (the challenge contract)")
            try:
                prompt_text, prompt_sha256, prompt_chars = load_prompt(attempt_prompt)
            except RealHeadError as exc:
                raise ExerciseError(str(exc)) from None
            prompt_facts = (prompt_text, prompt_sha256, prompt_chars)
        elif head is None:
            raise ExerciseError(
                "--head-execute requires --head: 'fake' for the lane-internal "
                "scripted head, or a real head (claude-code, codex-cli, qwen-code)"
            )
        else:
            raise ExerciseError(f"unknown head: {head} (shipped: fake, {', '.join(HEAD_IDS)})")
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
        row.update(status=_arm_status(outcome.document))
        if outcome.document.get("error"):
            row["reason"] = outcome.document["error"]
        projection = _result_projection(outcome.document)
        if projection:
            row["result"] = projection
        arms_lane.append(row)

    battery_lane: list[dict[str, Any]] = []
    if battery:
        battery_lane = _run_battery(ext)

    head_lane: dict[str, Any] | None = None
    attempt_executed = attempt_dir is not None
    if head_execute and head == FAKE_HEAD:
        head_lane = _execute_fake_head(
            attempt_dir=str(attempt_dir),  # type: ignore[arg-type]
            expected_path=str(expected_path),  # type: ignore[arg-type]
            trace_key=trace_key
            if trace_key is not None
            else os.environ.get("SPECAUDIT_CTF_MCP_TRACE_KEY"),
            claims_path=Path(agent_claims_path) if agent_claims_path else None,
        )
    elif head_execute:
        from .real_head import execute_real_head, resolve_timeout, RealHeadError

        if prompt_facts is None or head_command is None:
            # Keep malformed internal state an operator-facing error.
            raise ExerciseError(
                "internal: real-head execution reached without command or prompt"
            )
        prompt_text, prompt_sha256, prompt_chars = prompt_facts
        try:
            timeout_seconds = resolve_timeout()
        except RealHeadError as exc:
            raise ExerciseError(str(exc)) from None
        try:
            head_lane = execute_real_head(
                head=str(head),
                cmd=head_command,
                attempt_dir=str(attempt_dir),  # type: ignore[arg-type]
                expected_path=str(expected_path),  # type: ignore[arg-type]
                prompt_text=prompt_text,
                prompt_sha256=prompt_sha256,
                prompt_chars=prompt_chars,
                timeout_seconds=timeout_seconds,
                claims_path=Path(agent_claims_path) if agent_claims_path else None,
            )
        except RealHeadError as exc:
            # Command/setup failures (codex preflight, mcp-config write,
            # attempt-dir creation) are operator-facing usage errors:
            # exit 2 with a reason, never a traceback.
            raise ExerciseError(str(exc)) from None
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
                claims_path=Path(agent_claims_path) if agent_claims_path else None,
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
    # Every requested arm must be COMPLETE for a complete run: a degraded
    # reader row (partial or unknown source coverage) keeps the overall
    # exercise from reading as all-clear.
    arms_not_complete = [row for row in arms_lane if row["status"] != STATUS_COMPLETE]
    lanes_ok.append(not arms_not_complete)
    battery_failed = any(row["status"] == STATUS_FAILED for row in battery_lane)
    battery_not_complete = any(
        row["status"] in (STATUS_SKIPPED, STATUS_DEGRADED) for row in battery_lane
    )
    if battery:
        lanes_ok.append(not battery_failed)
    if attempt_executed:
        lanes_ok.append(head_lane.get("passed") is True)  # type: ignore[union-attr]
    if all(lanes_ok) and not battery_not_complete:
        status = STATUS_COMPLETE
    elif arm_failures or battery_failed:
        # A requested arm invocation or battery member that ran and
        # failed fails the run.
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
        "battery": battery_lane,
        "head": head_lane,
    }
    document["summary"] = _summary(document)
    return document


def _run_battery(ext: Extension) -> list[dict[str, Any]]:
    """Run the rehearsal preset; skip unavailable inputs and binaries.

    A member whose target env is unset is skipped BEFORE dispatch (the
    preset declares its target env, so no result string-matching).
    A member whose binary is absent comes back as a failed envelope
    whose limitations name "arm is not installed" (dispatch never
    propagates that error) and is skipped. Everything else stays
    fail-closed: a run that returns a failed envelope is a failed row
    and fails the run.
    """
    import os

    from .battery import BATTERY_PRESET
    rows: list[dict[str, Any]] = []
    for member in BATTERY_PRESET:
        row: dict[str, Any] = {"arm_id": member.arm_id, "action": member.action}
        member_args = dict(member.args)
        if member.target_env is not None:
            # The env names the target; the template owns its shape.
            target = os.environ.get(member.target_env, "").strip()
            if not target:
                row.update(
                    status=STATUS_SKIPPED,
                    reason=(
                        f"battery: {member.target_env} is unset; "
                        "target-facing member skipped (set a target host)"
                    ),
                )
                rows.append(row)
                continue
            member_args = {
                # Literal replacement, not str.format: a future member
                # template with unrelated braces must fail honestly (the
                # residual check below), never raise out of the row model.
                key: value.replace("{target}", target)
                if isinstance(value, str)
                else value
                for key, value in member_args.items()
            }
            if any(
                isinstance(value, str) and "{target}" in value
                for value in member_args.values()
            ):
                row.update(
                    status=STATUS_FAILED,
                    reason="battery: member args left an unresolved {target}",
                )
                rows.append(row)
                continue
        try:
            outcome = dispatch_invoke(
                ext, arm_id=member.arm_id, action=member.action, args=member_args
            )
        except Exception as exc:  # noqa: BLE001 - recorded per member, stay fail-closed
            row.update(status=STATUS_FAILED, reason=str(exc))
            rows.append(row)
            continue
        document = outcome.document
        if document.get("error") == f"{member.arm_id} is not installed":
            row.update(status=STATUS_SKIPPED, reason="battery: arm is not installed")
            rows.append(row)
            continue
        row.update(status=_arm_status(document))
        if document.get("error"):
            row["reason"] = document["error"]
        rows.append(row)
    return rows


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
    claims_path: Path | None = None,
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
            **({"claims_path": claims_path} if claims_path is not None else {}),
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
        # Same trace shape as a graded lane, all-failed: consumers can
        # branch uniformly on the worst failure paths.
        "trace": {
            "chain_ok": False,
            "close_ok": False,
            "records": 0,
            "tool_calls": 0,
            "attempt_id": None,
            "reasons": [reason],
        },
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
    if document.get("battery"):
        lane = document["battery"]
        ok = sum(1 for row in lane if row["status"] == STATUS_COMPLETE)
        skipped = sum(1 for row in lane if row["status"] == STATUS_SKIPPED)
        degraded = sum(1 for row in lane if row["status"] == STATUS_DEGRADED)
        detail = [
            f"{count} {name}"
            for name, count in (("skipped", skipped), ("degraded", degraded))
            if count
        ]
        parts.append(
            f"battery {ok}/{len(lane)}" + (f" ({', '.join(detail)})" if detail else "")
        )
    if document["head"] is not None:
        parts.append(f"head {document['head']['status']}")
    return "; ".join(parts)
