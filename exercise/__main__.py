"""``python -m exercise`` — compose a full rehearsal run (see runner.py)."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence

from .runner import ExerciseError, run_exercise

# Ledger vocabulary mirror (exercise_operator keeps the same local copy):
# duplicated literally so ``python -m exercise`` never imports
# attempt_ledger unless --ledger actually asks for it.
ASSISTANCE_CHOICES = ("first-pass", "assisted", "tuned", "held-out", "none")
_HEX_KEY = re.compile(r"[0-9a-f]{64}\Z")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="exercise",
        description=(
            "Compose the synthetic range, optional challenge grading, "
            "optional standalone arm invocations, and the agent-head lane "
            "(readiness probe, executed fake-head attempt, or out-of-band "
            "attempt grading) into one consolidated run report. Everything "
            "is synthetic; the report never claims success it cannot prove."
        ),
    )
    parser.add_argument("--challenge", default=None, help="challenge directory name recorded in the report")
    parser.add_argument("--fixtures", default=None, help="comma-separated fixture ids to report (default: all)")
    parser.add_argument(
        "--arms",
        default=None,
        help=(
            "JSON array of standalone arm requests: "
            '[{"arm_id": "...", "action": "...", "args": {...}}, ...] — '
            "rides the same admission path as python -m extension invoke"
        ),
    )
    parser.add_argument("--seed", type=int, default=None, help="seed applied to the range lifecycle run")
    parser.add_argument("--found", default=None, help="participant found-findings document (requires --expected)")
    parser.add_argument(
        "--expected",
        default=None,
        help=(
            "challenge expected-findings contract (requires --found, "
            "unless --attempt-dir/--head-execute supplies the found "
            "document from the attempt)"
        ),
    )
    parser.add_argument(
        "--head",
        default=None,
        help=(
            "agent head: claude-code | codex-cli | qwen-code for readiness probing; "
            "under --head-execute: 'fake' (the lane-internal scripted "
            "head) or a REAL head armed on this host via "
            "EXERCISE_HEAD_CLAUDE_CODE_CMD / EXERCISE_HEAD_CODEX_CLI_CMD / "
            "EXERCISE_HEAD_QWEN_CODE_CMD"
        ),
    )
    parser.add_argument(
        "--attempt-dir",
        default=None,
        help=(
            "grade an attempt directory (server-captured trace.ndjson + "
            "the agent's found.json) against --expected; the trace key "
            "must be in SPECAUDIT_CTF_MCP_TRACE_KEY"
        ),
    )
    parser.add_argument(
        "--agent-claims",
        default=None,
        help=(
            "optional JSON claim declarations bound by trace_sha256 and call seq; "
            "requires --attempt-dir and operator-held trace key"
        ),
    )
    parser.add_argument(
        "--head-execute",
        action="store_true",
        help=(
            "execute the named head and grade its attempt (requires "
            "--attempt-dir, --expected, --head): 'fake' runs the "
            "lane-internal scripted head; a real head (claude-code, "
            "codex-cli, qwen-code) is spawned headless only when armed via its "
            "EXERCISE_HEAD_*_CMD env and given --attempt-prompt"
        ),
    )
    parser.add_argument(
        "--attempt-prompt",
        default=None,
        help=(
            "operator-supplied attempt prompt file for real-head "
            "execution (the runner appends the deliverable trailer; "
            "only the prompt's hash is recorded)"
        ),
    )
    parser.add_argument(
        "--battery",
        action="store_true",
        help=(
            "run the default rehearsal battery preset (exercise/battery.py: "
            "the offline/contained trio - checkov IaC scan over the packaged "
            "range, semgrep inline rules under SEMGREP_SCAN_ROOT, the "
            "attack-stix-data demo-bundle lookup - plus the dual-gated "
            "target-facing pair wapiti/nmap, dispatched only when their "
            "arming scope env AND LAB_TARGET_HOST are set); unavailable or "
            "unarmed members are skipped (the run degrades), members that "
            "run and fail fail the run"
        ),
    )
    parser.add_argument("--out", default=None, help="write the report JSON here as well; stdout always gets it")
    parser.add_argument(
        "--ledger",
        type=Path,
        default=None,
        help=(
            "opt-in append-only attempt ledger (JSON-lines): after the run "
            "document is produced, append one row per executed lane "
            "(range, grade, arms, battery, head, run summary); the report "
            "and grading are unchanged, and a ledger failure fails the "
            "run closed"
        ),
    )
    parser.add_argument(
        "--ledger-key-hex",
        default=None,
        help="optional 64-hex HMAC key for the ledger (requires --ledger)",
    )
    parser.add_argument(
        "--assistance",
        choices=ASSISTANCE_CHOICES,
        help="ledger assistance class (default first-pass; requires --ledger)",
    )
    parser.add_argument(
        "--at",
        default=None,
        help="naive iso recording time for ledger rows; required with --ledger",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    ledger_key = None
    recorded_at = None
    assistance = "first-pass"
    if args.ledger is None:
        if args.ledger_key_hex is not None or args.assistance is not None or args.at is not None:
            parser.error("--ledger-key-hex/--assistance/--at require --ledger")
    else:
        if args.at is None:
            parser.error("--at is required with --ledger")
        try:
            recorded_at = datetime.fromisoformat(args.at)
        except ValueError:
            parser.error(f"--at is not an iso datetime: {args.at}")
        if recorded_at.tzinfo is not None:
            parser.error("--at must be naive; this CLI never reads a clock")
        if args.ledger_key_hex is not None:
            key_text = args.ledger_key_hex.strip().lower()
            if not _HEX_KEY.fullmatch(key_text):
                parser.error("--ledger-key-hex must be 64 hex characters")
            ledger_key = bytes.fromhex(key_text)
        assistance = args.assistance or "first-pass"

    arms: list[dict[str, Any]] = []
    if args.arms:
        try:
            parsed_arms = json.loads(args.arms)
        except json.JSONDecodeError as exc:
            print(f"exercise: --arms is not valid JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(parsed_arms, list) or not all(
            isinstance(row, dict) for row in parsed_arms
        ):
            print("exercise: --arms must be a JSON array of objects", file=sys.stderr)
            return 2
        arms = parsed_arms

    fixtures = None
    if args.fixtures is not None:
        fixtures = [item.strip() for item in args.fixtures.split(",")]
        if not fixtures or not all(fixtures):
            print("exercise: --fixtures must name at least one fixture id", file=sys.stderr)
            return 2

    try:
        document = run_exercise(
            challenge=args.challenge,
            fixtures=fixtures,
            arms=arms or None,
            seed=args.seed,
            found_path=args.found,
            expected_path=args.expected,
            head=args.head,
            attempt_dir=args.attempt_dir,
            agent_claims_path=args.agent_claims,
            head_execute=args.head_execute,
            battery=args.battery,
            attempt_prompt=args.attempt_prompt,
        )
    except ExerciseError as exc:
        print(f"exercise: {exc}", file=sys.stderr)
        return 2

    if args.ledger is not None:
        # Opt-in wiring, strictly after the document exists; the append is
        # additive and never mutates the report. Fail closed exactly like
        # exercise_operator: a run whose rows could not be appended never
        # exits as graded-and-ledgered (machine-readable error, exit 2).
        from .ledger_wiring import LedgerWiringError, append_document_rows

        try:
            append_document_rows(
                args.ledger, document, ledger_key=ledger_key,
                assistance=assistance, recorded_at=recorded_at)
        except LedgerWiringError as exc:
            print(json.dumps(
                {"ok": False, "reason": "ledger-error", "error": str(exc)},
                sort_keys=True))
            return 2

    payload = json.dumps(document, indent=2, sort_keys=True)
    print(payload)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload + "\n", encoding="utf-8")
    print(f"exercise: {document['summary']}", file=sys.stderr)
    return 0 if document["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
