"""``python -m score <envelope.json>...`` — gate scoring for execution-result
envelopes; ``python -m score --grade FOUND.json --expected CONTRACT.json``
— found-vs-expected challenge grading.

Both modes print their document (JSON, sorted keys) on stdout and exit
0 (passed), 1 (scorer ran; verdict negative — includes unreadable or
invalid envelope files, scored as failed entries), or 2 (scorer-level
usage error; no document).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .grading import GradingError, grade_files
from .rubric import RubricError, load_rubric
from .scorer import score_run, verdict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="score",
        description=(
            "Grade specaudit.ctf.execution-result.v1 envelope files, or "
            "grade a participant's found-findings document against a "
            "challenge's expected-findings contract. The run passes iff "
            "every envelope passes / the finding set matches exactly; "
            "transport_ok is informational and never a verdict; partial "
            "finding coverage never passes."
        ),
    )
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="execution-result.v1 envelope JSON files (AND semantics)",
    )
    parser.add_argument(
        "--rubric",
        type=Path,
        default=None,
        help="optional strict YAML rubric (see score/rubric.py)",
    )
    parser.add_argument(
        "--grade",
        type=Path,
        default=None,
        metavar="FOUND.json",
        help=(
            "challenge mode: the participant's found-findings document; "
            "requires --expected; envelopes must not be given"
        ),
    )
    parser.add_argument(
        "--expected",
        type=Path,
        default=None,
        metavar="CONTRACT.json",
        help="challenge mode: the challenge's expected-findings contract",
    )
    args = parser.parse_args(argv)

    if (args.grade is None) != (args.expected is None):
        print("score: --grade and --expected must be given together", file=sys.stderr)
        return 2
    if args.grade is not None:
        if args.files:
            print(
                "score: envelope files and --grade/--expected are mutually exclusive",
                file=sys.stderr,
            )
            return 2
        try:
            document = grade_files(args.grade, args.expected)
        except GradingError as exc:
            print(f"score: {exc}", file=sys.stderr)
            return 2
        json.dump(document, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return verdict(document)

    if not args.files:
        print("score: envelope files (or --grade/--expected) are required", file=sys.stderr)
        return 2

    try:
        rubric = load_rubric(args.rubric) if args.rubric else None
    except RubricError as exc:
        print(f"score: {exc}", file=sys.stderr)
        return 2

    document = score_run(args.files, rubric)
    json.dump(document, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return verdict(document)


if __name__ == "__main__":
    raise SystemExit(main())
