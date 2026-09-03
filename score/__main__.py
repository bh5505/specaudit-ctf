"""``python -m score <envelope.json>... [--rubric rubric.yaml]``.

Prints the score document (JSON, sorted keys) on stdout and exits 0
(run passed), 1 (scorer ran; verdict negative — includes unreadable or
invalid envelope files, scored as failed entries), or 2 (scorer-level
usage error; no score document).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .rubric import RubricError, load_rubric
from .scorer import score_run, verdict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="score",
        description=(
            "Grade specaudit.ctf.execution-result.v1 envelope files. "
            "The run passes iff every envelope passes; transport_ok is "
            "informational and never a verdict."
        ),
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="execution-result.v1 envelope JSON files (AND semantics)",
    )
    parser.add_argument(
        "--rubric",
        type=Path,
        default=None,
        help="optional strict YAML rubric (see score/rubric.py)",
    )
    args = parser.parse_args(argv)

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
