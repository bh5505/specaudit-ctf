"""Grade a participant's findings against a CTF challenge contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .grading import GradingError, grade_files, verdict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m score")
    parser.add_argument("--grade", type=Path, required=True, metavar="FOUND.json")
    parser.add_argument("--expected", type=Path, required=True, metavar="CONTRACT.json")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    try:
        document = grade_files(args.grade, args.expected)
    except GradingError as exc:
        print(f"score: {exc}", file=sys.stderr)
        return 2
    json.dump(document, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return verdict(document)


if __name__ == "__main__":
    raise SystemExit(main())
