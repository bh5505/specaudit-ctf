"""CLI: python -m extension.range [--out FILE]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .runner import RangeError, run_range


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m extension.range")
    parser.add_argument(
        "--out",
        help="write the result document here; stdout if omitted",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="stamp this seed on the result document",
    )
    try:
        ns = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 2

    try:
        document = run_range(seed=ns.seed)
    except RangeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    text = json.dumps(document, indent=2, sort_keys=True)
    if ns.out:
        Path(ns.out).write_text(text + "\n", encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text + "\n")
    return 0 if document.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
