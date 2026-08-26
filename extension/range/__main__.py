"""CLI: python -m extension.range [--out FILE]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..encode import encode_range_document, encode_range_failure, utc_now
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

    started = utc_now()
    try:
        document = run_range(seed=ns.seed)
    except RangeError as exc:
        envelope = encode_range_failure(
            exc, started_at=started, finished_at=utc_now()
        )
        _write(envelope, ns.out)
        print(str(exc), file=sys.stderr)
        return 2

    envelope = encode_range_document(
        document, started_at=started, finished_at=utc_now()
    )
    _write(envelope, ns.out)
    return 0 if envelope.get("status") == "complete" else 1


def _write(payload: Mapping[str, Any], out: str | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
