"""CLI: python -m extension.range [--out FILE]. Mode A is stdout-only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..encode import (
    ArtifactDirError,
    ArtifactHandoffError,
    AttemptContractError,
    bind_artifact_dir,
    encode_range_document,
    encode_range_failure,
    parse_attempt_id,
    utc_now,
)
from .runner import RangeError, run_range


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m extension.range")
    parser.add_argument(
        "--out",
        help="write the result document here; stdout if omitted; incompatible with --artifact-dir",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="apply this seed to the inner lifecycle run (hashed into the range-report artifact)",
    )
    parser.add_argument(
        "--attempt-id",
        default=None,
        help="validator-minted attempt-<64 lowercase hex> echoed in the result",
    )
    parser.add_argument(
        "--artifact-dir",
        default=None,
        help="absolute empty Unix directory bound before dispatch for digest-named artifacts",
    )
    try:
        ns = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 2

    artifact_dir = None
    try:
        try:
            attempt_id = parse_attempt_id(ns.attempt_id)
            if ns.out is not None and ns.artifact_dir is not None:
                raise ArtifactDirError(
                    "Mode A rejects --out when --artifact-dir is present; "
                    "emit the envelope on stdout only"
                )
            artifact_dir = bind_artifact_dir(ns.artifact_dir, attempt_id=attempt_id)
        except AttemptContractError as exc:
            print(str(exc), file=sys.stderr)
            return 2

        started = utc_now()
        try:
            document = run_range(seed=ns.seed)
        except RangeError as exc:
            envelope = encode_range_failure(
                exc,
                started_at=started,
                finished_at=utc_now(),
                attempt_id=attempt_id,
            )
            _write(envelope, ns.out)
            print(str(exc), file=sys.stderr)
            return 2

        try:
            envelope = encode_range_document(
                document,
                started_at=started,
                finished_at=utc_now(),
                attempt_id=attempt_id,
                artifact_dir=artifact_dir,
            )
        except ArtifactHandoffError as exc:
            _write(exc.envelope, ns.out)
            print(str(exc), file=sys.stderr)
            return 2
        _write(envelope, ns.out)
        return 0 if envelope.get("status") == "complete" else 1
    finally:
        if artifact_dir is not None:
            artifact_dir.close()


def _write(payload: Mapping[str, Any], out: str | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
