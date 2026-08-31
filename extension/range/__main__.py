"""CLI: python -m extension.range [--out FILE]. Mode A is stdout-only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..contract import Extension
from ..dispatch import dispatch_range
from ..encode import ArtifactDirError


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
        "--arm-ids",
        default=None,
        help=(
            "comma-separated curated arm ids; omitted auto-discovers curated "
            "arms as optional, an empty value runs lifecycle-only, and named "
            "arms are required (parity with the MCP run_range arm_ids argument)"
        ),
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

    if ns.out is not None and ns.artifact_dir is not None:
        message = str(
            ArtifactDirError(
                "Mode A rejects --out when --artifact-dir is present; "
                "emit the envelope on stdout only"
            )
        )
        print(message, file=sys.stderr)
        return 2

    arm_ids: list[str] | None = None
    if ns.arm_ids is not None:
        # Parity with the MCP shape check: an empty value is lifecycle-only
        # (required-empty); any whitespace-only entry is a caller shape error
        # (exit 2 here, JSON-RPC -32602 there) — never a silently dropped
        # arm. Entries are otherwise kept verbatim: arm ids are kebab-case,
        # so anything else fails the curated-arm domain check on both
        # transports with the same envelope.
        if ns.arm_ids == "":
            arm_ids = []
        else:
            arm_ids = ns.arm_ids.split(",")
            if any(not item.strip() for item in arm_ids):
                print("arm-ids entries must be non-empty", file=sys.stderr)
                return 2

    outcome = dispatch_range(
        Extension(),
        seed=ns.seed,
        arm_ids=arm_ids,
        attempt_id=ns.attempt_id,
        artifact_dir=ns.artifact_dir,
    )
    if outcome.envelope is not None:
        _write(outcome.envelope, ns.out)
    if outcome.stderr_line:
        print(outcome.stderr_line, file=sys.stderr)
    return outcome.exit_code


def _write(payload: Mapping[str, Any], out: str | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
