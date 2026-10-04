"""Operator-local request files for the bounded learning-operator arm.

This CLI's file access belongs to the local operator, never the attached MCP
server. Every run calls the same admission and envelope dispatch as extension.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from extension.arms.learning_operator import ACTIONS, ARM_ID, _sample
from extension.contract import Extension
from extension.dispatch import dispatch_invoke

MAX_REQUEST_BYTES = 256_000


def _read_report(directory: str, digest: str) -> dict:
    """Read the descriptor-bound Mode A artifact, rejecting substitutions."""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("invalid artifact digest")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("Mode A requires Unix nofollow directory reads")
    name = digest.replace(":", "-", 1)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("artifact is not a regular file")
            raw = stream.read(1_048_577)
    finally:
        os.close(directory_fd)
    if len(raw) > 1_048_576 or hashlib.sha256(raw).hexdigest() != digest[7:]:
        raise ValueError("artifact digest or size mismatch")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("artifact report must be an object")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sample = commands.add_parser("sample", help="write a synthetic, editable request")
    sample.add_argument("workflow", choices=sorted(ACTIONS))
    sample.add_argument("--out", type=Path, required=True, help="fresh local JSON path")
    run = commands.add_parser("run", help="dispatch an operator-held JSON request")
    run.add_argument("--request", type=Path, required=True, help="local JSON request, or - for stdin")
    run.add_argument("--attempt-id", required=True, help="fresh validator-minted attempt-<64 hex>")
    run.add_argument("--artifact-dir", required=True, help="fresh empty per-attempt Unix directory")
    ns = parser.parse_args(argv)
    if ns.command == "sample":
        document = {"arm_id": ARM_ID, "action": ns.workflow, "args": _sample(ns.workflow)}
        raw = (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
        if len(raw) > MAX_REQUEST_BYTES:
            parser.error("bundled sample exceeds request limit")
        try:
            with ns.out.open("xb") as stream:
                stream.write(raw)
        except OSError as exc:
            parser.error(f"cannot create sample: {exc}")
        print(ns.out)
        return 0
    try:
        if str(ns.request) == "-":
            raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        else:
            with ns.request.open("rb") as stream:
                raw = stream.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request exceeds 256000 bytes")
        def unique(pairs):
            out = {}
            for key, value in pairs:
                if key in out:
                    raise ValueError("duplicate JSON request key")
                out[key] = value
            return out
        request = json.loads(raw, object_pairs_hook=unique,
                             parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-JSON constant {value}")))
        if not isinstance(request, dict) or set(request) != {"arm_id", "action", "args"} or request["arm_id"] != ARM_ID or not isinstance(request["action"], str) or not isinstance(request["args"], dict):
            raise ValueError("request requires exact arm_id, action, and object args")
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        print(f"invalid operator request: {exc}", file=sys.stderr)
        return 2
    outcome = dispatch_invoke(Extension(), arm_id=ARM_ID, action=request["action"],
                              args=request["args"], attempt_id=ns.attempt_id,
                              artifact_dir=ns.artifact_dir)
    if outcome.envelope is not None:
        # The v1 envelope intentionally carries only a digest. Expose the
        # separately retained Mode A report for an operator to act on, while
        # preserving the unmodified execution envelope alongside it.
        report = None
        artifacts = outcome.envelope.get("artifacts", [])
        if outcome.exit_code == 0:
            if len(artifacts) != 1 or artifacts[0].get("kind") != "policy-report":
                print("completed run lacks one policy report", file=sys.stderr)
                return 2
            digest = artifacts[0].get("digest", "")
            if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                print("completed run has an invalid artifact digest", file=sys.stderr)
                return 2
            try:
                report = _read_report(ns.artifact_dir, digest)
            except (OSError, ValueError) as exc:
                print(f"cannot verify retained artifact: {exc}", file=sys.stderr)
                return 2
        print(json.dumps({"execution": outcome.envelope, "report": report}, sort_keys=True, indent=2))
    if outcome.stderr_line:
        print(outcome.stderr_line, file=sys.stderr)
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
