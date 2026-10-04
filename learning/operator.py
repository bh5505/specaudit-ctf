"""Operator-local request files for the bounded learning-operator arm.

This CLI's file access belongs to the local operator, never the attached MCP
server. Every run calls the same admission and envelope dispatch as extension.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path

from extension.arms.learning_operator import ACTIONS, ARM_ID, _sample
from extension.contract import Extension
from extension.dispatch import dispatch_invoke

MAX_REQUEST_BYTES = 256_000
MAX_REPORT_BYTES = 1_048_576


def _read_request_file(path: Path) -> bytes:
    """Read an unchanged regular request without following its leaf or blocking."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("operator requests require Unix nofollow, nonblocking file reads")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("request must be a regular file")
        if before.st_size > MAX_REQUEST_BYTES:
            raise ValueError("request exceeds 256000 bytes")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_REQUEST_BYTES + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise ValueError("request changed while reading")
        return raw
    finally:
        os.close(fd)


def _parse_request(raw: bytes) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON request key")
            out[key] = value
        return out

    def invalid_constant(value: str) -> None:
        raise ValueError(f"non-JSON constant {value}")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON number")
        return number

    request = json.loads(raw, object_pairs_hook=unique,
                         parse_constant=invalid_constant, parse_float=finite_float)

    def check_depth(value: object, depth: int = 0) -> None:
        if depth > 64:
            raise ValueError("JSON nesting limit exceeded")
        if isinstance(value, dict):
            for child in value.values():
                check_depth(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                check_depth(child, depth + 1)

    check_depth(request)
    if (not isinstance(request, dict) or set(request) != {"arm_id", "action", "args"}
            or request["arm_id"] != ARM_ID or not isinstance(request["action"], str)
            or not isinstance(request["args"], dict)):
        raise ValueError("request requires exact arm_id, action, and object args")
    return request


def _read_report(directory: str, digest: str) -> dict:
    """Read the descriptor-bound Mode A artifact, rejecting substitutions."""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("invalid artifact digest")
    if not all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")):
        raise ValueError("Mode A requires Unix nofollow, nonblocking directory reads")
    name = digest.replace(":", "-", 1)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                           | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("artifact is not a regular file")
            if before.st_size > MAX_REPORT_BYTES:
                raise ValueError("artifact exceeds byte limit")
            raw = stream.read(MAX_REPORT_BYTES + 1)
            after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise ValueError("artifact changed while reading")
    finally:
        os.close(directory_fd)
    if len(raw) > MAX_REPORT_BYTES or hashlib.sha256(raw).hexdigest() != digest[7:]:
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
            raw = _read_request_file(ns.request)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request exceeds 256000 bytes")
        request = _parse_request(raw)
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
