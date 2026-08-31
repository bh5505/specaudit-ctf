"""CLI: python -m extension list|describe|invoke."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from .contract import Extension, ExtensionError
from .dispatch import dispatch_invoke


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m extension")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list catalog entries")

    describe_parser = sub.add_parser("describe", help="describe one catalog entry")
    describe_parser.add_argument("id", help="catalog entry identifier (e.g., burp-mcp)")

    invoke_parser = sub.add_parser(
        "invoke", help="invoke a curated installed arm that is not held"
    )
    invoke_parser.add_argument("id", help="catalog entry identifier (e.g., checkov)")
    invoke_parser.add_argument("action", help="action name to invoke (e.g., scan)")
    invoke_parser.add_argument(
        "args",
        nargs="?",
        default="{}",
        help="JSON object of action arguments (default: {})",
    )
    invoke_parser.add_argument(
        "--attempt-id",
        default=None,
        help="validator-minted attempt-<64 lowercase hex> echoed in the result",
    )
    invoke_parser.add_argument(
        "--artifact-dir",
        default=None,
        help="absolute empty Unix directory bound before dispatch for digest-named artifacts",
    )

    try:
        ns = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 2

    try:
        ext = Extension()
        if ns.cmd == "list":
            _emit([entry.to_dict() for entry in ext.list_entries()])
            return 0
        if ns.cmd == "describe":
            try:
                _emit(ext.describe(ns.id).to_dict())
                return 0
            except ExtensionError as exc:
                print(str(exc), file=sys.stderr)
                return 2
        if ns.cmd == "invoke":
            args_error: ExtensionError | None = None
            args: dict[str, Any] = {}
            try:
                args = _parse_args_json(ns.args)
            except ExtensionError as exc:
                args_error = exc
            outcome = dispatch_invoke(
                ext,
                arm_id=ns.id,
                action=ns.action,
                args=args,
                args_error=args_error,
                attempt_id=ns.attempt_id,
                artifact_dir=ns.artifact_dir,
            )
            if outcome.envelope is not None:
                _emit(outcome.envelope)
            if outcome.stderr_line:
                print(outcome.stderr_line, file=sys.stderr)
            return outcome.exit_code
    except ExtensionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 2


def _parse_args_json(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExtensionError(f"Invalid JSON arguments: {exc.msg} at line {exc.lineno}, column {exc.colno}") from exc
    if not isinstance(parsed, dict):
        raise ExtensionError("JSON arguments must be an object (e.g., {\"key\": \"value\"})")
    return parsed


def _emit(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
