"""CLI: python -m extension list|describe|invoke|availability."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .contract import Extension, ExtensionError
from .dispatch import dispatch_invoke


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m extension")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list catalog entries")

    sub.add_parser(
        "availability",
        help="read-only host + arm availability report (nothing is invoked)",
    )

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
        default=None,
        help="JSON object of action arguments (default: {})",
    )
    invoke_parser.add_argument(
        "--args-file", default=None,
        help="operator-local, bounded regular JSON object file for action arguments",
    )
    invoke_parser.add_argument(
        "--include-report", action="store_true",
        help="print a JSON execution/report wrapper for learning-operator analyze_pack only",
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
        if ns.cmd == "availability":
            from .availability import build_report

            _emit(build_report(ext))
            return 0
        if ns.cmd == "describe":
            try:
                _emit(ext.describe(ns.id).to_dict())
                return 0
            except ExtensionError as exc:
                print(str(exc), file=sys.stderr)
                return 2
        if ns.cmd == "invoke":
            if ns.args_file is not None and ns.args is not None:
                print("choose either inline args or --args-file", file=sys.stderr)
                return 2
            if ns.include_report and (ns.id, ns.action) != ("learning-operator", "analyze_pack"):
                print("--include-report requires learning-operator analyze_pack", file=sys.stderr)
                return 2
            args_error: ExtensionError | None = None
            args: dict[str, Any] = {}
            try:
                if ns.args_file is not None:
                    # This local operator read never becomes an arm argument or
                    # an MCP path. The shared nofollow reader checks that the
                    # file remains unchanged throughout a bounded read.
                    from learning.operator import _parse_json_document, _read_request_file
                    parsed = _parse_json_document(_read_request_file(Path(ns.args_file)))
                    if not isinstance(parsed, dict):
                        raise ValueError("JSON arguments must be an object")
                    args = parsed
                else:
                    args = _parse_args_json(ns.args if ns.args is not None else "{}")
            except (ExtensionError, OSError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
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
                if ns.include_report:
                    _emit({"execution": outcome.envelope, "report": outcome.inline_report})
                else:
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
