"""CLI: python -m extension list|describe|invoke."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from .contract import Extension, ExtensionError


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m extension")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list catalog entries")

    describe_parser = sub.add_parser("describe", help="describe one catalog entry")
    describe_parser.add_argument("id", help="catalog entry identifier (e.g., burp-mcp)")

    invoke_parser = sub.add_parser(
        "invoke", help="invoke a curated installed arm that is not held"
    )
    invoke_parser.add_argument("id", help="catalog entry identifier (e.g., burp-mcp)")
    invoke_parser.add_argument("action", help="action name to invoke (e.g., list_tools)")
    invoke_parser.add_argument(
        "args",
        nargs="?",
        default="{}",
        help="JSON object of action arguments (default: {})",
    )

    try:
        ns = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 2

    ext = Extension()
    try:
        if ns.cmd == "list":
            _emit([entry.to_dict() for entry in ext.list_entries()])
            return 0
        if ns.cmd == "describe":
            _emit(ext.describe(ns.id).to_dict())
            return 0
        if ns.cmd == "invoke":
            args = _parse_args_json(ns.args)
            result = ext.invoke(ns.id, ns.action, args)
            _emit(result.to_dict())
            if not result.ok and result.error:
                print(f"Invoke failed for {ns.id}.{ns.action}: {result.error}", file=sys.stderr)
            return 0 if result.ok else 1
    except ExtensionError as exc:
        print(str(exc), file=sys.stderr)
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
