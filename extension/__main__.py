"""CLI: python -m extension list|describe|invoke."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from .contract import (
    TIER_HELD,
    Extension,
    ExtensionError,
    NotCuratedError,
    NotHeldError,
    UnmanifestedCapabilityError,
)
from .encode import encode_invoke_failure, encode_invoke_result, utc_now
from .invoke_profiles import invoke_profile


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
            _emit(ext.describe(ns.id).to_dict())
            return 0
        if ns.cmd == "invoke":
            started = utc_now()
            profile = None
            try:
                spec = ext.arm_spec(ns.id)
                if spec.tier == TIER_HELD:
                    raise NotHeldError(spec.id, spec.held_reason)
                if not spec.curated:
                    raise NotCuratedError(spec.id)
                profile = invoke_profile(ns.id, ns.action)
                if profile is None:
                    raise UnmanifestedCapabilityError(ns.id, ns.action)
                args = _parse_args_json(ns.args)
                result = ext.invoke(ns.id, ns.action, args)
            except ExtensionError as exc:
                _emit(
                    encode_invoke_failure(
                        exc,
                        arm_id=ns.id,
                        action=ns.action,
                        profile=profile,
                        started_at=started,
                        finished_at=utc_now(),
                    )
                )
                print(str(exc), file=sys.stderr)
                return 2
            _emit(
                encode_invoke_result(
                    result,
                    profile=profile,
                    started_at=started,
                    finished_at=utc_now(),
                )
            )
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
