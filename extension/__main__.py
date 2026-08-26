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
from .encode import (
    ArtifactHandoffError,
    AttemptContractError,
    bind_artifact_dir,
    encode_invoke_failure,
    encode_invoke_result,
    parse_attempt_id,
    utc_now,
)
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

    attempt_id = None
    artifact_dir = None
    try:
        if ns.cmd == "invoke":
            try:
                attempt_id = parse_attempt_id(ns.attempt_id)
                artifact_dir = bind_artifact_dir(
                    ns.artifact_dir, attempt_id=attempt_id
                )
            except AttemptContractError as exc:
                print(str(exc), file=sys.stderr)
                return 2

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
                            attempt_id=attempt_id,
                        )
                    )
                    print(str(exc), file=sys.stderr)
                    return 2
                try:
                    envelope = encode_invoke_result(
                        result,
                        profile=profile,
                        started_at=started,
                        finished_at=utc_now(),
                        attempt_id=attempt_id,
                        artifact_dir=artifact_dir,
                    )
                except ArtifactHandoffError as exc:
                    _emit(exc.envelope)
                    print(str(exc), file=sys.stderr)
                    return 2
                _emit(envelope)
                if not result.ok and result.error:
                    print(
                        f"Invoke failed for {ns.id}.{ns.action}: {result.error}",
                        file=sys.stderr,
                    )
                return 0 if result.ok else 1
        except ExtensionError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    finally:
        if artifact_dir is not None:
            artifact_dir.close()


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
