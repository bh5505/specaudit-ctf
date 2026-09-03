"""Verdict-vocabulary drift guard (public adaptation of the internal
drift check).

The closed vocabularies that decide verdicts live in TWO places: the
versioned JSON schemas (what producers and consumers contract on) and
the parser/catalog constants (what the code enforces). When those two
sides drift, an envelope can be schema-valid yet semantically refused
— or the reverse. This guard cross-references every shared vocabulary
and fails closed on any mismatch, naming what each side is missing.

Domain mismatch fails closed; this is a repository self-check, never a
live-engagement gate. Exit codes: ``0`` all domains agree, ``1`` drift
or unreadable sources (valid JSON report on stdout for both).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_EXECUTION_SCHEMA = _ROOT / "extension" / "schema" / "execution-result.v1.schema.json"
_MANIFEST_SCHEMA = _ROOT / "extension" / "schema" / "capability.manifest.v1.schema.json"


def _schema_enum(path: Path, pointer: str) -> list[str] | None:
    """Read a string-enum list at a JSON pointer; None on any failure."""
    try:
        node: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for token in pointer.strip("/").split("/"):
        if not isinstance(node, dict) or token not in node:
            return None
        node = node[token]
    if (
        isinstance(node, dict)
        and isinstance(node.get("enum"), list)
        and all(isinstance(item, str) for item in node["enum"])
    ):
        return list(node["enum"])
    return None


def _check(
    name: str,
    schema_path: Path,
    pointer: str,
    code_values: list[str],
) -> dict[str, Any]:
    schema_values = _schema_enum(schema_path, pointer)
    if schema_values is None:
        return {
            "ok": False,
            "detail": f"schema side unreadable or missing enum at {pointer}",
            "schema_only": [],
            "code_only": [],
        }
    schema_set, code_set = set(schema_values), set(code_values)
    schema_only = sorted(schema_set - code_set)
    code_only = sorted(code_set - schema_set)
    ok = not schema_only and not code_only
    detail = "ok" if ok else (
        "schema has values the code does not enforce: "
        f"{schema_only}; code enforces values the schema does not list: "
        f"{code_only}"
    )
    return {
        "ok": ok,
        "detail": detail,
        "schema_only": schema_only,
        "code_only": code_only,
    }


def drift_check() -> dict[str, Any]:
    """Cross-reference every shared verdict vocabulary; fail closed."""
    from extension import contract, envelopes

    checks = {
        "status_domain": _check(
            "status_domain",
            _EXECUTION_SCHEMA,
            "/properties/status",
            list(envelopes.ALLOWED_STATUSES),
        ),
        "side_effects_domain": _check(
            "side_effects_domain",
            _EXECUTION_SCHEMA,
            "/definitions/side_effects/items",
            sorted(envelopes.ALLOWED_SIDE_EFFECTS),
        ),
        "safety_class_domain": _check(
            "safety_class_domain",
            _EXECUTION_SCHEMA,
            "/definitions/safety_class",
            sorted(envelopes._SAFETY_RANK),
        ),
        "tier_domain": _check(
            "tier_domain",
            _MANIFEST_SCHEMA,
            "/properties/tier",
            sorted(contract.ALLOWED_TIERS),
        ),
    }
    return {
        "schema": "specaudit.ctf.score-drift.v1",
        "ok": all(check["ok"] for check in checks.values()),
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    try:
        report = drift_check()
    except (OSError, ValueError) as exc:
        print(f"drift: {exc}", file=sys.stderr)
        return 1
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
