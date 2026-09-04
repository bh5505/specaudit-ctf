"""Verdict-vocabulary drift guard (public adaptation of the internal
drift check).

The closed vocabularies that decide verdicts live in TWO places: the
versioned JSON schemas (what producers and consumers contract on) and
the parser/catalog constants (what the code enforces). When those two
sides drift, an envelope can be schema-valid yet semantically refused
— or the reverse. This guard cross-references every shared vocabulary
and fails closed on any mismatch, naming what each side is missing.
Two vocabularies (``safety_class``, ``side_effects``) are additionally
duplicated BETWEEN the execution-result and capability-manifest
schemas; those copies are checked against each other too, so a schema
edit on one side cannot silently diverge from its twin.

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
    schema_path: Path,
    pointer: str,
    code_values: list[str],
    code_label: str = "code",
) -> dict[str, Any]:
    schema_values = _schema_enum(schema_path, pointer)
    if schema_values is None:
        return {
            "ok": False,
            "detail": f"schema side unreadable or missing enum at {pointer} in {schema_path.name}",
            "schema_only": [],
            "code_only": [],
        }
    schema_set, code_set = set(schema_values), set(code_values)
    schema_only = sorted(schema_set - code_set)
    code_only = sorted(code_set - schema_set)
    ok = not schema_only and not code_only
    detail = "ok" if ok else (
        f"schema has values the {code_label} does not enforce: "
        f"{schema_only}; {code_label} enforces values the schema does not list: "
        f"{code_only}"
    )
    return {
        "ok": ok,
        "detail": detail,
        "schema_only": schema_only,
        "code_only": code_only,
    }


def _duplicate_check(pointer: str) -> dict[str, Any]:
    """Schema-vs-schema check for an enum duplicated across both schemas.

    ``safety_class`` and ``side_effects`` are defined in the
    execution-result schema AND copied into the capability-manifest
    schema. The execution copy is directly code-checked in the same
    run; the manifest copy is pinned transitively through this check
    (equality is transitive), so drift between the two schema copies
    cannot hide behind either side's code agreement.

    Result keys are renamed for the cross-schema context:
    ``manifest_only`` (values only the capability-manifest copy lists)
    and ``reference_only`` (values only the execution-result copy
    lists) — never ``schema_only``/``code_only``, which would mislabel
    schema-vs-schema drift as schema-vs-code.
    """
    reference = _schema_enum(_EXECUTION_SCHEMA, pointer)
    if reference is None:
        return {
            "ok": False,
            "detail": (
                "reference enum unreadable or missing at "
                f"{pointer} in the execution-result schema "
                f"({_EXECUTION_SCHEMA.name})"
            ),
            "manifest_only": [],
            "reference_only": [],
        }
    check = _check(
        _MANIFEST_SCHEMA,
        pointer,
        reference,
        code_label="execution-result schema",
    )
    manifest_only = list(check["schema_only"])
    reference_only = list(check["code_only"])
    if not check["ok"] and not manifest_only and not reference_only:
        # Unreadable manifest side: keep _check's fail-closed detail
        # (it names the manifest file).
        return {
            "ok": False,
            "detail": check["detail"],
            "manifest_only": [],
            "reference_only": [],
        }
    detail = "ok" if check["ok"] else (
        "capability-manifest schema has values the execution-result "
        f"schema does not list: {manifest_only}; execution-result "
        f"schema has values the capability-manifest schema does not "
        f"list: {reference_only}"
    )
    return {
        "ok": check["ok"],
        "detail": detail,
        "manifest_only": manifest_only,
        "reference_only": reference_only,
    }


def drift_check() -> dict[str, Any]:
    """Cross-reference every shared verdict vocabulary; fail closed."""
    from extension import contract, envelopes

    checks = {
        "status_domain": _check(
            _EXECUTION_SCHEMA,
            "/properties/status",
            list(envelopes.ALLOWED_STATUSES),
        ),
        "side_effects_domain": _check(
            _EXECUTION_SCHEMA,
            "/definitions/side_effects/items",
            sorted(envelopes.ALLOWED_SIDE_EFFECTS),
        ),
        "safety_class_domain": _check(
            _EXECUTION_SCHEMA,
            "/definitions/safety_class",
            sorted(envelopes.ALLOWED_SAFETY),
        ),
        "tier_domain": _check(
            _MANIFEST_SCHEMA,
            "/properties/tier",
            sorted(contract.ALLOWED_TIERS),
        ),
        "kind_domain": _check(
            _MANIFEST_SCHEMA,
            "/properties/kind",
            sorted(envelopes.ALLOWED_KINDS),
        ),
        "protocols_domain": _check(
            _MANIFEST_SCHEMA,
            "/properties/protocols/items",
            sorted(envelopes.ALLOWED_PROTOCOLS),
        ),
        "cleanup_proof_domain": _check(
            _MANIFEST_SCHEMA,
            "/properties/cleanup/properties/proof",
            sorted(envelopes.CLEANUP_PROOFS),
        ),
        # Cross-schema duplicates: safety_class and side_effects are
        # defined in BOTH schemas. The execution copy is directly
        # code-checked above; these checks pin the manifest copy to
        # it, so the two schema copies cannot drift apart.
        "safety_class_schema_dup": _duplicate_check(
            "/definitions/safety_class"
        ),
        "side_effects_schema_dup": _duplicate_check(
            "/definitions/side_effects/items"
        ),
    }
    return {
        "schema": "specaudit.ctf.score-drift.v1",
        "ok": all(check["ok"] for check in checks.values()),
        "checks": checks,
    }


def main() -> int:
    """No arguments; prints the JSON report and exits 0/1."""
    try:
        report = drift_check()
    except Exception as exc:  # noqa: BLE001 — fail closed with a report
        report = {
            "schema": "specaudit.ctf.score-drift.v1",
            "ok": False,
            "checks": {},
            "error": f"{type(exc).__name__}: {exc}",
        }
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
