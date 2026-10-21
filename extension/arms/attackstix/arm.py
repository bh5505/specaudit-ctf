"""Curated attack-stix-data arm: offline exact lookups over local STIX."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..mcp_client import redact
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    INPUT_HINT,
    CAVEATS,
    LIST_ACTIONS,
    MAX_BUNDLE_BYTES,
    MAX_OUTPUT_CHARS,
    args_refusal,
    bundle_refusal,
    demo_bundle_path,
)
from . import reader
from .reader import BundleError


class AttackStixArm:
    """Specialized transport for catalog id attack-stix-data.

    First-party in-process read arm: a stdlib STIX 2.1 reader with no
    subprocess and no endpoint. ``installed`` reports handler presence
    only — the corpus is per-invoke caller data (args.bundle), the same
    contract as every other file-consuming arm.
    """

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(offline exact lookups over a local STIX bundle only)",
            )
        if action == "cvelookup":
            return self._cve_lookup(spec, action, payload)
        refusal = args_refusal(action, payload)
        if refusal:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        if action == "relationships":
            # Cheap grammar before disk: a bad type filter is refused
            # without reading the bundle.
            type_refusal = _relationship_type_refusal(payload.get("type"))
            if type_refusal:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=type_refusal,
                )
        path, bundle_refused = bundle_refusal(payload.get("bundle"))
        if bundle_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=bundle_refused,
            )
        try:
            index = reader.load_bundle(path)
        except BundleError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        return self._lookup(spec, action, payload, index)

    def _cve_lookup(
        self, spec: ArmSpec, action: str, payload: dict[str, Any]
    ) -> Result:
        """Run one CVE-keyed lookup over the supplied bundle."""
        refusal = args_refusal(action, payload)
        raw_ids = payload.get("cve_ids")
        if refusal or not isinstance(raw_ids, list):
            reason = (
                "cve_ids_not_a_list"
                if not isinstance(raw_ids, list)
                else "input_refusal"
            )
            output = {"reason": reason, "results": [], "count_matched": 0}
            return Result(False, spec.id, action, output, refusal or reason)

        raw_path = payload.get("bundle_path")
        if raw_path is None:
            path = demo_bundle_path()
            path_refusal = None
        else:
            path, path_refusal = bundle_refusal(raw_path)
        if path_refusal or path is None:
            reason = "bundle_missing"
            output = {"reason": reason, "results": [], "count_matched": 0}
            return Result(False, spec.id, action, output, reason)

        try:
            snapshot = _read_bundle_snapshot(path)
            index = reader.load_bundle_bytes(snapshot)
        except (BundleError, OSError) as exc:
            reason = "bundle_invalid_json"
            output = {"reason": reason, "results": [], "count_matched": 0}
            return Result(False, spec.id, action, output, f"{reason}: {redact(str(exc))}")

        results: list[dict[str, Any]] = []
        total = 0
        for raw_id in raw_ids:
            normalized = _normalize_cve(raw_id)
            if normalized is None:
                row = {
                    "cve_id": None,
                    "query_sha256": _value_hash(raw_id),
                    "status": "unmatched",
                    "reason": "malformed_id",
                    "matched_objects": [],
                    "count_matched": 0,
                }
            else:
                matches = reader.find_cve_objects(index, normalized)
                count = len(matches)
                total += count
                row = {
                    "cve_id": normalized,
                    "status": "matched" if matches else "unmatched",
                    "reason": None if matches else "unknown_cve",
                    "matched_objects": matches,
                    "count_matched": count,
                }
            results.append(row)
        output = {"reason": None, "results": results, "count_matched": total}
        text = _canonical_json(output)
        if len(text) > MAX_OUTPUT_CHARS:
            reason = "output_too_large"
            failed = {"reason": reason, "results": [], "count_matched": 0}
            return Result(False, spec.id, action, failed, "CVE lookup output exceeds output cap")
        return Result(True, spec.id, action, output, None)

    def _lookup(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        index: dict[str, Any],
    ) -> Result:
        miss: str | None = None
        if action == "technique":
            subject = reader.find_technique(
                index,
                attack_id=_opt_str(payload.get("id")),
                name=_opt_str(payload.get("name")),
            )
            output: Any = (
                reader.project_technique(index, subject) if subject else None
            )
            miss = None if subject else _miss_text(payload, "technique")
        elif action == "software":
            subject = reader.find_software(index, _opt_str(payload.get("name")) or "")
            output = (
                reader.project_software(index, subject) if subject else None
            )
            miss = None if subject else _miss_text(payload, "software")
        elif action == "group":
            subject = reader.find_group(index, _opt_str(payload.get("name")) or "")
            output = reader.project_group(index, subject) if subject else None
            miss = None if subject else _miss_text(payload, "group")
        else:  # relationships
            subject = reader.find_technique(
                index,
                attack_id=_opt_str(payload.get("id")),
                name=_opt_str(payload.get("name")),
            )
            if subject is None:
                subject = reader.find_software(
                    index, _opt_str(payload.get("name")) or ""
                )
            if subject is None:
                subject = reader.find_group(
                    index, _opt_str(payload.get("name")) or ""
                )
            if subject is None:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=_miss_text(payload, "technique, software, or group"),
                )
            type_refusal = _relationship_type_refusal(payload.get("type"))
            if type_refusal:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=type_refusal,
                )
            output = reader.relationships_for(
                index, subject, relationship_type=_opt_str(payload.get("type"))
            )
        if miss:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=miss,
            )
        text = json.dumps(output, sort_keys=True)
        if len(text) > MAX_OUTPUT_CHARS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=(
                    f"result exceeds the {MAX_OUTPUT_CHARS} character output "
                    "cap; narrow the lookup"
                ),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=output,
            error=None,
        )

    def _list_tools(
        self, spec: ArmSpec, action: str, payload: dict
    ) -> Result:
        if payload:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="list_tools takes no caller arguments",
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={
                "actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "demo_bundle": str(demo_bundle_path()),
                "arg_keys": {key: sorted(vals) for key, vals in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "input_hint": INPUT_HINT,
            },
            error=None,
        )


_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)


def _canonical_json(value: Any) -> str:
    # ASCII escaping makes even lone-surrogate caller strings hashable and
    # printable, so malformed identifiers stay hashable without echoing raw input.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _value_hash(value: Any) -> str:
    try:
        encoded = _canonical_json(value)
    except (TypeError, ValueError):
        encoded = f"<{type(value).__name__}>"
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _normalize_cve(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip().upper()
    return value if _CVE_RE.fullmatch(value) else None


def _read_bundle_snapshot(path: Path) -> bytes:
    with path.open("rb") as handle:
        snapshot = handle.read(MAX_BUNDLE_BYTES + 1)
    if len(snapshot) > MAX_BUNDLE_BYTES:
        raise BundleError(f"bundle exceeds the {MAX_BUNDLE_BYTES} byte read cap")
    return snapshot


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()


def _miss_text(payload: dict, what: str) -> str:
    wanted = payload.get("id") or payload.get("name")
    return f"{what} {wanted!r} not found in this bundle"


def _relationship_type_refusal(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str) or raw not in reader.ALLOWED_RELATIONSHIP_TYPES:
        return (
            "args.type must be one of: "
            + ", ".join(sorted(reader.ALLOWED_RELATIONSHIP_TYPES))
        )
    return None
