"""Curated attack-stix-data arm: offline exact lookups over local STIX."""

from __future__ import annotations

import json
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
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
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
                "(offline exact lookups over a local STIX bundle only; "
                "there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
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
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "demo_bundle": str(demo_bundle_path()),
                "arg_keys": {key: sorted(vals) for key, vals in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )


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
