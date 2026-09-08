"""Curated claude-ad arm: AD methodology reads.

Reads Active Directory attack methodology data from a local JSON or YAML
file.  Prerequisites, observed facts, and inference are separated in every
result.  No action is authorized by a skill — framework mappings are
advisory annotations only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import yaml

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
    MAX_RESULTS,
    args_refusal,
    method_refusal,
)


class ClaudeAdArm:
    """Specialized transport for catalog id claude-ad.

    First-party in-process read arm: a stdlib YAML/JSON AD methodology
    reader with no subprocess and no endpoint.  ``installed`` reports
    handler presence only — the corpus is per-invoke caller data
    (args.method_file), the same contract as every other file-consuming arm.

    Prerequisites, observed facts, and inference are always returned as
    distinct fields.  No action is authorized by a skill.
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
                error=(
                    f"action {action!r} is not on the allowlist "
                    "(AD methodology reads over a local file; "
                    f"arming: {ARMING})"
                ),
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
        path, method_refused = method_refusal(payload.get("method_file"))
        if method_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=method_refused,
            )
        try:
            techniques = _load_method(path)
        except MethodError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if action == "technique":
            return self._technique(spec, action, payload, techniques)
        if action == "list_techniques":
            return self._list_techniques(spec, action, payload, techniques)
        # action == "list_prerequisites"
        return self._list_prerequisites(spec, action, techniques)

    def _technique(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        techniques: list[dict],
    ) -> Result:
        """Find a technique by technique_id or name."""
        technique_id = _opt_str(payload.get("technique_id"))
        name = _opt_str(payload.get("name"))
        match: dict | None = None
        for tech in techniques:
            if technique_id and tech.get("technique_id") == technique_id:
                match = tech
                break
            if name and tech.get("name", "").lower() == name.lower():
                match = tech
                break
        if match is None:
            wanted = technique_id or name
            return _fail(
                spec, action, f"technique {wanted!r} not found in methodology"
            )
        output = {
            "technique_id": match.get("technique_id"),
            "name": match.get("name"),
            "category": match.get("category"),
            "description": match.get("description"),
            "prerequisites": match.get("prerequisites", []),
            "observed_facts": match.get("observed_facts", []),
            "inference": match.get("inference", []),
            "mitre_mapping": match.get("mitre_mapping", {}),
        }
        text = json.dumps(output, sort_keys=True, default=str)
        if len(text) > MAX_OUTPUT_CHARS:
            return _fail(
                spec,
                action,
                f"result exceeds the {MAX_OUTPUT_CHARS} character output "
                "cap; the technique definition is too large",
            )
        return Result(
            ok=True, arm_id=spec.id, action=action, output=output, error=None
        )

    def _list_techniques(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        techniques: list[dict],
    ) -> Result:
        """Summary list of techniques, filterable by optional category."""
        category_filter = _opt_str(payload.get("category"))
        limit_raw = payload.get("limit", MAX_RESULTS)
        if not isinstance(limit_raw, int) or limit_raw < 1:
            limit_raw = MAX_RESULTS
        limit = min(limit_raw, MAX_RESULTS)
        results: list[dict] = []
        for tech in techniques:
            if category_filter:
                tech_cat = str(tech.get("category", "")).lower()
                if tech_cat != category_filter.lower():
                    continue
            results.append(
                {
                    "technique_id": tech.get("technique_id"),
                    "name": tech.get("name"),
                    "category": tech.get("category"),
                }
            )
            if len(results) >= limit:
                break
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"techniques": results, "count": len(results)},
            error=None,
        )

    def _list_prerequisites(
        self,
        spec: ArmSpec,
        action: str,
        techniques: list[dict],
    ) -> Result:
        """List unique prerequisites across all techniques."""
        seen: set[str] = set()
        unique: list[str] = []
        for tech in techniques:
            prereqs = tech.get("prerequisites", [])
            if not isinstance(prereqs, list):
                continue
            for prereq in prereqs:
                if not isinstance(prereq, str):
                    continue
                key = prereq.strip().lower()
                if key and key not in seen:
                    seen.add(key)
                    unique.append(prereq.strip())
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"prerequisites": sorted(unique), "count": len(unique)},
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
                "arg_keys": {
                    key: sorted(vals) for key, vals in ARG_KEYS.items()
                },
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )


class MethodError(Exception):
    """Raised when the AD methodology file cannot be loaded or parsed."""


def _load_method(path: Path) -> list[dict]:
    """Load AD methodology techniques from a JSON or YAML file.

    Accepts a JSON array of technique objects or a YAML mapping with a
    top-level ``techniques`` key containing a list.  Returns the list of
    technique dicts, or raises MethodError on any structural problem.
    Fail-closed: anything unexpected raises.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MethodError(f"could not read methodology file: {exc}") from exc
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MethodError(
                f"invalid JSON in methodology file: {exc}"
            ) from exc
        if isinstance(data, list):
            techniques = data
        elif isinstance(data, dict):
            techniques = data.get("techniques")
            if not isinstance(techniques, list):
                raise MethodError(
                    "JSON methodology must be an array or a mapping "
                    "with a 'techniques' list"
                )
        else:
            raise MethodError(
                "JSON methodology must be an array or a mapping "
                "with a 'techniques' list"
            )
    else:
        # YAML (.yaml / .yml)
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise MethodError(
                f"invalid YAML in methodology file: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise MethodError(
                "YAML methodology must be a mapping with a 'techniques' key"
            )
        techniques = data.get("techniques")
        if not isinstance(techniques, list):
            raise MethodError(
                "YAML methodology must contain a 'techniques' list"
            )
    # Validate each technique is a mapping with at least an identifier.
    for idx, item in enumerate(techniques):
        if not isinstance(item, dict):
            raise MethodError(f"technique entry {idx} is not a mapping")
        if not item.get("technique_id") and not item.get("name"):
            raise MethodError(
                f"technique entry {idx} must have at least "
                "'technique_id' or 'name'"
            )
    return techniques


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(
        ok=False,
        arm_id=spec.id,
        action=action,
        output=None,
        error=redact(error[:MAX_OUTPUT_CHARS]),
    )
