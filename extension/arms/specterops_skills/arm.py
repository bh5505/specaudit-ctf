"""Curated specterops-skills arm: methodology-only skill lookups."""

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
    catalog_refusal,
)


class SpecteropsSkillsArm:
    """Specialized transport for catalog id specterops-skills.

    First-party in-process read arm: a stdlib YAML/JSON catalog reader
    with no subprocess and no endpoint.  ``installed`` reports handler
    presence only — the corpus is per-invoke caller data (args.catalog),
    the same contract as every other file-consuming arm.
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
                    "(methodology-only skill lookups over a local catalog; "
                    "there is no dispatch tier)"
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
        path, catalog_refused = catalog_refusal(payload.get("catalog"))
        if catalog_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=catalog_refused,
            )
        try:
            skills = _load_catalog(path)
        except CatalogError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if action == "skill":
            return self._lookup_skill(spec, action, payload, skills)
        if action == "list_skills":
            return self._list_skills(spec, action, payload, skills)
        # Unreachable: guarded by ALLOWED_ACTIONS above, but fail-closed.
        return Result(
            ok=False,
            arm_id=spec.id,
            action=action,
            output=None,
            error=f"action {action!r} is unhandled",
        )

    def _lookup_skill(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        skills: list[dict],
    ) -> Result:
        skill_id = _opt_str(payload.get("skill_id"))
        name = _opt_str(payload.get("name"))
        match: dict | None = None
        for skill in skills:
            if skill_id and skill.get("skill_id") == skill_id:
                match = skill
                break
            if name and skill.get("name", "").lower() == name.lower():
                match = skill
                break
        if match is None:
            wanted = skill_id or name
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"skill {wanted!r} not found in this catalog",
            )
        output = {
            "skill_id": match.get("skill_id"),
            "name": match.get("name"),
            "category": match.get("category"),
            "description": match.get("description"),
            "tool_mapping": match.get("tool_mapping"),
            "steps": match.get("steps"),
        }
        text = json.dumps(output, sort_keys=True, default=str)
        if len(text) > MAX_OUTPUT_CHARS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=(
                    f"result exceeds the {MAX_OUTPUT_CHARS} character output "
                    "cap; the skill definition is too large"
                ),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=output,
            error=None,
        )

    def _list_skills(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        skills: list[dict],
    ) -> Result:
        category_filter = _opt_str(payload.get("category"))
        limit = payload.get("limit", MAX_RESULTS)
        if not isinstance(limit, int) or limit < 1:
            limit = MAX_RESULTS
        limit = min(limit, MAX_RESULTS)
        results: list[dict] = []
        for skill in skills:
            if category_filter:
                skill_cat = str(skill.get("category", "")).lower()
                if skill_cat != category_filter.lower():
                    continue
            results.append(
                {
                    "skill_id": skill.get("skill_id"),
                    "name": skill.get("name"),
                    "category": skill.get("category"),
                }
            )
            if len(results) >= limit:
                break
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"skills": results, "count": len(results)},
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
                "arg_keys": {key: sorted(vals) for key, vals in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )


class CatalogError(Exception):
    """Raised when a skills catalog cannot be loaded or parsed."""


def _load_catalog(path: Path) -> list[dict]:
    """Load a skills catalog from a JSON or YAML file.

    Accepts a JSON array of skill objects or a YAML mapping with a
    top-level ``skills`` key containing a list.  Returns the list of
    skill dicts, or raises CatalogError on any structural problem.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogError(f"could not read catalog: {exc}") from exc
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CatalogError(f"invalid JSON in catalog: {exc}") from exc
        if isinstance(data, list):
            skills = data
        elif isinstance(data, dict):
            skills = data.get("skills")
            if not isinstance(skills, list):
                raise CatalogError(
                    "JSON catalog must be an array or a mapping with a 'skills' list"
                )
        else:
            raise CatalogError(
                "JSON catalog must be an array or a mapping with a 'skills' list"
            )
    else:
        # YAML (.yaml / .yml)
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise CatalogError(f"invalid YAML in catalog: {exc}") from exc
        if not isinstance(data, dict):
            raise CatalogError("YAML catalog must be a mapping with a 'skills' key")
        skills = data.get("skills")
        if not isinstance(skills, list):
            raise CatalogError("YAML catalog must contain a 'skills' list")
    # Validate each skill is a mapping with at least an identifier.
    for idx, item in enumerate(skills):
        if not isinstance(item, dict):
            raise CatalogError(f"skill entry {idx} is not a mapping")
        if not item.get("skill_id") and not item.get("name"):
            raise CatalogError(
                f"skill entry {idx} must have at least 'skill_id' or 'name'"
            )
    return skills


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()
