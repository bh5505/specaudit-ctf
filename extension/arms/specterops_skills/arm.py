"""Curated specterops-skills arm: methodology-only skill lookups."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Mapping

import yaml
from yaml.events import AliasEvent

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..mcp_client import redact
from ..strict_data import (
    StrictDataError,
    StrictMappingMixin,
    bounded_tree_refusal,
    strict_json_loads,
)
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_CATALOG_BYTES,
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_OUTPUT_CHARS,
    MAX_RECORDS,
    MAX_RESULTS,
    args_refusal,
    catalog_refusal,
)


class SpecteropsSkillsArm:
    """Specialized transport for catalog id specterops-skills.

    First-party in-process read arm: a bounded YAML/JSON catalog reader
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
            return _fail(
                spec,
                action,
                f"action {action!r} is not on the allowlist "
                "(methodology-only skill lookups over a local catalog; "
                "there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, catalog_refused = catalog_refusal(payload.get("catalog"))
        if catalog_refused:
            return _fail(spec, action, catalog_refused)
        try:
            skills, source = _load_catalog(path)
        except CatalogError as exc:
            return _fail(spec, action, str(exc))
        except Exception:
            return _fail(spec, action, "catalog could not be parsed safely")
        if action == "skill":
            return self._lookup_skill(spec, action, payload, skills, source)
        if action == "list_skills":
            return self._list_skills(spec, action, payload, skills, source)
        # Unreachable: guarded by ALLOWED_ACTIONS above, but fail-closed.
        return _fail(spec, action, f"action {action!r} is unhandled")

    def _lookup_skill(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        skills: list[dict],
        source: dict[str, Any],
    ) -> Result:
        skill_id = _opt_str(payload.get("skill_id"))
        name = _opt_str(payload.get("name"))
        if skill_id is not None:
            match = next(
                (skill for skill in skills if skill["skill_id"] == skill_id),
                None,
            )
            if (
                match is not None
                and name is not None
                and match["name"].casefold() != name.casefold()
            ):
                return _fail(
                    spec,
                    action,
                    "args.skill_id and args.name do not identify the same skill",
                )
        else:
            matches = [
                skill
                for skill in skills
                if skill["name"].casefold() == (name or "").casefold()
            ]
            if len(matches) > 1:
                return _fail(
                    spec,
                    action,
                    "multiple skills match args.name; use args.skill_id",
                )
            match = matches[0] if matches else None
        if match is None:
            wanted = skill_id or name
            return _fail(
                spec,
                action,
                f"skill {wanted!r} not found in this catalog",
            )
        output = {
            "skill_id": match.get("skill_id"),
            "name": match.get("name"),
            "category": match.get("category"),
            "description": match.get("description"),
            "tool_mapping": match.get("tool_mapping"),
            "steps": match.get("steps"),
        }
        return _ok(spec, action, {"skill": output, "source": source})

    def _list_skills(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        skills: list[dict],
        source: dict[str, Any],
    ) -> Result:
        category_filter = _opt_str(payload.get("category"))
        limit_value = payload.get("limit")
        limit = limit_value if isinstance(limit_value, int) else MAX_RESULTS
        all_results: list[dict] = []
        for skill in skills:
            if category_filter:
                skill_cat = str(skill.get("category", "")).lower()
                if skill_cat != category_filter.lower():
                    continue
            all_results.append(
                {
                    "skill_id": skill.get("skill_id"),
                    "name": skill.get("name"),
                    "category": skill.get("category"),
                }
            )
        results = all_results[:limit]
        return _ok(
            spec,
            action,
            {
                "skills": results,
                "count": len(results),
                "total": len(all_results),
                "unfiltered_total": len(skills),
                "returned": len(results),
                "capped": len(results) < len(all_results),
                "source": source,
            },
        )

    def _list_tools(
        self, spec: ArmSpec, action: str, payload: dict
    ) -> Result:
        if payload:
            return _fail(spec, action, "list_tools takes no caller arguments")
        return _ok(
            spec,
            action,
            {
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": {key: sorted(vals) for key, vals in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
        )


class CatalogError(Exception):
    """Raised when a skills catalog cannot be loaded or parsed."""


def _load_catalog(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load a skills catalog from a JSON or YAML file.

    Accepts a JSON array of skill objects or a YAML mapping with a
    top-level ``skills`` key containing a list.  Returns the list of
    skill dicts, or raises CatalogError on any structural problem.
    """
    try:
        with path.open("rb") as handle:
            raw_bytes = handle.read(MAX_CATALOG_BYTES + 1)
    except OSError as exc:
        raise CatalogError("could not read catalog") from exc
    if len(raw_bytes) > MAX_CATALOG_BYTES:
        raise CatalogError(f"catalog exceeds the {MAX_CATALOG_BYTES} byte read cap")
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CatalogError("catalog is not valid UTF-8") from exc
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = strict_json_loads(raw)
        except StrictDataError as exc:
            raise CatalogError(str(exc)) from exc
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise CatalogError("invalid JSON in catalog") from exc
    else:
        try:
            data = yaml.load(raw, Loader=_BoundedSafeLoader)
        except StrictDataError as exc:
            raise CatalogError(str(exc)) from exc
        except (yaml.YAMLError, RecursionError, ValueError) as exc:
            raise CatalogError("invalid YAML in catalog") from exc
    refusal = _tree_refusal(data)
    if refusal:
        raise CatalogError(f"catalog {refusal}")
    if isinstance(data, list):
        skills = data
    elif isinstance(data, dict) and isinstance(data.get("skills"), list):
        skills = data["skills"]
    else:
        raise CatalogError("catalog must be an array or a mapping with a 'skills' list")
    if len(skills) > MAX_RECORDS:
        raise CatalogError(f"catalog exceeds the {MAX_RECORDS} skill cap")
    seen_ids: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for idx, item in enumerate(skills):
        if not isinstance(item, dict):
            raise CatalogError(f"skill entry {idx} is not a mapping")
        skill_id = item.get("skill_id")
        name = item.get("name")
        if not isinstance(skill_id, str) or not skill_id.strip():
            raise CatalogError(f"skill entry {idx} requires a non-empty string skill_id")
        if not isinstance(name, str) or not name.strip():
            raise CatalogError(f"skill entry {idx} requires a non-empty string name")
        for key in ("category", "description", "tool_mapping"):
            if key in item and item[key] is not None and not isinstance(item[key], str):
                raise CatalogError(
                    f"skill entry {idx} field {key!r} must be a string or null"
                )
        steps = item.get("steps")
        if steps is not None and (
            not isinstance(steps, list)
            or any(not isinstance(step, str) or not step.strip() for step in steps)
        ):
            raise CatalogError(
                f"skill entry {idx} field 'steps' must be a list of non-empty strings"
            )
        normalized_id = skill_id.strip()
        if normalized_id in seen_ids:
            raise CatalogError(f"catalog contains duplicate skill_id {normalized_id!r}")
        seen_ids.add(normalized_id)
        row = dict(item)
        row["skill_id"] = normalized_id
        row["name"] = name.strip()
        normalized.append(row)
    return normalized, _source(raw_bytes)


class _BoundedSafeLoader(StrictMappingMixin, yaml.SafeLoader):
    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._node_count = 0
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError("YAML aliases and anchors are not allowed")
        self._node_count += 1
        if self._node_count > MAX_DOCUMENT_NODES:
            raise yaml.YAMLError("YAML document exceeds the node cap")
        self._depth += 1
        if self._depth > MAX_DOCUMENT_DEPTH:
            self._depth -= 1
            raise yaml.YAMLError("YAML document exceeds the nesting-depth cap")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def _tree_refusal(data: Any) -> str | None:
    return bounded_tree_refusal(
        data,
        max_nodes=MAX_DOCUMENT_NODES,
        max_depth=MAX_DOCUMENT_DEPTH,
        max_text_chars=MAX_OUTPUT_CHARS,
    )


def _source(raw: bytes) -> dict[str, Any]:
    return {
        "kind": "operator-file",
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        rendered = json.dumps(
            output, sort_keys=True, ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError):
        return _fail(spec, action, "result could not be encoded safely")
    if len(rendered) > MAX_OUTPUT_CHARS:
        return _fail(
            spec,
            action,
            f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; narrow the lookup",
        )
    return Result(ok=True, arm_id=spec.id, action=action, output=output, error=None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(
        ok=False,
        arm_id=spec.id,
        action=action,
        output=None,
        error=redact(str(error))[:MAX_OUTPUT_CHARS],
    )
