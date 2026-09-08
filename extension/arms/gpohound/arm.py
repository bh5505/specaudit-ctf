"""Curated gpohound arm: GPO policy evidence reads."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping

try:
    import yaml as _yaml
except ImportError:
    _yaml = None  # type: ignore[assignment]

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..mcp_client import redact
from ..strict_data import (
    BoundedYamlNodeMixin,
    MAX_INTEGER_BITS,
    StrictDataError,
    StrictMappingMixin,
    secret_shaped_key,
    strict_json_loads,
)
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_EVIDENCE_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    evidence_refusal,
    limit_refusal,
)

_POLICY_KEYS = frozenset({"policy_id", "name", "status", "links", "filters", "settings"})
_LINK_KEYS = frozenset({"ou", "enforced", "enabled", "order", "block_inheritance"})
_FILTER_KEYS = frozenset({"security", "wmi"})
_MAX_TEXT = 4096
_MAX_TREE_NODES = 50_000
_MAX_TREE_DEPTH = 24


class _EvidenceError(ValueError):
    """Evidence is malformed or exceeds the closed reader contract."""


class GpohoundArm:
    """Bounded in-process reader over local GPO policy evidence."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(self, spec: ArmSpec, action: str, args: Mapping[str, Any]) -> Result:
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
                "(offline reads over local GPO policy evidence only; there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, refusal = evidence_refusal(payload.get("evidence"))
        if refusal:
            return _fail(spec, action, refusal)
        assert path is not None
        try:
            policies, source = _load_evidence(path)
        except _EvidenceError as exc:
            return _fail(spec, action, redact(str(exc)))

        if action == "policy":
            policy_id = _optional_query(payload.get("policy_id"))
            name = _optional_query(payload.get("name"))
            matches = [
                policy
                for policy in policies
                if (policy_id is not None and policy["policy_id"] == policy_id)
                or (name is not None and policy["name"].casefold() == name.casefold())
            ]
            if name is not None and len(matches) > 1:
                return _fail(spec, action, "multiple policies match args.name; use args.policy_id")
            match = matches[0] if matches else None
            if match is None:
                return _fail(spec, action, f"policy {policy_id or name!r} not found in this evidence")
            return _ok(spec, action, {"policy": _project_policy(match), "source": source})

        if action == "list_policies":
            raw_limit = limit_refusal(payload.get("limit"))
            if isinstance(raw_limit, str):
                return _fail(spec, action, raw_limit)
            status = _optional_query(payload.get("status"))
            matches = [
                policy
                for policy in policies
                if status is None or policy["status"].casefold() == status.casefold()
            ]
            rows = [_project_summary(policy) for policy in matches[:raw_limit]]
            return _ok(
                spec,
                action,
                {
                    "policies": rows,
                    "count": len(rows),
                    "total": len(matches),
                    "unfiltered_total": len(policies),
                    "returned": len(rows),
                    "capped": len(rows) < len(matches),
                    "source": source,
                },
            )

        gpo_id = payload["gpo_id"].strip()
        match = _find_policy(policies, policy_id=gpo_id)
        if match is None:
            return _fail(spec, action, f"GPO {gpo_id!r} not found in this evidence")
        all_links = [_project_link(link) for link in match["links"]]
        links = all_links[:MAX_RESULTS]
        return _ok(
            spec,
            action,
            {
                "gpo_id": gpo_id,
                "name": match["name"],
                "links": links,
                "link_count": len(links),
                "total": len(all_links),
                "returned": len(links),
                "capped": len(links) < len(all_links),
                "source": source,
            },
        )

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        if payload:
            return _fail(spec, action, "list_tools takes no caller arguments")
        return _ok(
            spec,
            action,
            {
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": {key: sorted(values) for key, values in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
        )


def _load_evidence(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = _read_bounded(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _EvidenceError("evidence is not strict UTF-8") from exc
    try:
        if path.suffix.lower() == ".json":
            data = strict_json_loads(text)
        else:
            if _yaml is None:
                raise _EvidenceError("PyYAML is required to load YAML evidence")
            data = _load_yaml(text)
    except _EvidenceError:
        raise
    except StrictDataError as exc:
        raise _EvidenceError(str(exc)) from exc
    except Exception as exc:  # parser boundary: never surface raw parser failures
        raise _EvidenceError(f"invalid {path.suffix.lower().lstrip('.')} evidence") from exc
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and set(data) == {"policies"} and isinstance(data["policies"], list):
        rows = data["policies"]
    else:
        raise _EvidenceError("evidence must be an array or an object containing only a policies array")
    if len(rows) > _MAX_TREE_NODES:
        raise _EvidenceError(f"evidence exceeds the {_MAX_TREE_NODES} policy cap")
    return _validate_policies(rows), _source(raw)


def _load_yaml(text: str) -> Any:
    if _yaml is None:
        raise _EvidenceError("PyYAML is required to load YAML evidence")

    class BoundedSafeLoader(
        BoundedYamlNodeMixin, StrictMappingMixin, _yaml.SafeLoader
    ):
        strict_alias_event_type = _yaml.AliasEvent

    return _yaml.load(text, Loader=BoundedSafeLoader)


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_EVIDENCE_BYTES + 1)
    except OSError as exc:
        raise _EvidenceError("could not read evidence") from exc
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise _EvidenceError(f"evidence exceeds the {MAX_EVIDENCE_BYTES} byte read cap")
    return raw


def _validate_policies(rows: list[Any]) -> list[dict[str, Any]]:
    policies: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        label = f"policy entry {index}"
        if not isinstance(raw, dict):
            raise _EvidenceError(f"{label} is not a mapping")
        if any(not isinstance(key, str) for key in raw):
            raise _EvidenceError(f"{label} field names must be strings")
        extra = sorted(set(raw) - _POLICY_KEYS)
        if extra:
            raise _EvidenceError(f"{label} has unknown fields: {', '.join(extra)}")
        missing = sorted({"policy_id", "name", "status", "links", "filters", "settings"} - set(raw))
        if missing:
            raise _EvidenceError(f"{label} is missing fields: {', '.join(missing)}")
        policy_id = _text(raw["policy_id"], f"{label}.policy_id")
        if policy_id in seen:
            raise _EvidenceError(f"duplicate policy_id: {policy_id}")
        seen.add(policy_id)
        links_raw = raw["links"]
        if not isinstance(links_raw, list):
            raise _EvidenceError(f"{label}.links must be a list")
        links = [_validate_link(item, f"{label}.links[{i}]") for i, item in enumerate(links_raw)]
        filters = _validate_filters(raw["filters"], f"{label}.filters")
        settings = _validated_tree(raw["settings"], f"{label}.settings")
        if not isinstance(settings, dict):
            raise _EvidenceError(f"{label}.settings must be a mapping")
        policies.append(
            {
                "policy_id": policy_id,
                "name": _text(raw["name"], f"{label}.name"),
                "status": _text(raw["status"], f"{label}.status"),
                "links": links,
                "filters": filters,
                "settings": settings,
            }
        )
    return policies


def _validate_link(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _EvidenceError(f"{label} is not a mapping")
    if any(not isinstance(key, str) for key in raw):
        raise _EvidenceError(f"{label} field names must be strings")
    extra = sorted(set(raw) - _LINK_KEYS)
    if extra:
        raise _EvidenceError(f"{label} has unknown fields: {', '.join(extra)}")
    link: dict[str, Any] = {"ou": _text(raw.get("ou"), f"{label}.ou")}
    for key in ("enforced", "enabled", "block_inheritance"):
        if key in raw:
            if not isinstance(raw[key], bool):
                raise _EvidenceError(f"{label}.{key} must be a boolean")
            link[key] = raw[key]
    if "order" in raw:
        if (
            not isinstance(raw["order"], int)
            or isinstance(raw["order"], bool)
            or raw["order"] < 0
            or raw["order"].bit_length() > MAX_INTEGER_BITS
        ):
            raise _EvidenceError(
                f"{label}.order must be a bounded non-negative integer"
            )
        link["order"] = raw["order"]
    return link


def _validate_filters(raw: Any, label: str) -> dict[str, list[str]]:
    if not isinstance(raw, dict):
        raise _EvidenceError(f"{label} must be a mapping")
    if any(not isinstance(key, str) for key in raw):
        raise _EvidenceError(f"{label} field names must be strings")
    extra = sorted(set(raw) - _FILTER_KEYS)
    if extra:
        raise _EvidenceError(f"{label} has unknown fields: {', '.join(extra)}")
    output: dict[str, list[str]] = {}
    for key in ("security", "wmi"):
        values = raw.get(key, [])
        if not isinstance(values, list):
            raise _EvidenceError(f"{label}.{key} must be a list")
        output[key] = [_text(value, f"{label}.{key}[{i}]") for i, value in enumerate(values)]
    return output


def _validated_tree(value: Any, label: str, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > _MAX_TREE_NODES or depth > _MAX_TREE_DEPTH:
        raise _EvidenceError(f"{label} exceeds the settings structure cap")
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            return _text(value, label)
        return value
    if isinstance(value, int):
        if value.bit_length() > MAX_INTEGER_BITS:
            raise _EvidenceError(
                f"{label} contains an integer exceeding the magnitude cap"
            )
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _EvidenceError(f"{label} contains a non-finite number")
        return value
    if isinstance(value, list):
        return [_validated_tree(item, f"{label}[{i}]", depth=depth + 1, budget=budget) for i, item in enumerate(value)]
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            clean = _text(key, f"{label} key")
            if clean in output:
                raise _EvidenceError(
                    f"{label} contains duplicate keys after normalization"
                )
            if secret_shaped_key(clean):
                raise _EvidenceError(f"{label} contains a secret-shaped field")
            output[clean] = _validated_tree(item, f"{label}.{clean}", depth=depth + 1, budget=budget)
        return output
    raise _EvidenceError(f"{label} contains an unsupported value")


def _project_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "policy_id": policy["policy_id"],
        "name": policy["name"],
        "status": policy["status"],
        "links": [_project_link(link) for link in policy["links"]],
        "filters": {key: list(values) for key, values in policy["filters"].items()},
        "settings": policy["settings"],
    }


def _project_summary(policy: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "policy_id": policy["policy_id"],
        "name": policy["name"],
        "status": policy["status"],
        "link_count": len(policy["links"]),
    }


def _project_link(link: Mapping[str, Any]) -> dict[str, Any]:
    return {key: link[key] for key in _LINK_KEYS if key in link}


def _find_policy(
    policies: list[dict[str, Any]], *, policy_id: str | None = None, name: str | None = None
) -> dict[str, Any] | None:
    for policy in policies:
        if policy_id is not None and policy["policy_id"] == policy_id:
            return policy
        if name is not None and policy["name"].casefold() == name.casefold():
            return policy
    return None


def _source(raw: bytes) -> dict[str, Any]:
    return {"kind": "operator-file", "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise _EvidenceError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
        raise _EvidenceError(f"{label} contains control characters")
    return value.strip()


def _optional_query(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        size = len(json.dumps(output, sort_keys=True, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        return _fail(spec, action, f"result could not be encoded: {exc}")
    if size > MAX_OUTPUT_CHARS:
        return _fail(spec, action, f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; narrow the lookup")
    return Result(True, spec.id, action, output, None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(False, spec.id, action, None, redact(str(error))[:MAX_OUTPUT_CHARS])
