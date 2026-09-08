"""Curated claude-ad arm: bounded reads over AD methodology evidence."""

from __future__ import annotations

import hashlib
import json
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
    StrictDataError,
    StrictMappingMixin,
    strict_json_loads,
)
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_METHOD_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    limit_refusal,
    method_refusal,
)

_TECHNIQUE_KEYS = frozenset(
    {
        "technique_id", "name", "category", "description", "prerequisites",
        "observed_facts", "inference", "mitre_mapping",
    }
)
_REQUIRED_TECHNIQUE_KEYS = _TECHNIQUE_KEYS - {"description"}
_MAX_TEXT = 16_384
_MAX_ITEMS = 50_000


class MethodError(ValueError):
    """The methodology cannot be parsed under the closed input contract."""


class ClaudeAdArm:
    """In-process, read-only methodology lookup with explicit provenance."""

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
                spec, action,
                f"action {action!r} is not on the allowlist "
                f"(AD methodology reads over a local file; arming: {ARMING})",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, refusal = method_refusal(payload.get("method_file"))
        if refusal:
            return _fail(spec, action, refusal)
        assert path is not None
        try:
            techniques, source = _load_method(path)
        except MethodError as exc:
            return _fail(spec, action, redact(str(exc)))

        if action == "technique":
            technique_id = _optional_query(payload.get("technique_id"))
            name = _optional_query(payload.get("name"))
            matches = [
                item for item in techniques
                if (technique_id is not None and item["technique_id"] == technique_id)
                or (name is not None and item["name"].casefold() == name.casefold())
            ]
            if name is not None and len(matches) > 1:
                return _fail(spec, action, "multiple techniques match args.name; use args.technique_id")
            match = matches[0] if matches else None
            if match is None:
                return _fail(spec, action, f"technique {technique_id or name!r} not found in methodology")
            return _ok(spec, action, {"technique": _project_technique(match), "source": source})

        if action == "list_techniques":
            refusal = limit_refusal(payload.get("limit"))
            if refusal:
                return _fail(spec, action, refusal)
            requested_limit = payload.get("limit")
            limit = MAX_RESULTS if requested_limit is None else requested_limit
            category = _optional_query(payload.get("category"))
            matches = [
                item for item in techniques
                if category is None or item["category"].casefold() == category.casefold()
            ]
            rows = [_project_summary(item) for item in matches[:limit]]
            return _ok(
                spec, action,
                {
                    "techniques": rows,
                    "count": len(rows),
                    "total": len(matches),
                    "unfiltered_total": len(techniques),
                    "returned": len(rows),
                    "capped": len(rows) < len(matches),
                    "source": source,
                },
            )

        prerequisites = sorted(
            {value for item in techniques for value in item["prerequisites"]},
            key=str.casefold,
        )
        rows = prerequisites[:MAX_RESULTS]
        return _ok(
            spec, action,
            {
                "prerequisites": rows,
                "count": len(rows),
                "total": len(prerequisites),
                "returned": len(rows),
                "capped": len(rows) < len(prerequisites),
                "source": source,
            },
        )

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        if payload:
            return _fail(spec, action, "list_tools takes no caller arguments")
        return _ok(
            spec, action,
            {
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": {key: sorted(values) for key, values in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
        )


def _load_method(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = _read_bounded(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MethodError("methodology is not strict UTF-8") from exc
    try:
        data = strict_json_loads(text) if path.suffix.lower() == ".json" else _load_yaml(text)
    except MethodError:
        raise
    except StrictDataError as exc:
        raise MethodError(str(exc)) from exc
    except Exception as exc:
        raise MethodError(f"invalid {path.suffix.lower().lstrip('.')} methodology") from exc
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and set(data) == {"techniques"} and isinstance(data["techniques"], list):
        rows = data["techniques"]
    else:
        raise MethodError("methodology must be an array or an object containing only a techniques array")
    if len(rows) > _MAX_ITEMS:
        raise MethodError(f"methodology exceeds the {_MAX_ITEMS} technique cap")
    return _validate_techniques(rows), _source(raw)


def _load_yaml(text: str) -> Any:
    if _yaml is None:
        raise MethodError("PyYAML is required to load YAML methodology")

    class BoundedSafeLoader(
        BoundedYamlNodeMixin, StrictMappingMixin, _yaml.SafeLoader
    ):
        strict_alias_event_type = _yaml.AliasEvent

    return _yaml.load(text, Loader=BoundedSafeLoader)


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_METHOD_BYTES + 1)
    except OSError as exc:
        raise MethodError("could not read methodology") from exc
    if len(raw) > MAX_METHOD_BYTES:
        raise MethodError(f"methodology exceeds the {MAX_METHOD_BYTES} byte read cap")
    return raw


def _validate_techniques(rows: list[Any]) -> list[dict[str, Any]]:
    techniques: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        label = f"technique entry {index}"
        if not isinstance(raw, dict):
            raise MethodError(f"{label} is not a mapping")
        if any(not isinstance(key, str) for key in raw):
            raise MethodError(f"{label} field names must be strings")
        extra = sorted(set(raw) - _TECHNIQUE_KEYS)
        missing = sorted(_REQUIRED_TECHNIQUE_KEYS - set(raw))
        if extra:
            raise MethodError(f"{label} has unknown fields: {', '.join(extra)}")
        if missing:
            raise MethodError(f"{label} is missing fields: {', '.join(missing)}")
        technique_id = _text(raw["technique_id"], f"{label}.technique_id")
        if technique_id in seen:
            raise MethodError(f"duplicate technique_id: {technique_id}")
        seen.add(technique_id)
        technique: dict[str, Any] = {
            "technique_id": technique_id,
            "name": _text(raw["name"], f"{label}.name"),
            "category": _text(raw["category"], f"{label}.category"),
            "prerequisites": _text_list(raw["prerequisites"], f"{label}.prerequisites"),
            "observed_facts": _text_list(raw["observed_facts"], f"{label}.observed_facts"),
            "inference": _text_or_list(raw["inference"], f"{label}.inference"),
            "mitre_mapping": _mapping_value(raw["mitre_mapping"], f"{label}.mitre_mapping"),
        }
        if "description" in raw:
            technique["description"] = _text(raw["description"], f"{label}.description")
        techniques.append(technique)
    return techniques


def _text_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_ITEMS:
        raise MethodError(f"{label} must be a bounded list of strings")
    return [_text(item, f"{label}[{index}]") for index, item in enumerate(value)]


def _text_or_list(value: Any, label: str) -> str | list[str]:
    return _text_list(value, label) if isinstance(value, list) else _text(value, label)


def _mapping_value(value: Any, label: str) -> str | list[str] | dict[str, str]:
    if isinstance(value, str):
        return _text(value, label)
    if isinstance(value, list):
        return _text_list(value, label)
    if isinstance(value, dict) and len(value) <= _MAX_ITEMS:
        if any(not isinstance(key, str) for key in value):
            raise MethodError(f"{label} field names must be strings")
        output: dict[str, str] = {}
        for key, item in value.items():
            clean = _text(key, f"{label} key")
            if clean in output:
                raise MethodError(
                    f"{label} contains duplicate keys after normalization"
                )
            output[clean] = _text(item, f"{label}.{clean}")
        return output
    raise MethodError(f"{label} must be a string, string list, or string mapping")


def _project_technique(item: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item[key] for key in _TECHNIQUE_KEYS if key in item}


def _project_summary(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "technique_id": item["technique_id"],
        "name": item["name"],
        "category": item["category"],
        "mitre_mapping": item["mitre_mapping"],
    }


def _source(raw: bytes) -> dict[str, Any]:
    return {"kind": "operator-file", "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise MethodError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
        raise MethodError(f"{label} contains control characters")
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
