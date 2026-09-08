"""Curated ad-pathfinder arm: offline lookups over local AD path exports."""

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
    MAX_EXPORT_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    export_refusal,
    limit_refusal,
)

_PATH_KEYS = frozenset(
    {"path_id", "source", "target", "datasource", "length", "risk_score", "nodes", "edges"}
)
_EDGE_KEYS = frozenset({"from", "to", "relation", "datasource", "blocked"})
_MAX_TEXT = 4096
_MAX_ITEMS = 50_000


class _ExportError(ValueError):
    """The export cannot be parsed without weakening the input contract."""


class AdPathfinderArm:
    """Bounded in-process reader for operator-supplied AD path exports."""

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
                "(offline AD path lookups over a local export only; there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, refusal = export_refusal(payload.get("export"))
        if refusal:
            return _fail(spec, action, refusal)
        assert path is not None
        try:
            paths, source = _load_export(path)
        except _ExportError as exc:
            return _fail(spec, action, redact(str(exc)))
        except Exception:
            return _fail(spec, action, "invoke failed")

        if action == "path":
            path_id = _optional_query(payload.get("path_id"))
            wanted_source = _optional_query(payload.get("source"))
            target = _optional_query(payload.get("target"))
            matches = [
                row
                for row in paths
                if (path_id is not None and row["path_id"] == path_id)
                or (
                    wanted_source is not None
                    and target is not None
                    and row["source"] == wanted_source
                    and row["target"] == target
                )
            ]
            if path_id is None and len(matches) > 1:
                return _fail(
                    spec,
                    action,
                    "multiple paths match args.source and args.target; use args.path_id",
                )
            match = matches[0] if matches else None
            if match is None:
                label = (
                    f"path_id={path_id!r}"
                    if path_id is not None
                    else f"source={wanted_source!r}, target={target!r}"
                )
                return _fail(spec, action, f"path not found for {label}")
            return _ok(spec, action, {"path": _project_path(match), "source": source})

        if action == "list_paths":
            limit, refusal = limit_refusal(payload.get("limit"))
            if refusal:
                return _fail(spec, action, refusal)
            assert limit is not None
            rows = [_project_summary(row) for row in paths[:limit]]
            return _ok(
                spec,
                action,
                {
                    "paths": rows,
                    "total": len(paths),
                    "returned": len(rows),
                    "capped": len(rows) < len(paths),
                    "source": source,
                },
            )

        datasources = sorted(
            {item for row in paths for item in _path_datasources(row)},
            key=str.casefold,
        )
        not_assessed_paths = sum(row["datasource"] is None for row in paths)
        coverage_status = (
            "assessed"
            if not_assessed_paths == 0
            else "not assessed"
            if not_assessed_paths == len(paths)
            else "partially assessed"
        )
        returned = datasources[:MAX_RESULTS]
        return _ok(
            spec,
            action,
            {
                "datasources": returned,
                "count": len(returned),
                "total": len(datasources),
                "returned": len(returned),
                "capped": len(returned) < len(datasources),
                "not_assessed_paths": not_assessed_paths,
                "coverage_status": coverage_status,
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


def _load_export(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = _read_bounded(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _ExportError("export is not strict UTF-8") from exc
    try:
        data = strict_json_loads(text) if path.suffix.lower() == ".json" else _load_yaml(text)
    except _ExportError:
        raise
    except StrictDataError as exc:
        raise _ExportError(str(exc)) from exc
    except Exception as exc:
        raise _ExportError(f"invalid {path.suffix.lower().lstrip('.')} export") from exc
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and set(data) == {"paths"} and isinstance(data["paths"], list):
        rows = data["paths"]
    else:
        raise _ExportError("export must be an array or an object containing only a paths array")
    if not rows:
        raise _ExportError(
            "export contains no paths; datasource coverage is not assessed"
        )
    if len(rows) > _MAX_ITEMS:
        raise _ExportError(f"export exceeds the {_MAX_ITEMS} path cap")
    return _validate_paths(rows), _source(raw)


def _load_yaml(text: str) -> Any:
    if _yaml is None:
        raise _ExportError("PyYAML is required to read YAML exports")

    class BoundedSafeLoader(
        BoundedYamlNodeMixin, StrictMappingMixin, _yaml.SafeLoader
    ):
        strict_alias_event_type = _yaml.AliasEvent

    return _yaml.load(text, Loader=BoundedSafeLoader)


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_EXPORT_BYTES + 1)
    except OSError as exc:
        raise _ExportError("could not read export") from exc
    if len(raw) > MAX_EXPORT_BYTES:
        raise _ExportError(f"export exceeds the {MAX_EXPORT_BYTES} byte read cap")
    return raw


def _validate_paths(rows: list[Any]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        label = f"path entry {index}"
        if not isinstance(raw, dict):
            raise _ExportError(f"{label} is not a mapping")
        if any(not isinstance(key, str) for key in raw):
            raise _ExportError(f"{label} field names must be strings")
        extra = sorted(set(raw) - _PATH_KEYS)
        missing = sorted(_PATH_KEYS - set(raw))
        if extra:
            raise _ExportError(f"{label} has unknown fields: {', '.join(extra)}")
        if missing:
            raise _ExportError(f"{label} is missing fields: {', '.join(missing)}")
        path_id = _text(raw["path_id"], f"{label}.path_id")
        if path_id in seen:
            raise _ExportError(f"duplicate path_id: {path_id}")
        seen.add(path_id)
        source = _text(raw["source"], f"{label}.source")
        target = _text(raw["target"], f"{label}.target")
        datasource = raw["datasource"]
        if datasource is not None:
            datasource = _text(datasource, f"{label}.datasource")
        length = raw["length"]
        if not isinstance(length, int) or isinstance(length, bool) or length < 0:
            raise _ExportError(f"{label}.length must be a non-negative integer")
        risk_score = raw["risk_score"]
        if (
            not isinstance(risk_score, (int, float))
            or isinstance(risk_score, bool)
            or (isinstance(risk_score, float) and not math.isfinite(risk_score))
            or risk_score < 0
            or risk_score > 10
        ):
            raise _ExportError(f"{label}.risk_score must be a finite number from 0 to 10")
        nodes_raw = raw["nodes"]
        if (
            not isinstance(nodes_raw, list)
            or not nodes_raw
            or len(nodes_raw) > _MAX_ITEMS
        ):
            raise _ExportError(f"{label}.nodes must be a non-empty bounded list")
        nodes = [_text(value, f"{label}.nodes[{i}]") for i, value in enumerate(nodes_raw)]
        edges_raw = raw["edges"]
        if not isinstance(edges_raw, list) or len(edges_raw) > _MAX_ITEMS:
            raise _ExportError(f"{label}.edges must be a bounded list")
        edges = [_validate_edge(value, f"{label}.edges[{i}]") for i, value in enumerate(edges_raw)]
        if length != len(nodes):
            raise _ExportError(f"{label}.length must equal the node count")
        if source != nodes[0] or target != nodes[-1]:
            raise _ExportError(
                f"{label}.source and target must match the path endpoints"
            )
        if len(edges) != len(nodes) - 1:
            raise _ExportError(
                f"{label}.edges must connect each adjacent pair of nodes exactly once"
            )
        for edge_index, edge in enumerate(edges):
            if edge["from"] != nodes[edge_index] or edge["to"] != nodes[edge_index + 1]:
                raise _ExportError(
                    f"{label}.edges[{edge_index}] does not match the adjacent nodes"
                )
        paths.append(
            {
                "path_id": path_id,
                "source": source,
                "target": target,
                "datasource": datasource,
                "length": length,
                "risk_score": risk_score,
                "nodes": nodes,
                "edges": edges,
            }
        )
    return paths


def _validate_edge(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _ExportError(f"{label} is not a mapping")
    if any(not isinstance(key, str) for key in raw):
        raise _ExportError(f"{label} field names must be strings")
    extra = sorted(set(raw) - _EDGE_KEYS)
    if extra:
        raise _ExportError(f"{label} has unknown fields: {', '.join(extra)}")
    edge: dict[str, Any] = {
        "from": _text(raw.get("from"), f"{label}.from"),
        "to": _text(raw.get("to"), f"{label}.to"),
    }
    for key in ("relation", "datasource"):
        if key in raw:
            edge[key] = _text(raw[key], f"{label}.{key}")
    if "blocked" in raw:
        if not isinstance(raw["blocked"], bool):
            raise _ExportError(f"{label}.blocked must be a boolean")
        edge["blocked"] = raw["blocked"]
    return edge


def _project_path(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "path_id": row["path_id"],
        "source": row["source"],
        "target": row["target"],
        "datasource": row["datasource"] or "not assessed",
        "length": row["length"],
        "risk_score": row["risk_score"],
        "nodes": list(row["nodes"]),
        "edges": [dict(edge) for edge in row["edges"]],
    }


def _project_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "path_id": row["path_id"],
        "source": row["source"],
        "target": row["target"],
        "datasource": row["datasource"] or "not assessed",
        "length": row["length"],
        "risk_score": row["risk_score"],
    }


def _path_datasources(row: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    if isinstance(row.get("datasource"), str):
        values.append(row["datasource"])
    else:
        values.append("not assessed")
    values.extend(
        edge["datasource"]
        for edge in row["edges"]
        if isinstance(edge.get("datasource"), str)
    )
    return values


def _source(raw: bytes) -> dict[str, Any]:
    return {
        "kind": "operator-file",
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise _ExportError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
        raise _ExportError(f"{label} contains control characters")
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
