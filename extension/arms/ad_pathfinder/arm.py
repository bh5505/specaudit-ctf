"""Curated ad-pathfinder arm: offline lookups over local AD path exports."""

from __future__ import annotations

import json
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
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    export_refusal,
    limit_refusal,
)


class AdPathfinderArm:
    """Specialized transport for catalog id ad-pathfinder.

    First-party in-process read arm: a stdlib JSON/YAML reader with no
    subprocess and no endpoint. ``installed`` reports handler presence
    only — the export file is per-invoke caller data (args.export), the
    same contract as every other file-consuming arm.
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
                "(offline AD path lookups over a local export only; "
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
        # Validate export path before disk I/O.
        path, export_refused = export_refusal(payload.get("export"))
        if export_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=export_refused,
            )
        paths = self._load_export(path)
        if isinstance(paths, str):
            # _load_export returned a refusal string.
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=paths,
            )
        return self._dispatch(spec, action, payload, paths)

    def _dispatch(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        paths: list[dict],
    ) -> Result:
        """Route validated actions against the loaded path data."""
        if action == "path":
            return self._get_path(spec, action, payload, paths)
        if action == "list_paths":
            return self._list_paths(spec, action, payload, paths)
        if action == "list_datasources":
            return self._list_datasources(spec, action, payload, paths)
        # Fail-closed: unreachable given the allowlist guard above.
        return Result(
            ok=False,
            arm_id=spec.id,
            action=action,
            output=None,
            error=f"action {action!r} is not implemented",
        )

    def _get_path(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        paths: list[dict],
    ) -> Result:
        """Find a single path by path_id or (source, target)."""
        path_id = _opt_str(payload.get("path_id"))
        source = _opt_str(payload.get("source"))
        target = _opt_str(payload.get("target"))

        found = None
        for entry in paths:
            if path_id and entry.get("path_id") == path_id:
                found = entry
                break
            if (
                source
                and target
                and entry.get("source") == source
                and entry.get("target") == target
            ):
                found = entry
                break

        if found is None:
            label = (
                f"path_id={path_id!r}" if path_id
                else f"source={source!r}, target={target!r}"
            )
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"path not found for {label}",
            )

        output = _project_path(found)
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

    def _list_paths(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        paths: list[dict],
    ) -> Result:
        """Return a summary of all paths, capped at limit."""
        limit, limit_refused = limit_refusal(payload.get("limit"))
        if limit_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=limit_refused,
            )
        summaries = []
        for entry in paths[:limit]:
            summaries.append({
                "path_id": entry.get("path_id"),
                "source": entry.get("source"),
                "target": entry.get("target"),
                "length": entry.get("length"),
                "risk_score": entry.get("risk_score"),
            })
        output = {
            "total": len(paths),
            "returned": len(summaries),
            "capped": len(paths) > limit,
            "paths": summaries,
        }
        text = json.dumps(output, sort_keys=True)
        if len(text) > MAX_OUTPUT_CHARS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=(
                    f"result exceeds the {MAX_OUTPUT_CHARS} character output "
                    "cap; reduce the limit"
                ),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=output,
            error=None,
        )

    def _list_datasources(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        paths: list[dict],
    ) -> Result:
        """Return unique datasources found across all paths."""
        datasources: set[str] = set()
        for entry in paths:
            ds = entry.get("datasource")
            if isinstance(ds, str) and ds.strip():
                datasources.add(ds.strip())
            # Also check edges for datasource fields.
            for edge in entry.get("edges", []):
                if isinstance(edge, dict):
                    eds = edge.get("datasource")
                    if isinstance(eds, str) and eds.strip():
                        datasources.add(eds.strip())
        output = {
            "count": len(datasources),
            "datasources": sorted(datasources),
        }
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
                "arg_keys": {key: sorted(vals) for key, vals in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )

    def _load_export(self, path: Path) -> list[dict] | str:
        """Load an AD path export from a local JSON or YAML file.

        Returns a list of path dicts on success, or a refusal string on
        error. A JSON file is expected to be a top-level array; a YAML
        file is expected to contain a ``paths`` key with a list value.
        """
        try:
            raw = path.read_bytes()
        except OSError as exc:
            return f"could not read export: {redact(str(exc))}"

        suffix = path.suffix.lower()
        if suffix == ".json":
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError) as exc:
                return f"export is not valid JSON: {redact(str(exc))}"
            if isinstance(data, list):
                return _validate_paths(data)
            if isinstance(data, dict) and isinstance(data.get("paths"), list):
                return _validate_paths(data["paths"])
            return (
                "JSON export must be an array of path objects or an object "
                "with a 'paths' key containing an array"
            )
        else:
            # YAML
            try:
                import yaml
            except ImportError:
                return "PyYAML is required to read YAML exports"
            try:
                data = yaml.safe_load(raw)
            except Exception as exc:
                return f"export is not valid YAML: {redact(str(exc))}"
            if isinstance(data, dict) and isinstance(data.get("paths"), list):
                return _validate_paths(data["paths"])
            if isinstance(data, list):
                return _validate_paths(data)
            return (
                "YAML export must contain a 'paths' key with a list of "
                "path objects, or be a top-level list"
            )


def _validate_paths(data: list) -> list[dict]:
    """Filter to only dict entries; silently skip non-dict items."""
    return [entry for entry in data if isinstance(entry, dict)]


def _project_path(entry: dict) -> dict:
    """Project a path entry to a consistent output shape.

    Missing datasource fields read as 'not assessed', never clean.
    """
    return {
        "path_id": entry.get("path_id"),
        "source": entry.get("source"),
        "target": entry.get("target"),
        "datasource": entry.get("datasource") or "not assessed",
        "length": entry.get("length"),
        "risk_score": entry.get("risk_score"),
        "nodes": entry.get("nodes", []),
        "edges": entry.get("edges", []),
    }


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()
