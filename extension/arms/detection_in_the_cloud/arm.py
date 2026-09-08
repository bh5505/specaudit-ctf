"""Curated detection-in-the-cloud arm: cloud detection playbook reads."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

import yaml
from yaml.events import AliasEvent

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..mcp_client import redact
from ..strict_data import (
    StrictDataError,
    StrictMappingMixin,
    bounded_tree_refusal,
    strict_json_loads,
)
from .policy import (
    ALLOWED_ACTIONS,
    ARG_KEYS,
    ARMING,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_DIRECTORY_ENTRIES,
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_OUTPUT_CHARS,
    MAX_PLAYBOOK_BYTES,
    MAX_RECORDS,
    MAX_RESULTS,
    PLAYBOOK_SUFFIXES,
    args_refusal,
    limit_refusal,
    playbook_dir_refusal,
)

_RULE_FILES = (
    "rules.json",
    "rules.yaml",
    "rules.yml",
    "detections.json",
    "detections.yaml",
    "detections.yml",
)


class _PlaybookError(ValueError):
    """A playbook input is malformed or exceeds a bounded read contract."""


class DetectionInTheCloudArm:
    """Bounded in-process reader over a local playbook directory."""

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
                f"(local playbook reads only; arming: {ARMING})",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        directory_text, refusal = playbook_dir_refusal(payload.get("playbook_dir"))
        if refusal:
            return _fail(spec, action, refusal)
        if directory_text is None:
            return _fail(spec, action, "playbook directory validation failed")
        directory = Path(directory_text)
        try:
            if action == "playbook":
                return self._playbook(spec, action, payload, directory)
            if action == "list_playbooks":
                return self._list_playbooks(spec, action, payload, directory)
            return self._list_rules(spec, action, payload, directory)
        except _PlaybookError as exc:
            return _fail(spec, action, str(exc))
        except Exception:
            return _fail(spec, action, "playbook data could not be processed safely")

    def _playbook(
        self, spec: ArmSpec, action: str, payload: dict, directory: Path
    ) -> Result:
        name = payload["name"].strip()
        if "/" in name or "\\" in name or ".." in name:
            raise _PlaybookError("name must be a bare filename, not a path")
        path = _find_playbook(directory, name)
        if path is None:
            return _fail(spec, action, f"playbook {name!r} not found")
        raw = _read_bounded(path)
        content = _parse_document(path, raw)
        if path.suffix.lower() != ".md":
            _validate_playbook(content)
        return _ok(
            spec,
            action,
            {"playbook": content, "source": _source(raw)},
        )

    def _list_playbooks(
        self, spec: ArmSpec, action: str, payload: dict, directory: Path
    ) -> Result:
        limit_value, refusal = limit_refusal(payload.get("limit"))
        if refusal:
            return _fail(spec, action, refusal)
        limit = limit_value if limit_value is not None else MAX_RESULTS
        entries = _playbook_entries(directory)
        rows = entries[:limit]
        listing_bytes = json.dumps(
            entries,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return _ok(
            spec,
            action,
            {
                "playbooks": rows,
                "total": len(entries),
                "returned": len(rows),
                "capped": len(rows) < len(entries),
                "source": _source(listing_bytes, kind="operator-directory-listing"),
            },
        )

    def _list_rules(
        self, spec: ArmSpec, action: str, payload: dict, directory: Path
    ) -> Result:
        limit_value, refusal = limit_refusal(payload.get("limit"))
        if refusal:
            return _fail(spec, action, refusal)
        limit = limit_value if limit_value is not None else MAX_RESULTS
        category = payload.get("category")
        category_filter = category.strip().casefold() if isinstance(category, str) else None
        candidates = [
            candidate
            for name in _RULE_FILES
            if (candidate := directory / name).is_file()
            and not candidate.is_symlink()
        ]
        if not candidates:
            return _fail(
                spec,
                action,
                "no rules or detections file found in playbook_dir",
            )
        if len(candidates) != 1:
            return _fail(
                spec,
                action,
                "playbook_dir contains multiple rules/detections files; "
                "supply an unambiguous directory snapshot",
            )
        path = candidates[0]
        raw = _read_bounded(path)
        data = _parse_document(path, raw)
        rules = _extract_rules(data)
        unfiltered_total = len(rules)
        if category_filter is not None:
            rules = [
                rule
                for rule in rules
                if rule.get("category", "").casefold() == category_filter
            ]
        rows = [
            {
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "severity": rule.get("severity", ""),
            }
            for rule in rules[:limit]
        ]
        return _ok(
            spec,
            action,
            {
                "rules": rows,
                "total": len(rules),
                "unfiltered_total": unfiltered_total,
                "returned": len(rows),
                "capped": len(rows) < len(rules),
                "source": _source(raw),
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
                "arg_keys": {key: sorted(values) for key, values in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
        )


def _find_playbook(directory: Path, name: str) -> Path | None:
    if any(name.casefold().endswith(suffix) for suffix in PLAYBOOK_SUFFIXES):
        names = [name]
    else:
        names = [name + suffix for suffix in PLAYBOOK_SUFFIXES]
    candidates = [
        candidate
        for candidate_name in names
        if (candidate := directory / candidate_name).is_file()
        and not candidate.is_symlink()
    ]
    if len(candidates) > 1:
        raise _PlaybookError(
            "multiple playbook files match args.name; include the file suffix"
        )
    return candidates[0] if candidates else None


def _playbook_entries(directory: Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    scanned = 0
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                scanned += 1
                if scanned > MAX_DIRECTORY_ENTRIES:
                    raise _PlaybookError(
                        f"playbook directory exceeds the {MAX_DIRECTORY_ENTRIES} entry cap"
                    )
                suffix = Path(entry.name).suffix.lower()
                if suffix not in PLAYBOOK_SUFFIXES:
                    continue
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    raise _PlaybookError(
                        f"playbook entry {entry.name!r} is not a regular non-symlink file"
                    )
                entries.append({"name": entry.name, "format": suffix.lstrip(".")})
    except OSError as exc:
        raise _PlaybookError("failed to scan playbook directory") from exc
    return sorted(entries, key=lambda row: row["name"])


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_PLAYBOOK_BYTES + 1)
    except OSError as exc:
        raise _PlaybookError("playbook file is unreadable") from exc
    if len(raw) > MAX_PLAYBOOK_BYTES:
        raise _PlaybookError(
            f"playbook file exceeds the {MAX_PLAYBOOK_BYTES} byte read cap"
        )
    return raw


def _parse_document(path: Path, raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _PlaybookError("playbook file is not valid UTF-8") from exc
    suffix = path.suffix.lower()
    if suffix == ".md":
        if not text.strip():
            raise _PlaybookError("Markdown playbook must not be empty")
        return text
    try:
        if suffix == ".json":
            data = strict_json_loads(text)
        else:
            data = yaml.load(text, Loader=_BoundedSafeLoader)
    except StrictDataError as exc:
        raise _PlaybookError(str(exc)) from exc
    except (json.JSONDecodeError, RecursionError, yaml.YAMLError, ValueError) as exc:
        label = "JSON" if suffix == ".json" else "YAML"
        raise _PlaybookError(f"playbook file is not valid {label}") from exc
    refusal = _tree_refusal(data)
    if refusal:
        raise _PlaybookError(f"playbook file {refusal}")
    return data


def _validate_playbook(data: Any) -> None:
    if not isinstance(data, dict):
        raise _PlaybookError("playbook document must be a mapping")
    if not any(key in data for key in ("name", "rules")):
        raise _PlaybookError(
            "playbook document must contain a non-empty name or a rules list"
        )
    if "name" in data and (
        not isinstance(data["name"], str) or not data["name"].strip()
    ):
        raise _PlaybookError("playbook field 'name' must be a non-empty string")
    if "rules" in data:
        _validate_rules(data["rules"])


def _extract_rules(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        keys = [key for key in ("rules", "detections") if key in data]
        if len(keys) != 1 or not isinstance(data[keys[0]], list):
            raise _PlaybookError(
                "rules file must contain exactly one rules/detections list"
            )
        rows = data[keys[0]]
    else:
        raise _PlaybookError(
            "rules file must be a list or mapping with a rules/detections list"
        )
    return _validate_rules(rows)


def _validate_rules(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise _PlaybookError("playbook field 'rules' must be a list")
    if len(rows) > MAX_RECORDS:
        raise _PlaybookError(f"rules file exceeds the {MAX_RECORDS} rule cap")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise _PlaybookError(f"rule {index} must be a mapping")
        identifiers = [key for key in ("rule_id", "id") if key in row]
        if len(identifiers) != 1:
            raise _PlaybookError(f"rule {index} requires exactly one rule_id/id")
        raw_id = row[identifiers[0]]
        name = row.get("name")
        if not isinstance(raw_id, str) or not raw_id.strip():
            raise _PlaybookError(f"rule {index} identifier must be a non-empty string")
        if not isinstance(name, str) or not name.strip():
            raise _PlaybookError(f"rule {index} requires a non-empty string name")
        for key in ("category", "severity"):
            if key in row and not isinstance(row[key], str):
                raise _PlaybookError(f"rule {index} field {key!r} must be a string")
        normalized_id = raw_id.strip()
        if normalized_id in seen:
            raise _PlaybookError(f"rules file contains duplicate id {normalized_id!r}")
        seen.add(normalized_id)
        normalized = dict(row)
        normalized["rule_id"] = normalized_id
        normalized.pop("id", None)
        normalized["name"] = name.strip()
        output.append(normalized)
    return output


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


def _source(raw: bytes, *, kind: str = "operator-file") -> dict[str, Any]:
    return {
        "kind": kind,
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        encoded = json.dumps(
            output, sort_keys=True, ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError):
        return _fail(spec, action, "result could not be encoded safely")
    if len(encoded) > MAX_OUTPUT_CHARS:
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
