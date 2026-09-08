"""Curated security-detections-mcp arm: local rule reads over frozen indexes."""

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
    ARG_KEYS,
    ARMING,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_INDEX_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RECORDS,
    MAX_RESULTS,
    args_refusal,
    index_refusal,
    limit_refusal,
)


class SecurityDetectionsMcpArm:
    """Specialized transport for catalog id security-detections-mcp.

    First-party in-process read arm: a stdlib detection-rule reader with
    no subprocess and no endpoint.  ``installed`` reports handler
    presence only — the index is per-invoke caller data (args.index).
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
                "(local rule reads over an operator-supplied frozen index only; "
                f"there is no dispatch tier; arming: {ARMING})",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, idx_refused = index_refusal(payload.get("index"))
        if idx_refused:
            return _fail(spec, action, idx_refused)
        if path is None:
            return _fail(spec, action, "index path validation failed")
        try:
            loaded = _load_index(path)
        except Exception:
            return _fail(spec, action, "index could not be parsed safely")
        if isinstance(loaded, str):
            return _fail(spec, action, loaded)
        rules, source = loaded
        return self._dispatch(spec, action, payload, rules, source)

    def _dispatch(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        rules: list[dict[str, Any]],
        source: dict[str, Any],
    ) -> Result:
        if action == "list_rules":
            return self._list_rules(spec, action, payload, rules, source)
        if action == "search_rules":
            return self._search_rules(spec, action, payload, rules, source)
        return self._get_rule(spec, action, payload, rules, source)

    def _list_rules(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        rules: list[dict[str, Any]],
        source: dict[str, Any],
    ) -> Result:
        limit_value, limit_err = limit_refusal(payload.get("limit"))
        if limit_err:
            return _fail(spec, action, limit_err)
        limit = limit_value if limit_value is not None else MAX_RESULTS
        rows = [
            {
                "rule_id": r["rule_id"],
                "name": r["name"],
                "severity": r.get("severity", ""),
            }
            for r in rules[:limit]
        ]
        return _ok(
            spec,
            action,
            {
                "total": len(rules),
                "returned": len(rows),
                "capped": len(rows) < len(rules),
                "rules": rows,
                "source": source,
            },
        )

    def _search_rules(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        rules: list[dict[str, Any]],
        source: dict[str, Any],
    ) -> Result:
        query_value = payload.get("query")
        if not isinstance(query_value, str) or not query_value.strip():
            return _fail(spec, action, "search_rules requires args.query as a non-empty string")
        query = query_value.strip().lower()
        limit_value, limit_err = limit_refusal(payload.get("limit"))
        if limit_err:
            return _fail(spec, action, limit_err)
        limit = limit_value if limit_value is not None else MAX_RESULTS
        all_matches = []
        for r in rules:
            try:
                searchable = json.dumps(
                    r, sort_keys=True, allow_nan=False
                ).lower()
            except (TypeError, ValueError):
                return _fail(spec, action, "index rule could not be searched safely")
            if query in searchable:
                all_matches.append(
                    {
                        "rule_id": r["rule_id"],
                        "name": r["name"],
                        "severity": r.get("severity", ""),
                    }
                )
        matches = all_matches[:limit]
        return _ok(
            spec,
            action,
            {
                "query": query_value,
                "total": len(all_matches),
                "returned": len(matches),
                "capped": len(matches) < len(all_matches),
                "rules": matches,
                "source": source,
            },
        )

    def _get_rule(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        rules: list[dict[str, Any]],
        source: dict[str, Any],
    ) -> Result:
        rule_id = str(payload.get("rule_id") or "").strip()
        for r in rules:
            if r["rule_id"] == rule_id:
                return _ok(
                    spec,
                    action,
                    {"rule": r, "source": source},
                    narrow="the rule definition is too large",
                )
        return _fail(spec, action, f"rule {rule_id!r} not found in this index")

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


def _load_index(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]] | str:
    """Load a detection-rule index from JSON or YAML.  Returns list or refusal."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_INDEX_BYTES + 1)
    except OSError:
        return "index is unreadable"
    if len(raw) > MAX_INDEX_BYTES:
        return f"index exceeds the {MAX_INDEX_BYTES} byte read cap"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "index is not valid UTF-8"
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            data = strict_json_loads(text)
        else:
            data = yaml.load(text, Loader=_BoundedSafeLoader)
    except StrictDataError as exc:
        return str(exc)
    except (json.JSONDecodeError, RecursionError, yaml.YAMLError, ValueError):
        return f"index is not valid {suffix.lstrip('.').upper()}"
    refusal = _tree_refusal(data)
    if refusal:
        return f"index {refusal}"
    if isinstance(data, list):
        rules = data
    elif isinstance(data, dict) and isinstance(data.get("rules"), list):
        rules = data["rules"]
    else:
        return "index must be a list of rules or a mapping with a 'rules' list"
    validated = _validate_rules(rules)
    if isinstance(validated, str):
        return validated
    return validated, _source(raw)


class _BoundedSafeLoader(StrictMappingMixin, yaml.SafeLoader):
    """SafeLoader that refuses graph expansion and bounds composition."""

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


def _validate_rules(data: list[Any]) -> list[dict[str, Any]] | str:
    if len(data) > MAX_RECORDS:
        return f"index exceeds the {MAX_RECORDS} record cap"
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            return f"index rule {index} must be a mapping"
        rule_id = item.get("rule_id")
        name = item.get("name")
        if not isinstance(rule_id, str) or not rule_id.strip():
            return f"index rule {index} requires a non-empty string rule_id"
        if not isinstance(name, str) or not name.strip():
            return f"index rule {index} requires a non-empty string name"
        for key in ("severity", "category"):
            if key in item and not isinstance(item[key], str):
                return f"index rule {index} field {key!r} must be a string"
        normalized_id = rule_id.strip()
        if normalized_id in seen:
            return f"index contains duplicate rule_id {normalized_id!r}"
        seen.add(normalized_id)
        normalized = dict(item)
        normalized["rule_id"] = normalized_id
        normalized["name"] = name.strip()
        rules.append(normalized)
    return rules


def _source(raw: bytes) -> dict[str, Any]:
    return {
        "kind": "operator-file",
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _ok(spec: ArmSpec, action: str, output: Any, *, narrow: str = "narrow the lookup") -> Result:
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
            f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; {narrow}",
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
