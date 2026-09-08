"""Curated security-detections-mcp arm: local rule reads over pinned indexes."""

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
    ARG_KEYS,
    ARMING,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
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
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(local rule reads over a pinned index only; "
                f"there is no dispatch tier; arming: {ARMING})",
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
        path, idx_refused = index_refusal(payload.get("index"))
        if idx_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=idx_refused,
            )
        rules = _load_index(path)
        if isinstance(rules, str):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=rules,
            )
        return self._dispatch(spec, action, payload, rules)

    def _dispatch(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        rules: list[dict[str, Any]],
    ) -> Result:
        if action == "list_rules":
            return self._list_rules(spec, action, payload, rules)
        if action == "search_rules":
            return self._search_rules(spec, action, payload, rules)
        return self._get_rule(spec, action, payload, rules)

    def _list_rules(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        rules: list[dict[str, Any]],
    ) -> Result:
        limit_raw, limit_err = limit_refusal(payload.get("limit"))
        if limit_err:
            return _fail(spec, action, limit_err)
        limit = limit_raw or MAX_RESULTS
        rows = [
            {"rule_id": r.get("rule_id", ""), "name": r.get("name", ""), "severity": r.get("severity", "")}
            for r in rules[:limit]
        ]
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"total": len(rules), "rules": rows},
            error=None,
        )

    def _search_rules(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        rules: list[dict[str, Any]],
    ) -> Result:
        query = str(payload.get("query") or "").strip().lower()
        if not query:
            return _fail(spec, action, "search_rules requires args.query")
        limit_raw, limit_err = limit_refusal(payload.get("limit"))
        if limit_err:
            return _fail(spec, action, limit_err)
        limit = limit_raw or MAX_RESULTS
        matches = []
        for r in rules:
            searchable = json.dumps(r, sort_keys=True).lower()
            if query in searchable:
                matches.append({"rule_id": r.get("rule_id", ""), "name": r.get("name", ""), "severity": r.get("severity", "")})
                if len(matches) >= limit:
                    break
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"query": payload["query"], "total": len(matches), "rules": matches},
            error=None,
        )

    def _get_rule(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        rules: list[dict[str, Any]],
    ) -> Result:
        rule_id = str(payload.get("rule_id") or "").strip()
        for r in rules:
            if str(r.get("rule_id", "")) == rule_id:
                text = json.dumps(r, sort_keys=True)
                if len(text) > MAX_OUTPUT_CHARS:
                    return _fail(spec, action, f"rule {rule_id!r} exceeds the output cap")
                return Result(ok=True, arm_id=spec.id, action=action, output=r, error=None)
        return _fail(spec, action, f"rule {rule_id!r} not found in this index")

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


def _load_index(path: Path) -> list[dict[str, Any]] | str:
    """Load a detection-rule index from JSON or YAML.  Returns list or refusal."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return f"index unreadable: {exc}"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "index is not valid UTF-8"
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        return f"index is not valid {suffix.lstrip('.').upper()}: {exc}"
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "rules" in data and isinstance(data["rules"], list):
        return data["rules"]
    return "index must be a list of rules or a mapping with a 'rules' key"


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(
        ok=False,
        arm_id=spec.id,
        action=action,
        output=None,
        error=redact(error[:MAX_OUTPUT_CHARS]),
    )
