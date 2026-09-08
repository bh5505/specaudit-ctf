"""Curated detection-in-the-cloud arm: cloud detection playbook reads."""

from __future__ import annotations

import json
import os
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
    ARG_KEYS,
    ARMING,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    MAX_PLAYBOOK_BYTES,
    MAX_RESULTS,
    PLAYBOOK_SUFFIXES,
    args_refusal,
    playbook_dir_refusal,
)

try:
    import yaml as _yaml
except ImportError:
    _yaml = None


class DetectionInTheCloudArm:
    """Specialized transport for catalog id detection-in-the-cloud.

    First-party in-process read arm: reads cloud detection methodology
    playbooks from a local directory.  ``installed`` reports handler
    presence only — the playbook_dir is per-invoke caller data.
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
                "(local playbook reads only; "
                f"arming: {ARMING})",
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
        pdir, dir_refused = playbook_dir_refusal(payload.get("playbook_dir"))
        if dir_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=dir_refused,
            )
        if action == "playbook":
            return self._playbook(spec, action, payload, pdir)
        if action == "list_playbooks":
            return self._list_playbooks(spec, action, payload, pdir)
        return self._list_rules(spec, action, payload, pdir)

    def _playbook(
        self, spec: ArmSpec, action: str, payload: dict, pdir: str
    ) -> Result:
        name = str(payload.get("name") or "").strip()
        if not name:
            return _fail(spec, action, "playbook requires args.name")
        if "/" in name or "\\" in name or ".." in name:
            return _fail(spec, action, "name must be a bare filename, not a path")
        matched = None
        for suffix in PLAYBOOK_SUFFIXES:
            candidate = os.path.join(pdir, name + suffix)
            if os.path.isfile(candidate):
                matched = candidate
                break
        if matched is None:
            candidate = os.path.join(pdir, name)
            if os.path.isfile(candidate) and any(name.endswith(s) for s in PLAYBOOK_SUFFIXES):
                matched = candidate
        if matched is None:
            return _fail(spec, action, f"playbook not found: {name!r} in {pdir!r}")
        try:
            size = os.path.getsize(matched)
        except OSError as exc:
            return _fail(spec, action, f"could not stat playbook: {exc}")
        if size > MAX_PLAYBOOK_BYTES:
            return _fail(spec, action, f"playbook exceeds {MAX_PLAYBOOK_BYTES} byte cap")
        try:
            with open(matched, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            return _fail(spec, action, f"playbook unreadable: {exc}")
        ext = os.path.splitext(matched)[1].lower()
        if ext == ".json":
            try:
                content = json.loads(raw)
            except json.JSONDecodeError as exc:
                return _fail(spec, action, f"invalid JSON: {exc}")
        elif ext in (".yaml", ".yml"):
            if _yaml is None:
                return _fail(spec, action, "PyYAML is not installed")
            try:
                content = _yaml.safe_load(raw)
            except Exception as exc:
                return _fail(spec, action, f"invalid YAML: {exc}")
        else:
            content = raw
        text = json.dumps(content, sort_keys=True) if not isinstance(content, str) else content
        if len(text) > MAX_OUTPUT_CHARS:
            return _fail(spec, action, f"playbook exceeds the {MAX_OUTPUT_CHARS} char output cap")
        return Result(ok=True, arm_id=spec.id, action=action, output=content, error=None)

    def _list_playbooks(
        self, spec: ArmSpec, action: str, payload: dict, pdir: str
    ) -> Result:
        limit = MAX_RESULTS
        try:
            entries = []
            for entry in sorted(os.listdir(pdir)):
                if any(entry.endswith(s) for s in PLAYBOOK_SUFFIXES):
                    full = os.path.join(pdir, entry)
                    if os.path.isfile(full):
                        entries.append({"name": entry, "format": os.path.splitext(entry)[1].lstrip(".")})
                        if len(entries) >= limit:
                            break
        except OSError as exc:
            return _fail(spec, action, f"failed to scan directory: {exc}")
        return Result(
            ok=True, arm_id=spec.id, action=action,
            output={"playbooks": entries, "total": len(entries)},
            error=None,
        )

    def _list_rules(
        self, spec: ArmSpec, action: str, payload: dict, pdir: str
    ) -> Result:
        category = str(payload.get("category") or "").strip().lower() or None
        rule_files = ["rules.json", "rules.yaml", "rules.yml", "detections.json", "detections.yaml", "detections.yml"]
        rule_data = None
        for fname in rule_files:
            candidate = os.path.join(pdir, fname)
            if os.path.isfile(candidate):
                try:
                    with open(candidate, encoding="utf-8") as fh:
                        raw = fh.read()
                except OSError:
                    continue
                ext = os.path.splitext(fname)[1].lower()
                if ext == ".json":
                    try:
                        rule_data = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                elif _yaml is not None:
                    try:
                        rule_data = _yaml.safe_load(raw)
                    except Exception:
                        continue
                break
        if rule_data is None:
            return _fail(spec, action, "no rules or detections file found in playbook_dir")
        if isinstance(rule_data, dict):
            rules_list = rule_data.get("rules", rule_data.get("detections", []))
        elif isinstance(rule_data, list):
            rules_list = rule_data
        else:
            return _fail(spec, action, "rules file must be a list or mapping with 'rules' key")
        if category:
            rules_list = [r for r in rules_list if isinstance(r, dict) and r.get("category", "").lower() == category]
        summaries = [
            {"rule_id": r.get("rule_id", r.get("id", "")), "name": r.get("name", ""), "severity": r.get("severity", "")}
            for r in rules_list[:MAX_RESULTS] if isinstance(r, dict)
        ]
        return Result(
            ok=True, arm_id=spec.id, action=action,
            output={"rules": summaries, "total": len(summaries)},
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


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(
        ok=False,
        arm_id=spec.id,
        action=action,
        output=None,
        error=redact(error[:MAX_OUTPUT_CHARS]),
    )
