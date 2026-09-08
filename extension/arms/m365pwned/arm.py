"""Curated m365pwned arm: synthetic M365 consent and data-access case reads."""

from __future__ import annotations

import json
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
    MAX_RESULTS,
    args_refusal,
    cases_file_refusal,
    limit_refusal,
)

try:
    import yaml as _yaml
except ImportError:
    _yaml = None


class M365PwnedArm:
    """Specialized transport for catalog id m365pwned.

    First-party in-process read arm: reads synthetic M365 consent and
    data-access case studies from a local JSON (or YAML) file.  No real
    tenant, mailbox, or file is ever accessed.  ``installed`` reports
    handler presence only — the cases_file is per-invoke caller data.
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
                "(synthetic case reads only; "
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
        cfile, file_refused = cases_file_refusal(payload.get("cases_file"))
        if file_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=file_refused,
            )
        cases = self._load_cases(cfile)
        if isinstance(cases, str):
            return _fail(spec, action, cases)
        if action == "case_study":
            return self._case_study(spec, action, payload, cases)
        if action == "list_case_studies":
            return self._list_case_studies(spec, action, payload, cases)
        return self._list_permissions(spec, action, payload, cases)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _case_study(
        self, spec: ArmSpec, action: str, payload: dict, cases: list[dict]
    ) -> Result:
        case_id = str(payload.get("case_id") or "").strip() or None
        name = str(payload.get("name") or "").strip() or None
        matched = None
        for entry in cases:
            if not isinstance(entry, dict):
                continue
            if case_id and str(entry.get("case_id", "")).strip() == case_id:
                matched = entry
                break
            if name and str(entry.get("name", "")).strip().lower() == name.lower():
                matched = entry
                break
        if matched is None:
            identifier = case_id or name or "<unknown>"
            return _fail(spec, action, f"case study not found: {identifier!r}")
        text = json.dumps(matched, sort_keys=True)
        if len(text) > MAX_OUTPUT_CHARS:
            return _fail(
                spec, action,
                f"case study exceeds the {MAX_OUTPUT_CHARS} char output cap",
            )
        return Result(ok=True, arm_id=spec.id, action=action, output=matched, error=None)

    def _list_case_studies(
        self, spec: ArmSpec, action: str, payload: dict, cases: list[dict]
    ) -> Result:
        limit_raw = payload.get("limit")
        limit, lrefusal = limit_refusal(limit_raw)
        if lrefusal:
            return _fail(spec, action, lrefusal)
        effective = limit or MAX_RESULTS
        summaries = []
        for entry in cases:
            if not isinstance(entry, dict):
                continue
            summaries.append({
                "case_id": entry.get("case_id", ""),
                "name": entry.get("name", ""),
                "description": entry.get("description", ""),
                "risk_level": (
                    entry.get("risk_assessment", {}).get("level", "")
                    if isinstance(entry.get("risk_assessment"), dict)
                    else ""
                ),
            })
            if len(summaries) >= effective:
                break
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"case_studies": summaries, "total": len(summaries)},
            error=None,
        )

    def _list_permissions(
        self, spec: ArmSpec, action: str, payload: dict, cases: list[dict]
    ) -> Result:
        case_id = str(payload.get("case_id") or "").strip()
        matched = None
        for entry in cases:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("case_id", "")).strip() == case_id:
                matched = entry
                break
        if matched is None:
            return _fail(spec, action, f"case study not found: {case_id!r}")
        permissions = matched.get("permissions", [])
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={
                "case_id": case_id,
                "name": matched.get("name", ""),
                "permissions": permissions,
                "total": len(permissions) if isinstance(permissions, list) else 0,
            },
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

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_cases(path: str) -> list[dict] | str:
        """Load case studies from a JSON array or a YAML with a
        ``case_studies`` key.  Returns the list on success or an error
        string on failure (fail-closed)."""
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            return f"cases file unreadable: {exc}"
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if ext in ("yaml", "yml"):
            if _yaml is None:
                return "PyYAML is not installed"
            try:
                data = _yaml.safe_load(raw)
            except Exception as exc:
                return f"invalid YAML: {exc}"
            if isinstance(data, dict):
                cases = data.get("case_studies")
                if isinstance(cases, list):
                    return cases
                return "YAML cases file must contain a 'case_studies' list"
            if isinstance(data, list):
                return data
            return "YAML cases file must be a list or a mapping with 'case_studies'"
        # Default: JSON
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            return f"invalid JSON: {exc}"
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            cases = data.get("case_studies")
            if isinstance(cases, list):
                return cases
            return "JSON cases file must be an array or a mapping with 'case_studies'"
        return "cases file must contain a JSON array or a mapping with 'case_studies'"


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(
        ok=False,
        arm_id=spec.id,
        action=action,
        output=None,
        error=redact(error[:MAX_OUTPUT_CHARS]),
    )
