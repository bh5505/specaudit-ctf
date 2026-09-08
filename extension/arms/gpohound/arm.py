"""Curated gpohound arm: GPO policy evidence reads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

try:
    import yaml as _yaml
except ImportError:
    _yaml = None  # type: ignore[assignment]

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
    EVIDENCE_SUFFIXES,
    LIST_ACTIONS,
    MAX_EVIDENCE_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    evidence_refusal,
    limit_refusal,
)


class GpohoundArm:
    """Specialized transport for catalog id gpohound.

    First-party in-process read arm: a stdlib reader over a local GPO
    policy evidence file with no subprocess and no endpoint.
    ``installed`` reports handler presence only — the evidence is
    per-invoke caller data (args.evidence), the same contract as every
    other file-consuming arm.

    Filtered-out policy is NOT effective access.  Security filters and
    WMI filters are not fully covered and should be validated separately.
    No shared-graph writes: this is a read-only evidence arm.
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
                error=(
                    f"action {action!r} is not on the allowlist "
                    "(offline reads over local GPO policy evidence only; "
                    "there is no dispatch tier)"
                ),
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
        path, ev_refused = evidence_refusal(payload.get("evidence"))
        if ev_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=ev_refused,
            )
        assert path is not None  # noqa: S101 — guarded by ev_refused
        try:
            policies = _load_evidence(path)
        except _EvidenceError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if action == "policy":
            return self._policy(spec, payload, policies)
        if action == "list_policies":
            return self._list_policies(spec, payload, policies)
        # action == "list_links"
        return self._list_links(spec, payload, policies)

    # -- action handlers --------------------------------------------------

    def _policy(
        self, spec: ArmSpec, payload: dict, policies: list[dict]
    ) -> Result:
        """Return the full definition for a single policy."""
        pid = _opt_str(payload.get("policy_id"))
        name = _opt_str(payload.get("name"))
        match = _find_policy(policies, policy_id=pid, name=name)
        if match is None:
            identifier = pid or name
            return Result(
                ok=False,
                arm_id=spec.id,
                action="policy",
                output=None,
                error=f"policy {identifier!r} not found in this evidence",
            )
        text = json.dumps(match, sort_keys=True, default=str)
        if len(text) > MAX_OUTPUT_CHARS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action="policy",
                output=None,
                error=(
                    f"result exceeds the {MAX_OUTPUT_CHARS} character "
                    "output cap; narrow the lookup"
                ),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action="policy",
            output=match,
            error=None,
        )

    def _list_policies(
        self, spec: ArmSpec, payload: dict, policies: list[dict]
    ) -> Result:
        """Return a summary list of policies (capped at limit), optionally filtered by status."""
        raw_limit = limit_refusal(payload.get("limit"))
        if isinstance(raw_limit, str):
            return Result(
                ok=False,
                arm_id=spec.id,
                action="list_policies",
                output=None,
                error=raw_limit,
            )
        limit = raw_limit
        status_filter = _opt_str(payload.get("status"))
        summaries: list[dict[str, Any]] = []
        for pol in policies:
            pol_status = str(pol.get("status", "")).strip().lower()
            if status_filter and pol_status != status_filter.lower():
                continue
            links = pol.get("links", [])
            link_count = len(links) if isinstance(links, list) else 0
            summaries.append(
                {
                    "policy_id": pol.get("policy_id", ""),
                    "name": pol.get("name", ""),
                    "status": pol.get("status", ""),
                    "link_count": link_count,
                }
            )
            if len(summaries) >= limit:
                break
        return Result(
            ok=True,
            arm_id=spec.id,
            action="list_policies",
            output={
                "count": len(summaries),
                "total": len(policies),
                "policies": summaries,
            },
            error=None,
        )

    def _list_links(
        self, spec: ArmSpec, payload: dict, policies: list[dict]
    ) -> Result:
        """Return links for a specific GPO identified by gpo_id."""
        gpo_id = str(payload.get("gpo_id") or "").strip()
        match = None
        for pol in policies:
            if str(pol.get("policy_id", "")).strip() == gpo_id:
                match = pol
                break
        if match is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action="list_links",
                output=None,
                error=f"GPO {gpo_id!r} not found in this evidence",
            )
        links = match.get("links", [])
        if not isinstance(links, list):
            links = []
        return Result(
            ok=True,
            arm_id=spec.id,
            action="list_links",
            output={
                "gpo_id": gpo_id,
                "name": match.get("name", ""),
                "link_count": len(links),
                "links": links,
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
                "arg_keys": {
                    key: sorted(vals) for key, vals in ARG_KEYS.items()
                },
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )


# -- evidence loading ------------------------------------------------------


class _EvidenceError(Exception):
    """Raised when the evidence file cannot be loaded."""


def _load_evidence(path: Path) -> list[dict]:
    """Load GPO policy evidence from a local JSON or YAML file.

    Accepted shapes:
    - A JSON file containing a top-level array of policy dicts.
    - A JSON or YAML file with a ``policies`` key whose value is a list.

    Returns the list of policy dicts, or raises ``_EvidenceError``.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise _EvidenceError(f"could not read evidence: {exc}") from exc

    suffix = path.suffix.lower()

    # --- JSON ---
    if suffix == ".json":
        try:
            data = json.loads(raw_bytes)
        except (json.JSONDecodeError, ValueError) as exc:
            raise _EvidenceError(f"invalid JSON in evidence: {exc}") from exc
        if isinstance(data, list):
            return _validate_list(data)
        if isinstance(data, dict):
            policies = data.get("policies")
            if isinstance(policies, list):
                return _validate_list(policies)
        raise _EvidenceError(
            "JSON evidence must be an array of policies or a mapping "
            "with a 'policies' key"
        )

    # --- YAML ---
    if suffix in (".yaml", ".yml"):
        if _yaml is None:
            raise _EvidenceError(
                "PyYAML is required to load YAML evidence files "
                "(pip install pyyaml)"
            )
        try:
            data = _yaml.safe_load(raw_bytes)
        except _yaml.YAMLError as exc:
            raise _EvidenceError(f"invalid YAML in evidence: {exc}") from exc
        if isinstance(data, dict):
            policies = data.get("policies")
            if isinstance(policies, list):
                return _validate_list(policies)
        if isinstance(data, list):
            return _validate_list(data)
        raise _EvidenceError(
            "YAML evidence must contain a 'policies' list or be a "
            "top-level list"
        )

    # suffix guard (should be unreachable after policy validation)
    raise _EvidenceError(
        f"unsupported evidence format: {suffix!r}; "
        "expected .json, .yaml, or .yml"
    )


def _validate_list(data: list) -> list[dict]:
    """Ensure every element in the evidence list is a dict."""
    out: list[dict] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise _EvidenceError(
                f"evidence entry {idx} is not a mapping "
                f"(got {type(item).__name__})"
            )
        out.append(item)
    return out


# -- helpers --------------------------------------------------------------


def _find_policy(
    policies: list[dict],
    *,
    policy_id: str | None = None,
    name: str | None = None,
) -> dict | None:
    """Exact-match search by policy_id or name (first match wins)."""
    for pol in policies:
        if policy_id is not None:
            if str(pol.get("policy_id", "")).strip() == policy_id:
                return pol
        if name is not None:
            if str(pol.get("name", "")).strip().lower() == name.lower():
                return pol
    return None


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()
