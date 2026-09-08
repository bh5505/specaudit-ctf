"""Curated agentseal arm: offline static fixture analysis."""

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
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    args_refusal,
    fixture_refusal,
)


class AgentSealArm:
    """Specialized transport for catalog id agentseal.

    First-party in-process read arm: a stdlib static analysis fixture
    reader with no subprocess and no endpoint.  ``installed`` reports
    handler presence only — the corpus is per-invoke caller data
    (args.fixture), the same contract as every other file-consuming arm.
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
                "(offline static fixture analysis only; "
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
        path, fix_refused = fixture_refusal(payload.get("fixture"))
        if fix_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=fix_refused,
            )
        try:
            data = _load_fixture(path)
        except FixtureError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if action == "analyze":
            return self._analyze(spec, action, payload, data)
        # action == "list_scenarios"
        return self._list_scenarios(spec, action, data)

    def _analyze(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        data: dict[str, Any],
    ) -> Result:
        """Return security findings/scenarios from the fixture."""
        scenarios = data.get("scenarios")
        findings = data.get("findings")

        if not isinstance(scenarios, list) and not isinstance(findings, list):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=(
                    "fixture must contain a 'scenarios' list or a "
                    "'findings' list at the top level"
                ),
            )

        # Prefer scenarios if present, otherwise findings.
        if isinstance(scenarios, list):
            items = scenarios
            key = "scenarios"
        else:
            items = findings  # type: ignore[assignment]
            key = "findings"

        # Optional filter by scenario_id.
        scenario_id = _opt_str(payload.get("scenario_id"))
        if scenario_id is not None and key == "scenarios":
            items = [
                item
                for item in items
                if isinstance(item, dict)
                and _opt_str(item.get("id")) == scenario_id
            ]
            if not items:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=f"scenario_id {scenario_id!r} not found in fixture",
                )

        text = json.dumps(items, sort_keys=True)
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
            output={key: items, "count": len(items)},
            error=None,
        )

    def _list_scenarios(
        self,
        spec: ArmSpec,
        action: str,
        data: dict[str, Any],
    ) -> Result:
        """Return scenario IDs and names from the fixture."""
        scenarios = data.get("scenarios")
        if not isinstance(scenarios, list):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="fixture does not contain a 'scenarios' list",
            )
        summary = []
        for item in scenarios:
            if not isinstance(item, dict):
                continue
            entry: dict[str, str | None] = {}
            sid = _opt_str(item.get("id"))
            if sid is not None:
                entry["id"] = sid
            name = _opt_str(item.get("name"))
            if name is not None:
                entry["name"] = name
            if entry:
                summary.append(entry)

        text = json.dumps(summary, sort_keys=True)
        if len(text) > MAX_OUTPUT_CHARS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=(
                    f"result exceeds the {MAX_OUTPUT_CHARS} character output "
                    "cap; supply a smaller fixture"
                ),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"scenarios": summary, "count": len(summary)},
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


class FixtureError(ValueError):
    """The fixture file is not a readable static analysis output."""


def _load_fixture(path: Any) -> dict[str, Any]:
    """Parse and validate a local static analysis fixture file.

    Supports JSON and YAML.  Fail-closed: anything unexpected raises
    :class:`FixtureError`, which the arm converts into an evaluated
    non-success.
    """
    suffix = str(getattr(path, "suffix", "")).lower()

    try:
        with open(path, encoding="utf-8", errors="strict") as handle:
            raw = handle.read()
    except OSError as exc:
        raise FixtureError(f"fixture could not be read: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise FixtureError(f"fixture is not valid UTF-8: {exc}") from exc

    if suffix == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise FixtureError(f"fixture is not valid JSON: {exc}") from exc
    else:
        # YAML path: use the stdlib-replacement safe approach.
        # If PyYAML is not installed, refuse rather than silently skip.
        try:
            import yaml  # type: ignore[import-untyped]
        except ModuleNotFoundError as exc:
            raise FixtureError(
                "YAML fixture requires PyYAML; install pyyaml to load .yaml/.yml files"
            ) from exc
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:  # type: ignore[union-attr]
            raise FixtureError(f"fixture is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise FixtureError(
            "fixture must be a JSON/YAML object at the top level"
        )
    return data


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()
