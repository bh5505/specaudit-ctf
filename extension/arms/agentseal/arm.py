"""Curated agentseal arm: offline static fixture analysis."""

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
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_FIXTURE_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RECORDS,
    MAX_RESULTS,
    args_refusal,
    fixture_refusal,
    limit_refusal,
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
            return _fail(
                spec,
                action,
                f"action {action!r} is not on the allowlist "
                "(offline static fixture analysis only; "
                "there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, fix_refused = fixture_refusal(payload.get("fixture"))
        if fix_refused:
            return _fail(spec, action, fix_refused)
        try:
            data, source = _load_fixture(path)
        except FixtureError as exc:
            return _fail(spec, action, str(exc))
        except Exception:
            return _fail(spec, action, "fixture could not be parsed safely")
        if action == "analyze":
            return self._analyze(spec, action, payload, data, source)
        # action == "list_scenarios"
        return self._list_scenarios(spec, action, payload, data, source)

    def _analyze(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        data: dict[str, Any],
        source: dict[str, Any],
    ) -> Result:
        """Return security findings/scenarios from the fixture."""
        scenarios = data.get("scenarios")
        findings = data.get("findings")

        if not isinstance(scenarios, list) and not isinstance(findings, list):
            return _fail(
                spec,
                action,
                "fixture must contain a 'scenarios' list or a "
                "'findings' list at the top level",
            )

        scenario_id = _opt_str(payload.get("scenario_id"))
        if (
            isinstance(scenarios, list)
            and isinstance(findings, list)
            and scenario_id is not None
        ):
            return _fail(
                spec,
                action,
                "args.scenario_id cannot safely select a fixture that also has "
                "unassociated top-level findings",
            )

        limit_value, refusal = limit_refusal(payload.get("limit"))
        if refusal:
            return _fail(spec, action, refusal)
        limit = limit_value if limit_value is not None else MAX_RESULTS

        # Dual-container fixtures are supported without silently discarding
        # either class of evidence.  Scenarios consume the single result budget
        # first, then top-level findings; per-container denominators expose any
        # truncation instead of making omitted evidence look absent.
        if isinstance(scenarios, list) and isinstance(findings, list):
            returned_scenarios = scenarios[:limit]
            remaining = limit - len(returned_scenarios)
            returned_findings = findings[:remaining]
            total = len(scenarios) + len(findings)
            returned = len(returned_scenarios) + len(returned_findings)
            return _ok(
                spec,
                action,
                {
                    "scenarios": returned_scenarios,
                    "findings": returned_findings,
                    "scenario_total": len(scenarios),
                    "finding_total": len(findings),
                    "scenario_returned": len(returned_scenarios),
                    "finding_returned": len(returned_findings),
                    "count": returned,
                    "total": total,
                    "returned": returned,
                    "capped": returned < total,
                    "source": source,
                },
            )

        if isinstance(scenarios, list):
            items = scenarios
            key = "scenarios"
        else:
            items = findings  # type: ignore[assignment]
            key = "findings"

        # Optional exact filter by scenario_id.
        if scenario_id is not None and key != "scenarios":
            return _fail(
                spec,
                action,
                "args.scenario_id cannot select a findings-only fixture",
            )
        if scenario_id is not None:
            items = [
                item
                for item in items
                if item["id"] == scenario_id
            ]
            if not items:
                return _fail(
                    spec,
                    action,
                    f"scenario_id {scenario_id!r} not found in fixture",
                )

        total = len(items)
        returned_items = items[:limit]
        return _ok(
            spec,
            action,
            {
                key: returned_items,
                "count": len(returned_items),
                "total": total,
                "returned": len(returned_items),
                "capped": len(returned_items) < total,
                "source": source,
            },
        )

    def _list_scenarios(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        data: dict[str, Any],
        source: dict[str, Any],
    ) -> Result:
        """Return scenario IDs and names from the fixture."""
        scenarios = data.get("scenarios")
        if not isinstance(scenarios, list):
            return _fail(spec, action, "fixture does not contain a 'scenarios' list")
        summary = []
        for item in scenarios:
            entry: dict[str, str | None] = {}
            sid = _opt_str(item.get("id"))
            if sid is not None:
                entry["id"] = sid
            name = _opt_str(item.get("name"))
            if name is not None:
                entry["name"] = name
            if entry:
                summary.append(entry)

        limit_value, refusal = limit_refusal(payload.get("limit"))
        if refusal:
            return _fail(spec, action, refusal)
        limit = limit_value if limit_value is not None else MAX_RESULTS
        rows = summary[:limit]
        return _ok(
            spec,
            action,
            {
                "scenarios": rows,
                "count": len(rows),
                "total": len(summary),
                "returned": len(rows),
                "capped": len(rows) < len(summary),
                "source": source,
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
                "arg_keys": {key: sorted(vals) for key, vals in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
        )


class FixtureError(ValueError):
    """The fixture file is not a readable static analysis output."""


def _load_fixture(
    path: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse and validate a local static analysis fixture file.

    Supports JSON and YAML.  Fail-closed: anything unexpected raises
    :class:`FixtureError`, which the arm converts into an evaluated
    non-success.
    """
    if path is None:
        raise FixtureError("fixture path validation failed")
    suffix = path.suffix.lower()

    try:
        with path.open("rb") as handle:
            raw_bytes = handle.read(MAX_FIXTURE_BYTES + 1)
    except OSError as exc:
        raise FixtureError("fixture could not be read") from exc
    if len(raw_bytes) > MAX_FIXTURE_BYTES:
        raise FixtureError(f"fixture exceeds the {MAX_FIXTURE_BYTES} byte read cap")
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixtureError("fixture is not valid UTF-8") from exc

    if suffix == ".json":
        try:
            data = strict_json_loads(raw)
        except StrictDataError as exc:
            raise FixtureError(str(exc)) from exc
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise FixtureError("fixture is not valid JSON") from exc
    else:
        try:
            data = yaml.load(raw, Loader=_BoundedSafeLoader)
        except StrictDataError as exc:
            raise FixtureError(str(exc)) from exc
        except (yaml.YAMLError, RecursionError, ValueError) as exc:
            raise FixtureError("fixture is not valid YAML") from exc

    if not isinstance(data, dict):
        raise FixtureError(
            "fixture must be a JSON/YAML object at the top level"
        )
    refusal = _tree_refusal(data)
    if refusal:
        raise FixtureError(f"fixture {refusal}")
    _validate_fixture_schema(data)
    return data, _source(raw_bytes)


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


def _validate_fixture_schema(data: dict[str, Any]) -> None:
    scenarios = data.get("scenarios")
    findings = data.get("findings")
    if not isinstance(scenarios, list) and not isinstance(findings, list):
        raise FixtureError(
            "fixture must contain a 'scenarios' list or a 'findings' list at the top level"
        )
    if scenarios is not None:
        if not isinstance(scenarios, list):
            raise FixtureError("fixture field 'scenarios' must be a list")
        if len(scenarios) > MAX_RECORDS:
            raise FixtureError(f"fixture exceeds the {MAX_RECORDS} scenario cap")
        seen: set[str] = set()
        for index, scenario in enumerate(scenarios):
            if not isinstance(scenario, dict):
                raise FixtureError(f"scenario {index} must be a mapping")
            scenario_id = scenario.get("id")
            if not isinstance(scenario_id, str) or not scenario_id.strip():
                raise FixtureError(f"scenario {index} requires a non-empty string id")
            normalized_id = scenario_id.strip()
            if normalized_id in seen:
                raise FixtureError(f"fixture contains duplicate scenario id {normalized_id!r}")
            seen.add(normalized_id)
            scenario["id"] = normalized_id
            if "name" in scenario and not isinstance(scenario["name"], str):
                raise FixtureError(f"scenario {index} field 'name' must be a string")
            _validate_findings(scenario.get("findings"), f"scenario {index}")
    if findings is not None:
        _validate_findings(findings, "fixture")


def _validate_findings(raw: Any, context: str) -> None:
    if raw is None:
        return
    if not isinstance(raw, list):
        raise FixtureError(f"{context} field 'findings' must be a list")
    if len(raw) > MAX_RECORDS:
        raise FixtureError(f"{context} exceeds the {MAX_RECORDS} finding cap")
    for index, finding in enumerate(raw):
        if not isinstance(finding, dict) or not finding:
            raise FixtureError(
                f"{context} finding {index} must be a non-empty mapping"
            )


def _source(raw: bytes) -> dict[str, Any]:
    return {
        "kind": "operator-file",
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
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


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()
