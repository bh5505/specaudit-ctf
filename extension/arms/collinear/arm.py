"""Curated collinear arm: cybersecurity simulated-world scenario reads."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
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
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_OUTPUT_CHARS,
    MAX_RECORDS,
    MAX_RESULTS,
    MAX_SCENARIOS_BYTES,
    args_refusal,
    limit_refusal,
    scenarios_refusal,
)

_INSTRUCTOR_KEYS = frozenset(
    {"expected_findings", "trace_keys", "expected_evidence"}
)
_SCENARIO_KEYS = frozenset(
    {
        "scenario_id",
        "name",
        "difficulty",
        "environment_type",
        "description",
        "environment_config",
        "task_brief",
        "expected_findings",
        "trace_keys",
        "expected_evidence",
    }
)
_MAX_TEXT = 16_384


class _ScenarioError(ValueError):
    """Scenario data is malformed or exceeds a bounded reader contract."""


class CollinearArm:
    """Bounded scenario reader with instructor-held answers kept private."""

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
                f"(simulated world scenario reads only; arming: {ARMING})",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, refusal = scenarios_refusal(payload.get("scenarios_file"))
        if refusal:
            return _fail(spec, action, refusal)
        if path is None:
            return _fail(spec, action, "scenarios path validation failed")
        try:
            scenarios, source = _load_scenarios(path)
        except _ScenarioError as exc:
            return _fail(spec, action, str(exc))
        except Exception:
            return _fail(spec, action, "scenarios file could not be parsed safely")
        if action == "scenario":
            return self._scenario(spec, action, payload, scenarios, source)
        if action == "list_scenarios":
            return self._list_scenarios(spec, action, payload, scenarios, source)
        return self._verify(spec, action, payload, scenarios, source)

    def _scenario(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        scenarios: list[dict[str, Any]],
        source: dict[str, Any],
    ) -> Result:
        scenario_id = _optional_text(payload.get("scenario_id"))
        name = _optional_text(payload.get("name"))
        if scenario_id is not None:
            match = next(
                (row for row in scenarios if row["scenario_id"] == scenario_id),
                None,
            )
            if (
                match is not None
                and name is not None
                and match["name"].casefold() != name.casefold()
            ):
                return _fail(
                    spec,
                    action,
                    "args.scenario_id and args.name do not identify the same scenario",
                )
            wanted = scenario_id
        else:
            matches = [
                row
                for row in scenarios
                if row["name"].casefold() == (name or "").casefold()
            ]
            if len(matches) > 1:
                return _fail(
                    spec,
                    action,
                    "multiple scenarios match args.name; use args.scenario_id",
                )
            match = matches[0] if matches else None
            wanted = name
        if match is None:
            return _fail(spec, action, f"scenario {wanted!r} not found")
        return _ok(
            spec,
            action,
            {"scenario": _strip_instructor(match), "source": source},
        )

    def _list_scenarios(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        scenarios: list[dict[str, Any]],
        source: dict[str, Any],
    ) -> Result:
        limit_value, refusal = limit_refusal(payload.get("limit"))
        if refusal:
            return _fail(spec, action, refusal)
        limit = limit_value if limit_value is not None else MAX_RESULTS
        rows = [
            {
                "scenario_id": row["scenario_id"],
                "name": row["name"],
                "difficulty": row.get("difficulty", ""),
                "environment_type": row.get("environment_type", ""),
            }
            for row in scenarios[:limit]
        ]
        return _ok(
            spec,
            action,
            {
                "scenarios": rows,
                "total": len(scenarios),
                "returned": len(rows),
                "capped": len(rows) < len(scenarios),
                "source": source,
            },
        )

    def _verify(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        scenarios: list[dict[str, Any]],
        source: dict[str, Any],
    ) -> Result:
        scenario_id = payload["scenario_id"].strip()
        scenario = next(
            (row for row in scenarios if row["scenario_id"] == scenario_id),
            None,
        )
        if scenario is None:
            return _fail(spec, action, f"scenario {scenario_id!r} not found")
        try:
            submitted = _validate_submission(payload.get("submission"))
        except _ScenarioError as exc:
            return _fail(spec, action, str(exc))

        expected = scenario["expected_findings"]
        try:
            expected_counter = Counter(_canonical(item) for item in expected)
            submitted_counter = Counter(_canonical(item) for item in submitted)
        except (TypeError, ValueError):
            return _fail(spec, action, "findings could not be compared safely")
        verdict = "pass" if submitted_counter == expected_counter else "fail"
        # Deliberately omit counts and partial scores: repeated submissions may
        # learn only the exact-completion verdict, not the answer-set size.
        return _ok(
            spec,
            action,
            {"scenario_id": scenario_id, "verdict": verdict, "source": source},
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


def _load_scenarios(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_SCENARIOS_BYTES + 1)
    except OSError as exc:
        raise _ScenarioError("scenarios file is unreadable") from exc
    if len(raw) > MAX_SCENARIOS_BYTES:
        raise _ScenarioError(
            f"scenarios file exceeds the {MAX_SCENARIOS_BYTES} byte read cap"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _ScenarioError("scenarios file is not valid UTF-8") from exc
    try:
        if path.suffix.lower() == ".json":
            data = strict_json_loads(text)
        else:
            data = yaml.load(text, Loader=_BoundedSafeLoader)
    except StrictDataError as exc:
        raise _ScenarioError(str(exc)) from exc
    except (json.JSONDecodeError, RecursionError, yaml.YAMLError, ValueError) as exc:
        label = "JSON" if path.suffix.lower() == ".json" else "YAML"
        raise _ScenarioError(f"scenarios file is not valid {label}") from exc
    refusal = _tree_refusal(data)
    if refusal:
        raise _ScenarioError(f"scenarios file {refusal}")
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and set(data) == {"scenarios"} and isinstance(
        data["scenarios"], list
    ):
        rows = data["scenarios"]
    else:
        raise _ScenarioError(
            "scenarios file must be an array or an object containing only a scenarios array"
        )
    return _validate_scenarios(rows), _source(raw)


def _validate_scenarios(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise _ScenarioError("scenarios must be a list")
    if len(rows) > MAX_RECORDS:
        raise _ScenarioError(f"scenarios file exceeds the {MAX_RECORDS} scenario cap")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise _ScenarioError(f"scenario {index} must be a mapping")
        extra = sorted(set(row) - _SCENARIO_KEYS)
        if extra:
            raise _ScenarioError(
                f"scenario {index} has unknown fields: {', '.join(extra)}"
            )
        scenario_id = _text(row.get("scenario_id"), f"scenario {index}.scenario_id")
        name = _text(row.get("name"), f"scenario {index}.name")
        if scenario_id in seen:
            raise _ScenarioError(f"scenarios file contains duplicate id {scenario_id!r}")
        seen.add(scenario_id)
        normalized = dict(row)
        normalized["scenario_id"] = scenario_id
        normalized["name"] = name
        for key in (
            "difficulty",
            "environment_type",
            "description",
            "task_brief",
        ):
            if key in row:
                normalized[key] = _text(row[key], f"scenario {index}.{key}")
        expected = row.get("expected_findings")
        if not isinstance(expected, list):
            raise _ScenarioError(
                f"scenario {index}.expected_findings must be a list"
            )
        if not expected:
            raise _ScenarioError(
                f"scenario {index}.expected_findings must be a non-empty list"
            )
        if len(expected) > MAX_RECORDS:
            raise _ScenarioError(
                f"scenario {index}.expected_findings exceeds the finding cap"
            )
        if any(not isinstance(item, dict) or not item for item in expected):
            raise _ScenarioError(
                f"scenario {index}.expected_findings must contain only non-empty mappings"
            )
        evidence = row.get("expected_evidence", [])
        if not isinstance(evidence, list) or any(
            not isinstance(item, str) or not item.strip() for item in evidence
        ):
            raise _ScenarioError(
                f"scenario {index}.expected_evidence must be a list of non-empty strings"
            )
        if "trace_keys" in row and not isinstance(row["trace_keys"], dict):
            raise _ScenarioError(f"scenario {index}.trace_keys must be a mapping")
        if "environment_config" in row and not isinstance(
            row["environment_config"], dict
        ):
            raise _ScenarioError(
                f"scenario {index}.environment_config must be a mapping"
            )
        output.append(normalized)
    return output


def _validate_submission(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, dict) or set(raw) != {"findings"}:
        raise _ScenarioError(
            "verify requires args.submission containing only a findings list"
        )
    findings = raw["findings"]
    if not isinstance(findings, list):
        raise _ScenarioError("args.submission.findings must be a list")
    if len(findings) > MAX_RECORDS:
        raise _ScenarioError("args.submission.findings exceeds the finding cap")
    refusal = _tree_refusal(findings)
    if refusal:
        raise _ScenarioError(f"args.submission.findings {refusal}")
    if any(not isinstance(item, dict) for item in findings):
        raise _ScenarioError(
            "args.submission.findings must contain only mappings"
        )
    return findings


def _strip_instructor(value: Any) -> Any:
    """Recursively remove instructor-only keys from learner-visible data."""
    if isinstance(value, dict):
        return {
            key: _strip_instructor(item)
            for key, item in value.items()
            if key not in _INSTRUCTOR_KEYS
        }
    if isinstance(value, list):
        return [_strip_instructor(item) for item in value]
    return value


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


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


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise _ScenarioError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
        raise _ScenarioError(f"{label} contains control characters")
    return value.strip()


def _optional_text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _source(raw: bytes) -> dict[str, Any]:
    return {
        "kind": "operator-file",
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
