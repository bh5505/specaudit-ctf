"""Curated collinear arm: cybersecurity simulated world scenario reads."""

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
    ARG_KEYS,
    ARMING,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    limit_refusal,
    scenarios_refusal,
)

try:
    import yaml as _yaml
except ImportError:
    _yaml = None

_INSTRUCTOR_KEYS = frozenset({"expected_findings", "trace_keys", "expected_evidence"})


class CollinearArm:
    """Specialized transport for catalog id collinear.

    First-party in-process read arm: reads cybersecurity simulated world
    scenario definitions from a local file.  ``installed`` reports handler
    presence only.  Instructor-held answer data is always stripped.
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
                "(simulated world scenario reads only; "
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
        path, sf_refused = scenarios_refusal(payload.get("scenarios_file"))
        if sf_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=sf_refused,
            )
        scenarios = _load_scenarios(path)
        if isinstance(scenarios, str):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=scenarios,
            )
        if action == "scenario":
            return self._scenario(spec, action, payload, scenarios)
        if action == "list_scenarios":
            return self._list_scenarios(spec, action, payload, scenarios)
        return self._verify(spec, action, payload, scenarios)

    def _scenario(
        self, spec: ArmSpec, action: str, payload: dict, scenarios: list[dict]
    ) -> Result:
        scenario_id = str(payload.get("scenario_id") or "").strip()
        name = str(payload.get("name") or "").strip()
        match = None
        for s in scenarios:
            if scenario_id and str(s.get("scenario_id", "")) == scenario_id:
                match = s
                break
            if name and str(s.get("name", "")).lower() == name.lower():
                match = s
                break
        if match is None:
            wanted = scenario_id or name
            return _fail(spec, action, f"scenario {wanted!r} not found")
        safe = _strip_instructor(match)
        text = json.dumps(safe, sort_keys=True)
        if len(text) > MAX_OUTPUT_CHARS:
            return _fail(spec, action, f"scenario exceeds the {MAX_OUTPUT_CHARS} char output cap")
        return Result(ok=True, arm_id=spec.id, action=action, output=safe, error=None)

    def _list_scenarios(
        self, spec: ArmSpec, action: str, payload: dict, scenarios: list[dict]
    ) -> Result:
        limit_raw, limit_err = limit_refusal(payload.get("limit"))
        if limit_err:
            return _fail(spec, action, limit_err)
        limit = limit_raw or MAX_RESULTS
        rows = []
        for s in scenarios[:limit]:
            rows.append({
                "scenario_id": s.get("scenario_id", ""),
                "name": s.get("name", ""),
                "difficulty": s.get("difficulty", ""),
                "environment_type": s.get("environment_type", ""),
            })
        return Result(
            ok=True, arm_id=spec.id, action=action,
            output={"scenarios": rows, "total": len(rows)},
            error=None,
        )

    def _verify(
        self, spec: ArmSpec, action: str, payload: dict, scenarios: list[dict]
    ) -> Result:
        scenario_id = str(payload.get("scenario_id") or "").strip()
        submission = payload.get("submission")
        if not isinstance(submission, dict):
            return _fail(spec, action, "verify requires args.submission as a mapping")
        match = None
        for s in scenarios:
            if str(s.get("scenario_id", "")) == scenario_id:
                match = s
                break
        if match is None:
            return _fail(spec, action, f"scenario {scenario_id!r} not found")
        expected = match.get("expected_findings", [])
        submitted = submission.get("findings", [])
        if not isinstance(expected, list):
            expected = []
        if not isinstance(submitted, list):
            submitted = []
        expected_set = {json.dumps(e, sort_keys=True) for e in expected}
        submitted_set = {json.dumps(e, sort_keys=True) for e in submitted}
        hits = expected_set & submitted_set
        precision = len(hits) / len(submitted_set) if submitted_set else 0.0
        recall = len(hits) / len(expected_set) if expected_set else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        return Result(
            ok=True, arm_id=spec.id, action=action,
            output={
                "scenario_id": scenario_id,
                "verdict": "pass" if recall > 0 else "fail",
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "expected_count": len(expected),
                "submitted_count": len(submitted),
                "matched_count": len(hits),
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


def _strip_instructor(scenario: dict) -> dict:
    """Remove instructor-held answer data from a scenario dict."""
    return {k: v for k, v in scenario.items() if k not in _INSTRUCTOR_KEYS}


def _load_scenarios(path: Path) -> list[dict[str, Any]] | str:
    """Load scenarios from JSON or YAML."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return f"scenarios file unreadable: {exc}"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "scenarios file is not valid UTF-8"
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(text)
        elif _yaml is not None:
            data = _yaml.safe_load(text)
        else:
            return "PyYAML is not installed; cannot parse YAML files"
    except (json.JSONDecodeError, Exception) as exc:
        return f"scenarios file is not valid {suffix.lstrip('.')}: {exc}"
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "scenarios" in data and isinstance(data["scenarios"], list):
        return data["scenarios"]
    return "scenarios file must be a list or a mapping with a 'scenarios' key"


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(
        ok=False,
        arm_id=spec.id,
        action=action,
        output=None,
        error=redact(error[:MAX_OUTPUT_CHARS]),
    )
