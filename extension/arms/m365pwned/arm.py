"""Curated m365pwned arm: strict reads over local M365 consent cases."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

try:
    import yaml as _yaml
except ImportError:
    _yaml = None  # type: ignore[assignment]

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..mcp_client import redact
from ..strict_data import (
    BoundedYamlNodeMixin,
    MAX_INTEGER_BITS,
    StrictDataError,
    StrictMappingMixin,
    strict_json_loads,
)
from .policy import (
    ALLOWED_ACTIONS,
    ARG_KEYS,
    ARMING,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_CASE_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    cases_file_refusal,
    limit_refusal,
)

_CASE_KEYS = frozenset(
    {
        "case_id", "name", "description", "risk_level", "consent_flow",
        "data_access", "permissions", "risk_assessment",
    }
)
_CONSENT_KEYS = frozenset({"user_action", "app_permissions", "flow_type", "admin_consent_required"})
_ACCESS_KEYS = frozenset({"mailbox_count", "files_accessed", "data_types"})
_RISK_LEVELS = frozenset({"critical", "high", "medium", "low", "informational", "info"})
_MAX_TEXT = 16_384
_MAX_ITEMS = 50_000


class _CasesError(ValueError):
    """The caller-supplied case corpus violates its closed schema."""


class M365PwnedArm:
    """Read-only consent case scenarios with explicit risk fields."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(self, spec: ArmSpec, action: str, args: Mapping[str, Any]) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return _fail(
                spec, action,
                f"action {action!r} is not on the allowlist (local consent-case reads only; arming: {ARMING})",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, refusal = cases_file_refusal(payload.get("cases_file"))
        if refusal:
            return _fail(spec, action, refusal)
        assert path is not None
        try:
            cases, source = _load_cases(path)
        except _CasesError as exc:
            return _fail(spec, action, redact(str(exc)))
        except Exception:
            return _fail(spec, action, "invoke failed")

        if action == "case_study":
            case_id = _optional_query(payload.get("case_id"))
            name = _optional_query(payload.get("name"))
            matches = [
                item for item in cases
                if (case_id is not None and item["case_id"] == case_id)
                or (name is not None and item["name"].casefold() == name.casefold())
            ]
            if name is not None and len(matches) > 1:
                return _fail(spec, action, "multiple case studies match args.name; use args.case_id")
            match = matches[0] if matches else None
            if match is None:
                return _fail(spec, action, f"case study not found: {case_id or name!r}")
            return _ok(spec, action, {"case_study": _project_case(match), "source": source})

        if action == "list_case_studies":
            limit, refusal = limit_refusal(payload.get("limit"))
            if refusal:
                return _fail(spec, action, refusal)
            effective = MAX_RESULTS if limit is None else limit
            rows = [_project_summary(item) for item in cases[:effective]]
            return _ok(
                spec, action,
                {
                    "case_studies": rows,
                    "total": len(cases),
                    "returned": len(rows),
                    "capped": len(rows) < len(cases),
                    "source": source,
                },
            )

        case_id = payload["case_id"].strip()
        match = next((item for item in cases if item["case_id"] == case_id), None)
        if match is None:
            return _fail(spec, action, f"case study not found: {case_id!r}")
        permissions = list(match["permissions"])
        rows = permissions[:MAX_RESULTS]
        return _ok(
            spec, action,
            {
                "case_id": match["case_id"],
                "name": match["name"],
                "permissions": rows,
                "total": len(permissions),
                "returned": len(rows),
                "capped": len(rows) < len(permissions),
                "source": source,
            },
        )

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        if payload:
            return _fail(spec, action, "list_tools takes no caller arguments")
        return _ok(
            spec, action,
            {
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": {key: sorted(values) for key, values in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
        )


def _load_cases(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = _read_bounded(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _CasesError("cases file is not strict UTF-8") from exc
    try:
        data = strict_json_loads(text) if path.suffix.lower() == ".json" else _load_yaml(text)
    except _CasesError:
        raise
    except StrictDataError as exc:
        raise _CasesError(str(exc)) from exc
    except Exception as exc:
        raise _CasesError(f"invalid {path.suffix.lower().lstrip('.')} cases file") from exc
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and set(data) == {"case_studies"} and isinstance(data["case_studies"], list):
        rows = data["case_studies"]
    else:
        raise _CasesError("cases file must be an array or an object containing only a case_studies array")
    if len(rows) > _MAX_ITEMS:
        raise _CasesError(f"cases file exceeds the {_MAX_ITEMS} case cap")
    return _validate_cases(rows), _source(raw)


def _load_yaml(text: str) -> Any:
    if _yaml is None:
        raise _CasesError("PyYAML is required to load YAML cases")

    class BoundedSafeLoader(
        BoundedYamlNodeMixin, StrictMappingMixin, _yaml.SafeLoader
    ):
        strict_alias_event_type = _yaml.AliasEvent

    return _yaml.load(text, Loader=BoundedSafeLoader)


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CASE_BYTES + 1)
    except OSError as exc:
        raise _CasesError("could not read cases file") from exc
    if len(raw) > MAX_CASE_BYTES:
        raise _CasesError(f"cases file exceeds the {MAX_CASE_BYTES} byte read cap")
    return raw


def _validate_cases(rows: list[Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        label = f"case entry {index}"
        if not isinstance(raw, dict):
            raise _CasesError(f"{label} is not a mapping")
        if any(not isinstance(key, str) for key in raw):
            raise _CasesError(f"{label} field names must be strings")
        extra = sorted(set(raw) - _CASE_KEYS)
        missing = sorted(_CASE_KEYS - set(raw))
        if extra:
            raise _CasesError(f"{label} has unknown fields: {', '.join(extra)}")
        if missing:
            raise _CasesError(f"{label} is missing fields: {', '.join(missing)}")
        case_id = _text(raw["case_id"], f"{label}.case_id")
        if case_id in seen:
            raise _CasesError(f"duplicate case_id: {case_id}")
        seen.add(case_id)
        risk_level = _text(raw["risk_level"], f"{label}.risk_level").casefold()
        if risk_level not in _RISK_LEVELS:
            raise _CasesError(f"{label}.risk_level is not recognized")
        consent_flow = _validate_consent(raw["consent_flow"], f"{label}.consent_flow")
        permissions = _text_list(raw["permissions"], f"{label}.permissions")
        missing_permissions = sorted(set(consent_flow.get("app_permissions", [])) - set(permissions))
        if missing_permissions:
            raise _CasesError(f"{label}.consent_flow references permissions absent from permissions")
        cases.append(
            {
                "case_id": case_id,
                "name": _text(raw["name"], f"{label}.name"),
                "description": _text(raw["description"], f"{label}.description"),
                "risk_level": risk_level,
                "consent_flow": consent_flow,
                "data_access": _validate_access(raw["data_access"], f"{label}.data_access"),
                "permissions": permissions,
                "risk_assessment": _text(raw["risk_assessment"], f"{label}.risk_assessment"),
            }
        )
    return cases


def _validate_consent(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _CasesError(f"{label} must be a mapping")
    if any(not isinstance(key, str) for key in raw):
        raise _CasesError(f"{label} field names must be strings")
    extra = sorted(set(raw) - _CONSENT_KEYS)
    if extra:
        raise _CasesError(f"{label} has unknown fields: {', '.join(extra)}")
    output: dict[str, Any] = {}
    for key in ("user_action", "flow_type"):
        if key in raw:
            output[key] = _text(raw[key], f"{label}.{key}")
    if "app_permissions" in raw:
        output["app_permissions"] = _text_list(raw["app_permissions"], f"{label}.app_permissions")
    if "admin_consent_required" in raw:
        if not isinstance(raw["admin_consent_required"], bool):
            raise _CasesError(f"{label}.admin_consent_required must be a boolean")
        output["admin_consent_required"] = raw["admin_consent_required"]
    return output


def _validate_access(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _CasesError(f"{label} must be a mapping")
    if any(not isinstance(key, str) for key in raw):
        raise _CasesError(f"{label} field names must be strings")
    extra = sorted(set(raw) - _ACCESS_KEYS)
    if extra:
        raise _CasesError(f"{label} has unknown fields: {', '.join(extra)}")
    output: dict[str, Any] = {}
    for key in ("mailbox_count", "files_accessed"):
        if key in raw:
            value = raw[key]
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                or value.bit_length() > MAX_INTEGER_BITS
            ):
                raise _CasesError(
                    f"{label}.{key} must be a bounded non-negative integer"
                )
            output[key] = value
    if "data_types" in raw:
        output["data_types"] = _text_list(raw["data_types"], f"{label}.data_types")
    return output


def _text_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_ITEMS:
        raise _CasesError(f"{label} must be a bounded list of strings")
    return [_text(item, f"{label}[{index}]") for index, item in enumerate(value)]


def _project_case(item: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item[key] for key in _CASE_KEYS}


def _project_summary(item: Mapping[str, Any]) -> dict[str, str]:
    return {
        "case_id": item["case_id"],
        "name": item["name"],
        "description": item["description"],
        "risk_level": item["risk_level"],
        "risk_assessment": item["risk_assessment"],
    }


def _source(raw: bytes) -> dict[str, Any]:
    return {"kind": "operator-file", "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise _CasesError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
        raise _CasesError(f"{label} contains control characters")
    return value.strip()


def _optional_query(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        size = len(json.dumps(output, sort_keys=True, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        return _fail(spec, action, f"result could not be encoded: {exc}")
    if size > MAX_OUTPUT_CHARS:
        return _fail(spec, action, f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; narrow the lookup")
    return Result(True, spec.id, action, output, None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(False, spec.id, action, None, redact(str(error))[:MAX_OUTPUT_CHARS])
