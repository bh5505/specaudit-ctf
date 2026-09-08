"""Causal tests for the two closed EVID-01 v2 singleton profiles."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Any

import jsonschema
import pytest
import yaml

import extension
from extension.arms.security_detections_mcp.arm import parse_index_bytes
from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.encode import mode_a_supported
from extension.invoke_profiles import INVOKE_PROFILES
from extension.mcp_server import TOOLS
from extension.observation_profiles import OBSERVATION_PROFILES
from extension.observations import (
    REASON_ATTEMPT_MISMATCH,
    REASON_EVIDENCE_MISMATCH,
    REASON_INVALID_ADMISSION,
    REASON_INVALID_POLICY_REPORT,
    REASON_OBSERVATION_MISMATCH,
    REASON_PROFILE_MISMATCH,
    REASON_REPLAY,
    REASON_SOURCE_MISMATCH,
    REASON_SUBJECT_MISMATCH,
    SCHEMA_VERSION_V2,
    SOURCE_ADMISSION_V2_SCHEMA_ID,
    TRUSTED_OBSERVATION_V2_SCHEMA_ID,
    ObservationError,
    derive_trusted_observation,
    issue_profile_source_admission,
    issue_source_admission,
    verify_source_admission,
    verify_trusted_observation,
)
from governance.check import PR97_ACTION_ARGUMENTS, PR97_ARM_IDS


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "extension" / "schema"
ADMISSION_V1_SCHEMA = SCHEMA_DIR / "source-admission.v1.schema.json"
OBSERVATION_V1_SCHEMA = SCHEMA_DIR / "trusted-observation.v1.schema.json"
ADMISSION_V2_SCHEMA = SCHEMA_DIR / "source-admission.v2.schema.json"
OBSERVATION_V2_SCHEMA = SCHEMA_DIR / "trusted-observation.v2.schema.json"

ATTEMPT_ID = "attempt-" + ("12" * 32)
OTHER_ATTEMPT_ID = "attempt-" + ("34" * 32)
SOURCE_TIME = "2026-09-08T09:00:00Z"
ISSUED_AT = "2026-09-08T10:00:00Z"
STARTED_AT = "2026-09-08T11:00:00Z"
FINISHED_AT = "2026-09-08T11:00:01Z"
VERIFIED_AT = "2026-09-08T12:00:00Z"
VALID_UNTIL = "2026-09-08T13:00:00Z"

SECURITY = {
    "capability_id": "security-detections-mcp.get_rule",
    "arm_id": "security-detections-mcp",
    "action": "get_rule",
    "subject_id": "RULE-001",
    "subject_field": "rule_id",
    "subject_kind": "detection-rule",
    "scope_kind": "detection-rule-record",
    "scope_identifier": "rule:RULE-001",
    "source_schema": "specaudit.ctf.security-detections-index-projection.v1",
    "formats": ("json", "yaml"),
}
RUBEUS = {
    "capability_id": "rubeus.telemetry",
    "arm_id": "rubeus",
    "action": "telemetry",
    "subject_id": "EVENT-001",
    "subject_field": "event_id",
    "subject_kind": "telemetry-event",
    "scope_kind": "telemetry-event-record",
    "scope_identifier": "event:EVENT-001",
    "source_schema": "specaudit.ctf.rubeus-telemetry-projection.v1",
    "formats": ("json", "jsonl"),
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _artifact_bytes(value: Any) -> bytes:
    """Match the execution-result encoder's canonical artifact form."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _digest(blob: bytes) -> str:
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _schema(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _validator(path: Path) -> jsonschema.Draft7Validator:
    return jsonschema.Draft7Validator(
        _schema(path), format_checker=jsonschema.FormatChecker()
    )


def _security_rules() -> list[dict[str, Any]]:
    return [
        {
            "rule_id": SECURITY["subject_id"],
            "name": "Synthetic café login rule",
            "severity": "high",
            "category": "authentication",
            "definition": {
                "query": "event.category == 'login'",
                "threshold": 0,
            },
            "tags": ["synthetic", "authentication"],
        },
        {
            "rule_id": "RULE-002",
            "name": "Synthetic near miss",
            "severity": "medium",
            "category": "network",
            "definition": {"query": "event.category == 'network'"},
        },
    ]


def _rubeus_events() -> list[dict[str, Any]]:
    return [
        {
            "event_id": RUBEUS["subject_id"],
            "category": "kerberos",
            "description": "Synthetic AS-REQ from approved administration",
            "severity": "medium",
            "indicators": [
                {"type": "encryption_type", "value": "[REDACTED]"}
            ],
        },
        {
            "event_id": "EVENT-002",
            "category": "ldap",
            "description": "Synthetic near miss",
            "severity": "low",
            "indicators": [{"type": "query_size", "value": "<REDACTED>"}],
        },
    ]


def _source_bytes(case: dict[str, Any], source_format: str) -> bytes:
    if case is SECURITY:
        rows = _security_rules()
        if source_format == "json":
            return _canonical(rows)
        assert source_format == "yaml"
        return yaml.safe_dump(
            rows, sort_keys=False, allow_unicode=True
        ).encode("utf-8")

    rows = _rubeus_events()
    if source_format == "json":
        return _canonical(rows)
    assert source_format == "jsonl"
    return b"\n".join(_canonical(row) for row in rows) + b"\n"


def _issue(
    case: dict[str, Any],
    raw: bytes,
    source_format: str,
    *,
    attempt_id: str = ATTEMPT_ID,
    subject_id: str | None = None,
) -> dict[str, Any]:
    return issue_profile_source_admission(
        capability_id=case["capability_id"],
        subject_id=subject_id or case["subject_id"],
        attempt_id=attempt_id,
        raw_artifact=raw,
        source_format=source_format,
        source_id=f"synthetic-{case['arm_id']}-source",
        source_revision="snapshot-2026-09-08",
        source_timestamp=SOURCE_TIME,
        logical_locator=f"source://synthetic/{case['arm_id']}/snapshot-2026-09-08",
        raw_artifact_locator=f"custody://ctf-evidence/{case['arm_id']}/raw",
        authority_ref="operator://source-admission/evid-01-fixture",
        issuer_id="ctf-evidence-custodian",
        issuer_version="0.1.0",
        producer_revision="git:6a6a652",
        issued_at=ISSUED_AT,
        valid_from=ISSUED_AT,
        valid_until=VALID_UNTIL,
        limitations=("synthetic-source", "data-rights-not-evaluated"),
    )


def _mode_a_bundle(
    base: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
    raw: bytes,
    source_format: str,
    *,
    attempt_id: str = ATTEMPT_ID,
) -> tuple[dict[str, Any], bytes]:
    if not mode_a_supported():
        pytest.skip("Mode A is Unix-only")
    base.mkdir(parents=True, exist_ok=True)
    suffix = "yaml" if source_format == "yaml" else source_format
    source = base / f"source.{suffix}"
    source.write_bytes(raw)
    artifacts = base / f"mode-a-{attempt_id[-8:]}"
    artifacts.mkdir()
    times = iter((STARTED_AT, FINISHED_AT))
    monkeypatch.setattr("extension.dispatch.utc_now", lambda: next(times))
    if case is SECURITY:
        args = {"index": str(source), "rule_id": case["subject_id"]}
    else:
        args = {
            "telemetry_file": str(source),
            "event_id": case["subject_id"],
        }
    outcome = dispatch_invoke(
        Extension(),
        arm_id=case["arm_id"],
        action=case["action"],
        args=args,
        attempt_id=attempt_id,
        artifact_dir=str(artifacts),
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert len(outcome.envelope["artifacts"]) == 1
    digest = outcome.envelope["artifacts"][0]["digest"]
    report = (
        artifacts / ("sha256-" + digest.removeprefix("sha256:"))
    ).read_bytes()
    return dict(outcome.envelope), report


def _complete(
    base: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
    source_format: str = "json",
    *,
    attempt_id: str = ATTEMPT_ID,
) -> tuple[bytes, dict[str, Any], dict[str, Any], bytes, dict[str, Any]]:
    raw = _source_bytes(case, source_format)
    admission = _issue(
        case, raw, source_format, attempt_id=attempt_id
    )
    result, report = _mode_a_bundle(
        base,
        monkeypatch,
        case,
        raw,
        source_format,
        attempt_id=attempt_id,
    )
    observation = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    return raw, admission, result, report, observation


def _replace_report(
    result: dict[str, Any], payload: dict[str, Any]
) -> tuple[dict[str, Any], bytes]:
    report = _artifact_bytes(payload)
    forged = copy.deepcopy(result)
    forged["artifacts"] = [
        {
            "digest": _digest(report),
            "kind": "policy-report",
            "redaction": "credentials-stripped",
        }
    ]
    forged["budget"]["spent"]["output_bytes"] = len(report)
    return forged, report


def _legacy_kwargs(raw: bytes) -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "raw_artifact": raw,
        "source_format": "json",
        "source_id": "local-vulnerability-slice",
        "source_revision": "snapshot-2026-09-08",
        "source_timestamp": SOURCE_TIME,
        "logical_locator": "source://local-vulnerability/snapshot-2026-09-08",
        "raw_artifact_locator": "custody://ctf-evidence/vulnify/raw",
        "authority_ref": "operator://source-admission/evid-01-fixture",
        "issuer_id": "ctf-evidence-custodian",
        "issuer_version": "0.1.0",
        "producer_revision": "git:6a6a652",
        "issued_at": ISSUED_AT,
        "valid_from": ISSUED_AT,
        "valid_until": VALID_UNTIL,
        "limitations": ("synthetic-source",),
    }


def _legacy_complete(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict[str, Any], dict[str, Any]]:
    cve_id = "CVE-2026-1234"
    raw = _canonical([{"cve_id": cve_id, "name": "Synthetic issue"}])
    admission = issue_source_admission(cve_id=cve_id, **_legacy_kwargs(raw))
    base.mkdir(parents=True, exist_ok=True)
    source = base / "feed.json"
    source.write_bytes(raw)
    artifacts = base / "mode-a"
    artifacts.mkdir()
    times = iter((STARTED_AT, FINISHED_AT))
    monkeypatch.setattr("extension.dispatch.utc_now", lambda: next(times))
    outcome = dispatch_invoke(
        Extension(),
        arm_id="vulnify",
        action="lookup",
        args={"feed": str(source), "cve_id": cve_id},
        attempt_id=ATTEMPT_ID,
        artifact_dir=str(artifacts),
    )
    assert outcome.exit_code == 0 and outcome.envelope is not None
    digest = outcome.envelope["artifacts"][0]["digest"]
    report = (
        artifacts / ("sha256-" + digest.removeprefix("sha256:"))
    ).read_bytes()
    observation = derive_trusted_observation(
        admission=admission,
        execution_result=outcome.envelope,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    return admission, observation


def test_v1_schema_bytes_are_frozen_and_v2_schemas_are_closed_draft7() -> None:
    assert hashlib.sha256(ADMISSION_V1_SCHEMA.read_bytes()).hexdigest() == (
        "c117bfe07505497417ff4e828478a3d69c89455dae8e5fe98a885e9d198843c6"
    )
    assert hashlib.sha256(OBSERVATION_V1_SCHEMA.read_bytes()).hexdigest() == (
        "5675b3724da896192d63b6ca848c2c3c0cbc7bd8534b5b65540539866c0e8748"
    )
    for path, schema_id in (
        (ADMISSION_V2_SCHEMA, SOURCE_ADMISSION_V2_SCHEMA_ID),
        (OBSERVATION_V2_SCHEMA, TRUSTED_OBSERVATION_V2_SCHEMA_ID),
    ):
        schema = _schema(path)
        jsonschema.Draft7Validator.check_schema(schema)
        assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert schema["additionalProperties"] is False
        assert schema["properties"]["schema"]["const"] == schema_id
        assert schema["properties"]["schema_version"]["const"] == 2
        assert len(schema["oneOf"]) == 2


def test_v2_registry_is_frozen_ordered_and_does_not_expand_public_dispatch() -> None:
    assert isinstance(OBSERVATION_PROFILES, MappingProxyType)
    assert tuple(OBSERVATION_PROFILES) == (
        "vulnify.lookup",
        "security-detections-mcp.get_rule",
        "rubeus.telemetry",
    )
    assert TOOLS == ("list", "describe", "invoke", "run_range")
    assert len(INVOKE_PROFILES) == 212
    assert len(PR97_ARM_IDS) == 14
    assert sum(
        len(actions) - ("list_tools" in actions)
        for actions in PR97_ACTION_ARGUMENTS.values()
    ) == 38
    assert "issue_profile_source_admission" not in extension.__all__
    assert not hasattr(extension, "issue_profile_source_admission")
    assert all("observation" not in capability for capability in INVOKE_PROFILES)


def test_fresh_default_import_still_excludes_all_observation_modules() -> None:
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, sys, extension; print(json.dumps({"
                "'observations': 'extension.observations' in sys.modules,"
                "'profiles': 'extension.observation_profiles' in sys.modules,"
                "'issuer': hasattr(extension, 'issue_profile_source_admission')}))"
            ),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(probe.stdout) == {
        "observations": False,
        "profiles": False,
        "issuer": False,
    }


def test_generic_vulnify_issuer_is_byte_compatible_with_v1_wrapper() -> None:
    cve_id = "CVE-2026-1234"
    raw = _canonical([{"cve_id": cve_id, "name": "Synthetic issue"}])
    legacy = issue_source_admission(cve_id=cve_id, **_legacy_kwargs(raw))
    generic = issue_profile_source_admission(
        capability_id="vulnify.lookup",
        subject_id=cve_id,
        **_legacy_kwargs(raw),
    )
    assert generic == legacy
    assert generic["schema"] == "specaudit.ctf.source-admission.v1"
    assert generic["schema_version"] == 1


@pytest.mark.parametrize(
    ("case", "source_format"),
    [
        pytest.param(SECURITY, "json", id="security-json"),
        pytest.param(SECURITY, "yaml", id="security-yaml"),
        pytest.param(RUBEUS, "json", id="rubeus-json"),
        pytest.param(RUBEUS, "jsonl", id="rubeus-jsonl"),
    ],
)
def test_each_v2_profile_derives_from_real_mode_a_and_reverifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
    source_format: str,
) -> None:
    raw, admission, result, report, observation = _complete(
        tmp_path / f"{case['arm_id']}-{source_format}",
        monkeypatch,
        case,
        source_format,
    )
    _validator(ADMISSION_V2_SCHEMA).validate(admission)
    _validator(OBSERVATION_V2_SCHEMA).validate(observation)
    assert admission["schema"] == SOURCE_ADMISSION_V2_SCHEMA_ID
    assert admission["schema_version"] == SCHEMA_VERSION_V2
    assert observation["schema"] == TRUSTED_OBSERVATION_V2_SCHEMA_ID
    assert observation["schema_version"] == SCHEMA_VERSION_V2
    assert admission["source"]["schema"] == {
        "id": case["source_schema"],
        "version": 1,
        "format": source_format,
    }
    assert admission["subject"] == {
        "kind": case["subject_kind"],
        case["subject_field"]: case["subject_id"],
    }
    assert admission["scope"] == {
        "kind": case["scope_kind"],
        "identifier": case["scope_identifier"],
    }
    assert observation["source"]["raw_artifact"]["digest"] == _digest(raw)
    assert observation["bindings"]["policy_report"] == {
        "digest": _digest(report),
        "bytes": len(report),
    }
    assert observation["evidence"]["class"] == "declared"
    assert observation["evidence"]["applicability"] == {
        "assessed": False,
        "status": "not-assessed",
    }
    report_doc = json.loads(report)
    if case is SECURITY:
        rule = report_doc["rule"]
        assert observation["evidence"]["record"] == {
            "rule_id": rule["rule_id"],
            "name": rule["name"],
            "definition_digest": _digest(_artifact_bytes(rule)),
        }
        assert {
            "rule-deployment-not-established",
            "operating-effectiveness-not-assessed",
        } <= set(observation["limitations"])
    else:
        assert observation["evidence"]["record"] == report_doc["telemetry"]
        assert "value" not in json.dumps(observation["evidence"])
        assert {
            "event-authenticity-not-established",
            "event-time-not-established",
            "compromise-not-inferred",
        } <= set(observation["limitations"])
    checked = verify_trusted_observation(
        observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert checked.accepted is True and checked.reasons == ()


def test_v1_and_v2_schemas_remain_disjoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    v1_admission, v1_observation = _legacy_complete(
        tmp_path / "v1", monkeypatch
    )
    _, v2_admission, _, _, v2_observation = _complete(
        tmp_path / "v2", monkeypatch, SECURITY
    )
    for document, wrong_schema in (
        (v1_admission, ADMISSION_V2_SCHEMA),
        (v2_admission, ADMISSION_V1_SCHEMA),
        (v1_observation, OBSERVATION_V2_SCHEMA),
        (v2_observation, OBSERVATION_V1_SCHEMA),
    ):
        with pytest.raises(jsonschema.ValidationError):
            _validator(wrong_schema).validate(document)


def _set_path(document: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    target: Any = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = copy.deepcopy(value)


def test_v2_schemas_reject_cross_profile_splices_and_open_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, security_admission, _, _, security_observation = _complete(
        tmp_path / "security", monkeypatch, SECURITY
    )
    _, rubeus_admission, _, _, rubeus_observation = _complete(
        tmp_path / "rubeus", monkeypatch, RUBEUS
    )
    for path in (
        ("capability_id",),
        ("arm_id",),
        ("action",),
        ("source", "schema"),
        ("subject",),
        ("scope",),
    ):
        malformed = copy.deepcopy(security_admission)
        source: Any = rubeus_admission
        for part in path:
            source = source[part]
        _set_path(malformed, path, source)
        with pytest.raises(jsonschema.ValidationError):
            _validator(ADMISSION_V2_SCHEMA).validate(malformed)

    for path in (
        ("capability_id",),
        ("arm_id",),
        ("action",),
        ("source", "schema"),
        ("subject",),
        ("scope",),
        ("evidence",),
    ):
        malformed = copy.deepcopy(security_observation)
        source = rubeus_observation
        for part in path:
            source = source[part]
        _set_path(malformed, path, source)
        with pytest.raises(jsonschema.ValidationError):
            _validator(OBSERVATION_V2_SCHEMA).validate(malformed)

    open_rule = copy.deepcopy(security_observation)
    open_rule["evidence"]["record"]["severity"] = "high"
    with pytest.raises(jsonschema.ValidationError):
        _validator(OBSERVATION_V2_SCHEMA).validate(open_rule)
    leaked_indicator = copy.deepcopy(rubeus_observation)
    leaked_indicator["evidence"]["record"]["indicators"][0]["value"] = (
        "[REDACTED]"
    )
    with pytest.raises(jsonschema.ValidationError):
        _validator(OBSERVATION_V2_SCHEMA).validate(leaked_indicator)


@pytest.mark.parametrize("case", (SECURITY, RUBEUS), ids=("security", "rubeus"))
def test_v2_issuer_rejects_absent_and_schema_unsafe_subjects(
    case: dict[str, Any],
) -> None:
    raw = _source_bytes(case, "json")
    with pytest.raises(ObservationError) as absent:
        _issue(case, raw, "json", subject_id="ABSENT-999")
    assert REASON_SUBJECT_MISMATCH in absent.value.reasons
    with pytest.raises(ObservationError) as unsafe:
        _issue(case, raw, "json", subject_id="unsafe subject")
    assert REASON_INVALID_ADMISSION in unsafe.value.reasons


@pytest.mark.parametrize("case", (SECURITY, RUBEUS), ids=("security", "rubeus"))
def test_cross_attempt_and_cross_profile_results_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
) -> None:
    raw = _source_bytes(case, "json")
    admission = _issue(case, raw, "json")
    result, report = _mode_a_bundle(
        tmp_path / case["arm_id"],
        monkeypatch,
        case,
        raw,
        "json",
        attempt_id=OTHER_ATTEMPT_ID,
    )
    with pytest.raises(ObservationError) as cross_attempt:
        derive_trusted_observation(
            admission=admission,
            execution_result=result,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_ATTEMPT_MISMATCH in cross_attempt.value.reasons

    other = RUBEUS if case is SECURITY else SECURITY
    other_raw = _source_bytes(other, "json")
    other_result, other_report = _mode_a_bundle(
        tmp_path / f"other-{case['arm_id']}",
        monkeypatch,
        other,
        other_raw,
        "json",
    )
    with pytest.raises(ObservationError) as cross_profile:
        derive_trusted_observation(
            admission=admission,
            execution_result=other_result,
            policy_report=other_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_PROFILE_MISMATCH in cross_profile.value.reasons


@pytest.mark.parametrize("case", (SECURITY, RUBEUS), ids=("security", "rubeus"))
def test_coherently_rehashed_unrelated_record_and_false_source_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
) -> None:
    raw, admission, result, report, _ = _complete(
        tmp_path / case["arm_id"], monkeypatch, case
    )
    payload = json.loads(report)
    record_key = "rule" if case is SECURITY else "telemetry"
    if case is SECURITY:
        payload[record_key]["definition"]["query"] = "forged unrelated query"
    else:
        payload[record_key]["description"] = "forged unrelated event"
    forged_result, forged_report = _replace_report(result, payload)
    with pytest.raises(ObservationError) as unrelated:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_SUBJECT_MISMATCH in unrelated.value.reasons

    payload = json.loads(report)
    payload["source"]["sha256"] = "sha256:" + ("0" * 64)
    forged_result, forged_report = _replace_report(result, payload)
    with pytest.raises(ObservationError) as false_source:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_SOURCE_MISMATCH in false_source.value.reasons


def test_security_full_rule_replay_distinguishes_python_equal_json_types(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, _ = _complete(
        tmp_path, monkeypatch, SECURITY
    )
    payload = json.loads(report)
    assert payload["rule"]["definition"]["threshold"] == 0
    payload["rule"]["definition"]["threshold"] = False
    forged_result, forged_report = _replace_report(result, payload)
    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_SUBJECT_MISMATCH in excinfo.value.reasons


def test_security_definition_digest_binds_unprojected_rule_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete(
        tmp_path, monkeypatch, SECURITY
    )
    original = observation["evidence"]["record"]["definition_digest"]
    rule = json.loads(report)["rule"]
    mutated_rule = copy.deepcopy(rule)
    mutated_rule["definition"]["threshold"] = 1
    assert _digest(_artifact_bytes(mutated_rule)) != original

    tampered = copy.deepcopy(observation)
    tampered["evidence"]["record"]["definition_digest"] = _digest(
        _artifact_bytes(mutated_rule)
    )
    checked = verify_trusted_observation(
        tampered,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert checked.accepted is False
    assert REASON_EVIDENCE_MISMATCH in checked.reasons
    assert REASON_OBSERVATION_MISMATCH in checked.reasons


@pytest.mark.parametrize("case", (SECURITY, RUBEUS), ids=("security", "rubeus"))
def test_v2_policy_report_tamper_replay_and_pure_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, Any],
) -> None:
    raw, admission, result, report, observation = _complete(
        tmp_path / case["arm_id"], monkeypatch, case
    )
    with pytest.raises(ObservationError) as noncanonical:
        derive_trusted_observation(
            admission=admission,
            execution_result=result,
            policy_report=report + b" ",
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_INVALID_POLICY_REPORT in noncanonical.value.reasons

    replayed = verify_trusted_observation(
        observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids={observation["observation_id"]},
    )
    assert replayed.accepted is False and REASON_REPLAY in replayed.reasons
    malformed_seen = verify_trusted_observation(
        observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=observation["observation_id"],
    )
    assert malformed_seen.accepted is False
    assert REASON_REPLAY in malformed_seen.reasons

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("v2 verifier attempted I/O or dispatch")

    monkeypatch.setattr("pathlib.Path.open", forbidden)
    monkeypatch.setattr("extension.contract.Extension.invoke", forbidden)
    pure = verify_trusted_observation(
        observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert pure.accepted is True and pure.reasons == ()


def test_forged_security_report_cannot_exceed_the_arm_output_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chunks = ["x" * 16_000 for _ in range(14)]
    rules = [
        {
            "rule_id": SECURITY["subject_id"],
            "name": "Bounded but too large for the producer",
            "definition": {"chunks": chunks},
        }
    ]
    raw = _canonical(rules)
    admission = _issue(SECURITY, raw, "json")
    parsed, source, _ = parse_index_bytes(raw, format="json")
    payload = {"rule": parsed[0], "source": source}
    forged_report = _artifact_bytes(payload)
    assert 200_000 < len(forged_report) < 1_048_576

    small_raw = _source_bytes(SECURITY, "json")
    result, _ = _mode_a_bundle(
        tmp_path, monkeypatch, SECURITY, small_raw, "json"
    )
    forged_result, forged_report = _replace_report(result, payload)
    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_INVALID_POLICY_REPORT in excinfo.value.reasons


def test_v2_schema_rejects_terminal_newlines_and_invalid_calendar_dates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, admission, _, _, observation = _complete(
        tmp_path, monkeypatch, SECURITY
    )
    malformed = copy.deepcopy(admission)
    malformed["subject"]["rule_id"] += "\n"
    with pytest.raises(jsonschema.ValidationError):
        _validator(ADMISSION_V2_SCHEMA).validate(malformed)
    malformed = copy.deepcopy(observation)
    malformed["custody"]["policy_report_locator"] += "\n"
    with pytest.raises(jsonschema.ValidationError):
        _validator(OBSERVATION_V2_SCHEMA).validate(malformed)
    invalid_date = copy.deepcopy(observation)
    invalid_date["verified_at"] = "2026-09-31T12:00:00Z"
    with pytest.raises(jsonschema.ValidationError):
        _validator(OBSERVATION_V2_SCHEMA).validate(invalid_date)


def test_v2_admission_raw_binding_and_observation_unknown_fields_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete(
        tmp_path, monkeypatch, RUBEUS
    )
    other = _canonical(_rubeus_events()[:1])
    checked = verify_source_admission(
        admission, raw_artifact=other, at_time=VERIFIED_AT
    )
    assert checked.accepted is False

    extra = copy.deepcopy(observation)
    extra["trusted"] = True
    checked = verify_trusted_observation(
        extra,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert checked.accepted is False
    assert REASON_OBSERVATION_MISMATCH in checked.reasons
