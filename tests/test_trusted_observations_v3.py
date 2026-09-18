"""Material causal tests for the EVID-01 gpohound.policy v3 profile."""

from __future__ import annotations

import copy
import hashlib
import json
from itertools import combinations
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

import extension.observations as observation_module
from extension.arms.gpohound.arm import (
    parse_policy_evidence_bytes,
    render_producer_output_bytes,
)
from extension.arms.gpohound.policy import MAX_OUTPUT_CHARS
from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.encode import mode_a_supported
from extension.observations import (
    REASON_ATTEMPT_MISMATCH,
    REASON_CUSTODY_MISMATCH,
    REASON_INVALID_POLICY_REPORT,
    REASON_OBSERVATION_MISMATCH,
    REASON_PROFILE_MISMATCH,
    REASON_RAW_ARTIFACT_MISMATCH,
    REASON_REPLAY,
    REASON_SOURCE_MISMATCH,
    REASON_SUBJECT_MISMATCH,
    REASON_UNKNOWN_SCHEMA,
    SCHEMA_VERSION_V2,
    SCHEMA_VERSION_V3,
    SOURCE_ADMISSION_V3_SCHEMA_ID,
    TRUSTED_OBSERVATION_V2_SCHEMA_ID,
    TRUSTED_OBSERVATION_V3_SCHEMA_ID,
    ObservationError,
    derive_trusted_observation,
    issue_profile_source_admission,
    verify_source_admission,
    verify_trusted_observation,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "extension" / "schema"
ADMISSION_SCHEMAS = (
    SCHEMA_DIR / "source-admission.v1.schema.json",
    SCHEMA_DIR / "source-admission.v2.schema.json",
    SCHEMA_DIR / "source-admission.v3.schema.json",
)
OBSERVATION_SCHEMAS = (
    SCHEMA_DIR / "trusted-observation.v1.schema.json",
    SCHEMA_DIR / "trusted-observation.v2.schema.json",
    SCHEMA_DIR / "trusted-observation.v3.schema.json",
)
ADMISSION_V3_SCHEMA = ADMISSION_SCHEMAS[-1]
OBSERVATION_V3_SCHEMA = OBSERVATION_SCHEMAS[-1]

ATTEMPT_ID = "attempt-" + ("56" * 32)
OTHER_ATTEMPT_ID = "attempt-" + ("78" * 32)
SOURCE_TIME = "2026-09-09T09:00:00Z"
ISSUED_AT = "2026-09-09T10:00:00Z"
STARTED_AT = "2026-09-09T11:00:00Z"
FINISHED_AT = "2026-09-09T11:00:01Z"
VERIFIED_AT = "2026-09-09T12:00:00Z"
VALID_UNTIL = "2026-09-09T13:00:00Z"
POLICY_ID = "GPO-001"
BRACED_POLICY_ID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"

CALLER_LIMITATIONS = {"data-rights-not-evaluated", "synthetic-source"}
DERIVED_LIMITATIONS = {
    "applicability-not-assessed",
    "source-admission-is-not-governance-promotion",
    "upstream-equivalence-not-established",
    "policy-application-not-established",
    "effective-access-not-inferred",
    "security-filter-applicability-not-assessed",
    "wmi-filter-applicability-not-assessed",
    "item-level-targeting-not-represented",
    "policy-conflicts-not-simulated",
}


def _artifact_bytes(value: Any) -> bytes:
    """Match the execution-result artifact encoder's canonical JSON."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
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


def _policies() -> list[dict[str, Any]]:
    return [
        {
            "policy_id": POLICY_ID,
            "name": "Synthetic domain baseline",
            "status": "active",
            "links": [
                {
                    "ou": "OU=Servers,DC=example,DC=test",
                    "enforced": True,
                    "enabled": True,
                    "order": 0,
                    "block_inheritance": False,
                },
                {
                    "ou": "OU=Workstations,DC=example,DC=test",
                    "enforced": False,
                    "enabled": True,
                    "order": 1,
                    "block_inheritance": True,
                },
            ],
            "filters": {
                "security": ["S-1-5-21-1000", "S-1-5-21-2000"],
                "wmi": ["SELECT * FROM Win32_OperatingSystem"],
            },
            "settings": {
                "password_policy": {
                    "minimum_length": 14,
                    "history": {"enabled": False, "count": 0},
                },
                "audit": ["logon", {"subcategory": "process-creation"}],
            },
        },
        {
            "policy_id": "GPO-002",
            "name": "Synthetic near miss",
            "status": "disabled",
            "links": [],
            "filters": {"security": [], "wmi": []},
            "settings": {},
        },
    ]


def _source_bytes(
    source_format: str, *, policies: list[dict[str, Any]] | None = None
) -> bytes:
    rows = _policies() if policies is None else policies
    if source_format == "json":
        return _artifact_bytes(rows)
    assert source_format in {"yaml", "yml"}
    return yaml.safe_dump(
        rows, sort_keys=False, allow_unicode=True
    ).encode("utf-8")


def _issue(
    raw: bytes,
    source_format: str = "json",
    *,
    subject_id: str = POLICY_ID,
    attempt_id: str = ATTEMPT_ID,
) -> dict[str, Any]:
    return issue_profile_source_admission(
        capability_id="gpohound.policy",
        subject_id=subject_id,
        attempt_id=attempt_id,
        raw_artifact=raw,
        source_format=source_format,
        source_id="synthetic-gpohound-source",
        source_revision="snapshot-2026-09-09",
        source_timestamp=SOURCE_TIME,
        logical_locator="source://synthetic/gpohound/snapshot-2026-09-09",
        raw_artifact_locator="custody://ctf-evidence/gpohound/raw",
        authority_ref="operator://source-admission/evid-01-fixture",
        issuer_id="ctf-evidence-custodian",
        issuer_version="0.1.0",
        producer_revision="git:40efc7a",
        issued_at=ISSUED_AT,
        valid_from=ISSUED_AT,
        valid_until=VALID_UNTIL,
        limitations=tuple(sorted(CALLER_LIMITATIONS)),
    )


def _mode_a_bundle(
    base: Path,
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
    source_format: str = "json",
    *,
    attempt_id: str = ATTEMPT_ID,
    subject_id: str = POLICY_ID,
) -> tuple[dict[str, Any], bytes]:
    if not mode_a_supported():
        pytest.skip("Mode A is Unix-only")
    base.mkdir(parents=True, exist_ok=True)
    source = base / f"policy-evidence.{source_format}"
    source.write_bytes(raw)
    artifacts = base / "mode-a"
    artifacts.mkdir()
    times = iter((STARTED_AT, FINISHED_AT))
    monkeypatch.setattr("extension.dispatch.utc_now", lambda: next(times))
    outcome = dispatch_invoke(
        Extension(),
        arm_id="gpohound",
        action="policy",
        args={"evidence": str(source), "policy_id": subject_id},
        attempt_id=attempt_id,
        artifact_dir=str(artifacts),
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert len(outcome.envelope["artifacts"]) == 1
    report_digest = outcome.envelope["artifacts"][0]["digest"]
    report = (
        artifacts / ("sha256-" + report_digest.removeprefix("sha256:"))
    ).read_bytes()
    return dict(outcome.envelope), report


def _complete(
    base: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_format: str = "json",
    *,
    policies: list[dict[str, Any]] | None = None,
) -> tuple[bytes, dict[str, Any], dict[str, Any], bytes, dict[str, Any]]:
    raw = _source_bytes(source_format, policies=policies)
    admission = _issue(raw, source_format)
    result, report = _mode_a_bundle(
        base, monkeypatch, raw, source_format
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


def _alter_policy(policy: dict[str, Any], mutation: str) -> None:
    if mutation == "status":
        policy["status"] = "disabled"
    elif mutation == "link-sequence":
        policy["links"].reverse()
    elif mutation == "link-content":
        policy["links"][0]["ou"] = "OU=Forged,DC=example,DC=test"
    elif mutation == "security-filter":
        policy["filters"]["security"].append("S-1-5-21-9999")
    elif mutation == "wmi-filter":
        policy["filters"]["wmi"][0] = "SELECT * FROM Win32_ComputerSystem"
    elif mutation == "nested-setting":
        policy["settings"]["password_policy"]["minimum_length"] = 8
    elif mutation == "policy-id":
        policy["policy_id"] = "GPO-999"
    elif mutation == "name":
        policy["name"] = "Forged policy name"
    elif mutation == "python-equal-json-type":
        policy["settings"]["password_policy"]["history"]["count"] = False
    else:  # pragma: no cover - test table is closed below
        raise AssertionError(f"unknown mutation: {mutation}")


def test_v3_schemas_are_closed_draft7_and_pairwise_disjoint() -> None:
    for paths, expected_v3_id in (
        (ADMISSION_SCHEMAS, SOURCE_ADMISSION_V3_SCHEMA_ID),
        (OBSERVATION_SCHEMAS, TRUSTED_OBSERVATION_V3_SCHEMA_ID),
    ):
        selectors: list[tuple[str, int]] = []
        for version, path in enumerate(paths, 1):
            schema = _schema(path)
            jsonschema.Draft7Validator.check_schema(schema)
            assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
            assert schema["additionalProperties"] is False
            assert {"schema", "schema_version"} <= set(schema["required"])
            selector = (
                schema["properties"]["schema"]["const"],
                schema["properties"]["schema_version"]["const"],
            )
            assert selector[1] == version
            selectors.append(selector)
        assert selectors[-1] == (expected_v3_id, SCHEMA_VERSION_V3)
        for left, right in combinations(selectors, 2):
            assert left[0] != right[0] and left[1] != right[1]

    admission_v3 = _schema(ADMISSION_V3_SCHEMA)
    observation_v3 = _schema(OBSERVATION_V3_SCHEMA)
    assert admission_v3["properties"]["capability_id"]["const"] == (
        "gpohound.policy"
    )
    assert observation_v3["properties"]["capability_id"]["const"] == (
        "gpohound.policy"
    )


@pytest.mark.parametrize("source_format", ("json", "yaml", "yml"))
def test_v3_real_mode_a_derives_exact_evidence_and_reverifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_format: str,
) -> None:
    raw, admission, result, report, observation = _complete(
        tmp_path, monkeypatch, source_format
    )
    _validator(ADMISSION_V3_SCHEMA).validate(admission)
    _validator(OBSERVATION_V3_SCHEMA).validate(observation)
    assert admission["schema"] == SOURCE_ADMISSION_V3_SCHEMA_ID
    assert admission["schema_version"] == SCHEMA_VERSION_V3
    assert observation["schema"] == TRUSTED_OBSERVATION_V3_SCHEMA_ID
    assert observation["schema_version"] == SCHEMA_VERSION_V3
    assert admission["source"]["schema"] == {
        "id": "specaudit.ctf.gpohound-policy-evidence-projection.v1",
        "version": 1,
        "format": source_format,
    }
    assert admission["subject"] == {
        "kind": "gpo-policy",
        "policy_id": POLICY_ID,
    }
    assert admission["scope"] == {
        "kind": "gpo-policy-record",
        "identifier": f"policy:{POLICY_ID}",
    }
    policy = json.loads(report)["policy"]
    assert observation["evidence"] == {
        "class": "declared",
        "record": {
            "policy_id": policy["policy_id"],
            "name": policy["name"],
            "declared_status": policy["status"],
            "definition_digest": _digest(_artifact_bytes(policy)),
        },
        "applicability": {"assessed": False, "status": "not-assessed"},
    }
    assert set(observation["limitations"]) - set(admission["limitations"]) == (
        DERIVED_LIMITATIONS
    )
    assert set(admission["limitations"]) == CALLER_LIMITATIONS
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


def test_v3_accepts_conventional_braced_gpo_id_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policies = _policies()
    policies[0]["policy_id"] = BRACED_POLICY_ID
    raw = _source_bytes("json", policies=policies)
    admission = _issue(raw, subject_id=BRACED_POLICY_ID)
    result, report = _mode_a_bundle(
        tmp_path,
        monkeypatch,
        raw,
        subject_id=BRACED_POLICY_ID,
    )
    observation = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )

    assert admission["subject"]["policy_id"] == BRACED_POLICY_ID
    assert admission["scope"]["identifier"] == f"policy:{BRACED_POLICY_ID}"
    assert observation["evidence"]["record"]["policy_id"] == BRACED_POLICY_ID
    _validator(ADMISSION_V3_SCHEMA).validate(admission)
    _validator(OBSERVATION_V3_SCHEMA).validate(observation)
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


def test_v3_derivation_rejects_source_attempt_profile_subject_and_report_splices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, _ = _complete(tmp_path, monkeypatch)

    source_payload = json.loads(report)
    source_payload["source"]["sha256"] = "sha256:" + ("0" * 64)
    forged_result, forged_report = _replace_report(result, source_payload)
    with pytest.raises(ObservationError) as source_error:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_SOURCE_MISMATCH in source_error.value.reasons

    wrong_attempt = copy.deepcopy(result)
    wrong_attempt["attempt_id"] = OTHER_ATTEMPT_ID
    with pytest.raises(ObservationError) as attempt_error:
        derive_trusted_observation(
            admission=admission,
            execution_result=wrong_attempt,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_ATTEMPT_MISMATCH in attempt_error.value.reasons

    wrong_profile = copy.deepcopy(result)
    wrong_profile["capability_id"] = "rubeus.telemetry"
    with pytest.raises(ObservationError) as profile_error:
        derive_trusted_observation(
            admission=admission,
            execution_result=wrong_profile,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_PROFILE_MISMATCH in profile_error.value.reasons

    with pytest.raises(ObservationError) as subject_error:
        _issue(raw, subject_id="GPO-999")
    assert REASON_SUBJECT_MISMATCH in subject_error.value.reasons

    report_payload = json.loads(report)
    report_payload["trusted"] = True
    forged_result, forged_report = _replace_report(result, report_payload)
    with pytest.raises(ObservationError) as report_error:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_INVALID_POLICY_REPORT in report_error.value.reasons

    raw_check = verify_source_admission(
        admission, raw_artifact=raw + b"\n", at_time=VERIFIED_AT
    )
    assert raw_check.accepted is False
    assert REASON_RAW_ARTIFACT_MISMATCH in raw_check.reasons


def test_v3_verifier_rejects_custody_replay_and_schema_splices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete(
        tmp_path, monkeypatch
    )

    custody = copy.deepcopy(observation)
    custody["custody"]["result_assertion"] = "validator-held-mode-a"
    checked = verify_trusted_observation(
        custody,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert checked.accepted is False
    assert REASON_CUSTODY_MISMATCH in checked.reasons
    assert REASON_OBSERVATION_MISMATCH in checked.reasons

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

    spliced_admission = copy.deepcopy(admission)
    spliced_admission["schema"] = "specaudit.ctf.source-admission.v2"
    spliced_admission["schema_version"] = 2
    admission_check = verify_source_admission(
        spliced_admission, raw_artifact=raw, at_time=VERIFIED_AT
    )
    assert admission_check.accepted is False
    assert REASON_PROFILE_MISMATCH in admission_check.reasons

    spliced_observation = copy.deepcopy(observation)
    spliced_observation["schema"] = "specaudit.ctf.trusted-observation.v2"
    spliced_observation["schema_version"] = 2
    observation_check = verify_trusted_observation(
        spliced_observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert observation_check.accepted is False
    assert REASON_PROFILE_MISMATCH in observation_check.reasons

    split_selector = copy.deepcopy(observation)
    split_selector["schema_version"] = 2
    selector_check = verify_trusted_observation(
        split_selector,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert selector_check.accepted is False
    assert REASON_UNKNOWN_SCHEMA in selector_check.reasons


def test_definition_digest_and_raw_replay_cover_every_policy_field_and_json_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete(
        tmp_path, monkeypatch
    )
    payload = json.loads(report)
    original_policy = payload["policy"]
    original_digest = _digest(_artifact_bytes(original_policy))
    assert observation["evidence"]["record"]["definition_digest"] == (
        original_digest
    )

    for mutation in (
        "status",
        "link-sequence",
        "link-content",
        "security-filter",
        "wmi-filter",
        "nested-setting",
        "policy-id",
        "name",
        "python-equal-json-type",
    ):
        forged_payload = copy.deepcopy(payload)
        forged_policy = forged_payload["policy"]
        _alter_policy(forged_policy, mutation)
        if mutation == "python-equal-json-type":
            assert forged_policy == original_policy
            original_value = original_policy["settings"]["password_policy"][
                "history"
            ]["count"]
            forged_value = forged_policy["settings"]["password_policy"][
                "history"
            ]["count"]
            assert original_value == forged_value
            assert type(original_value) is not type(forged_value)
        assert _digest(_artifact_bytes(forged_policy)) != original_digest

        forged_result, forged_report = _replace_report(result, forged_payload)
        with pytest.raises(ObservationError) as excinfo:
            derive_trusted_observation(
                admission=admission,
                execution_result=forged_result,
                policy_report=forged_report,
                raw_artifact=raw,
                verified_at=VERIFIED_AT,
            )
        assert REASON_SUBJECT_MISMATCH in excinfo.value.reasons, mutation


def test_producer_near_both_caps_is_accepted_and_forged_over_cap_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    near_cap = _policies()
    near_cap[0]["settings"] = {
        "nodes": [0] * 49_800,
        "chunks": ["x" * 4_000 for _ in range(12)],
    }
    raw, admission, result, report, observation = _complete(
        tmp_path / "near-cap",
        monkeypatch,
        policies=near_cap,
    )
    producer_bytes = render_producer_output_bytes(json.loads(report))
    assert 190_000 < len(producer_bytes) <= MAX_OUTPUT_CHARS
    _validator(OBSERVATION_V3_SCHEMA).validate(observation)
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

    over_cap = _policies()
    over_cap[0]["settings"] = {
        "chunks": ["x" * 4_096 for _ in range(49)]
    }
    over_raw = _source_bytes("json", policies=over_cap)
    over_admission = _issue(over_raw)
    parsed, source, _ = parse_policy_evidence_bytes(over_raw, format="json")
    over_payload = {"policy": parsed[0], "source": source}
    assert MAX_OUTPUT_CHARS < len(render_producer_output_bytes(over_payload))

    small_raw = _source_bytes("json")
    small_result, _ = _mode_a_bundle(
        tmp_path / "small-result", monkeypatch, small_raw
    )
    forged_result, forged_report = _replace_report(
        small_result, over_payload
    )
    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=over_admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=over_raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_INVALID_POLICY_REPORT in excinfo.value.reasons


def test_v3_copy_bounds_are_strict_without_reducing_v1_v2_headroom() -> None:
    at_v3_text_cap = {"record": {"x" * 4_096: "y" * 4_096}}
    assert observation_module._v3_document_copy(at_v3_text_cap) == (
        at_v3_text_cap
    )

    over_v3_text_cap = {"record": {"field": "x" * 4_097}}
    with pytest.raises(ValueError, match="text exceeds cap"):
        observation_module._v3_document_copy(over_v3_text_cap)
    assert observation_module._v2_document_copy(over_v3_text_cap) == (
        over_v3_text_cap
    )
    assert observation_module._document_copy(over_v3_text_cap) == (
        over_v3_text_cap
    )

    over_v3_key_cap = {"k" * 4_097: "value"}
    with pytest.raises(TypeError, match="keys must be bounded"):
        observation_module._v3_document_copy(over_v3_key_cap)
    assert observation_module._v2_document_copy(over_v3_key_cap) == (
        over_v3_key_cap
    )

    routed_v2 = {
        "schema": TRUSTED_OBSERVATION_V2_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION_V2,
        "capability_id": "security-detections-mcp.get_rule",
        **over_v3_text_cap,
    }
    assert observation_module._observation_document_copy(routed_v2) == routed_v2
    routed_v3 = {
        "schema": TRUSTED_OBSERVATION_V3_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION_V3,
        "capability_id": "gpohound.policy",
        **over_v3_text_cap,
    }
    with pytest.raises(ValueError, match="text exceeds cap"):
        observation_module._observation_document_copy(routed_v3)
