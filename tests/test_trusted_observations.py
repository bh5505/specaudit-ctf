"""Causal tests for the opt-in EVID-01 vulnify.lookup slice."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Any

import jsonschema
import pytest

import extension
import extension.observations as observation_module
from extension.arms.vulnify.arm import (
    FeedError,
    parse_feed_bytes,
    render_producer_output_bytes,
)
from extension.arms.vulnify.policy import MAX_OUTPUT_CHARS
from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.encode import mode_a_supported
from extension.invoke_profiles import INVOKE_PROFILES
from extension.mcp_server import TOOLS
from extension.observation_profiles import (
    OBSERVATION_PROFILES,
    ObservationProfile,
    observation_profile,
)
from extension.observations import (
    REASON_ADMISSION_ID_MISMATCH,
    REASON_ADMISSION_WINDOW,
    REASON_ARTIFACT_MISMATCH,
    REASON_ATTEMPT_MISMATCH,
    REASON_BINDING_MISMATCH,
    REASON_CUSTODY_MISMATCH,
    REASON_EVIDENCE_MISMATCH,
    REASON_EXECUTION_NOT_COMPLETE,
    REASON_INVALID_ADMISSION,
    REASON_INVALID_EXECUTION,
    REASON_INVALID_POLICY_REPORT,
    REASON_OBSERVATION_ID_MISMATCH,
    REASON_OBSERVATION_MISMATCH,
    REASON_RAW_ARTIFACT_MISMATCH,
    REASON_REPLAY,
    REASON_SOURCE_MISMATCH,
    REASON_SUBJECT_MISMATCH,
    REASON_UNKNOWN_SCHEMA,
    SOURCE_ADMISSION_SCHEMA_ID,
    TRUSTED_OBSERVATION_SCHEMA_ID,
    ObservationError,
    derive_trusted_observation,
    issue_source_admission,
    verify_source_admission,
    verify_trusted_observation,
)
from governance.check import PR97_ACTION_ARGUMENTS, PR97_ARM_IDS

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "extension" / "schema"
ADMISSION_SCHEMA = SCHEMA_DIR / "source-admission.v1.schema.json"
OBSERVATION_SCHEMA = SCHEMA_DIR / "trusted-observation.v1.schema.json"

ATTEMPT_ID = "attempt-" + ("ab" * 32)
OTHER_ATTEMPT_ID = "attempt-" + ("cd" * 32)
SOURCE_TIME = "2026-09-08T09:00:00Z"
ISSUED_AT = "2026-09-08T10:00:00Z"
STARTED_AT = "2026-09-08T11:00:00Z"
FINISHED_AT = "2026-09-08T11:00:01Z"
VERIFIED_AT = "2026-09-08T12:00:00Z"
VALID_UNTIL = "2026-09-08T13:00:00Z"
CVE_ID = "CVE-2026-1234"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(blob: bytes) -> str:
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _artifact_canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _raw_feed(*, second_cve: str = "CVE-2026-9999") -> bytes:
    return _canonical(
        [
            {
                "cve_id": CVE_ID,
                "name": "Synthetic declared issue",
                "severity": "high",
                "description": "Fixture record; applicability is not assessed",
                "published": SOURCE_TIME,
            },
            {
                "cve_id": second_cve,
                "name": "Synthetic near miss",
                "severity": "critical",
            },
        ]
    )


def _raw_feed_with_unicode() -> bytes:
    return _canonical(
        [
            {
                "cve_id": CVE_ID,
                "name": "Synthetic café issue",
                "description": "Déclaré source record",
            }
        ]
    )


def _admission(
    raw: bytes,
    *,
    attempt_id: str = ATTEMPT_ID,
    cve_id: str = CVE_ID,
    source_timestamp: str | None = SOURCE_TIME,
    source_format: str = "json",
    issued_at: str = ISSUED_AT,
    valid_from: str = ISSUED_AT,
    valid_until: str = VALID_UNTIL,
) -> dict[str, Any]:
    return issue_source_admission(
        attempt_id=attempt_id,
        raw_artifact=raw,
        source_format=source_format,
        source_id="local-vulnerability-slice",
        source_revision="snapshot-2026-09-08",
        source_timestamp=source_timestamp,
        logical_locator="source://local-vulnerability-slice/snapshot-2026-09-08",
        raw_artifact_locator="custody://ctf-evidence-custodian/raw/vulnerability-slice",
        authority_ref="operator://source-admission/evid-01-fixture",
        cve_id=cve_id,
        issuer_id="ctf-evidence-custodian",
        issuer_version="0.1.0",
        producer_revision="git:6f73840f1f49ae38",
        issued_at=issued_at,
        valid_from=valid_from,
        valid_until=valid_until,
        limitations=("synthetic-source", "data-rights-not-evaluated"),
    )


def _mode_a_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
    *,
    attempt_id: str = ATTEMPT_ID,
    cve_id: str = CVE_ID,
    feed_format: str = "json",
) -> tuple[dict[str, Any], bytes]:
    if not mode_a_supported():
        pytest.skip("Mode A is Unix-only")
    feed = tmp_path / f"feed.{feed_format}"
    feed.write_bytes(raw)
    artifacts = tmp_path / "mode-a"
    artifacts.mkdir()
    times = iter((STARTED_AT, FINISHED_AT))
    monkeypatch.setattr("extension.dispatch.utc_now", lambda: next(times))
    outcome = dispatch_invoke(
        Extension(),
        arm_id="vulnify",
        action="lookup",
        args={"feed": str(feed), "cve_id": cve_id},
        attempt_id=attempt_id,
        artifact_dir=str(artifacts),
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert len(outcome.envelope["artifacts"]) == 1
    digest = outcome.envelope["artifacts"][0]["digest"]
    policy_report = (
        artifacts / ("sha256-" + digest.removeprefix("sha256:"))
    ).read_bytes()
    return dict(outcome.envelope), policy_report


def _complete_slice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[bytes, dict[str, Any], dict[str, Any], bytes, dict[str, Any]]:
    raw = _raw_feed()
    admission = _admission(raw)
    result, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    observation = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    return raw, admission, result, report, observation


def _replace_policy_report(
    result: dict[str, Any], payload: dict[str, Any]
) -> tuple[dict[str, Any], bytes]:
    report = _artifact_canonical(payload)
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


def _schema(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_contract_schemas_are_closed_draft7() -> None:
    admission = _schema(ADMISSION_SCHEMA)
    observation = _schema(OBSERVATION_SCHEMA)
    for schema, schema_id in (
        (admission, SOURCE_ADMISSION_SCHEMA_ID),
        (observation, TRUSTED_OBSERVATION_SCHEMA_ID),
    ):
        jsonschema.Draft7Validator.check_schema(schema)
        assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert schema["additionalProperties"] is False
        assert schema["properties"]["schema"]["const"] == schema_id
        assert schema["properties"]["schema_version"]["const"] == 1


def test_contract_schemas_reject_terminal_newlines_and_invalid_calendar_dates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admission = _admission(_raw_feed())
    admission_validator = jsonschema.Draft7Validator(
        _schema(ADMISSION_SCHEMA), format_checker=jsonschema.FormatChecker()
    )
    for path in (
        ("admission_id",),
        ("attempt_id",),
        ("issuer", "id"),
        ("issued_at",),
        ("source", "logical_locator"),
        ("source", "raw_artifact", "digest"),
        ("subject", "cve_id"),
        ("scope", "identifier"),
        ("limitations", 0),
    ):
        malformed = copy.deepcopy(admission)
        target: Any = malformed
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] += "\n"
        with pytest.raises(jsonschema.ValidationError):
            admission_validator.validate(malformed)
    invalid_date = copy.deepcopy(admission)
    invalid_date["issued_at"] = "2026-09-31T10:00:00Z"
    with pytest.raises(jsonschema.ValidationError):
        admission_validator.validate(invalid_date)

    _, _, _, _, observation = _complete_slice(tmp_path, monkeypatch)
    observation_validator = jsonschema.Draft7Validator(
        _schema(OBSERVATION_SCHEMA), format_checker=jsonschema.FormatChecker()
    )
    for path in (("observation_id",), ("custody", "policy_report_locator")):
        malformed = copy.deepcopy(observation)
        target = malformed
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] += "\n"
        with pytest.raises(jsonschema.ValidationError):
            observation_validator.validate(malformed)
    invalid_date = copy.deepcopy(observation)
    invalid_date["verified_at"] = "2026-09-31T12:00:00Z"
    with pytest.raises(jsonschema.ValidationError):
        observation_validator.validate(invalid_date)


def test_observation_registry_is_frozen_and_does_not_admit_actions() -> None:
    assert isinstance(OBSERVATION_PROFILES, MappingProxyType)
    assert tuple(OBSERVATION_PROFILES) == (
        "vulnify.lookup",
        "security-detections-mcp.get_rule",
        "rubeus.telemetry",
    )
    for capability_id, profile in OBSERVATION_PROFILES.items():
        assert observation_profile(capability_id) is profile
        invoke = INVOKE_PROFILES[capability_id]
        assert (profile.capability_id, profile.arm_id, profile.action) == (
            invoke.capability_id,
            invoke.arm_id,
            invoke.action,
        )
        assert (profile.tool_name, profile.tool_version) == (
            invoke.tool_name,
            invoke.tool_version,
        )
    profile = OBSERVATION_PROFILES["vulnify.lookup"]
    with pytest.raises(TypeError):
        OBSERVATION_PROFILES["other.lookup"] = profile  # type: ignore[index]
    legacy_constructed = ObservationProfile(
        "example.lookup",
        "example",
        "lookup",
        "specaudit-ctf",
        "0.1.0",
        "example.schema.v1",
        1,
        "example-record",
        "example-record",
        "policy-report",
        "credentials-stripped",
        "declared",
    )
    assert legacy_constructed.contract_version == 1
    assert legacy_constructed.source_formats == ()


def test_sidecar_preserves_public_dispatch_and_pr97_rosters() -> None:
    assert TOOLS == ("list", "describe", "invoke", "run_range")
    assert len(INVOKE_PROFILES) == 212
    assert len(PR97_ARM_IDS) == 14
    assert sum(
        len(actions) - ("list_tools" in actions)
        for actions in PR97_ACTION_ARGUMENTS.values()
    ) == 38
    assert sum("list_tools" in actions for actions in PR97_ACTION_ARGUMENTS.values()) == 14
    assert "issue_source_admission" not in extension.__all__
    assert not hasattr(extension, "issue_source_admission")
    assert all("observation" not in capability for capability in INVOKE_PROFILES)


def test_fresh_default_import_does_not_load_observation_sidecar() -> None:
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, sys, extension; "
                "print(json.dumps({"
                "'observations': 'extension.observations' in sys.modules, "
                "'profiles': 'extension.observation_profiles' in sys.modules, "
                "'issuer': hasattr(extension, 'issue_source_admission')}))"
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


@pytest.mark.parametrize("format", ("json", "jsonl", "yaml"))
def test_shared_feed_byte_parser_replays_arm_normalization(format: str) -> None:
    rows = [{"cve_id": CVE_ID, "name": "Synthetic"}]
    if format == "json":
        raw = _canonical(rows)
    elif format == "jsonl":
        raw = _canonical(rows[0]) + b"\n"
    else:
        raw = f"- cve_id: {CVE_ID}\n  name: Synthetic\n".encode()
    records, source, provenance = parse_feed_bytes(raw, format=format)
    assert records == rows
    assert source == {"kind": "operator-file", "sha256": _digest(raw), "bytes": len(raw)}
    assert provenance["snapshot_digest"] == source["sha256"]


def test_shared_feed_byte_parser_refuses_unknown_format() -> None:
    with pytest.raises(FeedError, match="format is not supported"):
        parse_feed_bytes(_raw_feed(), format="toml")


@pytest.mark.parametrize("format", ("json", "jsonl", "yaml"))
def test_observation_derives_for_each_declared_feed_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, format: str
) -> None:
    row = {"cve_id": CVE_ID, "name": "Synthetic"}
    if format == "json":
        raw = _canonical([row])
    elif format == "jsonl":
        raw = _canonical(row) + b"\n"
    else:
        raw = f"- cve_id: {CVE_ID}\n  name: Synthetic\n".encode()
    admission = _admission(raw, source_format=format)
    result, report = _mode_a_bundle(
        tmp_path, monkeypatch, raw, feed_format=format
    )
    observation = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    jsonschema.validate(observation, _schema(OBSERVATION_SCHEMA))
    checked = verify_trusted_observation(
        observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert checked.accepted is True


def test_source_admission_is_deterministic_schema_valid_and_byte_bound() -> None:
    raw = _raw_feed()
    first = _admission(raw)
    second = _admission(raw)
    assert first == second
    assert hashlib.sha256(_canonical(first)).hexdigest() == (
        "353eba462b577133988247836413fef1242588cb1a59df25f438fea0fbe6e2d9"
    )
    jsonschema.validate(first, _schema(ADMISSION_SCHEMA))
    assert first["source"]["raw_artifact"]["digest"] == _digest(raw)
    assert first["source"]["raw_artifact"]["bytes"] == len(raw)
    assert first["scope"] == {
        "kind": "vulnerability-record",
        "identifier": f"cve:{CVE_ID}",
    }
    checked = verify_source_admission(first, raw_artifact=raw, at_time=ISSUED_AT)
    assert checked.accepted is True and checked.reasons == ()


def test_source_admission_has_no_implicit_authority_or_clock_defaults() -> None:
    signature = inspect.signature(issue_source_admission)
    for name in (
        "source_id",
        "source_revision",
        "logical_locator",
        "raw_artifact_locator",
        "authority_ref",
        "issuer_id",
        "issuer_version",
        "producer_revision",
        "issued_at",
        "valid_from",
        "valid_until",
    ):
        assert signature.parameters[name].default is inspect.Parameter.empty
    verify_signature = inspect.signature(verify_trusted_observation)
    assert (
        verify_signature.parameters["seen_observation_ids"].default
        is inspect.Parameter.empty
    )


def test_unknown_source_time_stays_explicit() -> None:
    admission = _admission(_raw_feed(), source_timestamp=None)
    assert admission["source"]["timestamp"] == {"status": "unknown", "value": None}
    assert admission["source"]["freshness"] == "not-assessed"
    jsonschema.validate(admission, _schema(ADMISSION_SCHEMA))


def test_source_admission_rejects_absent_subject_and_invalid_time() -> None:
    raw = _raw_feed()
    with pytest.raises(ObservationError) as absent:
        _admission(raw, cve_id="CVE-2026-7777")
    assert REASON_SUBJECT_MISMATCH in absent.value.reasons
    with pytest.raises(ObservationError) as invalid:
        issue_source_admission(
            **{
                **{
                    key: value
                    for key, value in _issue_kwargs(raw).items()
                    if key != "source_timestamp"
                },
                "source_timestamp": "2026-09-31T00:00:00Z",
            }
        )
    assert REASON_ADMISSION_WINDOW in invalid.value.reasons

    too_long = _issue_kwargs(raw)
    too_long["valid_until"] = "2026-09-10T10:00:00Z"
    with pytest.raises(ObservationError) as long_window:
        issue_source_admission(**too_long)
    assert REASON_ADMISSION_WINDOW in long_window.value.reasons


def test_source_admission_rejects_newline_terminated_identifiers() -> None:
    kwargs = _issue_kwargs(_raw_feed())
    kwargs["attempt_id"] = ATTEMPT_ID + "\n"
    with pytest.raises(ObservationError) as excinfo:
        issue_source_admission(**kwargs)
    assert REASON_INVALID_ADMISSION in excinfo.value.reasons

    oversized = _issue_kwargs(_raw_feed())
    oversized["cve_id"] = "CVE-2026-" + ("1" * 24)
    with pytest.raises(ObservationError) as excinfo:
        issue_source_admission(**oversized)
    assert REASON_INVALID_ADMISSION in excinfo.value.reasons


def _issue_kwargs(raw: bytes) -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "raw_artifact": raw,
        "source_format": "json",
        "source_id": "local-vulnerability-slice",
        "source_revision": "snapshot-2026-09-08",
        "source_timestamp": SOURCE_TIME,
        "logical_locator": "source://local-vulnerability-slice/snapshot-2026-09-08",
        "raw_artifact_locator": "custody://ctf-evidence-custodian/raw/vulnerability-slice",
        "authority_ref": "operator://source-admission/evid-01-fixture",
        "cve_id": CVE_ID,
        "issuer_id": "ctf-evidence-custodian",
        "issuer_version": "0.1.0",
        "producer_revision": "git:6f73840f1f49ae38",
        "issued_at": ISSUED_AT,
        "valid_from": ISSUED_AT,
        "valid_until": VALID_UNTIL,
        "limitations": ("synthetic-source",),
    }


def test_admission_tamper_and_wrong_raw_bytes_fail_closed() -> None:
    raw = _raw_feed()
    admission = _admission(raw)
    tampered = copy.deepcopy(admission)
    tampered["source"]["raw_artifact"]["digest"] = "sha256:" + ("0" * 64)
    checked = verify_source_admission(tampered, raw_artifact=raw, at_time=ISSUED_AT)
    assert checked.accepted is False
    assert REASON_ADMISSION_ID_MISMATCH in checked.reasons
    assert REASON_RAW_ARTIFACT_MISMATCH in checked.reasons

    hostile_format = copy.deepcopy(admission)
    hostile_format["source"]["schema"]["format"] = []
    checked = verify_source_admission(
        hostile_format, raw_artifact=raw, at_time=ISSUED_AT
    )
    assert checked.accepted is False
    assert REASON_INVALID_ADMISSION in checked.reasons

    hostile_time = copy.deepcopy(admission)
    hostile_time["issued_at"] = None
    checked = verify_source_admission(
        hostile_time, raw_artifact=raw, at_time=ISSUED_AT
    )
    assert checked.accepted is False
    assert REASON_ADMISSION_WINDOW in checked.reasons
    other_raw = _raw_feed(second_cve="CVE-2026-8888")
    checked = verify_source_admission(
        admission, raw_artifact=other_raw, at_time=ISSUED_AT
    )
    assert checked.accepted is False
    assert REASON_RAW_ARTIFACT_MISMATCH in checked.reasons


def test_bytes_subclasses_cannot_split_parsed_content_from_hashed_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _raw_feed()

    class ForgedBytes(bytes):
        def decode(self, *args: Any, **kwargs: Any) -> str:
            return raw.decode(*args, **kwargs)

    class WrappedBytes(bytes):
        pass

    class WrappedText(str):
        pass

    forged_raw = ForgedBytes(b"not-json-and-no-cve")
    with pytest.raises(FeedError, match="immutable bytes"):
        parse_feed_bytes(forged_raw, format="json")
    with pytest.raises(FeedError, match="format is not supported"):
        parse_feed_bytes(raw, format=WrappedText("json"))
    with pytest.raises(ObservationError) as issue_error:
        issue_source_admission(**_issue_kwargs(forged_raw))
    assert REASON_RAW_ARTIFACT_MISMATCH in issue_error.value.reasons

    admission = _admission(raw)
    checked = verify_source_admission(
        admission, raw_artifact=ForgedBytes(raw), at_time=VERIFIED_AT
    )
    assert checked.accepted is False
    assert REASON_RAW_ARTIFACT_MISMATCH in checked.reasons

    result, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    with pytest.raises(ObservationError) as report_error:
        derive_trusted_observation(
            admission=admission,
            execution_result=result,
            policy_report=WrappedBytes(report),
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_ARTIFACT_MISMATCH in report_error.value.reasons


def test_admission_use_outside_window_fails_closed() -> None:
    raw = _raw_feed()
    checked = verify_source_admission(
        _admission(raw), raw_artifact=raw, at_time="2026-09-08T14:00:00Z"
    )
    assert checked.accepted is False
    assert REASON_ADMISSION_WINDOW in checked.reasons


def test_string_subclass_cannot_lie_about_admission_window() -> None:
    raw = _raw_feed()
    admission = _admission(raw)

    class LyingTime(str):
        def __le__(self, other: Any) -> bool:
            return True

        def __ge__(self, other: Any) -> bool:
            return True

    outside = LyingTime("2026-09-09T14:00:00Z")
    checked = verify_source_admission(
        admission, raw_artifact=raw, at_time=outside
    )
    assert checked.accepted is False
    assert REASON_ADMISSION_WINDOW in checked.reasons


def test_malformed_admission_never_reaches_bundle_field_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _raw_feed()
    _, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    malformed = {"schema": SOURCE_ADMISSION_SCHEMA_ID}
    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=malformed,
            execution_result={},
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert excinfo.value.reasons


def test_unknown_schema_keeps_v1_reason_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )
    malformed_admission = copy.deepcopy(admission)
    malformed_admission["schema"] = "specaudit.ctf.source-admission.unknown"
    checked_admission = verify_source_admission(
        malformed_admission, raw_artifact=raw, at_time=VERIFIED_AT
    )
    assert checked_admission.accepted is False
    assert checked_admission.reasons == (REASON_UNKNOWN_SCHEMA,)

    malformed_observation = copy.deepcopy(observation)
    malformed_observation["schema"] = (
        "specaudit.ctf.trusted-observation.unknown"
    )
    checked_observation = verify_trusted_observation(
        malformed_observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert checked_observation.accepted is False
    assert checked_observation.reasons == (
        REASON_UNKNOWN_SCHEMA,
        REASON_OBSERVATION_ID_MISMATCH,
        REASON_OBSERVATION_MISMATCH,
    )


@pytest.mark.parametrize(
    "capability_id", (None, "", "unknown.lookup", False, 7)
)
def test_malformed_v1_observation_capability_keeps_reason_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capability_id: Any,
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )
    malformed = copy.deepcopy(observation)
    malformed["capability_id"] = capability_id
    checked = verify_trusted_observation(
        malformed,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert checked.accepted is False
    assert checked.reasons == (
        REASON_OBSERVATION_ID_MISMATCH,
        REASON_OBSERVATION_MISMATCH,
    )


def test_v2_headroom_does_not_change_oversized_v1_reason_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )
    deeply_nested: Any = "leaf"
    for _ in range(66):
        deeply_nested = [deeply_nested]
    for hostile_evidence in (
        [None] * 50_020,
        deeply_nested,
        "x" * 20_000,
    ):
        malformed = copy.deepcopy(observation)
        malformed["evidence"] = hostile_evidence
        checked = verify_trusted_observation(
            malformed,
            admission=admission,
            execution_result=result,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
            seen_observation_ids=(),
        )
        assert checked.accepted is False
        assert checked.reasons == (REASON_OBSERVATION_MISMATCH,)


def test_mapping_iteration_failure_is_a_fail_closed_verification_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )

    class ExplodingItems(dict[str, Any]):
        def items(self) -> Any:
            raise RuntimeError("synthetic mapping failure")

    admission_check = verify_source_admission(
        ExplodingItems(admission), raw_artifact=raw, at_time=VERIFIED_AT
    )
    assert admission_check.accepted is False
    assert admission_check.reasons == (REASON_INVALID_ADMISSION,)

    observation_check = verify_trusted_observation(
        ExplodingItems(observation),
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert observation_check.accepted is False
    assert observation_check.reasons == (REASON_OBSERVATION_MISMATCH,)


def test_real_mode_a_slice_derives_schema_valid_attributable_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )
    jsonschema.validate(observation, _schema(OBSERVATION_SCHEMA))
    assert observation["attempt_id"] == ATTEMPT_ID
    assert observation["producer"] == admission["producer"]
    assert observation["verifier"] == admission["issuer"]
    assert observation["collected_at"] == FINISHED_AT
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
    assert observation["custody"]["result_assertion"] == "validator-attested-mode-a"
    assert "custody-verified" not in json.dumps(observation)
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


def test_observation_derivation_is_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, first = _complete_slice(tmp_path, monkeypatch)
    second = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    assert first == second
    assert hashlib.sha256(_canonical(first)).hexdigest() == (
        "5fc442203b3cbd09052862d5657c595b6a964e0d5ad97ed2d8ffe5f4cd0a5a82"
    )


def test_policy_report_canonicalization_matches_encoder_for_unicode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _raw_feed_with_unicode()
    admission = _admission(raw)
    result, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    assert b"\\u00e9" in report
    observation = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    assert observation["evidence"]["record"]["name"] == "Synthetic café issue"


def test_large_unicode_policy_report_stays_within_observation_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "é" * 12_000
    raw = _canonical(
        [{"cve_id": CVE_ID, "name": text, "description": text, "source": text}]
    )
    admission = _admission(raw)
    result, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    assert 200_000 < len(report) <= 1_048_576
    observation = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    jsonschema.validate(observation, _schema(OBSERVATION_SCHEMA))


def test_near_limit_valid_policy_report_has_observation_metadata_headroom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text_chars = 174_369
    aliases = ["\x7f" * 16_384 for _ in range(text_chars // 16_384)]
    aliases.append("\x7f" * (text_chars % 16_384))
    raw = _canonical([{"cve_id": CVE_ID, "aliases": aliases}])
    admission = _admission(raw)
    result, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    assert len(render_producer_output_bytes(json.loads(report))) < MAX_OUTPUT_CHARS
    assert 1_000_000 < len(report) <= 1_048_576

    observation = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    encoded_observation = _artifact_canonical(observation)
    assert 1_048_576 < len(encoded_observation) <= 2_097_152
    jsonschema.validate(observation, _schema(OBSERVATION_SCHEMA))


def test_report_that_vulnify_producer_would_refuse_cannot_be_forged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _canonical(
        [{"cve_id": CVE_ID, "aliases": ["x" * 16_384 for _ in range(20)]}]
    )
    feed = tmp_path / "producer-refusal.json"
    feed.write_bytes(raw)
    produced = Extension().invoke(
        "vulnify", "lookup", {"feed": str(feed), "cve_id": CVE_ID}
    )
    assert produced.ok is False
    assert produced.error is not None and "output cap" in produced.error

    records, source, provenance = parse_feed_bytes(raw, format="json")
    payload = {
        "vulnerability": records[0],
        "source": source,
        "provenance": provenance,
    }
    assert len(render_producer_output_bytes(payload)) > MAX_OUTPUT_CHARS
    admission = _admission(raw)
    result, _ = _mode_a_bundle(tmp_path, monkeypatch, _raw_feed())
    forged_result, forged_report = _replace_policy_report(result, payload)
    assert len(forged_report) <= 1_048_576

    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_INVALID_POLICY_REPORT in excinfo.value.reasons


def test_cross_attempt_result_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _raw_feed()
    admission = _admission(raw)
    result, report = _mode_a_bundle(
        tmp_path, monkeypatch, raw, attempt_id=OTHER_ATTEMPT_ID
    )
    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=result,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_ATTEMPT_MISMATCH in excinfo.value.reasons


def test_result_without_attempt_or_complete_semantics_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, _ = _complete_slice(tmp_path, monkeypatch)
    no_attempt = copy.deepcopy(result)
    no_attempt.pop("attempt_id")
    with pytest.raises(ObservationError) as absent:
        derive_trusted_observation(
            admission=admission,
            execution_result=no_attempt,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_ATTEMPT_MISMATCH in absent.value.reasons

    failed = copy.deepcopy(result)
    failed["status"] = "failed"
    with pytest.raises(ObservationError) as noncomplete:
        derive_trusted_observation(
            admission=admission,
            execution_result=failed,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_EXECUTION_NOT_COMPLETE in noncomplete.value.reasons


def test_coherently_rewritten_zero_step_transport_failure_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, _ = _complete_slice(tmp_path, monkeypatch)
    forged = copy.deepcopy(result)
    forged["transport_ok"] = False
    forged["budget"]["spent"]["tool_steps"] = 0
    forged["scope"]["touched"] = []
    forged["side_effects"] = ["none"]

    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_EXECUTION_NOT_COMPLETE in excinfo.value.reasons


@pytest.mark.parametrize(
    "path",
    (("approval_ref",), ("roe_ref",), ("cleanup", "proof_digest")),
)
def test_schema_required_execution_fields_cannot_be_omitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str, ...],
) -> None:
    raw, admission, result, report, _ = _complete_slice(tmp_path, monkeypatch)
    malformed = copy.deepcopy(result)
    if len(path) == 1:
        malformed.pop(path[0])
    else:
        malformed[path[0]].pop(path[1])

    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=malformed,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_INVALID_EXECUTION in excinfo.value.reasons


@pytest.mark.parametrize(
    ("field", "nested"),
    (
        ("side_effects", None),
        ("scope", "authorized"),
        ("coverage", "complete"),
    ),
)
def test_hostile_execution_json_types_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    nested: str | None,
) -> None:
    raw, admission, result, report, _ = _complete_slice(tmp_path, monkeypatch)
    malformed = copy.deepcopy(result)
    if nested is None:
        malformed[field] = [{}]
    else:
        malformed[field][nested] = [{}]

    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=malformed,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_INVALID_EXECUTION in excinfo.value.reasons


def test_extra_or_wrong_policy_artifact_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, _ = _complete_slice(tmp_path, monkeypatch)
    extra = copy.deepcopy(result)
    extra["artifacts"].append(
        {
            "digest": "sha256:" + ("0" * 64),
            "kind": "other",
            "redaction": "credentials-stripped",
        }
    )
    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=extra,
            policy_report=report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_ARTIFACT_MISMATCH in excinfo.value.reasons

    with pytest.raises(ObservationError) as oversized:
        derive_trusted_observation(
            admission=admission,
            execution_result=result,
            policy_report=b"x" * 1_048_577,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_ARTIFACT_MISMATCH in oversized.value.reasons


def test_tampered_or_noncanonical_policy_report_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, _ = _complete_slice(tmp_path, monkeypatch)
    with pytest.raises(ObservationError) as tampered:
        derive_trusted_observation(
            admission=admission,
            execution_result=result,
            policy_report=report + b" ",
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_ARTIFACT_MISMATCH in tampered.value.reasons
    assert REASON_INVALID_POLICY_REPORT in tampered.value.reasons


def test_coherently_rehashed_unrelated_record_is_still_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, _ = _complete_slice(tmp_path, monkeypatch)
    payload = json.loads(report)
    payload["vulnerability"]["cve_id"] = "CVE-2026-9999"
    forged_result, forged_report = _replace_policy_report(result, payload)
    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_SUBJECT_MISMATCH in excinfo.value.reasons


def test_coherently_rehashed_false_source_provenance_is_still_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, _ = _complete_slice(tmp_path, monkeypatch)
    payload = json.loads(report)
    payload["source"]["sha256"] = "sha256:" + ("0" * 64)
    forged_result, forged_report = _replace_policy_report(result, payload)
    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_SOURCE_MISMATCH in excinfo.value.reasons


def test_json_type_change_cannot_match_source_record_by_python_equality(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _canonical([{"cve_id": CVE_ID, "cvss": 0}])
    admission = _admission(raw)
    result, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    payload = json.loads(report)
    payload["vulnerability"]["cvss"] = False
    forged_result, forged_report = _replace_policy_report(result, payload)

    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=forged_result,
            policy_report=forged_report,
            raw_artifact=raw,
            verified_at=VERIFIED_AT,
        )
    assert REASON_SUBJECT_MISMATCH in excinfo.value.reasons


def test_result_outside_admission_window_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, _ = _complete_slice(tmp_path, monkeypatch)
    late = copy.deepcopy(result)
    late["started_at"] = "2026-09-08T14:00:00Z"
    late["finished_at"] = "2026-09-08T14:00:01Z"
    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=late,
            policy_report=report,
            raw_artifact=raw,
            verified_at="2026-09-08T14:00:02Z",
        )
    assert REASON_ADMISSION_WINDOW in excinfo.value.reasons


def test_calendar_invalid_result_timestamp_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _raw_feed()
    admission = _admission(
        raw,
        source_timestamp=None,
        issued_at="2026-02-28T00:00:00Z",
        valid_from="2026-02-28T00:00:00Z",
        valid_until="2026-03-01T00:00:00Z",
    )
    result, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    invalid = copy.deepcopy(result)
    invalid["started_at"] = "2026-02-29T11:00:00Z"
    invalid["finished_at"] = "2026-02-29T11:00:01Z"

    with pytest.raises(ObservationError) as excinfo:
        derive_trusted_observation(
            admission=admission,
            execution_result=invalid,
            policy_report=report,
            raw_artifact=raw,
            verified_at="2026-03-01T00:00:00Z",
        )
    assert REASON_INVALID_EXECUTION in excinfo.value.reasons


def test_replay_requires_external_seen_set_and_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )
    checked = verify_trusted_observation(
        observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids={observation["observation_id"]},
    )
    assert checked.accepted is False
    assert REASON_REPLAY in checked.reasons

    numeric_variant = copy.deepcopy(result)
    original_spend = numeric_variant["budget"]["spent"]["spend"]
    numeric_variant["budget"]["spent"]["spend"] = (
        0.0 if type(original_spend) is int else 0
    )
    assert type(numeric_variant["budget"]["spent"]["spend"]) is not type(
        original_spend
    )
    variant = derive_trusted_observation(
        admission=admission,
        execution_result=numeric_variant,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    assert variant["observation_id"] == observation["observation_id"]
    checked = verify_trusted_observation(
        variant,
        admission=admission,
        execution_result=numeric_variant,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids={observation["observation_id"]},
    )
    assert checked.accepted is False
    assert REASON_REPLAY in checked.reasons

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

    corrupt_seen = verify_trusted_observation(
        observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids={"corrupt-ledger-entry"},
    )
    assert corrupt_seen.accepted is False
    assert REASON_REPLAY in corrupt_seen.reasons

    later_verified_at = "2026-09-08T12:00:01Z"
    reverified = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=later_verified_at,
    )
    assert reverified["observation_id"] == observation["observation_id"]
    checked = verify_trusted_observation(
        reverified,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=later_verified_at,
        seen_observation_ids={observation["observation_id"]},
    )
    assert checked.accepted is False
    assert REASON_REPLAY in checked.reasons


def test_string_subclass_cannot_hide_seen_observation_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )

    class LyingId(str):
        def __hash__(self) -> int:
            return 0

        def __eq__(self, other: Any) -> bool:
            return False

    checked = verify_trusted_observation(
        observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(LyingId(observation["observation_id"]),),
    )
    assert checked.accepted is False
    assert REASON_REPLAY in checked.reasons


@pytest.mark.parametrize(
    "path,value,expected_reason",
    (
        (("custody", "result_assertion"), "validator-held-mode-a", REASON_CUSTODY_MISMATCH),
        (("bindings", "execution_result_digest"), "sha256:" + ("0" * 64), REASON_BINDING_MISMATCH),
        (("evidence", "class"), "observed", REASON_EVIDENCE_MISMATCH),
        (("source", "revision"), "different-snapshot", REASON_SOURCE_MISMATCH),
        (("subject", "cve_id"), "CVE-2026-9999", REASON_SUBJECT_MISMATCH),
    ),
)
def test_observation_field_tampering_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str, str],
    value: str,
    expected_reason: str,
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )
    tampered = copy.deepcopy(observation)
    tampered[path[0]][path[1]] = value
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
    assert expected_reason in checked.reasons
    assert REASON_OBSERVATION_MISMATCH in checked.reasons


@pytest.mark.parametrize(
    "path,value,expected_reason",
    (
        (("evidence", "record", "cvss"), False, REASON_EVIDENCE_MISMATCH),
        (("evidence", "applicability", "assessed"), 0, REASON_EVIDENCE_MISMATCH),
        (("source", "schema", "version"), True, REASON_SOURCE_MISMATCH),
    ),
)
def test_python_equal_json_type_tampering_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str, ...],
    value: bool | int,
    expected_reason: str,
) -> None:
    raw = _canonical([{"cve_id": CVE_ID, "cvss": 0}])
    admission = _admission(raw)
    result, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    observation = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    tampered = copy.deepcopy(observation)
    target: Any = tampered
    for part in path[:-1]:
        target = target[part]
    original = target[path[-1]]
    assert original == value
    assert type(original) is not type(value)
    target[path[-1]] = value

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
    assert expected_reason in checked.reasons
    assert REASON_OBSERVATION_MISMATCH in checked.reasons


def test_surrogate_pair_cannot_alias_valid_unicode_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _canonical([{"cve_id": CVE_ID, "name": "😀"}])
    admission = _admission(raw)
    result, report = _mode_a_bundle(tmp_path, monkeypatch, raw)
    observation = derive_trusted_observation(
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
    )
    tampered = copy.deepcopy(observation)
    tampered["evidence"]["record"]["name"] = "\ud83d\ude00"
    assert tampered["evidence"]["record"]["name"] != "😀"

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
    assert REASON_OBSERVATION_MISMATCH in checked.reasons


def test_document_size_cap_precedes_full_canonical_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = {"rows": ["x" * 16_384] * 200}

    def forbidden_serializer(value: Any) -> bytes:
        raise AssertionError("oversized document reached full serialization")

    monkeypatch.setattr(
        observation_module, "_canonical_bytes", forbidden_serializer
    )
    with pytest.raises(ValueError, match="size cap"):
        observation_module._document_copy(oversized)
    checked = verify_source_admission(
        oversized, raw_artifact=b"[]", at_time=ISSUED_AT
    )
    assert checked.accepted is False
    assert REASON_INVALID_ADMISSION in checked.reasons


def test_observation_unknown_field_and_nonfinite_data_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )
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
    nonfinite = copy.deepcopy(observation)
    nonfinite["evidence"]["record"]["cvss"] = float("nan")
    checked = verify_trusted_observation(
        nonfinite,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert checked.accepted is False
    assert REASON_OBSERVATION_MISMATCH in checked.reasons


def test_observation_id_tamper_fails_even_when_body_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )
    tampered = copy.deepcopy(observation)
    tampered["observation_id"] = "trusted-observation-" + ("0" * 64)
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
    assert REASON_OBSERVATION_ID_MISMATCH in checked.reasons


def test_verifier_is_pure_after_inputs_are_acquired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, admission, result, report, observation = _complete_slice(
        tmp_path, monkeypatch
    )

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("trusted-observation verifier attempted I/O or dispatch")

    monkeypatch.setattr("pathlib.Path.open", forbidden)
    monkeypatch.setattr("extension.contract.Extension.invoke", forbidden)
    checked = verify_trusted_observation(
        observation,
        admission=admission,
        execution_result=result,
        policy_report=report,
        raw_artifact=raw,
        verified_at=VERIFIED_AT,
        seen_observation_ids=(),
    )
    assert checked.accepted is True


def test_observation_schema_rejects_extra_field_and_false_custody_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, _, _, observation = _complete_slice(tmp_path, monkeypatch)
    schema = _schema(OBSERVATION_SCHEMA)
    extra = copy.deepcopy(observation)
    extra["grading_authority"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(extra, schema)
    custody = copy.deepcopy(observation)
    custody["custody"]["result_assertion"] = "custody-verified"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(custody, schema)
