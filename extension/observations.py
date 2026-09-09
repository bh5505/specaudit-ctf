"""Pure, opt-in trusted-observation derivation for exact local-read slices.

The default extension does not import this module.  A trusted caller supplies
an admission minted before dispatch, the parsed execution-result object, the
exact policy-report bytes it attests were acquired through Mode A, and the
exact raw source bytes it already holds.  This module performs no I/O, reads no
clock, dispatches nothing, and grants no grading, governance, or source rights.

``validator-attested-mode-a`` is intentionally an assertion in the returned
record.  Execution-result v1 permits an attempt id without ``--artifact-dir``,
so these pure functions cannot prove how the caller obtained the bytes.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from .arms.rubeus.arm import (
    parse_telemetry_bytes,
    render_producer_output_bytes as render_rubeus_output_bytes,
)
from .arms.rubeus.policy import MAX_OUTPUT_CHARS as RUBEUS_MAX_OUTPUT_CHARS
from .arms.security_detections_mcp.arm import (
    parse_index_bytes,
    render_producer_output_bytes as render_security_rule_output_bytes,
)
from .arms.security_detections_mcp.policy import (
    MAX_OUTPUT_CHARS as SECURITY_RULE_MAX_OUTPUT_CHARS,
)
from .arms.strict_data import StrictDataError, strict_json_loads
from .arms.vulnify.arm import (
    FeedError,
    parse_feed_bytes,
    render_producer_output_bytes as render_vulnify_output_bytes,
)
from .arms.vulnify.policy import MAX_OUTPUT_CHARS as VULNIFY_MAX_OUTPUT_CHARS
from .envelopes import STATUS_COMPLETE, parse_execution_result
from .invoke_profiles import INVOKE_PROFILES
from .observation_profiles import (
    OBSERVATION_PROFILES,
    ObservationProfile,
    observation_profile,
)

SOURCE_ADMISSION_SCHEMA_ID = "specaudit.ctf.source-admission.v1"
TRUSTED_OBSERVATION_SCHEMA_ID = "specaudit.ctf.trusted-observation.v1"
SCHEMA_VERSION = 1
SOURCE_ADMISSION_V2_SCHEMA_ID = "specaudit.ctf.source-admission.v2"
TRUSTED_OBSERVATION_V2_SCHEMA_ID = "specaudit.ctf.trusted-observation.v2"
SCHEMA_VERSION_V2 = 2

REASON_INVALID_ADMISSION = "invalid-source-admission"
REASON_UNKNOWN_SCHEMA = "unknown-observation-schema"
REASON_PROFILE_MISMATCH = "observation-profile-mismatch"
REASON_ADMISSION_ID_MISMATCH = "source-admission-id-mismatch"
REASON_ADMISSION_WINDOW = "source-admission-window-mismatch"
REASON_SOURCE_PARSE = "source-artifact-parse-failed"
REASON_RAW_ARTIFACT_MISMATCH = "raw-artifact-mismatch"
REASON_SUBJECT_MISMATCH = "subject-mismatch"
REASON_INVALID_EXECUTION = "invalid-execution-result"
REASON_EXECUTION_NOT_COMPLETE = "execution-result-not-complete"
REASON_ATTEMPT_MISMATCH = "attempt-mismatch"
REASON_ARTIFACT_MISMATCH = "policy-report-artifact-mismatch"
REASON_INVALID_POLICY_REPORT = "invalid-policy-report"
REASON_SOURCE_MISMATCH = "source-provenance-mismatch"
REASON_OBSERVATION_ID_MISMATCH = "trusted-observation-id-mismatch"
REASON_OBSERVATION_MISMATCH = "trusted-observation-mismatch"
REASON_CUSTODY_MISMATCH = "custody-assertion-mismatch"
REASON_BINDING_MISMATCH = "observation-binding-mismatch"
REASON_EVIDENCE_MISMATCH = "observation-evidence-mismatch"
REASON_REPLAY = "trusted-observation-replay"

_ATTEMPT_ID_RE = re.compile(r"^attempt-[0-9a-f]{64}$")
_ADMISSION_ID_RE = re.compile(r"^source-admission-[0-9a-f]{64}$")
_OBSERVATION_ID_RE = re.compile(r"^trusted-observation-[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")
_LIMITATION_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s]+$")
_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)

_MAX_DOCUMENT_BYTES = 2_097_152
_MAX_DOCUMENT_NODES = 50_000
_MAX_DOCUMENT_DEPTH = 64
_MAX_TEXT = 16_384
# The security source tree and each selected Rubeus record are bounded at
# 50,000 nodes and depth 64.  Their v2 singleton reports and observation
# documents add bounded contract wrappers, so reserve explicit headroom rather
# than rejecting an arm-complete artifact at the sidecar boundary.
_V2_MAX_DOCUMENT_NODES = 50_256
_V2_MAX_DOCUMENT_DEPTH = 68
_V2_MAX_TEXT = SECURITY_RULE_MAX_OUTPUT_CHARS
# Security's bounded-tree gate applies the same producer cap to mapping keys;
# keep that parity explicit while retaining an independently tunable limit.
_V2_MAX_KEY_TEXT = SECURITY_RULE_MAX_OUTPUT_CHARS
_MAX_NUMBER_BITS = 65_536
_MAX_CVE_ID = 32
_MAX_POLICY_REPORT_BYTES = 1_048_576
_MAX_ADMISSION_VALIDITY_SECONDS = 24 * 60 * 60

_ADMISSION_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "admission_id",
        "attempt_id",
        "capability_id",
        "arm_id",
        "action",
        "issuer",
        "producer",
        "issued_at",
        "validity",
        "source",
        "subject",
        "scope",
        "custody",
        "evidence_class",
        "limitations",
    }
)
_OBSERVATION_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "observation_id",
        "admission_id",
        "attempt_id",
        "capability_id",
        "arm_id",
        "action",
        "producer",
        "verifier",
        "subject",
        "scope",
        "collected_at",
        "verified_at",
        "source",
        "custody",
        "bindings",
        "evidence",
        "limitations",
    }
)
_EXECUTION_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "capability_id",
        "tool",
        "attempt_id",
        "scope",
        "safety_class",
        "side_effects",
        "approval_ref",
        "roe_ref",
        "budget",
        "started_at",
        "finished_at",
        "status",
        "transport_ok",
        "artifacts",
        "coverage",
        "cleanup",
        "limitations",
    }
)


@dataclass(frozen=True)
class VerificationResult:
    """Fail-closed result returned by admission and observation verifiers."""

    accepted: bool
    reasons: tuple[str, ...]


class ObservationError(ValueError):
    """Raised when a builder cannot produce a verified contract document."""

    def __init__(self, reasons: Sequence[str]) -> None:
        self.reasons = _unique(reasons)
        super().__init__(", ".join(self.reasons))


_ParsedSource = tuple[
    list[dict[str, Any]], dict[str, Any], dict[str, Any]
]


@dataclass(frozen=True)
class _ReplayAdapter:
    adapter_id: str
    parse: Callable[[bytes, str], _ParsedSource]
    render: Callable[[Any], bytes]
    max_output_bytes: int
    report_has_provenance: bool
    project_evidence: Callable[[dict[str, Any]], dict[str, Any]]


def _parse_vulnify_source(raw: bytes, format: str) -> _ParsedSource:
    return parse_feed_bytes(raw, format=format)


def _parse_security_rule_source(raw: bytes, format: str) -> _ParsedSource:
    return parse_index_bytes(raw, format=format)


def _parse_rubeus_source(raw: bytes, format: str) -> _ParsedSource:
    return parse_telemetry_bytes(raw, format=format)


def _complete_evidence_record(record: dict[str, Any]) -> dict[str, Any]:
    return _document_copy(record)


def _security_rule_evidence_record(
    record: dict[str, Any],
) -> dict[str, Any]:
    return {
        "rule_id": record["rule_id"],
        "name": record["name"],
        "definition_digest": _sha256(_canonical_bytes(record)),
    }


_REPLAY_ADAPTERS = MappingProxyType(
    {
        "vulnify.lookup": _ReplayAdapter(
            adapter_id="vulnify-feed-v1",
            parse=_parse_vulnify_source,
            render=render_vulnify_output_bytes,
            max_output_bytes=VULNIFY_MAX_OUTPUT_CHARS,
            report_has_provenance=True,
            project_evidence=_complete_evidence_record,
        ),
        "security-detections-mcp.get_rule": _ReplayAdapter(
            adapter_id="security-detections-index-v1",
            parse=_parse_security_rule_source,
            render=render_security_rule_output_bytes,
            max_output_bytes=SECURITY_RULE_MAX_OUTPUT_CHARS,
            report_has_provenance=False,
            project_evidence=_security_rule_evidence_record,
        ),
        "rubeus.telemetry": _ReplayAdapter(
            adapter_id="rubeus-telemetry-v1",
            parse=_parse_rubeus_source,
            render=render_rubeus_output_bytes,
            max_output_bytes=RUBEUS_MAX_OUTPUT_CHARS,
            report_has_provenance=False,
            project_evidence=_complete_evidence_record,
        ),
    }
)


def issue_source_admission(
    *,
    attempt_id: str,
    raw_artifact: bytes,
    source_format: str,
    source_id: str,
    source_revision: str,
    source_timestamp: str | None,
    logical_locator: str,
    raw_artifact_locator: str,
    authority_ref: str,
    cve_id: str,
    issuer_id: str,
    issuer_version: str,
    producer_revision: str,
    issued_at: str,
    valid_from: str,
    valid_until: str,
    limitations: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a deterministic, per-attempt admission for ``vulnify.lookup``.

    The caller is responsible for being the trusted validator and for the
    custody and authority assertions it supplies.  There is deliberately no
    default source, revision, rights decision, locator, issuer, or clock.
    """
    profile = _required_profile()
    reasons = _issue_input_reasons(
        attempt_id=attempt_id,
        raw_artifact=raw_artifact,
        source_format=source_format,
        source_id=source_id,
        source_revision=source_revision,
        source_timestamp=source_timestamp,
        logical_locator=logical_locator,
        raw_artifact_locator=raw_artifact_locator,
        authority_ref=authority_ref,
        cve_id=cve_id,
        issuer_id=issuer_id,
        issuer_version=issuer_version,
        producer_revision=producer_revision,
        issued_at=issued_at,
        valid_from=valid_from,
        valid_until=valid_until,
        limitations=limitations,
    )
    if reasons:
        raise ObservationError(reasons)
    if type(raw_artifact) is not bytes:
        raise ObservationError((REASON_RAW_ARTIFACT_MISMATCH,))
    records, source_claim, provenance = parse_feed_bytes(
        raw_artifact, format=source_format
    )
    if not any(record.get("cve_id") == cve_id for record in records):
        raise ObservationError((REASON_SUBJECT_MISMATCH,))

    source_time = {
        "status": "known" if source_timestamp is not None else "unknown",
        "value": source_timestamp,
    }
    normalized_limitations = sorted(set(limitations))
    body: dict[str, Any] = {
        "schema": SOURCE_ADMISSION_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "capability_id": profile.capability_id,
        "arm_id": profile.arm_id,
        "action": profile.action,
        "issuer": {"id": issuer_id, "version": issuer_version},
        "producer": {
            "id": profile.tool_name,
            "version": profile.tool_version,
            "revision": producer_revision,
        },
        "issued_at": issued_at,
        "validity": {"not_before": valid_from, "not_after": valid_until},
        "source": {
            "id": source_id,
            "revision": source_revision,
            "schema": {
                "id": profile.source_schema_id,
                "version": profile.source_schema_version,
                "format": source_format,
            },
            "timestamp": source_time,
            "freshness": "not-assessed",
            "logical_locator": logical_locator,
            "authority_ref": authority_ref,
            "raw_artifact": {
                "digest": source_claim["sha256"],
                "bytes": source_claim["bytes"],
                "normalized_records_digest": provenance["normalization"][
                    "records_sha256"
                ],
            },
        },
        "subject": {"kind": profile.subject_kind, "cve_id": cve_id},
        "scope": {
            "kind": profile.scope_kind,
            "identifier": f"cve:{cve_id}",
        },
        "custody": {
            "controller": issuer_id,
            "source_assertion": "validator-held-before-attempt",
            "raw_artifact_locator": raw_artifact_locator,
        },
        "evidence_class": profile.evidence_class,
        "limitations": normalized_limitations,
    }
    admission = _add_content_id(body, field="admission_id", prefix="source-admission")
    checked = verify_source_admission(
        admission, raw_artifact=raw_artifact, at_time=valid_from
    )
    if not checked.accepted:
        raise ObservationError(checked.reasons)
    return admission


def issue_profile_source_admission(
    *,
    capability_id: str,
    subject_id: str,
    attempt_id: str,
    raw_artifact: bytes,
    source_format: str,
    source_id: str,
    source_revision: str,
    source_timestamp: str | None,
    logical_locator: str,
    raw_artifact_locator: str,
    authority_ref: str,
    issuer_id: str,
    issuer_version: str,
    producer_revision: str,
    issued_at: str,
    valid_from: str,
    valid_until: str,
    limitations: Sequence[str] = (),
) -> dict[str, Any]:
    """Build an explicit admission for one frozen observation profile.

    ``vulnify.lookup`` deliberately routes through the original v1 issuer so
    its public contract and serialized output remain byte-compatible.  The
    two singleton profiles added after v1 mint only the closed v2 contract.
    """
    profile = _required_profile(capability_id)
    if profile.contract_version == SCHEMA_VERSION:
        if profile.capability_id != "vulnify.lookup":
            raise ObservationError((REASON_PROFILE_MISMATCH,))
        return issue_source_admission(
            attempt_id=attempt_id,
            raw_artifact=raw_artifact,
            source_format=source_format,
            source_id=source_id,
            source_revision=source_revision,
            source_timestamp=source_timestamp,
            logical_locator=logical_locator,
            raw_artifact_locator=raw_artifact_locator,
            authority_ref=authority_ref,
            cve_id=subject_id,
            issuer_id=issuer_id,
            issuer_version=issuer_version,
            producer_revision=producer_revision,
            issued_at=issued_at,
            valid_from=valid_from,
            valid_until=valid_until,
            limitations=limitations,
        )
    if profile.contract_version != SCHEMA_VERSION_V2:
        raise ObservationError((REASON_PROFILE_MISMATCH,))

    reasons = _profile_issue_input_reasons(
        profile=profile,
        subject_id=subject_id,
        attempt_id=attempt_id,
        raw_artifact=raw_artifact,
        source_format=source_format,
        source_id=source_id,
        source_revision=source_revision,
        source_timestamp=source_timestamp,
        logical_locator=logical_locator,
        raw_artifact_locator=raw_artifact_locator,
        authority_ref=authority_ref,
        issuer_id=issuer_id,
        issuer_version=issuer_version,
        producer_revision=producer_revision,
        issued_at=issued_at,
        valid_from=valid_from,
        valid_until=valid_until,
        limitations=limitations,
    )
    if reasons:
        raise ObservationError(reasons)
    adapter = _adapter_for_profile(profile)
    try:
        records, source_claim, provenance = adapter.parse(
            raw_artifact, source_format
        )
    except (TypeError, ValueError) as exc:
        raise ObservationError((REASON_SOURCE_PARSE,)) from exc
    matches = [
        record
        for record in records
        if record.get(profile.subject_id_field) == subject_id
    ]
    if len(matches) != 1:
        raise ObservationError((REASON_SUBJECT_MISMATCH,))

    source_time = {
        "status": "known" if source_timestamp is not None else "unknown",
        "value": source_timestamp,
    }
    body: dict[str, Any] = {
        "schema": SOURCE_ADMISSION_V2_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION_V2,
        "attempt_id": attempt_id,
        "capability_id": profile.capability_id,
        "arm_id": profile.arm_id,
        "action": profile.action,
        "issuer": {"id": issuer_id, "version": issuer_version},
        "producer": {
            "id": profile.tool_name,
            "version": profile.tool_version,
            "revision": producer_revision,
        },
        "issued_at": issued_at,
        "validity": {"not_before": valid_from, "not_after": valid_until},
        "source": {
            "id": source_id,
            "revision": source_revision,
            "schema": {
                "id": profile.source_schema_id,
                "version": profile.source_schema_version,
                "format": source_format,
            },
            "timestamp": source_time,
            "freshness": "not-assessed",
            "logical_locator": logical_locator,
            "authority_ref": authority_ref,
            "raw_artifact": {
                "digest": source_claim["sha256"],
                "bytes": source_claim["bytes"],
                "normalized_records_digest": provenance["normalization"][
                    "records_sha256"
                ],
            },
        },
        "subject": {
            "kind": profile.subject_kind,
            profile.subject_id_field: subject_id,
        },
        "scope": {
            "kind": profile.scope_kind,
            "identifier": f"{profile.scope_prefix}:{subject_id}",
        },
        "custody": {
            "controller": issuer_id,
            "source_assertion": "validator-held-before-attempt",
            "raw_artifact_locator": raw_artifact_locator,
        },
        "evidence_class": profile.evidence_class,
        "limitations": sorted(set(limitations)),
    }
    admission = _add_content_id(
        body, field="admission_id", prefix="source-admission"
    )
    checked = verify_source_admission(
        admission, raw_artifact=raw_artifact, at_time=valid_from
    )
    if not checked.accepted:
        raise ObservationError(checked.reasons)
    return admission


def verify_source_admission(
    admission: Mapping[str, Any], *, raw_artifact: bytes, at_time: str
) -> VerificationResult:
    """Verify a source admission and its exact raw bytes at a declared time."""
    try:
        document = _document_copy(admission)
    except (TypeError, ValueError):
        return _verification((REASON_INVALID_ADMISSION,))
    reasons = list(_admission_structure_reasons(document))
    if reasons:
        return _verification(reasons)
    profile = _profile_for_document(document, observation=False)
    if profile is None:
        return _verification((REASON_PROFILE_MISMATCH,))
    try:
        adapter = _adapter_for_profile(profile)
    except ObservationError as exc:
        return _verification(exc.reasons)
    if not _valid_timestamp(at_time):
        reasons.append(REASON_ADMISSION_WINDOW)
    else:
        validity = document["validity"]
        if not validity["not_before"] <= at_time <= validity["not_after"]:
            reasons.append(REASON_ADMISSION_WINDOW)

    expected_id = _content_id(
        {key: value for key, value in document.items() if key != "admission_id"},
        prefix="source-admission",
    )
    if document.get("admission_id") != expected_id:
        reasons.append(REASON_ADMISSION_ID_MISMATCH)

    source = document["source"]
    raw_claim = source["raw_artifact"]
    if type(raw_artifact) is not bytes:
        reasons.append(REASON_RAW_ARTIFACT_MISMATCH)
    else:
        try:
            records, computed_source, provenance = adapter.parse(
                raw_artifact, source["schema"]["format"]
            )
        except (FeedError, TypeError, ValueError):
            reasons.append(REASON_SOURCE_PARSE)
        else:
            expected_raw_claim = {
                "digest": computed_source["sha256"],
                "bytes": computed_source["bytes"],
                "normalized_records_digest": provenance["normalization"][
                    "records_sha256"
                ],
            }
            if _canonical_bytes(raw_claim) != _canonical_bytes(
                expected_raw_claim
            ):
                reasons.append(REASON_RAW_ARTIFACT_MISMATCH)
            subject_id = document["subject"][profile.subject_id_field]
            matches = [
                record
                for record in records
                if record.get(profile.subject_id_field) == subject_id
            ]
            if len(matches) != 1:
                reasons.append(REASON_SUBJECT_MISMATCH)
    return _verification(reasons)


def derive_trusted_observation(
    *,
    admission: Mapping[str, Any],
    execution_result: Mapping[str, Any],
    policy_report: bytes,
    raw_artifact: bytes,
    verified_at: str,
) -> dict[str, Any]:
    """Derive one deterministic observation after all byte bindings verify."""
    inputs, reasons = _validated_inputs(
        admission=admission,
        execution_result=execution_result,
        policy_report=policy_report,
        raw_artifact=raw_artifact,
        verified_at=verified_at,
    )
    if reasons:
        raise ObservationError(reasons)
    if inputs is None:
        raise ObservationError((REASON_INVALID_EXECUTION,))
    try:
        return _build_observation(*inputs, verified_at=verified_at)
    except (TypeError, ValueError) as exc:
        raise ObservationError((REASON_OBSERVATION_MISMATCH,)) from exc


def verify_trusted_observation(
    observation: Mapping[str, Any],
    *,
    admission: Mapping[str, Any],
    execution_result: Mapping[str, Any],
    policy_report: bytes,
    raw_artifact: bytes,
    verified_at: str,
    seen_observation_ids: Collection[str],
) -> VerificationResult:
    """Verify an exact observation bundle and reject caller-tracked replay.

    Replay state is intentionally external: this pure helper accepts the
    validator's already-seen id collection and never mutates it.  The trusted
    caller must preserve that collection across calls; this call rejects
    collections whose length or iteration is internally inconsistent.
    """
    try:
        document = _observation_document_copy(observation)
    except (TypeError, ValueError):
        return _verification((REASON_OBSERVATION_MISMATCH,))
    reasons = list(_observation_structure_reasons(document))
    observation_id = document.get("observation_id")
    try:
        if isinstance(seen_observation_ids, (str, bytes)) or not isinstance(
            seen_observation_ids, Collection
        ):
            raise TypeError("seen ids must be a repeatable collection")
        size_before = len(seen_observation_ids)
        replayed = False
        seen_count = 0
        for item in seen_observation_ids:
            seen_count += 1
            if type(item) is not str or not _OBSERVATION_ID_RE.fullmatch(item):
                raise ValueError("seen ids must contain exact observation ids")
            if type(observation_id) is str and item == observation_id:
                replayed = True
        if len(seen_observation_ids) != size_before or seen_count != size_before:
            raise ValueError("seen ids must have stable complete iteration")
    except (OverflowError, TypeError, ValueError, RuntimeError):
        reasons.append(REASON_REPLAY)
    else:
        if replayed:
            reasons.append(REASON_REPLAY)
    recomputed_id = _observation_identity(document)
    if observation_id != recomputed_id:
        reasons.append(REASON_OBSERVATION_ID_MISMATCH)

    inputs, input_reasons = _validated_inputs(
        admission=admission,
        execution_result=execution_result,
        policy_report=policy_report,
        raw_artifact=raw_artifact,
        verified_at=verified_at,
    )
    reasons.extend(input_reasons)
    if inputs is None:
        return _verification(reasons)
    try:
        expected = _build_observation(*inputs, verified_at=verified_at)
    except (TypeError, ValueError):
        reasons.append(REASON_OBSERVATION_MISMATCH)
        return _verification(reasons)
    if document.get("observation_id") != expected["observation_id"]:
        reasons.append(REASON_OBSERVATION_ID_MISMATCH)
    for field, reason in (
        ("custody", REASON_CUSTODY_MISMATCH),
        ("bindings", REASON_BINDING_MISMATCH),
        ("evidence", REASON_EVIDENCE_MISMATCH),
        ("source", REASON_SOURCE_MISMATCH),
        ("subject", REASON_SUBJECT_MISMATCH),
        ("scope", REASON_SUBJECT_MISMATCH),
    ):
        if _canonical_bytes(document.get(field)) != _canonical_bytes(
            expected[field]
        ):
            reasons.append(reason)
    if _canonical_bytes(document) != _canonical_bytes(expected):
        reasons.append(REASON_OBSERVATION_MISMATCH)
    return _verification(reasons)


def _validated_inputs(
    *,
    admission: Mapping[str, Any],
    execution_result: Mapping[str, Any],
    policy_report: bytes,
    raw_artifact: bytes,
    verified_at: str,
) -> tuple[
    tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes] | None,
    tuple[str, ...],
]:
    try:
        admission_doc = _document_copy(admission)
    except (TypeError, ValueError):
        return None, (REASON_INVALID_ADMISSION,)
    admission_check = verify_source_admission(
        admission_doc, raw_artifact=raw_artifact, at_time=verified_at
    )
    reasons = list(admission_check.reasons)
    if not admission_check.accepted:
        return None, _unique(reasons)
    try:
        result_doc = _document_copy(execution_result)
    except (TypeError, ValueError):
        return None, _unique([*reasons, REASON_INVALID_EXECUTION])
    if not _exact_execution_shape(result_doc):
        reasons.append(REASON_INVALID_EXECUTION)
    try:
        parsed = parse_execution_result(result_doc)
    except (KeyError, TypeError, ValueError):
        return None, _unique([*reasons, REASON_INVALID_EXECUTION])
    if not parsed.schema_ok or parsed.result is None:
        reasons.append(REASON_INVALID_EXECUTION)
    elif (
        parsed.status != STATUS_COMPLETE
        or parsed.reasons
        or parsed.result.transport_ok is not True
        or parsed.result.budget.spent.tool_steps != 1
    ):
        reasons.append(REASON_EXECUTION_NOT_COMPLETE)
    if parsed.result is None:
        return None, _unique(reasons)

    profile = _profile_for_document(admission_doc, observation=False)
    if profile is None:
        return None, _unique([*reasons, REASON_PROFILE_MISMATCH])
    try:
        adapter = _adapter_for_profile(profile)
    except ObservationError as exc:
        return None, _unique([*reasons, *exc.reasons])
    result = parsed.result
    if result.capability_id != profile.capability_id:
        reasons.append(REASON_PROFILE_MISMATCH)
    if result.attempt_id != admission_doc.get("attempt_id"):
        reasons.append(REASON_ATTEMPT_MISMATCH)
    if result.tool.name != profile.tool_name or result.tool.version != profile.tool_version:
        reasons.append(REASON_PROFILE_MISMATCH)
    producer = admission_doc.get("producer")
    if isinstance(producer, dict) and (
        producer.get("id") != result.tool.name
        or producer.get("version") != result.tool.version
    ):
        reasons.append(REASON_PROFILE_MISMATCH)

    validity = admission_doc.get("validity")
    issued_at = admission_doc.get("issued_at")
    if not _valid_timestamp(result.started_at) or not _valid_timestamp(
        result.finished_at
    ):
        reasons.append(REASON_INVALID_EXECUTION)
    elif isinstance(validity, dict) and all(
        isinstance(value, str)
        for value in (
            issued_at,
            validity.get("not_before"),
            validity.get("not_after"),
            result.started_at,
            result.finished_at,
            verified_at,
        )
    ):
        if not (
            issued_at <= result.started_at
            and validity["not_before"] <= result.started_at
            and result.started_at <= result.finished_at
            and result.finished_at <= verified_at
            and verified_at <= validity["not_after"]
        ):
            reasons.append(REASON_ADMISSION_WINDOW)

    if type(policy_report) is not bytes:
        reasons.append(REASON_ARTIFACT_MISMATCH)
        return None, _unique(reasons)
    if not policy_report or len(policy_report) > _MAX_POLICY_REPORT_BYTES:
        reasons.append(REASON_ARTIFACT_MISMATCH)
        return None, _unique(reasons)
    report_digest = _sha256(policy_report)
    expected_artifacts = (
        (
            report_digest,
            profile.artifact_kind,
            profile.artifact_redaction,
        ),
    )
    actual_artifacts = tuple(
        (artifact.digest, artifact.kind, artifact.redaction)
        for artifact in result.artifacts
    )
    if actual_artifacts != expected_artifacts:
        reasons.append(REASON_ARTIFACT_MISMATCH)
    if result.budget.spent.output_bytes != len(policy_report):
        reasons.append(REASON_ARTIFACT_MISMATCH)

    if profile.contract_version == SCHEMA_VERSION_V2:
        report_max_nodes = _V2_MAX_DOCUMENT_NODES
        report_max_depth = _V2_MAX_DOCUMENT_DEPTH
        report_copy = _v2_document_copy
    else:
        report_max_nodes = _MAX_DOCUMENT_NODES
        report_max_depth = _MAX_DOCUMENT_DEPTH
        report_copy = _document_copy
    try:
        text = policy_report.decode("utf-8")
        report_value = strict_json_loads(
            text,
            max_nodes=report_max_nodes,
            max_depth=report_max_depth,
        )
        if not isinstance(report_value, dict):
            raise ValueError("policy report is not an object")
        report_doc = report_copy(report_value)
        if _canonical_bytes(report_doc) != policy_report:
            raise ValueError("policy report is not the canonical producer artifact")
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        StrictDataError,
        TypeError,
        ValueError,
    ):
        reasons.append(REASON_INVALID_POLICY_REPORT)
        return None, _unique(reasons)

    try:
        producer_rendered = adapter.render(report_doc)
    except (OverflowError, TypeError, ValueError):
        reasons.append(REASON_INVALID_POLICY_REPORT)
        return None, _unique(reasons)
    if len(producer_rendered) > adapter.max_output_bytes:
        reasons.append(REASON_INVALID_POLICY_REPORT)
        return None, _unique(reasons)
    expected_report_keys = {profile.report_record_key, "source"}
    if adapter.report_has_provenance:
        expected_report_keys.add("provenance")
    if set(report_doc) != expected_report_keys:
        reasons.append(REASON_INVALID_POLICY_REPORT)
    try:
        records, expected_source, expected_provenance = adapter.parse(
            raw_artifact, admission_doc["source"]["schema"]["format"]
        )
    except (FeedError, TypeError, ValueError):
        reasons.append(REASON_SOURCE_PARSE)
        return None, _unique(reasons)
    subject_id = admission_doc["subject"][profile.subject_id_field]
    matches = [
        record
        for record in records
        if record.get(profile.subject_id_field) == subject_id
    ]
    if len(matches) != 1 or _canonical_bytes(
        report_doc.get(profile.report_record_key)
    ) != _canonical_bytes(matches[0]):
        reasons.append(REASON_SUBJECT_MISMATCH)
    source_mismatch = _canonical_bytes(
        report_doc.get("source")
    ) != _canonical_bytes(expected_source)
    if adapter.report_has_provenance:
        source_mismatch = source_mismatch or _canonical_bytes(
            report_doc.get("provenance")
        ) != _canonical_bytes(expected_provenance)
    if source_mismatch:
        reasons.append(REASON_SOURCE_MISMATCH)
    if reasons:
        return None, _unique(reasons)
    return (admission_doc, result_doc, report_doc, policy_report), ()


def _build_observation(
    admission: dict[str, Any],
    execution_result: dict[str, Any],
    report: dict[str, Any],
    policy_report: bytes,
    *,
    verified_at: str,
) -> dict[str, Any]:
    profile = _profile_for_document(admission, observation=False)
    if profile is None:
        raise ValueError("admission does not select a frozen profile")
    adapter = _adapter_for_profile(profile)
    policy_digest = _sha256(policy_report)
    attempt_id = admission["attempt_id"]
    filename = "sha256-" + policy_digest.removeprefix("sha256:")
    limitations = sorted(
        set(admission["limitations"]) | set(profile.derived_limitations)
    )
    if profile.contract_version == SCHEMA_VERSION:
        schema_id = TRUSTED_OBSERVATION_SCHEMA_ID
        schema_version = SCHEMA_VERSION
        document_copy = _document_copy
    elif profile.contract_version == SCHEMA_VERSION_V2:
        schema_id = TRUSTED_OBSERVATION_V2_SCHEMA_ID
        schema_version = SCHEMA_VERSION_V2
        document_copy = _v2_document_copy
    else:
        raise ValueError("profile selects an unknown contract version")
    body: dict[str, Any] = {
        "schema": schema_id,
        "schema_version": schema_version,
        "admission_id": admission["admission_id"],
        "attempt_id": attempt_id,
        "capability_id": admission["capability_id"],
        "arm_id": admission["arm_id"],
        "action": admission["action"],
        "producer": document_copy(admission["producer"]),
        "verifier": document_copy(admission["issuer"]),
        "subject": document_copy(admission["subject"]),
        "scope": document_copy(admission["scope"]),
        "collected_at": execution_result["finished_at"],
        "verified_at": verified_at,
        "source": document_copy(admission["source"]),
        "custody": {
            "controller": admission["custody"]["controller"],
            "source_assertion": admission["custody"]["source_assertion"],
            "result_assertion": "validator-attested-mode-a",
            "raw_artifact_locator": admission["custody"][
                "raw_artifact_locator"
            ],
            "policy_report_locator": f"mode-a://{attempt_id}/{filename}",
        },
        "bindings": {
            "admission_digest": _sha256(_canonical_bytes(admission)),
            "execution_result_digest": _sha256(
                _canonical_bytes(execution_result)
            ),
            "policy_report": {
                "digest": policy_digest,
                "bytes": len(policy_report),
            },
        },
        "evidence": {
            "class": admission["evidence_class"],
            "record": adapter.project_evidence(
                document_copy(report[profile.report_record_key])
            ),
            "applicability": {"assessed": False, "status": "not-assessed"},
        },
        "limitations": limitations,
    }
    observation = document_copy(body)
    observation["observation_id"] = _observation_identity(observation)
    return observation


def _issue_input_reasons(**values: Any) -> tuple[str, ...]:
    reasons: list[str] = []
    if type(values["attempt_id"]) is not str or not _ATTEMPT_ID_RE.fullmatch(
        values["attempt_id"]
    ):
        reasons.append(REASON_INVALID_ADMISSION)
    if type(values["raw_artifact"]) is not bytes:
        reasons.append(REASON_RAW_ARTIFACT_MISMATCH)
    if type(values["source_format"]) is not str or values[
        "source_format"
    ] not in {"json", "jsonl", "yaml"}:
        reasons.append(REASON_INVALID_ADMISSION)
    for field in ("source_id", "source_revision", "issuer_id", "issuer_version"):
        if not _valid_identifier(values[field]):
            reasons.append(REASON_INVALID_ADMISSION)
    if not _valid_identifier(values["producer_revision"]):
        reasons.append(REASON_INVALID_ADMISSION)
    for field in ("logical_locator", "raw_artifact_locator", "authority_ref"):
        if not _valid_ref(values[field]):
            reasons.append(REASON_INVALID_ADMISSION)
    if (
        type(values["cve_id"]) is not str
        or len(values["cve_id"]) > _MAX_CVE_ID
        or not _CVE_ID_RE.fullmatch(values["cve_id"])
    ):
        reasons.append(REASON_INVALID_ADMISSION)
    for field in ("issued_at", "valid_from", "valid_until"):
        if not _valid_timestamp(values[field]):
            reasons.append(REASON_ADMISSION_WINDOW)
    source_timestamp = values["source_timestamp"]
    if source_timestamp is not None and not _valid_timestamp(source_timestamp):
        reasons.append(REASON_ADMISSION_WINDOW)
    if not _valid_admission_window(
        values["issued_at"], values["valid_from"], values["valid_until"]
    ):
        reasons.append(REASON_ADMISSION_WINDOW)
    if not reasons:
        if source_timestamp is not None and source_timestamp > values["issued_at"]:
            reasons.append(REASON_ADMISSION_WINDOW)
    try:
        _normalized_limitations(values["limitations"])
    except (TypeError, ValueError):
        reasons.append(REASON_INVALID_ADMISSION)
    if type(values["raw_artifact"]) is bytes:
        try:
            parse_feed_bytes(
                values["raw_artifact"], format=values["source_format"]
            )
        except (FeedError, TypeError, ValueError):
            reasons.append(REASON_SOURCE_PARSE)
    return _unique(reasons)


def _profile_issue_input_reasons(
    *, profile: ObservationProfile, subject_id: Any, **values: Any
) -> tuple[str, ...]:
    reasons: list[str] = []
    if type(values["attempt_id"]) is not str or not _ATTEMPT_ID_RE.fullmatch(
        values["attempt_id"]
    ):
        reasons.append(REASON_INVALID_ADMISSION)
    if type(values["raw_artifact"]) is not bytes:
        reasons.append(REASON_RAW_ARTIFACT_MISMATCH)
    if (
        type(values["source_format"]) is not str
        or values["source_format"] not in profile.source_formats
    ):
        reasons.append(REASON_INVALID_ADMISSION)
    for field in ("source_id", "source_revision", "issuer_id", "issuer_version"):
        if not _valid_identifier(values[field]):
            reasons.append(REASON_INVALID_ADMISSION)
    if not _valid_identifier(values["producer_revision"]):
        reasons.append(REASON_INVALID_ADMISSION)
    for field in ("logical_locator", "raw_artifact_locator", "authority_ref"):
        if not _valid_ref(values[field]):
            reasons.append(REASON_INVALID_ADMISSION)
    if not _valid_subject_id(profile, subject_id):
        reasons.append(REASON_INVALID_ADMISSION)
    for field in ("issued_at", "valid_from", "valid_until"):
        if not _valid_timestamp(values[field]):
            reasons.append(REASON_ADMISSION_WINDOW)
    source_timestamp = values["source_timestamp"]
    if source_timestamp is not None and not _valid_timestamp(source_timestamp):
        reasons.append(REASON_ADMISSION_WINDOW)
    if not _valid_admission_window(
        values["issued_at"], values["valid_from"], values["valid_until"]
    ):
        reasons.append(REASON_ADMISSION_WINDOW)
    if not reasons and source_timestamp is not None:
        if source_timestamp > values["issued_at"]:
            reasons.append(REASON_ADMISSION_WINDOW)
    try:
        _normalized_limitations(values["limitations"])
    except (TypeError, ValueError):
        reasons.append(REASON_INVALID_ADMISSION)
    if type(values["raw_artifact"]) is bytes:
        try:
            _adapter_for_profile(profile).parse(
                values["raw_artifact"], values["source_format"]
            )
        except (ObservationError, TypeError, ValueError):
            reasons.append(REASON_SOURCE_PARSE)
    return _unique(reasons)


def _admission_structure_reasons(document: dict[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    if set(document) != _ADMISSION_KEYS:
        return (REASON_INVALID_ADMISSION,)
    if _contract_version_for_document(document, observation=False) is None:
        reasons.append(REASON_UNKNOWN_SCHEMA)
    if not isinstance(document.get("admission_id"), str) or not _ADMISSION_ID_RE.fullmatch(
        document["admission_id"]
    ):
        reasons.append(REASON_INVALID_ADMISSION)
    if not isinstance(document.get("attempt_id"), str) or not _ATTEMPT_ID_RE.fullmatch(
        document["attempt_id"]
    ):
        reasons.append(REASON_INVALID_ADMISSION)
    profile = _profile_for_structure(document, observation=False)
    if profile is None:
        reasons.append(REASON_PROFILE_MISMATCH)
        return _unique(reasons)
    if (
        document.get("capability_id") != profile.capability_id
        or document.get("arm_id") != profile.arm_id
        or document.get("action") != profile.action
        or document.get("evidence_class") != profile.evidence_class
    ):
        reasons.append(REASON_PROFILE_MISMATCH)
    issuer = document.get("issuer")
    producer = document.get("producer")
    if (
        not _exact_mapping(issuer, {"id", "version"})
        or not _valid_identifier(issuer.get("id"))
        or not _valid_identifier(issuer.get("version"))
    ):
        reasons.append(REASON_INVALID_ADMISSION)
    if (
        not _exact_mapping(producer, {"id", "version", "revision"})
        or producer.get("id") != profile.tool_name
        or producer.get("version") != profile.tool_version
        or not _valid_identifier(producer.get("revision"))
    ):
        reasons.append(REASON_PROFILE_MISMATCH)
    issued_at = document.get("issued_at")
    validity = document.get("validity")
    if (
        not _valid_timestamp(issued_at)
        or not _exact_mapping(validity, {"not_before", "not_after"})
        or not _valid_timestamp(validity.get("not_before"))
        or not _valid_timestamp(validity.get("not_after"))
        or not _valid_admission_window(
            issued_at, validity.get("not_before"), validity.get("not_after")
        )
    ):
        reasons.append(REASON_ADMISSION_WINDOW)
    source = document.get("source")
    if not _valid_source(source, profile=profile, issued_at=issued_at):
        reasons.append(REASON_INVALID_ADMISSION)
    subject = document.get("subject")
    scope = document.get("scope")
    subject_id = (
        subject.get(profile.subject_id_field)
        if isinstance(subject, dict)
        else None
    )
    if (
        not _exact_mapping(subject, {"kind", profile.subject_id_field})
        or subject.get("kind") != profile.subject_kind
        or not _valid_subject_id(profile, subject_id)
        or scope
        != {
            "kind": profile.scope_kind,
            "identifier": f"{profile.scope_prefix}:{subject_id}",
        }
    ):
        reasons.append(REASON_SUBJECT_MISMATCH)
    custody = document.get("custody")
    issuer_id = issuer.get("id") if isinstance(issuer, dict) else None
    if (
        not _exact_mapping(
            custody,
            {"controller", "source_assertion", "raw_artifact_locator"},
        )
        or custody.get("controller") != issuer_id
        or custody.get("source_assertion") != "validator-held-before-attempt"
        or not _valid_ref(custody.get("raw_artifact_locator"))
    ):
        reasons.append(REASON_INVALID_ADMISSION)
    try:
        normalized = _normalized_limitations(document.get("limitations"))
        if document.get("limitations") != normalized:
            reasons.append(REASON_INVALID_ADMISSION)
    except (TypeError, ValueError):
        reasons.append(REASON_INVALID_ADMISSION)
    return _unique(reasons)


def _observation_structure_reasons(document: dict[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    if set(document) != _OBSERVATION_KEYS:
        return (REASON_OBSERVATION_MISMATCH,)
    contract_version = _contract_version_for_document(
        document, observation=True
    )
    if contract_version is None:
        reasons.append(REASON_UNKNOWN_SCHEMA)
    elif (
        contract_version == SCHEMA_VERSION_V2
        and _profile_for_structure(document, observation=True) is None
    ):
        reasons.append(REASON_PROFILE_MISMATCH)
    if not isinstance(document.get("observation_id"), str) or not _OBSERVATION_ID_RE.fullmatch(
        document["observation_id"]
    ):
        reasons.append(REASON_OBSERVATION_ID_MISMATCH)
    if not isinstance(document.get("admission_id"), str) or not _ADMISSION_ID_RE.fullmatch(
        document["admission_id"]
    ):
        reasons.append(REASON_OBSERVATION_MISMATCH)
    if not isinstance(document.get("attempt_id"), str) or not _ATTEMPT_ID_RE.fullmatch(
        document["attempt_id"]
    ):
        reasons.append(REASON_OBSERVATION_MISMATCH)
    for field in ("collected_at", "verified_at"):
        if not _valid_timestamp(document.get(field)):
            reasons.append(REASON_OBSERVATION_MISMATCH)
    if not isinstance(document.get("limitations"), list):
        reasons.append(REASON_OBSERVATION_MISMATCH)
    return _unique(reasons)


def _valid_source(
    value: Any, *, profile: ObservationProfile, issued_at: Any
) -> bool:
    if not _exact_mapping(
        value,
        {
            "id",
            "revision",
            "schema",
            "timestamp",
            "freshness",
            "logical_locator",
            "authority_ref",
            "raw_artifact",
        },
    ):
        return False
    schema = value.get("schema")
    timestamp = value.get("timestamp")
    raw = value.get("raw_artifact")
    if (
        not _valid_identifier(value.get("id"))
        or not _valid_identifier(value.get("revision"))
        or not _valid_ref(value.get("logical_locator"))
        or not _valid_ref(value.get("authority_ref"))
        or value.get("freshness") != "not-assessed"
        or not _exact_mapping(schema, {"id", "version", "format"})
        or schema.get("id") != profile.source_schema_id
        or schema.get("version") != profile.source_schema_version
        or type(schema.get("version")) is not int
        or type(schema.get("format")) is not str
        or schema.get("format") not in profile.source_formats
        or not _exact_mapping(timestamp, {"status", "value"})
        or not _exact_mapping(
            raw, {"digest", "bytes", "normalized_records_digest"}
        )
        or not _valid_digest(raw.get("digest"))
        or not _valid_digest(raw.get("normalized_records_digest"))
        or type(raw.get("bytes")) is not int
        or raw.get("bytes") < 1
    ):
        return False
    if timestamp.get("status") == "known":
        return (
            _valid_timestamp(issued_at)
            and _valid_timestamp(timestamp.get("value"))
            and timestamp["value"] <= issued_at
        )
    return timestamp == {"status": "unknown", "value": None}


def _contract_version_for_document(
    document: Mapping[str, Any], *, observation: bool
) -> int | None:
    schema = document.get("schema")
    version = document.get("schema_version")
    if type(version) is not int:
        return None
    if observation:
        if schema == TRUSTED_OBSERVATION_SCHEMA_ID and version == SCHEMA_VERSION:
            return version
        if (
            schema == TRUSTED_OBSERVATION_V2_SCHEMA_ID
            and version == SCHEMA_VERSION_V2
        ):
            return version
        return None
    if schema == SOURCE_ADMISSION_SCHEMA_ID and version == SCHEMA_VERSION:
        return version
    if (
        schema == SOURCE_ADMISSION_V2_SCHEMA_ID
        and version == SCHEMA_VERSION_V2
    ):
        return version
    return None


def _profile_for_document(
    document: Mapping[str, Any], *, observation: bool
) -> ObservationProfile | None:
    version = _contract_version_for_document(document, observation=observation)
    capability_id = document.get("capability_id")
    if version is None or type(capability_id) is not str:
        return None
    profile = observation_profile(capability_id)
    if profile is None or profile.contract_version != version:
        return None
    return profile


def _profile_for_structure(
    document: Mapping[str, Any], *, observation: bool
) -> ObservationProfile | None:
    """Select a capability profile without conflating an unknown schema.

    Structure validation reports an unknown schema independently.  A profile
    mismatch is warranted only when the capability itself is unknown or a
    recognized contract version conflicts with that capability's frozen
    profile.
    """
    capability_id = document.get("capability_id")
    if type(capability_id) is not str:
        return None
    profile = observation_profile(capability_id)
    if profile is None:
        return None
    version = _contract_version_for_document(document, observation=observation)
    if version is not None and profile.contract_version != version:
        return None
    return profile


def _required_profile(
    capability_id: str = "vulnify.lookup",
) -> ObservationProfile:
    if type(capability_id) is not str:
        raise ObservationError((REASON_PROFILE_MISMATCH,))
    profile = observation_profile(capability_id)
    if profile is None:
        raise ObservationError((REASON_PROFILE_MISMATCH,))
    return profile


def _adapter_for_profile(profile: ObservationProfile) -> _ReplayAdapter:
    if tuple(_REPLAY_ADAPTERS) != tuple(OBSERVATION_PROFILES):
        raise ObservationError((REASON_PROFILE_MISMATCH,))
    adapter = _REPLAY_ADAPTERS.get(profile.capability_id)
    invoke = INVOKE_PROFILES.get(profile.capability_id)
    if (
        adapter is None
        or adapter.adapter_id != profile.replay_adapter_id
        or invoke is None
        or (
            profile.capability_id,
            profile.arm_id,
            profile.action,
            profile.tool_name,
            profile.tool_version,
        )
        != (
            invoke.capability_id,
            invoke.arm_id,
            invoke.action,
            invoke.tool_name,
            invoke.tool_version,
        )
    ):
        raise ObservationError((REASON_PROFILE_MISMATCH,))
    return adapter


def _valid_subject_id(profile: ObservationProfile, value: Any) -> bool:
    if profile.capability_id == "vulnify.lookup":
        return (
            type(value) is str
            and len(value) <= _MAX_CVE_ID
            and bool(_CVE_ID_RE.fullmatch(value))
        )
    return _valid_identifier(value)


def _normalized_limitations(value: Any) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError("limitations must be a sequence")
    result: list[str] = []
    for item in value:
        if (
            type(item) is not str
            or len(item) > 128
            or not _LIMITATION_RE.fullmatch(item)
        ):
            raise ValueError("invalid limitation code")
        result.append(item)
    if len(result) > 64 or len(result) != len(set(result)):
        raise ValueError("invalid limitation set")
    return sorted(result)


def _document_copy(value: Any) -> dict[str, Any]:
    return _bounded_document_copy(
        value,
        max_nodes=_MAX_DOCUMENT_NODES,
        max_depth=_MAX_DOCUMENT_DEPTH,
        max_text=_MAX_TEXT,
        max_key_text=_MAX_TEXT,
    )


def _v2_document_copy(value: Any) -> dict[str, Any]:
    return _bounded_document_copy(
        value,
        max_nodes=_V2_MAX_DOCUMENT_NODES,
        max_depth=_V2_MAX_DOCUMENT_DEPTH,
        max_text=_V2_MAX_TEXT,
        max_key_text=_V2_MAX_KEY_TEXT,
    )


def _observation_document_copy(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _document_copy(value)
    try:
        schema_id = value.get("schema")
        schema_version = value.get("schema_version")
        capability_id = value.get("capability_id")
    except RuntimeError as exc:
        raise TypeError("document mapping could not be inspected") from exc
    profile = (
        observation_profile(capability_id)
        if type(capability_id) is str
        else None
    )
    if (
        type(schema_id) is str
        and schema_id == TRUSTED_OBSERVATION_V2_SCHEMA_ID
        and type(schema_version) is int
        and schema_version == SCHEMA_VERSION_V2
        and profile is not None
        and profile.contract_version == SCHEMA_VERSION_V2
    ):
        candidate = _v2_document_copy(value)
        if (
            candidate.get("schema") == TRUSTED_OBSERVATION_V2_SCHEMA_ID
            and candidate.get("schema_version") == SCHEMA_VERSION_V2
            and type(candidate.get("schema_version")) is int
            and candidate.get("capability_id") == capability_id
        ):
            return candidate
        return _document_copy(candidate)
    return _document_copy(value)


def _bounded_document_copy(
    value: Any,
    *,
    max_nodes: int,
    max_depth: int,
    max_text: int,
    max_key_text: int,
) -> dict[str, Any]:
    counters = [0, 0]
    try:
        copied = _json_value(
            value,
            depth=0,
            counters=counters,
            max_nodes=max_nodes,
            max_depth=max_depth,
            max_text=max_text,
            max_key_text=max_key_text,
        )
    except RuntimeError as exc:
        raise TypeError("document mapping could not be copied") from exc
    if not isinstance(copied, dict):
        raise TypeError("document must be a mapping")
    return copied


def _json_value(
    value: Any,
    *,
    depth: int,
    counters: list[int],
    max_nodes: int,
    max_depth: int,
    max_text: int,
    max_key_text: int,
) -> Any:
    if depth > max_depth:
        raise ValueError("document exceeds depth cap")
    counters[0] += 1
    if counters[0] > max_nodes:
        raise ValueError("document exceeds node cap")
    if value is None or type(value) in {bool, int, str}:
        if type(value) is str:
            if len(value) > max_text:
                raise ValueError("document text exceeds cap")
            _require_utf8_text(value)
        if type(value) is int and value.bit_length() > _MAX_NUMBER_BITS:
            raise ValueError("document number exceeds cap")
        _add_document_bytes(counters, len(_scalar_json_bytes(value)))
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("document contains non-finite number")
        _add_document_bytes(counters, len(_scalar_json_bytes(value)))
        return value
    if isinstance(value, Mapping):
        _add_document_bytes(counters, 2)
        copied: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or len(key) > max_key_text:
                raise TypeError("document keys must be bounded exact strings")
            _require_utf8_text(key)
            if key in copied:
                raise TypeError("document keys must be unique strings")
            if copied:
                _add_document_bytes(counters, 1)
            _add_document_bytes(counters, len(_scalar_json_bytes(key)) + 1)
            copied[key] = _json_value(
                item,
                depth=depth + 1,
                counters=counters,
                max_nodes=max_nodes,
                max_depth=max_depth,
                max_text=max_text,
                max_key_text=max_key_text,
            )
        return copied
    if isinstance(value, list):
        _add_document_bytes(counters, 2)
        copied_list: list[Any] = []
        for item in value:
            if copied_list:
                _add_document_bytes(counters, 1)
            copied_list.append(
                _json_value(
                    item,
                    depth=depth + 1,
                    counters=counters,
                    max_nodes=max_nodes,
                    max_depth=max_depth,
                    max_text=max_text,
                    max_key_text=max_key_text,
                )
            )
        return copied_list
    raise TypeError("document is not strict JSON data")


def _scalar_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")


def _require_utf8_text(value: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("document text is not valid Unicode") from exc


def _add_document_bytes(counters: list[int], amount: int) -> None:
    counters[1] += amount
    if counters[1] > _MAX_DOCUMENT_BYTES:
        raise ValueError("document exceeds size cap")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _add_content_id(
    body: dict[str, Any], *, field: str, prefix: str
) -> dict[str, Any]:
    payload = _document_copy(body)
    payload[field] = _content_id(payload, prefix=prefix)
    return payload


def _content_id(body: Mapping[str, Any], *, prefix: str) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical_bytes(body)).hexdigest()}"


def _observation_identity(document: Mapping[str, Any]) -> str:
    """Return the per-schema one-observation-per-attempt replay identity."""
    return _content_id(
        {
            "schema": document.get("schema"),
            "schema_version": document.get("schema_version"),
            "capability_id": document.get("capability_id"),
            "attempt_id": document.get("attempt_id"),
        },
        prefix="trusted-observation",
    )


def _sha256(blob: bytes) -> str:
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _valid_timestamp(value: Any) -> bool:
    if type(value) is not str or not _TIMESTAMP_RE.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _valid_admission_window(issued_at: Any, valid_from: Any, valid_until: Any) -> bool:
    if not all(_valid_timestamp(value) for value in (issued_at, valid_from, valid_until)):
        return False
    issued = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    start = datetime.strptime(valid_from, "%Y-%m-%dT%H:%M:%SZ")
    end = datetime.strptime(valid_until, "%Y-%m-%dT%H:%M:%SZ")
    return (
        issued <= start <= end
        and (end - start).total_seconds() <= _MAX_ADMISSION_VALIDITY_SECONDS
    )


def _exact_execution_shape(document: Mapping[str, Any]) -> bool:
    return set(document) == _EXECUTION_KEYS and _exact_mapping(
        document.get("cleanup"), {"required", "proof_digest", "residual"}
    )


def _valid_identifier(value: Any) -> bool:
    return type(value) is str and bool(_IDENTIFIER_RE.fullmatch(value))


def _valid_ref(value: Any) -> bool:
    if type(value) is not str or len(value) > 1_024:
        return False
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return not any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in value
    ) and bool(_REF_RE.fullmatch(value))


def _valid_digest(value: Any) -> bool:
    return type(value) is str and bool(_DIGEST_RE.fullmatch(value))


def _exact_mapping(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _verification(reasons: Sequence[str]) -> VerificationResult:
    normalized = _unique(reasons)
    return VerificationResult(accepted=not normalized, reasons=normalized)


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


__all__ = [
    "SCHEMA_VERSION",
    "SCHEMA_VERSION_V2",
    "SOURCE_ADMISSION_SCHEMA_ID",
    "SOURCE_ADMISSION_V2_SCHEMA_ID",
    "TRUSTED_OBSERVATION_SCHEMA_ID",
    "TRUSTED_OBSERVATION_V2_SCHEMA_ID",
    "ObservationError",
    "VerificationResult",
    "derive_trusted_observation",
    "issue_profile_source_admission",
    "issue_source_admission",
    "verify_source_admission",
    "verify_trusted_observation",
]
