"""Reader-observation binding for acquired trusted-side inputs.

An observation binds acquired bytes to an attempt identity. The observation
id is a stable replay identity derived from the binding fields only -- never
a content digest -- and the recorded resolved path is an audit locator, not
identity. Verification re-derives the whole document from the acquisition;
the caller owns the durable seen-id set, and nothing is stored module-side.
No network, no subprocess, no clock reads.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re

from reader_evidence.acquisition import AcquisitionRecord, DirectoryManifest

SCHEMA = "specaudit.ctf.reader-observation.v1"
SCHEMA_VERSION = 1
CUSTODY = "operator-asserted-root"
EVIDENCE_CLASS = "declared"
LIMITATIONS = (
    "operator-asserted-root-not-verified-custody",
    "bytes-acquired-in-bounded-read-window-stability-reattested",
    "content-bound-unsigned",
    "locator-is-not-identity",
    "applicability-not-assessed",
)
_ATTEMPT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{7,63}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_FIELD = 256
_FIELDS = {"schema", "schema_version", "observation_id", "attempt_id", "arm_id", "action",
           "handler_revision", "collected_at", "input", "execution_result_digest", "custody",
           "evidence_class", "limitations"}


class ObservationError(ValueError):
    """Raised when an observation binding or document is structurally invalid."""


@dataclass(frozen=True)
class VerificationResult:
    """Verifier outcome; reasons use replayed / cross-attempt / document-mismatch / malformed."""

    ok: bool
    reasons: tuple[str, ...]


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def observation_identity(attempt_id: str, arm_id: str, action: str) -> str:
    """Replay identity over schema, version, attempt, arm, and action.

    Deliberately not a content digest: identical bytes under a different
    attempt mint a fresh id, while any repeat of the same binding collides so
    the caller's seen set can refuse the replay.
    """
    payload = "\x1f".join((SCHEMA, str(SCHEMA_VERSION), attempt_id, arm_id, action))
    return _digest(payload.encode("utf-8"))


def _field(value: object, *, label: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > _MAX_FIELD
            or any(ord(char) < 32 for char in value)):
        raise ObservationError(f"{label} must be a nonempty bounded string")
    return value


def _attempt_id(value: object) -> str:
    if not isinstance(value, str) or not _ATTEMPT_ID.fullmatch(value):
        raise ObservationError("attempt id must match [a-z0-9][a-z0-9._-]{7,63}")
    return value


def _digest_field(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ObservationError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def _collected_at(value: object) -> datetime:
    """Naive datetime in bind; canonical naive iso spelling in re-derivation."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ObservationError(f"collected_at is not an iso datetime: {value!r}") from exc
    if not isinstance(value, datetime) or value.tzinfo is not None:
        raise ObservationError("collected_at must be naive; callers own the clock")
    return value


def _binding(observation: dict) -> tuple[str, str, str, str, str, datetime]:
    """Validate and extract the identity fields of an observed document."""
    return (
        _attempt_id(observation.get("attempt_id")),
        _field(observation.get("arm_id"), label="arm_id"),
        _field(observation.get("action"), label="action"),
        _field(observation.get("handler_revision"), label="handler_revision"),
        _digest_field(observation.get("execution_result_digest"),
                      label="execution_result_digest"),
        _collected_at(observation.get("collected_at")),
    )


def _document(acquisition: object, *, attempt_id: str, arm_id: str, action: str,
              handler_revision: str, execution_result_digest: str,
              collected_at: datetime) -> dict:
    if isinstance(acquisition, AcquisitionRecord):
        input_block = {"size_bytes": acquisition.size_bytes, "sha256": acquisition.sha256,
                       # The locator is recorded for audit only; it is not identity.
                       "resolved_path": acquisition.resolved_path,
                       "logical_suffix": acquisition.suffix}
    elif isinstance(acquisition, DirectoryManifest):
        input_block = {"manifest_digest": directory_manifest_digest(acquisition),
                       "entry_count": len(acquisition.entries),
                       "total_bytes": acquisition.total_bytes,
                       "resolved_path": acquisition.resolved_path}
    else:
        raise ObservationError("acquisition must be an AcquisitionRecord or DirectoryManifest")
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "observation_id": observation_identity(attempt_id, arm_id, action),
        "attempt_id": attempt_id,
        "arm_id": arm_id,
        "action": action,
        "handler_revision": handler_revision,
        "collected_at": collected_at.isoformat(),
        "input": input_block,
        "execution_result_digest": execution_result_digest,
        "custody": CUSTODY,
        "evidence_class": EVIDENCE_CLASS,
        "limitations": list(LIMITATIONS),
    }


def bind_reader_observation(acquisition: AcquisitionRecord, *, attempt_id: str, arm_id: str,
                            action: str, handler_revision: str, execution_result_digest: str,
                            collected_at: datetime) -> dict:
    """Mint a reader-observation.v1 document for one acquired file.

    Input digests bind bytes; they do not sign them, and custody stays
    operator-asserted because the root's chain is not verified here.
    """
    return _document(
        acquisition,
        attempt_id=_attempt_id(attempt_id),
        arm_id=_field(arm_id, label="arm_id"),
        action=_field(action, label="action"),
        handler_revision=_field(handler_revision, label="handler_revision"),
        execution_result_digest=_digest_field(execution_result_digest,
                                              label="execution_result_digest"),
        collected_at=_collected_at(collected_at),
    )


def directory_manifest_digest(manifest: DirectoryManifest) -> str:
    """Content digest over the canonical entries and manifest summary fields."""
    summary = {"entries": list(manifest.entries), "resolved_path": manifest.resolved_path,
               "total_bytes": manifest.total_bytes}
    canonical = json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _digest(canonical.encode("utf-8"))


def bind_directory_observation(manifest: DirectoryManifest, *, attempt_id: str, arm_id: str,
                               action: str, handler_revision: str, execution_result_digest: str,
                               collected_at: datetime) -> dict:
    """Mint a reader-observation.v1 over a manifest: the input block carries a
    manifest digest over the canonical entry list plus summary fields."""
    if not isinstance(manifest, DirectoryManifest):
        raise ObservationError("manifest must be a DirectoryManifest")
    return _document(
        manifest,
        attempt_id=_attempt_id(attempt_id),
        arm_id=_field(arm_id, label="arm_id"),
        action=_field(action, label="action"),
        handler_revision=_field(handler_revision, label="handler_revision"),
        execution_result_digest=_digest_field(execution_result_digest,
                                              label="execution_result_digest"),
        collected_at=_collected_at(collected_at),
    )


def verify_reader_observation(observation: object, *, acquisition: object,
                              seen_observation_ids: object) -> VerificationResult:
    """Re-derive the full document from the acquisition; require exact equality.

    The acquisition carries no attempt identity of its own, so the detectable
    splice signal is an observation id that disagrees with the identity fields
    of its own body: refused as cross-attempt. An id present in the caller's
    durable seen set is replayed. Any other re-derivation difference (input
    digest, custody, limitations, non-canonical collected_at) is a
    document-mismatch. The seen set is never copied or stored here.
    """
    if not isinstance(observation, dict) or set(observation) != _FIELDS:
        return VerificationResult(False, ("malformed",))
    if (observation.get("schema") != SCHEMA
            or observation.get("schema_version") != SCHEMA_VERSION
            or observation.get("custody") != CUSTODY
            or observation.get("evidence_class") != EVIDENCE_CLASS
            or observation.get("limitations") != list(LIMITATIONS)
            or not isinstance(observation.get("input"), dict)):
        return VerificationResult(False, ("malformed",))
    observed_id = observation.get("observation_id")
    if not isinstance(observed_id, str) or not _DIGEST.fullmatch(observed_id):
        return VerificationResult(False, ("malformed",))
    reasons: list[str] = []
    if (isinstance(seen_observation_ids, (set, frozenset, tuple, list))
            and observed_id in seen_observation_ids):
        reasons.append("replayed")
    try:
        attempt_id, arm_id, action, handler_revision, result_digest, collected_at = (
            _binding(observation))
    except ObservationError:
        reasons.append("malformed")
        return VerificationResult(False, tuple(reasons))
    if observed_id != observation_identity(attempt_id, arm_id, action):
        reasons.append("cross-attempt")
    try:
        expected = _document(acquisition, attempt_id=attempt_id, arm_id=arm_id, action=action,
                             handler_revision=handler_revision,
                             execution_result_digest=result_digest, collected_at=collected_at)
    except ObservationError:
        reasons.append("document-mismatch")
        return VerificationResult(False, tuple(reasons))
    if observation != expected:
        reasons.append("document-mismatch")
    return VerificationResult(ok=not reasons, reasons=tuple(reasons))
