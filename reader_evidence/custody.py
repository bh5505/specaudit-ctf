"""Authenticated durable custody / replay journal over reader observations.

One JSON-lines record per observed acquisition (``reader-observation.v1``
document + its ``AcquisitionRecord``). The journal chains and optionally
MACs custody assertions; it never claims what it cannot know:

- ``operator-asserted-custody``: the caller asserts holding the artifact.
  The journal records the assertion and verifies nothing.
- ``verified-custody``: the journal writer actually held the bytes at
  append time (the bytes are re-received and their digest recomputed
  against the acquisition record). ``verify_journal`` can re-verify a
  retained record against caller-supplied artifacts.
- ``source-authentic`` is NOT claimable by this local library: the name
  exists only as a constant and every write of it is refused. Whether an
  artifact's SOURCE is authentic remains an open operator gate.

Integrity limits, stated honestly (mirrors attempt_ledger): the HMAC key
is an operator-chosen LOCAL trust root — nothing here claims an operator
provisioned or used it, and a key holder can always rewrite history. In
unkeyed mode the chain detects in-place edits only while the operator
independently retains the last head digest, and it authenticates nothing.
Neither mode makes the stored file immutable. Replay detection is bounded
by the journal itself: an observation id absent from the retained records
cannot be recognized as a replay.

``acquisition_digest`` binds the AcquisitionRecord's content-identity
fields (size_bytes, sha256) so caller-retained artifact bytes can be
re-verified from the record alone; the full observation document (locator
fields included) is bound through observation_digest and lives outside
the journal, like every ledger detail body. One journal serves one
attempt: journal_id is derived from the attempt id, and a record whose
attempt differs is refused as cross-attempt. No network, no subprocess,
no clock reads: callers supply every timestamp, and no seen-id state is
stored anywhere but the journal itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
import re
from typing import Mapping, Sequence

from reader_evidence.acquisition import AcquisitionRecord
from reader_evidence.observations import (
    _MAX_FIELD,
    _ATTEMPT_ID as _OBSERVATION_ATTEMPT_ID,
    verify_reader_observation,
)

CUSTODY_JOURNAL_SCHEMA = "specaudit.ctf.custody-journal.v1"
SCHEMA_VERSION = 1
# Writable states. "source-authentic" is exposed as a name ONLY: appending
# or carrying it is refused, because local bytes cannot prove source
# authenticity (that gate belongs to the operator).
CUSTODY_OPERATOR_ASSERTED = "operator-asserted-custody"
CUSTODY_VERIFIED = "verified-custody"
CUSTODY_SOURCE_AUTHENTIC = "source-authentic"
WRITABLE_CUSTODY_STATES = frozenset({CUSTODY_OPERATOR_ASSERTED, CUSTODY_VERIFIED})

# Bound for caller-supplied verified bytes: the journal re-holds them only
# long enough to recompute the digest, never stores them, and refuses
# unbounded reads.
MAX_VERIFIED_BYTES = 65_536 * 1024

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TAG_FIELD = "auth_tag"
_CONTENT_FIELDS = ("seq", "journal_id", "observation_id", "observation_digest",
                   "acquisition_digest", "attempt_id", "arm_id", "action",
                   "custody_state", "recorded_at", "prev_record_digest")
_ROW_FIELDS = frozenset({"schema", "schema_version", *_CONTENT_FIELDS,
                         "record_digest"})


class CustodyError(ValueError):
    """Typed custody refusal; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class VerificationResult:
    """Verifier outcome; reasons use malformed / seq-mismatch /
    prev-digest-mismatch / record-digest-mismatch / auth-tag-mismatch /
    auth-tag-missing / auth-tag-present-without-key / replayed-observation /
    cross-attempt / custody-bytes-mismatch / head-mismatch."""

    ok: bool
    reasons: tuple[str, ...]


def _canonical(document: Mapping[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=False).encode("utf-8")


def _digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _field(value: object, *, label: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > _MAX_FIELD
            or any(ord(char) < 32 for char in value)):
        raise CustodyError("malformed", f"{label} must be a nonempty bounded string")
    return value


def _digest_field(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise CustodyError("malformed", f"{label} must be sha256:<64 lowercase hex>")
    return value


def _attempt_id(value: object) -> str:
    if not isinstance(value, str) or not _OBSERVATION_ATTEMPT_ID.fullmatch(value):
        raise CustodyError("malformed",
                           "attempt id must match [a-z0-9][a-z0-9._-]{7,63}")
    return value


def _recorded_at(value: object) -> str:
    """Normalize a caller-supplied naive iso datetime to canonical iso text."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise CustodyError("malformed",
                               f"recorded_at is not an iso datetime: {value!r}") from exc
    if not isinstance(value, datetime) or value.tzinfo is not None:
        raise CustodyError("malformed", "recorded_at must be naive; callers own the clock")
    return value.isoformat()


def journal_identity(attempt_id: str) -> str:
    """The journal id: derived from the attempt identity, so a record that
    claims another journal's id under a different attempt is detectable."""
    payload = "\x1f".join((CUSTODY_JOURNAL_SCHEMA, str(SCHEMA_VERSION), attempt_id))
    return _digest_bytes(payload.encode("utf-8"))


def observation_digest(observation: Mapping[str, object]) -> str:
    """Content digest over the canonical observation document (held outside
    the journal; the journal carries only this binding)."""
    return _digest_bytes(_canonical(observation))


def acquisition_digest(acquisition: AcquisitionRecord) -> str:
    """Content-identity digest of one acquisition record.

    Covers exactly the fields that identify the BYTES (size_bytes, sha256);
    locator and time fields are audit metadata carried by the observation
    document, not content identity. Defined over these fields so a verifier
    holding only artifact bytes can recompute the digest and compare.
    """
    fields = {"sha256": acquisition.sha256, "size_bytes": acquisition.size_bytes}
    return _digest_bytes(_canonical(fields))


def _digest_of_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def record_digest(record: Mapping[str, object]) -> str:
    """Recompute the chain digest: sha256 over the canonical record minus
    record_digest and auth_tag."""
    body = {key: value for key, value in record.items()
            if key not in ("record_digest", _TAG_FIELD)}
    return _digest_bytes(_canonical(body))


def _head(records: Sequence[Mapping[str, object]]) -> str | None:
    return records[-1].get("record_digest") if records else None


def append_observation(
    journal_records: Sequence[Mapping[str, object]],
    observation: Mapping[str, object],
    acquisition: AcquisitionRecord,
    *,
    custody_state: str,
    recorded_at: datetime | str,
    hmac_key: bytes | None = None,
    verified_bytes: bytes | None = None,
) -> tuple[tuple[dict, ...], str]:
    """Append one custody record for an observed acquisition.

    Refusals (typed, fail-closed):
    - custody_state ``source-authentic``: reason
      ``source-authenticity-not-locally-claimable`` (always);
    - custody_state ``verified-custody`` without re-received bytes whose
      recomputed digest matches the acquisition: ``custody-bytes-mismatch``;
    - an observation that does not re-derive from the acquisition
      (shape, binding, or identity mismatch): ``observation-mismatch``;
    - a repeated observation_id in the journal: ``replayed-observation``;
    - an attempt differing from the journal's bound attempt:
      ``cross-attempt``.

    With hmac_key, the stored record gains auth_tag = HMAC-SHA256(key,
    canonical record bytes including record_digest). Returns the new
    records tuple and the new head digest. The existing records are not
    re-verified here; callers verify the loaded journal first.
    """
    if not isinstance(journal_records, (list, tuple)):
        raise CustodyError("malformed", "journal records must be a list or tuple")
    if any(not isinstance(item, Mapping) for item in journal_records):
        raise CustodyError("malformed", "journal records must contain only record objects")
    if not isinstance(acquisition, AcquisitionRecord):
        raise CustodyError("malformed", "acquisition must be an AcquisitionRecord")
    if custody_state == CUSTODY_SOURCE_AUTHENTIC:
        raise CustodyError(
            "source-authenticity-not-locally-claimable",
            "source-authenticity is an open operator gate; local bytes and a "
            "local key cannot claim it, so this journal refuses the state")
    if custody_state not in WRITABLE_CUSTODY_STATES:
        raise CustodyError(
            "malformed",
            f"custody_state must be one of {sorted(WRITABLE_CUSTODY_STATES)}")
    if custody_state == CUSTODY_VERIFIED:
        if verified_bytes is None:
            raise CustodyError(
                "custody-bytes-mismatch",
                "verified-custody requires the acquisition bytes at append time")
        data = bytes(verified_bytes)
        if len(data) > MAX_VERIFIED_BYTES:
            raise CustodyError("oversized",
                               f"verified bytes exceed the {MAX_VERIFIED_BYTES}-byte cap")
        if (len(data) != acquisition.size_bytes
                or _digest_of_bytes(data) != acquisition.sha256):
            raise CustodyError(
                "custody-bytes-mismatch",
                "re-received bytes do not match the acquisition record's digest")
    # Reuse the observation binding check: the document must re-derive
    # exactly from this acquisition (shape, input block, identity fields).
    check = verify_reader_observation(
        observation, acquisition=acquisition, seen_observation_ids=())
    if not check.ok:
        raise CustodyError(
            "observation-mismatch",
            f"observation does not bind this acquisition: {', '.join(check.reasons)}")
    attempt_id = _attempt_id(observation.get("attempt_id"))
    existing = tuple(dict(item) for item in journal_records)
    for prior in existing:
        if prior.get("observation_id") == observation.get("observation_id"):
            raise CustodyError(
                "replayed-observation",
                f"observation {observation.get('observation_id')} is already journalled")
    journal_id = journal_identity(attempt_id)
    for prior in existing:
        if prior.get("attempt_id") != attempt_id or prior.get("journal_id") != journal_id:
            raise CustodyError(
                "cross-attempt",
                "one journal serves one attempt; a differing attempt_id is refused")
    stored: dict = {
        "schema": CUSTODY_JOURNAL_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "seq": len(existing) + 1,
        "journal_id": journal_id,
        "observation_id": observation["observation_id"],
        "observation_digest": observation_digest(observation),
        "acquisition_digest": acquisition_digest(acquisition),
        "attempt_id": attempt_id,
        "arm_id": _field(observation.get("arm_id"), label="arm_id"),
        "action": _field(observation.get("action"), label="action"),
        "custody_state": custody_state,
        "recorded_at": _recorded_at(recorded_at),
        "prev_record_digest": _head(existing),
    }
    stored["record_digest"] = record_digest(stored)
    if hmac_key is not None:
        if not isinstance(hmac_key, bytes) or not hmac_key:
            raise CustodyError("malformed", "hmac_key must be nonempty bytes")
        stored[_TAG_FIELD] = hmac.new(
            hmac_key, _canonical(stored), hashlib.sha256).hexdigest()
    return existing + (stored,), stored["record_digest"]


def _record_problems(record: Mapping[str, object], *, seq: int,
                     prev_digest: object) -> list[str]:
    """Structural, state and chain problems of one stored record."""
    problems: list[str] = []
    keys = set(record)
    if keys != _ROW_FIELDS and keys != _ROW_FIELDS | {_TAG_FIELD}:
        return ["malformed"]
    if (record.get("schema") != CUSTODY_JOURNAL_SCHEMA
            or record.get("schema_version") != SCHEMA_VERSION
            or not isinstance(record.get("seq"), int)
            or isinstance(record.get("seq"), bool)):
        return ["malformed"]
    try:
        if record.get("custody_state") not in WRITABLE_CUSTODY_STATES:
            # A hand-written source-authentic row must not pass, even before
            # the digest checks run.
            raise CustodyError(
                "malformed",
                f"custody_state must be one of {sorted(WRITABLE_CUSTODY_STATES)}")
        _digest_field(record.get("journal_id"), label="journal_id")
        _digest_field(record.get("observation_id"), label="observation_id")
        _digest_field(record.get("observation_digest"), label="observation_digest")
        _digest_field(record.get("acquisition_digest"), label="acquisition_digest")
        _attempt_id(record.get("attempt_id"))
        _field(record.get("arm_id"), label="arm_id")
        _field(record.get("action"), label="action")
        _recorded_at(record.get("recorded_at"))
        prev = record.get("prev_record_digest")
        if prev is not None:
            _digest_field(prev, label="prev_record_digest")
        digest_value = record.get("record_digest")
        if not isinstance(digest_value, str) or not _DIGEST.fullmatch(digest_value):
            raise CustodyError("malformed",
                               "record_digest must be sha256:<64 lowercase hex>")
    except CustodyError:
        return ["malformed"]
    if record["seq"] != seq:
        problems.append("seq-mismatch")
    if record.get("prev_record_digest") != prev_digest:
        problems.append("prev-digest-mismatch")
    if record_digest(record) != record["record_digest"]:
        problems.append("record-digest-mismatch")
    return problems


def verify_journal(
    records: Sequence[Mapping[str, object]],
    *,
    hmac_key: bytes | None = None,
    retained_head: str | None = None,
    artifacts: Mapping[str, bytes] | None = None,
) -> VerificationResult:
    """Full-journal verification: per-record shape, state taxonomy,
    sequential seq, prev-record chaining, record-digest recomputation,
    replay detection, and attempt/journal consistency. With hmac_key,
    every record's auth_tag is checked; a tagged record without the key
    is refused as auth-tag-present-without-key rather than silently
    passing unverified. Truncation is detected ONLY against
    retained_head. ``artifacts`` (observation_id → bytes) re-verifies
    ``verified-custody`` records whose observation id is present;
    retained bytes that no longer match are custody-bytes-mismatch
    (absent artifacts are simply unverifiable here). Neither mode
    authenticates the file as a whole; see the module docstring for the
    honest limits."""
    if not isinstance(records, (list, tuple)) or any(
            not isinstance(item, Mapping) for item in records):
        return VerificationResult(False, ("malformed",))
    reasons: list[str] = []
    seen_observations: set[str] = set()
    verified_digests: dict[str, str] = {}
    bound_attempt: str | None = None
    prev_digest: object = None
    for index, record in enumerate(records):
        seq = index + 1
        keys = set(record)
        tagged = _TAG_FIELD in keys
        if hmac_key is not None and not tagged:
            reasons.append("auth-tag-missing")
        if hmac_key is None and tagged:
            reasons.append("auth-tag-present-without-key")
        problems = _record_problems(record, seq=seq, prev_digest=prev_digest)
        reasons.extend(problems)
        if not problems:
            observation_id = record["observation_id"]
            if observation_id in seen_observations:
                reasons.append("replayed-observation")
            seen_observations.add(observation_id)
            attempt_id = record["attempt_id"]
            if attempt_id != bound_attempt:
                if bound_attempt is None and record.get(
                        "journal_id") == journal_identity(attempt_id):
                    bound_attempt = attempt_id
                else:
                    reasons.append("cross-attempt")
            if record["custody_state"] == CUSTODY_VERIFIED:
                verified_digests[observation_id] = record["acquisition_digest"]
            if hmac_key is not None and tagged:
                expected = hmac.new(hmac_key, _canonical(
                    {key: value for key, value in record.items()
                     if key != _TAG_FIELD}),
                    hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, record[_TAG_FIELD]):
                    reasons.append("auth-tag-mismatch")
        prev_digest = record.get("record_digest") if isinstance(record, Mapping) else None
    if retained_head is not None:
        head = records[-1].get("record_digest") if records else None
        if head != retained_head:
            reasons.append("head-mismatch")
    if artifacts is not None:
        for observation_id, data in artifacts.items():
            # Absent observation ids are simply unverifiable here; only a
            # retained artifact that contradicts its record is a mismatch.
            if observation_id not in verified_digests:
                continue
            if not isinstance(data, (bytes, bytearray)):
                reasons.append("custody-bytes-mismatch")
                continue
            candidate = _digest_bytes(_canonical(
                {"sha256": _digest_of_bytes(bytes(data)), "size_bytes": len(data)}))
            if candidate != verified_digests[observation_id]:
                reasons.append("custody-bytes-mismatch")
    return VerificationResult(not reasons, tuple(dict.fromkeys(reasons)))
