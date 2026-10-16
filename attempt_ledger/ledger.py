"""Append-only attempt ledger for CTF evaluation runs.

One row per graded or dispatched attempt. Rows chain through SHA-256
digests over canonical JSON (sort_keys, compact separators, non-finite
numbers refused). The caller supplies every timestamp and every detail
digest: the structured detail document itself lives OUTSIDE the ledger
and is never copied into it.

Integrity limits, stated honestly: in unkeyed mode the chain detects
in-place edits only while the operator independently retains the last
head digest, and it authenticates nothing; in keyed mode each row
carries an HMAC-SHA256 tag under an operator-held key, so a holder of
the file alone cannot forge or retarget rows, but the key holder can
always rewrite history. Neither mode makes the stored file immutable.

The denominator is every row: failures, refusals, timeouts and
abstentions are never dropped from summaries, and lanes are never
compared as equivalent. No network, no subprocess, no clock reads, no
stored module state.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
import re
from typing import Mapping, Sequence

SCHEMA = "specaudit.ctf.attempt-ledger.v1"
SCHEMA_VERSION = 1
LANES = frozenset({
    "fixture-backed", "live-service", "planted-code", "self-study",
    "operator-rehearsal",
})
ATTEMPT_CLASSES = frozenset({
    "setup-failure", "refusal", "parse-failure", "not-found", "timeout",
    "crash", "safety-stop", "interruption", "abstention", "completion",
})
ASSISTANCE = frozenset({"first-pass", "assisted", "tuned", "held-out", "none"})
COMPLETION = "completion"
_ATTEMPT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{7,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_FIELD = 256
# append_row accepts exactly these content fields (outcome optional);
# schema, schema_version, ledger_seq, prev_row_digest, row_digest and the
# optional auth_tag are derived here and must never be caller-supplied.
_CONTENT_FIELDS = frozenset({
    "attempt_id", "lane", "subject", "attempt_class", "assistance",
    "detail_digest", "recorded_at",
})
_ROW_FIELDS = frozenset({
    "schema", "schema_version", "ledger_seq", "attempt_id", "lane", "subject",
    "attempt_class", "outcome", "assistance", "detail_digest", "recorded_at",
    "prev_row_digest", "row_digest",
})
_TAG_FIELD = "auth_tag"


class LedgerError(ValueError):
    """Typed ledger refusal; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class VerificationResult:
    """Verifier outcome; reasons use malformed / seq-mismatch / prev-digest-mismatch
    / row-digest-mismatch / auth-tag-mismatch / auth-tag-missing /
    auth-tag-present-without-key / attempt-identity-conflict / head-mismatch."""

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
        raise LedgerError("malformed", f"{label} must be a nonempty bounded string")
    return value


def _attempt_id(value: object) -> str:
    if not isinstance(value, str) or not _ATTEMPT_ID.fullmatch(value):
        raise LedgerError("malformed", "attempt id must match [a-z0-9][a-z0-9._-]{7,127}")
    return value


def _digest_field(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise LedgerError("malformed", f"{label} must be sha256:<64 lowercase hex>")
    return value


def _recorded_at(value: object) -> str:
    """Normalize a caller-supplied naive iso datetime to canonical iso text."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise LedgerError("malformed", f"recorded_at is not an iso datetime: {value!r}") from exc
    if not isinstance(value, datetime) or value.tzinfo is not None:
        raise LedgerError("malformed", "recorded_at must be naive; callers own the clock")
    return value.isoformat()


def _outcome(value: object, *, attempt_class: str) -> str | None:
    if value is None:
        if attempt_class == COMPLETION:
            raise LedgerError("malformed", "completion rows require a nonempty outcome")
        return None
    return _field(value, label="outcome")


def _taxonomy(row: Mapping[str, object]) -> None:
    if row.get("lane") not in LANES:
        raise LedgerError("malformed", f"lane must be one of {sorted(LANES)}")
    if row.get("attempt_class") not in ATTEMPT_CLASSES:
        raise LedgerError("malformed", f"attempt_class must be one of {sorted(ATTEMPT_CLASSES)}")
    if row.get("assistance") not in ASSISTANCE:
        raise LedgerError("malformed", f"assistance must be one of {sorted(ASSISTANCE)}")


def _content(row: Mapping[str, object]) -> dict:
    """Validate caller-supplied content; returns the normalized content dict."""
    keys = set(row)
    if not keys <= _CONTENT_FIELDS | {"outcome"} or not keys:
        raise LedgerError(
            "malformed",
            "row content must contain only attempt_id, lane, subject, attempt_class, "
            "assistance, detail_digest, recorded_at and optional outcome")
    attempt_class = row.get("attempt_class")
    if attempt_class not in ATTEMPT_CLASSES:
        raise LedgerError("malformed", f"attempt_class must be one of {sorted(ATTEMPT_CLASSES)}")
    if row.get("lane") not in LANES:
        raise LedgerError("malformed", f"lane must be one of {sorted(LANES)}")
    if row.get("assistance") not in ASSISTANCE:
        raise LedgerError("malformed", f"assistance must be one of {sorted(ASSISTANCE)}")
    return {
        "attempt_id": _attempt_id(row.get("attempt_id")),
        "lane": _field(row.get("lane"), label="lane"),
        "subject": _field(row.get("subject"), label="subject"),
        "attempt_class": attempt_class,
        "outcome": _outcome(row.get("outcome"), attempt_class=attempt_class),
        "assistance": _field(row.get("assistance"), label="assistance"),
        "detail_digest": _digest_field(row.get("detail_digest"), label="detail_digest"),
        "recorded_at": _recorded_at(row.get("recorded_at")),
    }


def row_digest(row: Mapping[str, object]) -> str:
    """Recompute the chain digest: sha256 over the canonical row minus
    row_digest and auth_tag."""
    body = {key: value for key, value in row.items()
            if key not in ("row_digest", _TAG_FIELD)}
    return _digest_bytes(_canonical(body))


def append_row(rows: Sequence[Mapping[str, object]], row: Mapping[str, object], *,
               expected_head: str | None = None,
               hmac_key: bytes | None = None) -> tuple[tuple[dict, ...], str]:
    """Validate one attempt against the taxonomy and chain it onto ``rows``.

    Enforces seq = len(rows) + 1, prev_row_digest = previous row_digest
    (None iff seq 1), and attempt identity: reusing an attempt_id with a
    DIFFERENT (attempt_class, assistance, lane) triple is refused as
    attempt-identity-conflict; the same triple is a legitimate retry and
    is allowed. When expected_head is given it must equal the head of the
    chain being extended (out-of-band anchoring of the pre-append head);
    any other value is refused as head-mismatch. With hmac_key, the
    stored row gains auth_tag = HMAC-SHA256(key, canonical row bytes
    including row_digest). Returns the new rows tuple and the new head
    digest. The existing rows are not re-verified here; callers verify
    the loaded chain first.
    """
    if not isinstance(rows, (list, tuple)):
        raise LedgerError("malformed", "rows must be a list or tuple of row objects")
    if any(not isinstance(item, Mapping) for item in rows):
        raise LedgerError("malformed", "rows must contain only row objects")
    content = _content(row)
    existing = tuple(dict(item) for item in rows)
    current_head = existing[-1].get("row_digest") if existing else None
    if expected_head is not None and expected_head != current_head:
        raise LedgerError(
            "head-mismatch",
            f"expected head {expected_head} does not anchor this chain (head {current_head})")
    for prior in existing:
        if prior.get("attempt_id") != content["attempt_id"]:
            continue
        if (prior.get("attempt_class"), prior.get("assistance"), prior.get("lane")) != (
                content["attempt_class"], content["assistance"], content["lane"]):
            raise LedgerError(
                "attempt-identity-conflict",
                "attempt_id reuse with a different (attempt_class, assistance, lane) "
                "triple is refused; the same triple is a legitimate retry")
    stored: dict = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "ledger_seq": len(existing) + 1,
        **content,
        "prev_row_digest": current_head,
    }
    stored["row_digest"] = row_digest(stored)
    if hmac_key is not None:
        if not isinstance(hmac_key, bytes) or not hmac_key:
            raise LedgerError("malformed", "hmac_key must be nonempty bytes")
        stored[_TAG_FIELD] = hmac.new(
            hmac_key, _canonical(stored), hashlib.sha256).hexdigest()
    return existing + (stored,), stored["row_digest"]


def _row_problems(row: Mapping[str, object], *, seq: int,
                  prev_digest: object) -> list[str]:
    """Structural, taxonomic and chain problems of one stored row."""
    problems: list[str] = []
    keys = set(row)
    if keys != _ROW_FIELDS and keys != _ROW_FIELDS | {_TAG_FIELD}:
        return ["malformed"]
    if (row.get("schema") != SCHEMA or row.get("schema_version") != SCHEMA_VERSION
            or not isinstance(row.get("ledger_seq"), int)
            or isinstance(row.get("ledger_seq"), bool)):
        return ["malformed"]
    try:
        _taxonomy(row)
        _attempt_id(row.get("attempt_id"))
        _field(row.get("subject"), label="subject")
        _digest_field(row.get("detail_digest"), label="detail_digest")
        _recorded_at(row.get("recorded_at"))
        _outcome(row.get("outcome"), attempt_class=row.get("attempt_class"))
        _field(row.get("assistance"), label="assistance")
        digest_value = row.get("row_digest")
        if not isinstance(digest_value, str) or not _DIGEST.fullmatch(digest_value):
            raise LedgerError("malformed", "row_digest must be sha256:<64 lowercase hex>")
    except LedgerError:
        return ["malformed"]
    if row["ledger_seq"] != seq:
        problems.append("seq-mismatch")
    if row.get("prev_row_digest") != prev_digest:
        problems.append("prev-digest-mismatch")
    if row_digest(row) != row["row_digest"]:
        problems.append("row-digest-mismatch")
    return problems


def verify_ledger(rows: Sequence[Mapping[str, object]], *, hmac_key: bytes | None = None,
                  retained_head: str | None = None) -> VerificationResult:
    """Full-chain verification: per-row structure and taxonomy, sequential
    ledger_seq, prev_row_digest chaining, row_digest recomputation, and
    attempt-id consistency (a reused attempt_id must keep its
    (attempt_class, assistance, lane) triple). With hmac_key, every row's
    auth_tag is checked; a keyed row without the key is refused as
    auth-tag-present-without-key rather than silently passing unverified.
    Truncation is detected ONLY against retained_head: without it a
    shortened chain verifies as far as it goes -- retain the head
    out-of-band if tail-drop matters. Neither mode authenticates the
    file as a whole; see the module docstring for the honest limits.
    """
    if not isinstance(rows, (list, tuple)) or any(not isinstance(item, Mapping) for item in rows):
        return VerificationResult(False, ("malformed",))
    reasons: list[str] = []
    identities: dict[str, tuple[object, object, object]] = {}
    prev_digest: object = None
    for index, row in enumerate(rows):
        seq = index + 1
        keys = set(row)
        tagged = _TAG_FIELD in keys
        if hmac_key is not None and not tagged:
            reasons.append("auth-tag-missing")
        if hmac_key is None and tagged:
            reasons.append("auth-tag-present-without-key")
        problems = _row_problems(row, seq=seq, prev_digest=prev_digest)
        reasons.extend(problems)
        if not problems:
            attempt_id = row["attempt_id"]
            triple = (row["attempt_class"], row["assistance"], row["lane"])
            if attempt_id in identities and identities[attempt_id] != triple:
                reasons.append("attempt-identity-conflict")
            identities[attempt_id] = triple
            if hmac_key is not None and tagged:
                expected = hmac.new(hmac_key, _canonical(
                    {key: value for key, value in row.items() if key != _TAG_FIELD}),
                    hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, row[_TAG_FIELD]):
                    reasons.append("auth-tag-mismatch")
        prev_digest = row.get("row_digest") if isinstance(row, Mapping) else None
    if retained_head is not None:
        head = rows[-1].get("row_digest") if rows else None
        if head != retained_head:
            reasons.append("head-mismatch")
    return VerificationResult(not reasons, tuple(dict.fromkeys(reasons)))


def summarize(rows: Sequence[Mapping[str, object]]) -> dict:
    """Count one ledger, keeping the honest denominator.

    total, by_class, by_lane and by_assistance count EVERY row: failures,
    refusals, timeouts and abstentions are never dropped, and lanes are
    never compared as equivalent -- by_lane exists so each lane's
    completion share is read against its own denominator. numerators
    carries the completion counts (completions, completions_by_lane,
    completions_by_assistance) separately from that denominator. Raises
    LedgerError on any structurally invalid row; it does not authenticate
    (call verify_ledger for that).
    """
    if not isinstance(rows, (list, tuple)) or any(not isinstance(item, Mapping) for item in rows):
        raise LedgerError("malformed", "rows must be a list or tuple of row objects")
    by_class: dict[str, int] = {}
    by_lane: dict[str, int] = {}
    by_assistance: dict[str, int] = {}
    completions_by_lane: dict[str, int] = {}
    completions_by_assistance: dict[str, int] = {}
    completions = 0
    for row in rows:
        # Chain fields are passed through so only structure, taxonomy and
        # the row's own digest are checked here; chaining is verify_ledger's job.
        if _row_problems(row, seq=row.get("ledger_seq"),
                         prev_digest=row.get("prev_row_digest")):
            raise LedgerError("malformed",
                              f"row {row.get('ledger_seq')!r} is not a valid ledger row")
        by_class[row["attempt_class"]] = by_class.get(row["attempt_class"], 0) + 1
        by_lane[row["lane"]] = by_lane.get(row["lane"], 0) + 1
        by_assistance[row["assistance"]] = by_assistance.get(row["assistance"], 0) + 1
        if row["attempt_class"] == COMPLETION:
            completions += 1
            completions_by_lane[row["lane"]] = completions_by_lane.get(row["lane"], 0) + 1
            completions_by_assistance[row["assistance"]] = (
                completions_by_assistance.get(row["assistance"], 0) + 1)
    def sort(counts: dict[str, int]) -> dict[str, int]:
        return dict(sorted(counts.items()))

    return {
        "total": len(rows),
        "by_class": sort(by_class),
        "by_lane": sort(by_lane),
        "by_assistance": sort(by_assistance),
        "numerators": {
            "completions": completions,
            "completions_by_lane": sort(completions_by_lane),
            "completions_by_assistance": sort(completions_by_assistance),
        },
    }
