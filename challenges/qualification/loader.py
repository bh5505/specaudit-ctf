"""Calibration-seed loader and the seed/human-calibration discriminator.

A calibration seed is a machine-discriminated author sample: its embedded
adjudication always carries reviewer ``calibration-seed`` AND a null
``adjusted_score``. The pair of markers is the contract: any code path that
would count a seed chain as human calibration must not exist, so this module
ships exactly one counting rule -- :func:`is_human_calibration` -- and it
refuses every seed by construction. An adjudication with a null adjusted
score is never counted as human calibration, whichever reviewer it names:
counting in that direction would be the seed-shaped hole this module exists
to close. The conservative failure direction is a refused count, never a
counted seed.

Digests are ``sha256:<64 hex>`` over canonical JSON bytes (sort_keys, compact
separators, non-finite numbers refused) of the embedded submission document,
recomputed on load: a seed whose embedded submission does not hash to its own
``submission_digest`` is refused, so the anchored sample cannot drift from
its digest. No network, no subprocess, no clock reads.
"""
from __future__ import annotations

from datetime import date
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

SEED_SCHEMA = "specaudit.ctf.calibration-seed.v1"
SEED_REVIEWER = "calibration-seed"

_SEED_FIELDS = frozenset({
    "schema", "pilot", "seed_id", "anchored_sample",
    "rubric_dimensions_touched", "adjudication", "note",
})
_SAMPLE_FIELDS = frozenset({
    "description", "submission_schema", "submission_digest", "submission",
    "machine_check",
})
_ADJUDICATION_FIELDS = frozenset({
    "original_score", "adjusted_score", "reviewer", "rationale", "decided_on",
})
_MACHINE_CHECK_KINDS = frozenset({
    "review-workpaper-structural", "agent-trace-grade", "detection-grade",
    "capture-reference",
})
_MAX_FIELD = 1024
_MAX_DOC_BYTES = 262_144
_DIGEST = None  # compiled lazily; see _digest_field


class SeedError(ValueError):
    """Typed seed refusal; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _digest_pattern():
    global _DIGEST
    if _DIGEST is None:
        import re
        _DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
    return _DIGEST


def _text(value: object, *, label: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > _MAX_FIELD
            or any(ord(char) < 32 for char in value)):
        raise SeedError("malformed", f"{label} must be a nonempty bounded string")
    return value


def _digest_field(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _digest_pattern().fullmatch(value):
        raise SeedError("malformed", f"{label} must be sha256:<64 lowercase hex>")
    return value


def canonical_bytes(document: Any) -> bytes:
    """Canonical JSON bytes: sort_keys, compact separators, allow_nan=False.

    The same canonicalization the attempt ledger uses, so a submission
    digest is stable across loaders and hosts.
    """
    try:
        return json.dumps(document, sort_keys=True, separators=(",", ":"),
                          allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SeedError("malformed", f"submission is not canonicalizable: {exc}") from exc


def submission_digest(submission: Any) -> str:
    """The digest a seed's ``submission_digest`` must carry."""
    return "sha256:" + hashlib.sha256(canonical_bytes(submission)).hexdigest()


def load_seed(path: str | Path) -> dict:
    """Load and validate one calibration-seed JSON file; closed shape.

    Refuses: unknown or missing top-level/sample/adjudication fields, a
    reviewer other than ``calibration-seed``, a non-null ``adjusted_score``,
    and an embedded submission whose recomputed digest differs from the
    recorded ``submission_digest``. Returns the parsed document; it never
    mutates the file and never reads a clock.
    """
    raw = Path(path).read_bytes()
    if len(raw) > _MAX_DOC_BYTES:
        raise SeedError("oversized", f"seed exceeds {_MAX_DOC_BYTES} bytes: {path}")
    try:
        seed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SeedError("malformed", f"seed is not valid UTF-8 JSON: {path}: {exc}") from exc
    _validate_seed(seed, source=str(path))
    return seed


def _validate_seed(seed: object, *, source: str) -> None:
    if not isinstance(seed, Mapping) or set(seed) != _SEED_FIELDS:
        raise SeedError(
            "malformed",
            f"{source}: seed needs exactly {sorted(_SEED_FIELDS)}")
    if seed["schema"] != SEED_SCHEMA:
        raise SeedError("malformed",
                        f"{source}: unsupported seed schema {seed['schema']!r}")
    _text(seed.get("pilot"), label=f"{source}: pilot")
    _text(seed.get("seed_id"), label=f"{source}: seed_id")
    _text(seed.get("note"), label=f"{source}: note")
    dimensions = seed.get("rubric_dimensions_touched")
    if (not isinstance(dimensions, list) or not dimensions
            or len(dimensions) > 16
            or any(not isinstance(item, str) or not item for item in dimensions)):
        raise SeedError("malformed",
                        f"{source}: rubric_dimensions_touched must be a nonempty "
                        "bounded string list")
    for item in dimensions:
        _text(item, label=f"{source}: rubric dimension")

    sample = seed.get("anchored_sample")
    if not isinstance(sample, Mapping) or set(sample) != _SAMPLE_FIELDS:
        raise SeedError(
            "malformed",
            f"{source}: anchored_sample needs exactly {sorted(_SAMPLE_FIELDS)}")
    _text(sample.get("description"), label=f"{source}: anchored_sample.description")
    _text(sample.get("submission_schema"), label=f"{source}: submission_schema")
    _digest_field(sample.get("submission_digest"), label=f"{source}: submission_digest")
    machine = sample.get("machine_check")
    if (not isinstance(machine, Mapping) or set(machine) != {"kind", "expectation"}
            or machine.get("kind") not in _MACHINE_CHECK_KINDS
            or not isinstance(machine.get("expectation"), Mapping)):
        raise SeedError("malformed",
                        f"{source}: machine_check needs kind (one of "
                        f"{sorted(_MACHINE_CHECK_KINDS)}) and expectation object")

    adjudication = seed.get("adjudication")
    if (not isinstance(adjudication, Mapping)
            or set(adjudication) != _ADJUDICATION_FIELDS):
        raise SeedError(
            "malformed",
            f"{source}: adjudication needs exactly {sorted(_ADJUDICATION_FIELDS)}")
    # The two markers that make a seed machine-discriminated are mandatory:
    # a seed with a person-like or role reviewer, or a retained adjustment,
    # is refused at load time -- before any counting code can see it.
    if adjudication.get("reviewer") != SEED_REVIEWER:
        raise SeedError("seed-reviewer-required",
                        f"{source}: seed adjudication reviewer must be "
                        f"{SEED_REVIEWER!r}")
    if adjudication.get("adjusted_score") is not None:
        raise SeedError("seed-adjusted-score-must-be-null",
                        f"{source}: seed adjudication adjusted_score must be null; "
                        "a seed is an author sample awaiting FIRST human "
                        "double-scoring, not a rescoring loop")
    _text(adjudication.get("original_score"), label=f"{source}: original_score")
    _text(adjudication.get("rationale"), label=f"{source}: rationale")
    decided = adjudication.get("decided_on")
    _text(decided, label=f"{source}: decided_on")
    try:
        date.fromisoformat(decided)
    except ValueError as exc:
        raise SeedError("malformed",
                        f"{source}: decided_on is not an ISO date: {decided!r}") from exc

    recomputed = submission_digest(sample.get("submission"))
    if recomputed != sample["submission_digest"]:
        raise SeedError(
            "submission-digest-mismatch",
            f"{source}: embedded submission hashes to {recomputed}, not the "
            f"recorded {sample['submission_digest']}")


def is_human_calibration(chain: object) -> bool:
    """Whether one evidence-chain adjudication counts as HUMAN calibration.

    False for every calibration seed, by construction: a seed's adjudication
    names reviewer ``calibration-seed`` and carries a null adjusted_score,
    and this rule counts a chain as human calibration only when BOTH the
    reviewer is not the seed marker AND the adjusted score is retained.
    Accepts a full evidence-chain document (reads its ``adjudication``
    layer) or a bare adjudication mapping. Anything malformed is False.
    """
    adjudication: object = chain
    if isinstance(chain, Mapping) and isinstance(chain.get("adjudication"), Mapping):
        adjudication = chain["adjudication"]
    if not isinstance(adjudication, Mapping):
        return False
    if adjudication.get("reviewer") == SEED_REVIEWER:
        return False
    if adjudication.get("adjusted_score") is None:
        return False
    return True
