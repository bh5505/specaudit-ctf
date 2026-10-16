"""Five-layer adjudication evidence chain for CTF evaluation runs.

A chain binds five separately-attributable layers -- raw custody,
observations, inference, adjudication, workpaper -- plus sibling
machine/human verdicts and inherited limitations. Every layer body
lives OUTSIDE the chain: the chain carries only its digest and the
attribution fields listed here. Layer digest values are opaque to this
module; only their shape, taxonomy and cross-layer references are
verified.

Verification limits, stated honestly: the chain authenticates nothing
cryptographically and proves no custody -- digests bind bytes only
when the operator retains those bytes; sibling verdicts are verified
as siblings (no override field is admitted, ever), and evidence_class
values are carried through unchanged, so an observation declared
"declared" can never be upgraded to "observed" by chaining. The
adjudication date is checked against a caller-supplied as_of; this
module never reads a clock. No network, no subprocess, no stored
module state.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import re

SCHEMA = "specaudit.ctf.evidence-chain.v1"
SCHEMA_VERSION = 1
EVIDENCE_CLASSES = frozenset({"declared", "observed", "inferred"})
ANALYST_ROLE = "analyst"
RUBRIC_SOURCE = "rubric"
GRADING_SOURCE = "score.grading"
# A machine verdict from grading is exact fixture coverage only; any chain
# built on one inherits this limitation verbatim.
GRADING_LIMITATION = "machine-verdict-is-exact-fixture-coverage-only"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_FIELD = 256
_MAX_ITEMS = 64
_TOP_FIELDS = frozenset({
    "schema", "schema_version", "raw", "observations", "inference",
    "adjudication", "workpaper", "machine_verdict", "human_verdict",
    "inherited_limitations",
})


class ChainError(ValueError):
    """Typed evidence-chain refusal; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class VerificationResult:
    """Verifier outcome; reasons use malformed / inference-reference-mismatch /
    unanchored-observation / future-decision / override-verdict-present."""

    ok: bool
    reasons: tuple[str, ...]


def _field(value: object, *, label: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > _MAX_FIELD
            or any(ord(char) < 32 for char in value)):
        raise ChainError("malformed", f"{label} must be a nonempty bounded string")
    return value


def _digest_field(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ChainError("malformed", f"{label} must be sha256:<64 lowercase hex>")
    return value


def _verdict(value: object, *, label: str, sources: frozenset[str] | None) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"source", "digest"}:
        raise ChainError("malformed", f"{label} must be exactly {{source, digest}} or null")
    source = _field(value.get("source"), label=f"{label}.source")
    if sources is not None and source not in sources:
        raise ChainError("malformed", f"{label}.source must be one of {sorted(sources)}")
    return {"source": source, "digest": _digest_field(value.get("digest"),
                                                      label=f"{label}.digest")}


def _raw_items(raw: object) -> list[dict]:
    if not isinstance(raw, (list, tuple)) or not raw or len(raw) > _MAX_ITEMS:
        raise ChainError("malformed", f"raw must be a nonempty list of at most {_MAX_ITEMS} items")
    items = []
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != {"digest", "locator", "custody_note"}:
            raise ChainError("malformed", "raw items need exactly digest, locator, custody_note")
        items.append({
            # The locator is advisory-only: an audit hint, never identity or custody.
            "digest": _digest_field(entry.get("digest"), label="raw.digest"),
            "locator": _field(entry.get("locator"), label="raw.locator"),
            "custody_note": _field(entry.get("custody_note"), label="raw.custody_note"),
        })
    return items


def _observations(observations: object) -> list[dict]:
    if (not isinstance(observations, (list, tuple)) or not observations
            or len(observations) > _MAX_ITEMS):
        raise ChainError("malformed",
                         f"observations must be a nonempty list of at most {_MAX_ITEMS} items")
    items = []
    for entry in observations:
        if not isinstance(entry, dict):
            raise ChainError("malformed", "observations items must be objects")
        keys = set(entry)
        if keys != {"digest", "evidence_class"} and keys != {
                "observation_id", "digest", "evidence_class"}:
            raise ChainError("malformed",
                             "observation items need exactly optional observation_id, digest, "
                             "evidence_class")
        # evidence_class is carried through UNCHANGED; chaining never upgrades
        # declared to observed.
        evidence_class = entry.get("evidence_class")
        if evidence_class not in EVIDENCE_CLASSES:
            raise ChainError("malformed",
                             f"evidence_class must be one of {sorted(EVIDENCE_CLASSES)}")
        item = {"digest": _digest_field(entry.get("digest"), label="observation.digest"),
                "evidence_class": evidence_class}
        if "observation_id" in keys:
            item["observation_id"] = _field(entry.get("observation_id"),
                                            label="observation.observation_id")
        items.append(item)
    return items


def _inference(inference: object) -> dict:
    if not isinstance(inference, dict) or set(inference) != {
            "digest", "author_role", "statement_count"}:
        raise ChainError("malformed",
                         "inference needs exactly digest, author_role, statement_count")
    if inference.get("author_role") != ANALYST_ROLE:
        raise ChainError("malformed", f"inference.author_role must be {ANALYST_ROLE!r}")
    count = inference.get("statement_count")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10_000:
        raise ChainError("malformed", "inference.statement_count must be an integer in [1, 10000]")
    return {"digest": _digest_field(inference.get("digest"), label="inference.digest"),
            "author_role": ANALYST_ROLE, "statement_count": count}


def _decided_on(value: object) -> date:
    if not isinstance(value, str) or len(value) != 10:
        raise ChainError("malformed", "adjudication.decided_on must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ChainError("malformed",
                         f"adjudication.decided_on is not an ISO date: {value!r}") from exc


def _adjudication(adjudication: object, *, require_inference_digest: bool) -> dict:
    required = {"digest", "reviewer", "original_score", "adjusted_score", "rationale",
                "decided_on"} | ({"inference_digest"} if require_inference_digest else set())
    if not isinstance(adjudication, dict) or set(adjudication) != required:
        raise ChainError(
            "malformed",
            "adjudication needs exactly digest, reviewer, original_score, adjusted_score, "
            "rationale, decided_on" + (", inference_digest" if require_inference_digest else ""))
    original = adjudication.get("original_score")
    adjusted = adjudication.get("adjusted_score")
    # The original score is ALWAYS retained; the adjustment may be null but the
    # pair may not both be null.
    _field(original, label="adjudication.original_score")
    if adjusted is not None:
        _field(adjusted, label="adjudication.adjusted_score")
    out = {
        "digest": _digest_field(adjudication.get("digest"), label="adjudication.digest"),
        "reviewer": _field(adjudication.get("reviewer"), label="adjudication.reviewer"),
        "original_score": original,
        "adjusted_score": adjusted,
        "rationale": _field(adjudication.get("rationale"), label="adjudication.rationale"),
        "decided_on": _decided_on(adjudication.get("decided_on")).isoformat(),
    }
    if require_inference_digest:
        out["inference_digest"] = _digest_field(adjudication.get("inference_digest"),
                                                label="adjudication.inference_digest")
    return out


def _workpaper(workpaper: object) -> dict:
    if not isinstance(workpaper, dict) or set(workpaper) != {"digest", "conclusion"}:
        raise ChainError("malformed", "workpaper needs exactly digest, conclusion")
    return {"digest": _digest_field(workpaper.get("digest"), label="workpaper.digest"),
            "conclusion": _field(workpaper.get("conclusion"), label="workpaper.conclusion")}


def build_chain(raw: object, observations: object, inference: object,
                adjudication: object, workpaper: object, *,
                machine_verdict: object = None,
                human_verdict: object = None) -> dict:
    """Validate the five layers and assemble one evidence-chain.v1 document.

    Strict: every field set is exact, digests must be sha256:<64 hex>, and
    evidence_class values are carried through unchanged. The adjudication
    layer gains inference_digest here, binding it to the exact inference
    digest. When machine_verdict comes from grading, the chain inherits
    the source-verdict limitation verbatim; siblings stay siblings and no
    final/override verdict field exists to add. The document holds
    digests only; layer bodies stay with their custodians.
    """
    machine = _verdict(machine_verdict, label="machine_verdict", sources=None)
    human = _verdict(human_verdict, label="human_verdict",
                     sources=frozenset({RUBRIC_SOURCE}))
    inherited = ([GRADING_LIMITATION]
                 if machine is not None and machine["source"] == GRADING_SOURCE else [])
    inference_out = _inference(inference)
    adjudication_out = _adjudication(adjudication, require_inference_digest=False)
    # The adjudication layer binds to the exact inference digest here.
    adjudication_out["inference_digest"] = inference_out["digest"]
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "raw": _raw_items(raw),
        "observations": _observations(observations),
        "inference": inference_out,
        "adjudication": adjudication_out,
        "workpaper": _workpaper(workpaper),
        "machine_verdict": machine,
        "human_verdict": human,
        "inherited_limitations": inherited,
    }


def verify_chain(chain: object, *, as_of: date) -> VerificationResult:
    """Re-validate structure and the cross-layer rules.

    The adjudication must reference the exact inference digest; every
    observation digest must be present in the raw layer (unanchored
    observations are refused); decided_on may not lie in the future
    relative to the caller-supplied as_of; verdicts remain siblings --
    any "final_verdict" key, or any other key outside the closed schema,
    is refused. Re-runs the same strict layer validation as build_chain.
    """
    if not isinstance(chain, dict):
        return VerificationResult(False, ("malformed",))
    reasons: list[str] = []
    if "final_verdict" in chain:
        reasons.append("override-verdict-present")
    if set(chain) != _TOP_FIELDS:
        reasons.append("malformed")
        return VerificationResult(False, tuple(dict.fromkeys(reasons)))
    if chain.get("schema") != SCHEMA or chain.get("schema_version") != SCHEMA_VERSION:
        reasons.append("malformed")
    try:
        raw = _raw_items(chain.get("raw"))
        observations = _observations(chain.get("observations"))
        inference = _inference(chain.get("inference"))
        adjudication = _adjudication(chain.get("adjudication"),
                                     require_inference_digest=True)
        _workpaper(chain.get("workpaper"))
        _verdict(chain.get("machine_verdict"), label="machine_verdict", sources=None)
        _verdict(chain.get("human_verdict"), label="human_verdict",
                 sources=frozenset({RUBRIC_SOURCE}))
        limitations = chain.get("inherited_limitations")
        if (not isinstance(limitations, list) or len(limitations) > _MAX_ITEMS
                or len(set(limitations)) != len(limitations)):
            raise ChainError("malformed",
                             "inherited_limitations must be a bounded string list, without repeats")
        for item in limitations:
            _field(item, label="inherited_limitations item")
    except ChainError:
        reasons.append("malformed")
        return VerificationResult(False, tuple(dict.fromkeys(reasons)))
    if adjudication["inference_digest"] != inference["digest"]:
        reasons.append("inference-reference-mismatch")
    raw_digests = {item["digest"] for item in raw}
    if any(item["digest"] not in raw_digests for item in observations):
        reasons.append("unanchored-observation")
    if _decided_on(adjudication["decided_on"]) > as_of:
        reasons.append("future-decision")
    machine = chain.get("machine_verdict")
    if (machine is not None and machine["source"] == GRADING_SOURCE
            and GRADING_LIMITATION not in chain["inherited_limitations"]):
        reasons.append("missing-inherited-limitation")
    return VerificationResult(not reasons, tuple(dict.fromkeys(reasons)))
