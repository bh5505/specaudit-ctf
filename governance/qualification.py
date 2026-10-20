"""Promotion-qualification contract (bounded unit U-GOV.e).

Defines and verifies the intended admission/promotion decision contract over
the twelve frozen 2026-10-14 historical promotion events in
``governance/register.v2.yaml``. The criterion set is EXACTLY
``candidate_admission.REQUIRED_ADMISSION_FIELDS``, imported by identity as
the sole criterion authority; the GOV-01 item-3 clause "owner, regression,
side-effect and egress contracts enforced" names four elements already
inside that field set — it is emphasis, not an addition, and no new
taxonomy is introduced. Each loaded event is projected onto these criteria
with fail-closed attestation states (``evidenced | partial | unevidenced |
contradicted``), and an event qualifies only when every criterion is
evidenced AND the executed-evidence store returns outcome ``passed`` for
the regression, egress, side-effects, rights, and owner criteria. The
zero-of-twelve outcome is computed by that conjunction — never asserted
and never hardcoded: rights are contradicted on all twelve events because
each frozen decision accepts ``no-license-or-data-rights-clearance``, the
regression citation is partial with outcome ``authorized-not-executed``
(``operator-authorized`` is not an executed outcome), and the remaining
contract fields are unevidenced because a selection/admission decision
record carries them nowhere.

Roster enforcement is read-only: each loaded event's canonical-JSON digest
is recomputed with ``governance.check._sha256`` and compared ONLY against
the imported frozen ``V2_AUTHORIZED_PROMOTION_EVENTS`` literals (never
against digests derived from the register being assessed). Any thirteenth
event id, missing id, or digest mismatch fails as
``qualification-roster-mismatch`` / ``qualification-event-digest-mismatch``
and halts the assessment: the twelve frozen snapshots bind fidelity to the
recorded decisions, and freezing alone satisfies no criterion.

Evidence-store protocol: the store maps a recomputed event digest to
records ``{criterion, ref, outcome, dated_on, content_sha256}``. A record
counts only when its ``ref`` matches the reserved convention
``governance/reviews/executed/<event-id>.<YYYY-MM-DD>.json`` and
resolves through the ``_read_file_snapshot`` bounds (no-follow, bounded,
regular file) to bytes whose digest equals the recorded ``content_sha256``,
its ``outcome`` is exactly ``passed``, and its ``dated_on`` is on or after
the event's ``decided_on``. Event citations (``verification_result``,
``regression_case``, ``exercised_path``) are never resolved as references
or paths. This increment ships ``NULL_EVIDENCE_STORE`` as the default —
nothing satisfies it — and creates no ``governance/reviews/executed/``
directory and no artifact; the committed triple gate for future executed
evidence (roster table + anchor table + committed artifact) stays closed.

Protocol versus authority: a qualification report is a decision-contract
statement, not a promotion. It grants no admission, shipment, or support
claim, never mutates the register, never re-reads the register YAML bytes
(it operates on ``Registry.document``), and preserves the R15/R38 refusal
decisions untouched (no event subjects them). Reviewer attribution is not
authentication, and source-plane events never imply runtime or module
admission. No W2, admission, or promotion work is implemented here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from candidate_admission import REQUIRED_ADMISSION_FIELDS
from capability_records import (
    is_reference,
    is_reference_list,
    is_sha256_digest,
    is_stable_id,
)

from governance.check import (
    MAX_EVIDENCE_BYTES,
    REPOSITORY_ROOT,
    RegisterLoadError,
    Registry,
    V2_AUTHORIZED_PROMOTION_EVENTS,
    _read_file_snapshot,
    _sha256,
    load_register_v2,
)
from governance.reviews import ERROR_SCHEMA_ID

QUALIFICATION_VERSION = "specaudit.ctf.governance.promotion-qualification.v1"
REPORT_SCHEMA_ID = "specaudit.ctf.governance.promotion-qualification-report.v1"

QUALIFICATION_LIMITS: tuple[str, ...] = (
    "Computed, not asserted: the zero-of-twelve outcome falls out of the "
    "per-criterion conjunction; no qualification count is hardcoded.",
    "Structural validity is not execution: field presence and citation "
    "resolvability never prove a test ran or a control held.",
    "Reviewer attribution is not authentication: the recorded reviewer "
    "string does not establish who decided or who ran anything.",
    "Plane independence: source-plane events never imply runtime or "
    "module admission.",
    "No promotion authority: a qualification report grants no admission, "
    "shipment, support, or execution claim.",
    "The register is never mutated: assessment is read-only over "
    "Registry.document copies and the frozen roster tables.",
)

REQUIREMENTS = ("integrity", "qualify")

ATTESTATION_STATES = ("evidenced", "partial", "unevidenced", "contradicted")

# The GOV-01 item-3 emphasis ("owner, regression, side-effect and egress
# contracts enforced") plus the two rights fields: the criteria for which
# field attestation alone is never enough — a valid executed-evidence store
# record with outcome "passed" is additionally required before an event can
# qualify. Subset of REQUIRED_ADMISSION_FIELDS by construction.
EXECUTED_EVIDENCE_CRITERIA = frozenset(
    {
        "regression_case",
        "side_effects",
        "egress",
        "named_owner",
        "code_license",
        "data_rights",
    }
)

SOURCE_PLANE_PREFIX = "source:"
# Every frozen event accepts this limitation: the events affirmatively
# document non-clearance, which no protocol output can un-document.
RIGHTS_NON_CLEARANCE = "no-license-or-data-rights-clearance"

# Reserved executed-evidence reference convention. The date in the filename
# must equal the record's dated_on, so a reference cannot outlive its date.
EXECUTED_PROMOTION_REF = re.compile(
    r"^governance/reviews/executed/"
    r"([A-Za-z0-9][A-Za-z0-9._:-]*)\.([0-9]{4}-[0-9]{2}-[0-9]{2})\.json$"
)


class QualificationError(ValueError):
    """Raised when a promotion-qualification input is structurally invalid."""


class _NullEvidenceStore(Mapping):
    """The shipped store: no executed evidence exists, so nothing counts."""

    def __getitem__(self, key: Any) -> Any:
        raise KeyError(key)

    def __iter__(self):
        return iter(())

    def __len__(self) -> int:
        return 0


NULL_EVIDENCE_STORE: Mapping[str, Sequence[Mapping[str, Any]]] = (
    _NullEvidenceStore()
)


@dataclass(frozen=True)
class CriterionAttestation:
    """One criterion's fail-closed attestation for one event."""

    criterion: str
    state: str
    outcome: str | None
    sources: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "criterion": self.criterion,
            "state": self.state,
            "outcome": self.outcome,
            "sources": list(self.sources),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class EventQualification:
    """One event's complete qualification outcome."""

    event_id: str | None
    subject: str | None
    to_status: str | None
    decided_on: str | None
    event_digest: str
    digest_binds_frozen_table: bool
    criteria: tuple[CriterionAttestation, ...]
    unmet: tuple[str, ...]
    qualifies: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "subject": self.subject,
            "to_status": self.to_status,
            "decided_on": self.decided_on,
            "event_digest": self.event_digest,
            "digest_binds_frozen_table": self.digest_binds_frozen_table,
            "qualifies": self.qualifies,
            "unmet": list(self.unmet),
            "criteria": [item.as_dict() for item in self.criteria],
        }


@dataclass(frozen=True)
class QualificationIssue:
    """One deterministic roster, digest, or chronology issue."""

    category: str
    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True)
class PopulationQualificationReport:
    """Complete population qualification outcome; the roster gates it all."""

    requirement: str
    as_of: date
    register_sha256: str | None
    document_sha256: str
    events_total: int
    qualified_count: int
    per_event: tuple[EventQualification, ...]
    roster_ok: bool
    issues: tuple[QualificationIssue, ...]
    limitations: tuple[str, ...] = QUALIFICATION_LIMITS

    @property
    def integrity_ok(self) -> bool:
        return not any(issue.category == "integrity" for issue in self.issues)

    @property
    def ok(self) -> bool:
        if self.requirement == "integrity":
            return self.integrity_ok
        if self.requirement == "qualify":
            return (
                self.integrity_ok
                and self.roster_ok
                and self.events_total == len(self.per_event)
                and all(item.qualifies for item in self.per_event)
            )
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA_ID,
            "version": QUALIFICATION_VERSION,
            "requirement": self.requirement,
            "as_of": self.as_of.isoformat(),
            "ok": self.ok,
            "integrity_ok": self.integrity_ok,
            "register_sha256": self.register_sha256,
            "document_sha256": self.document_sha256,
            "counts": {
                "events_total": self.events_total,
                "qualified_count": self.qualified_count,
                "issues": len(self.issues),
            },
            "roster_ok": self.roster_ok,
            "per_event": [item.as_dict() for item in self.per_event],
            "issues": [issue.as_dict() for issue in self.issues],
            "limitations": list(self.limitations),
        }


def _add(
    issues: list[QualificationIssue],
    category: str,
    code: str,
    path: str,
    message: str,
) -> None:
    issues.append(
        QualificationIssue(
            category=category, code=code, path=path, message=message
        )
    )


def _is_digest_list(value: Any) -> bool:
    # Mirrors candidate_admission._is_digest_list: a bounded nonempty list
    # of exact lowercase sha256 content digests.
    return (
        isinstance(value, (list, tuple))
        and 1 <= len(value) <= 256
        and all(is_sha256_digest(item) for item in value)
    )


def _is_case_value(value: Any) -> bool:
    # Mirrors candidate_admission._is_case_value: one bounded reference
    # string, or a nonempty bounded list of bounded references.
    if isinstance(value, str):
        return is_reference(value)
    return is_reference_list(value, allow_empty=False)


def _verification_outcome(event: Mapping[str, Any]) -> str | None:
    """Map the event's recorded verification_result to an honest outcome.

    Only ``passed``/``failed`` are executed outcomes; anything else a
    frozen decision recorded (``operator-authorized`` on all twelve) is
    authorization, not execution.
    """

    value = event.get("verification_result")
    if value == "passed" or value == "failed":
        return value
    if value is None:
        return None
    return "authorized-not-executed"


def _parsed_date(value: Any) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _store_outcome(
    evidence_store: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    event_digest: str,
    criterion: str,
    event_id: str | None,
    decided_on: date | None,
    repo_root: Path,
) -> str | None:
    """Return ``passed`` when one valid executed record covers the criterion.

    Every gate must hold on the same record: the store key is the
    recomputed event digest, the criterion names this criterion exactly,
    the ref matches the reserved convention for this event id with the
    record's own date, the ref resolves through the bounded no-follow
    file snapshot to bytes matching the recorded digest, the outcome is
    exactly ``passed``, and dated_on is on or after the event decision.
    Anything else counts as nothing — including a verification_result or
    citation string that happens to name an existing file.
    """

    if decided_on is None:
        return None
    try:
        records = evidence_store.get(event_digest)  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        return None
    if not isinstance(records, (list, tuple)):
        return None
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if record.get("criterion") != criterion:
            continue
        if record.get("outcome") != "passed":
            continue
        dated = _parsed_date(record.get("dated_on"))
        if dated is None or dated < decided_on:
            continue
        ref = record.get("ref")
        match = (
            EXECUTED_PROMOTION_REF.fullmatch(ref)
            if isinstance(ref, str)
            else None
        )
        if match is None:
            continue
        if match.group(1) != event_id or match.group(2) != dated.isoformat():
            continue
        relative = PurePosixPath(ref)
        try:
            snapshot = _read_file_snapshot(
                repo_root.joinpath(*relative.parts),
                label="executed promotion evidence",
                max_bytes=MAX_EVIDENCE_BYTES,
            )
        except RegisterLoadError:
            continue
        if record.get("content_sha256") != snapshot.sha256:
            continue
        return "passed"
    return None


def _attest(
    criterion: str,
    *,
    state: str,
    event: Mapping[str, Any],
    sources: tuple[str, ...],
    reason: str,
    outcome: str | None = None,
) -> CriterionAttestation:
    return CriterionAttestation(
        criterion=criterion,
        state=state,
        outcome=outcome,
        sources=sources,
        reason=reason,
    )


def _attest_candidate_id(event: Mapping[str, Any]) -> CriterionAttestation:
    subject = event.get("subject")
    if not isinstance(subject, str) or not subject:
        return _attest(
            "candidate_id", state="unevidenced", event=event, sources=(),
            reason="the event records no subject",
        )
    # Split the plane prefix: the raw "source:R01" string is itself a valid
    # stable id by the repository predicate, so the plane is decided here
    # and only the remainder is shape-checked.
    if not subject.startswith(SOURCE_PLANE_PREFIX):
        return _attest(
            "candidate_id", state="unevidenced", event=event, sources=("subject",),
            reason=(
                f"subject {subject!r} is not on the source plane; "
                "source-plane events never imply runtime or module admission"
            ),
        )
    remainder = subject.split(":", 1)[1]
    if is_stable_id(remainder):
        return _attest(
            "candidate_id", state="evidenced", event=event, sources=("subject",),
            reason="the subject names the source-plane candidate with a bounded stable id",
        )
    return _attest(
        "candidate_id", state="unevidenced", event=event, sources=("subject",),
        reason="the subject remainder is not a bounded stable id",
    )


def _attest_pinned_revision(event: Mapping[str, Any]) -> CriterionAttestation:
    versions = event.get("supported_versions")
    revisions = event.get("source_revisions")
    versions_ok = is_reference_list(versions, allow_empty=False)
    revisions_ok = is_reference_list(revisions, allow_empty=False)
    if versions_ok and revisions_ok:
        return _attest(
            "pinned_revision", state="evidenced", event=event,
            sources=("supported_versions", "source_revisions"),
            reason="the event pins the verified upstream revision with its supported-version citation",
        )
    if versions_ok or revisions_ok:
        return _attest(
            "pinned_revision", state="partial", event=event,
            sources=("supported_versions", "source_revisions"),
            reason="only one of the version citation and the revision pin is recorded",
        )
    return _attest(
        "pinned_revision", state="unevidenced", event=event,
        sources=("supported_versions", "source_revisions"),
        reason="the event records no version citation and no revision pin",
    )


def _attest_revision_hashes(event: Mapping[str, Any]) -> CriterionAttestation:
    if _is_digest_list(event.get("revision_hashes")):
        return _attest(
            "revision_hashes", state="evidenced", event=event,
            sources=("revision_hashes",),
            reason="the event carries a bounded list of exact sha256 content digests",
        )
    if is_reference_list(event.get("source_revisions"), allow_empty=False):
        return _attest(
            "revision_hashes", state="partial", event=event,
            sources=("source_revisions",),
            reason=(
                "source_revisions are git commit pins, not sha256 content "
                "digests; admitted-slice content digests live on the source "
                "rows, not on the events"
            ),
        )
    return _attest(
        "revision_hashes", state="unevidenced", event=event,
        sources=("revision_hashes", "source_revisions"),
        reason="the event records no content digest of any kind",
    )


def _attest_rights(
    criterion: str, event: Mapping[str, Any], store_outcome: str | None
) -> CriterionAttestation:
    # A frozen decision that accepts the non-clearance limitation is
    # contradicted regardless of any store record: the events document
    # non-clearance, and a record cannot un-document its own decision.
    limitations = event.get("limitations_accepted")
    if isinstance(limitations, (list, tuple)) and (
        RIGHTS_NON_CLEARANCE in limitations
    ):
        noun = "license" if criterion == "code_license" else "data-rights"
        return _attest(
            criterion, state="contradicted", event=event,
            sources=("limitations_accepted",),
            reason=(
                f"the event accepts {RIGHTS_NON_CLEARANCE!r}: the frozen "
                f"decision documents {noun} non-clearance"
            ),
        )
    if is_reference(event.get(criterion)):
        if store_outcome == "passed":
            return _attest(
                criterion, state="evidenced", event=event,
                sources=(criterion,), outcome=store_outcome,
                reason="the event declares the fact and an executed record resolves under the reserved convention",
            )
        return _attest(
            criterion, state="partial", event=event, sources=(criterion,),
            reason="the event declares the fact but no executed clearance record resolves",
        )
    return _attest(
        criterion, state="unevidenced", event=event, sources=(criterion,),
        reason=f"the event records no {criterion} fact",
    )


def _attest_store_backed(
    criterion: str,
    event: Mapping[str, Any],
    store_outcome: str | None,
    *,
    absent_reason: str,
    valid: bool,
) -> CriterionAttestation:
    if not valid:
        return _attest(
            criterion, state="unevidenced", event=event, sources=(criterion,),
            reason=absent_reason,
        )
    if store_outcome == "passed":
        return _attest(
            criterion, state="evidenced", event=event, sources=(criterion,),
            outcome=store_outcome,
            reason="the event declares the contract and an executed record resolves under the reserved convention",
        )
    return _attest(
        criterion, state="partial", event=event, sources=(criterion,),
        reason="the event declares the contract but no executed record resolves under the reserved convention",
    )


def _attest_regression_case(
    event: Mapping[str, Any], store_outcome: str | None
) -> CriterionAttestation:
    outcome = _verification_outcome(event)
    citations_ok = _is_case_value(
        event.get("regression_case")
    ) and _is_case_value(event.get("exercised_path"))
    if citations_ok and store_outcome == "passed":
        return _attest(
            "regression_case", state="evidenced", event=event,
            sources=("regression_case", "exercised_path"), outcome=store_outcome,
            reason="an executed regression record resolves under the reserved convention",
        )
    if citations_ok:
        return _attest(
            "regression_case", state="partial", event=event,
            sources=("regression_case", "exercised_path"), outcome=outcome,
            reason=(
                "citations are recorded references and existence is never "
                "execution proof; the recorded verification_result is not "
                "an executed outcome"
            ),
        )
    return _attest(
        "regression_case", state="unevidenced", event=event,
        sources=("regression_case", "exercised_path"), outcome=outcome,
        reason="the event records no regression citation pair",
    )


def _attest_declaration(
    criterion: str, event: Mapping[str, Any], *, valid: bool
) -> CriterionAttestation:
    if valid:
        return _attest(
            criterion, state="evidenced", event=event, sources=(criterion,),
            reason="the event record declares the criterion in bounded form",
        )
    return _attest(
        criterion, state="unevidenced", event=event, sources=(criterion,),
        reason=(
            "the event records the selection/admission decision only; "
            f"no {criterion} attestation"
        ),
    )


def _attest_promotion_evidence(event: Mapping[str, Any]) -> CriterionAttestation:
    event_id = event.get("id")
    evidence = event.get("promotion_evidence")
    if is_reference_list(evidence, allow_empty=False) and (
        event_id not in evidence
    ):
        return _attest(
            "promotion_evidence", state="evidenced", event=event,
            sources=("promotion_evidence",),
            reason="the event cites promotion evidence distinct from itself",
        )
    return _attest(
        "promotion_evidence", state="unevidenced", event=event,
        sources=("promotion_evidence", "id"),
        reason=(
            "the event's own id is its row's promotion_evidence citation; "
            "self-reference satisfies nothing"
        ),
    )


def assess_event(
    event: Mapping[str, Any],
    evidence_store: Mapping[str, Sequence[Mapping[str, Any]]] = NULL_EVIDENCE_STORE,
    *,
    repo_root: Path | str | None = None,
) -> EventQualification:
    """Project one promotion event onto the frozen admission criterion set.

    Fail-closed and read-only: the event mapping is never mutated, every
    criterion defaults to unevidenced, and qualification requires every
    criterion evidenced plus an executed ``passed`` store record for the
    regression/egress/side-effects/rights/owner criteria. The zero-of-
    twelve population outcome falls out of this conjunction.
    """

    if not isinstance(event, Mapping):
        raise QualificationError("promotion event must be a mapping")
    root = Path(repo_root) if repo_root is not None else REPOSITORY_ROOT
    event_digest = _sha256(event)
    digest_binds = any(
        event_digest == digest
        for _event_id, digest in V2_AUTHORIZED_PROMOTION_EVENTS.values()
    )
    decided = _parsed_date(event.get("decided_on"))

    def store_passed(criterion: str) -> str | None:
        return _store_outcome(
            evidence_store,
            event_digest=event_digest,
            criterion=criterion,
            event_id=(
                event.get("id") if isinstance(event.get("id"), str) else None
            ),
            decided_on=decided,
            repo_root=root,
        )

    attestations = (
        _attest_candidate_id(event),
        _attest_pinned_revision(event),
        _attest_revision_hashes(event),
        _attest_rights("code_license", event, store_passed("code_license")),
        _attest_rights("data_rights", event, store_passed("data_rights")),
        _attest_store_backed(
            "named_owner", event, store_passed("named_owner"),
            valid=is_reference(event.get("named_owner")),
            absent_reason=(
                "the recorded reviewer is attribution, not ownership; "
                "the event names no owner"
            ),
        ),
        _attest_declaration(
            "data_classification", event,
            valid=is_reference(event.get("data_classification")),
        ),
        _attest_declaration(
            "action_surface", event,
            valid=is_reference(event.get("action_surface")),
        ),
        _attest_store_backed(
            "side_effects", event, store_passed("side_effects"),
            valid=is_reference_list(event.get("side_effects"), allow_empty=True),
            absent_reason=(
                "the event declares no side-effect contract and no "
                "executed record covers one"
            ),
        ),
        _attest_store_backed(
            "egress", event, store_passed("egress"),
            valid=is_reference(event.get("egress")),
            absent_reason=(
                "the event declares no egress contract and no executed "
                "record covers one"
            ),
        ),
        _attest_declaration(
            "cost_behavior", event,
            valid=is_reference(event.get("cost_behavior")),
        ),
        _attest_declaration(
            "cleanup_semantics", event,
            valid=is_reference(event.get("cleanup_semantics")),
        ),
        _attest_declaration(
            "offline_tests", event,
            valid=_is_case_value(event.get("offline_tests")),
        ),
        _attest_declaration(
            "denied_egress_tests", event,
            valid=_is_case_value(event.get("denied_egress_tests")),
        ),
        _attest_declaration(
            "provenance_semantics", event,
            valid=is_reference(event.get("provenance_semantics")),
        ),
        _attest_declaration(
            "negative_cases", event,
            valid=_is_case_value(event.get("negative_cases")),
        ),
        _attest_declaration(
            "inconclusive_cases", event,
            valid=_is_case_value(event.get("inconclusive_cases")),
        ),
        _attest_regression_case(event, store_passed("regression_case")),
        _attest_promotion_evidence(event),
    )
    unmet = tuple(
        item.criterion for item in attestations if item.state != "evidenced"
    )
    event_id = event.get("id") if isinstance(event.get("id"), str) else None
    return EventQualification(
        event_id=event_id,
        subject=event.get("subject") if isinstance(event.get("subject"), str) else None,
        to_status=(
            event.get("to_status")
            if isinstance(event.get("to_status"), str)
            else None
        ),
        decided_on=(
            event.get("decided_on")
            if isinstance(event.get("decided_on"), str)
            else None
        ),
        event_digest=event_digest,
        digest_binds_frozen_table=digest_binds,
        criteria=attestations,
        unmet=unmet,
        qualifies=not unmet,
    )


def _roster_check(
    events: Any,
) -> tuple[list[QualificationIssue], dict[str, Mapping[str, Any]]]:
    """Compare loaded events against the frozen literal table, read-only.

    Expected ids and digests come ONLY from the imported frozen literals,
    never from the register being assessed. Missing ids, extra ids,
    duplicates, non-mapping events, subject/source binding breaks, and
    digest drift all fail integrity.
    """

    issues: list[QualificationIssue] = []
    by_id: dict[str, Mapping[str, Any]] = {}
    if not isinstance(events, list):
        _add(
            issues, "integrity", "qualification-roster-mismatch",
            "promotion_events",
            "promotion_events must be a list",
        )
        return issues, by_id
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            _add(
                issues, "integrity", "qualification-event-invalid",
                f"promotion_events[{index}]",
                "promotion event must be a mapping",
            )
            continue
        event_id = event.get("id")
        if not isinstance(event_id, str):
            _add(
                issues, "integrity", "qualification-event-invalid",
                f"promotion_events[{index}]",
                "promotion event id must be a string",
            )
            continue
        if event_id in by_id:
            _add(
                issues, "integrity", "qualification-roster-mismatch",
                f"promotion_event:{event_id}",
                f"duplicate promotion event id {event_id!r}",
            )
            continue
        by_id[event_id] = event
    expected: dict[str, tuple[str, str]] = {
        event_id: (source_id, digest)
        for source_id, (event_id, digest) in (
            V2_AUTHORIZED_PROMOTION_EVENTS.items()
        )
    }
    missing = sorted(set(expected) - set(by_id))
    extra = sorted(set(by_id) - set(expected))
    if missing or extra or len(events) != len(expected):
        _add(
            issues, "integrity", "qualification-roster-mismatch",
            "promotion_events",
            "expected exactly the twelve recorded source promotion events; "
            f"missing={missing!r}; extra={extra!r}",
        )
    for event_id in sorted(set(by_id) & set(expected)):
        source_id, digest = expected[event_id]
        event = by_id[event_id]
        if event.get("subject") != f"source:{source_id}":
            _add(
                issues, "integrity", "qualification-roster-mismatch",
                f"promotion_event:{event_id}",
                f"the frozen event for source:{source_id} is bound to "
                f"{event.get('subject')!r}",
            )
        if _sha256(event) != digest:
            _add(
                issues, "integrity", "qualification-event-digest-mismatch",
                f"promotion_event:{event_id}",
                f"event differs from the complete recorded decision for "
                f"source:{source_id}",
            )
    return issues, by_id


def assess_population(
    registry: Registry,
    evidence_store: Mapping[str, Sequence[Mapping[str, Any]]] = NULL_EVIDENCE_STORE,
    *,
    as_of: date,
    requirement: str = "integrity",
    repo_root: Path | str | None = None,
) -> PopulationQualificationReport:
    """Qualify the frozen promotion-event population of a loaded register.

    Read-only over ``registry.document``: the register is never mutated
    and its YAML bytes are never re-parsed. The roster gate runs first and
    halts the per-event assessment fail-closed on any mismatch.
    """

    if requirement not in REQUIREMENTS:
        raise ValueError(f"unknown requirement: {requirement}")
    issues, by_id = _roster_check(registry.document.get("promotion_events"))
    roster_ok = not issues
    per_event: tuple[EventQualification, ...] = ()
    if roster_ok:
        for event_id in sorted(by_id):
            event = by_id[event_id]
            decided = _parsed_date(event.get("decided_on"))
            if decided is None:
                _add(
                    issues, "integrity", "qualification-decision-invalid",
                    f"promotion_event:{event_id}",
                    "decided_on must be a real YYYY-MM-DD calendar date",
                )
            elif decided > as_of:
                _add(
                    issues, "integrity", "qualification-decision-in-future",
                    f"promotion_event:{event_id}",
                    f"decided_on {decided.isoformat()} is later than the "
                    f"as-of {as_of.isoformat()}; the decision does not "
                    "exist at the assessed date",
                )
        per_event = tuple(
            assess_event(
                by_id[event_id], evidence_store, repo_root=repo_root
            )
            for event_id in sorted(by_id)
        )
    qualified_count = sum(1 for item in per_event if item.qualifies)
    return PopulationQualificationReport(
        requirement=requirement,
        as_of=as_of,
        register_sha256=registry.register_sha256,
        document_sha256=_sha256(registry.document),
        events_total=(
            len(registry.document.get("promotion_events") or ())
            if isinstance(registry.document.get("promotion_events"), list)
            else 0
        ),
        qualified_count=qualified_count,
        per_event=per_event,
        roster_ok=roster_ok,
        issues=tuple(issues),
    )


def _iso_date(value: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from exc
    if parsed.isoformat() != value:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Promotion-qualification contract verifier (U-GOV.e)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser(
        "check", help="qualify the frozen promotion-event population"
    )
    check.add_argument("--as-of", type=_iso_date, required=True)
    check.add_argument("--require", choices=REQUIREMENTS, default="integrity")
    check.add_argument("--format", choices=("json",), default="json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fail-closed qualification check: 0 satisfied, 1 gaps, 2 invalid.

    No --register override exists: the assessment always reads the
    canonical register v2 through its bounded loader and never mutates it.
    """

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.require not in REQUIREMENTS:
            raise ValueError(f"unknown requirement: {args.require}")
        registry = load_register_v2()
        report = assess_population(
            registry,
            NULL_EVIDENCE_STORE,
            as_of=args.as_of,
            requirement=args.require,
        )
    except (QualificationError, RegisterLoadError, ValueError) as exc:
        payload = {
            "schema": ERROR_SCHEMA_ID,
            "ok": False,
            "error": str(exc),
        }
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2
    except Exception as exc:
        payload = {
            "schema": ERROR_SCHEMA_ID,
            "ok": False,
            "error": (
                "promotion qualification failed closed: "
                f"{type(exc).__name__}: {exc}"
            ),
        }
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), allow_nan=False, indent=2, sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
