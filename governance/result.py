"""Executed review-result verifier (bounded unit U-GOV.d).

A real verifier for the closed review-result v1 protocol: it reconciles one
result cycle's dated ``executed-check`` outcomes one-to-one against the full
authoritative population (109 sources + 29 modules + 227 runtimes = 365
entities, each with three declared triggers = 1,095 entity/trigger pairs)
at that cycle's own revision-bound register epoch, re-hashes sha256-bound
evidence from offline local Git blobs, requires a new date-named Git blob
with 1,095 detailed result rows matching the cycle summary, checks heading
anchors, cross-checks each row's ``checked_via``/``evidence_ref`` against
the epoch register's declared trigger check, requires the epoch register
at the same revision to record the cycle date itself, binds the cycle to
the independently pinned v1 genesis record digest, and refuses premature
cycles, stale epochs, empty-commit relabels, future observations, and
unsupported positive claims in deterministic JSON. Reported dues are the
epoch register's dues at ``inspected_revision`` with explicit
``cycle_reviewed_on``/``epoch_reviewed_on`` provenance, not a post-cycle
projection.

Protocol versus operation: this module defines what a genuine re-review
cycle must prove and verifies it when one is presented. It does not perform
a review, and no executed cycle has been performed under this protocol: the
committed tree ships no result artifact, the governed source/runtime dues
(2027-01-11) and module due (2027-04-13) are unsatisfied, and the v1
history verifier's ``recurring_operation_ok`` remains false. A result dated
before the latest governed due date (2027-04-13) fails closed as
``cycle-too-early``: v1 defines only full-population cycles, so a cycle
that precedes any class obligation cannot complete one. A policy change
needs a later explicit version, not silent acceptance.

Revision binding mirrors the U-GOV.b history verifier: every evidence file
and the authoritative ``governance/register.v2.yaml`` resolve from offline
local Git objects at the cycle's exact 40-hex ``inspected_revision``
(absolute binary, subprocess argv, local ``cat-file``/``ls-tree`` only, no
fetch or network), never from the working tree and never from a
caller-supplied path. The epoch runtime roster is additionally anchored to
the genesis inspected revision, so a coordinated substitution that preserves
all 365 entity and 1,095 pair counts still fails. Fail outcomes never block
completion by themselves: the protocol verifies the custody and consistency
of attributed result records, not who performed the checks or whether their
human conclusions are true. No W2, admission, or promotion logic lives here.

This module reuses the closed Git/parse primitives of
:mod:`governance.reviews` without changing that unit: the v1 history bytes,
digests, and verdict are untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Mapping, Sequence

import jsonschema

from governance.reviews import (
    CHECKED_VIA_VALUES,
    EVIDENCE_SUFFIXES,
    EXPECTED_ENTITIES,
    EXPECTED_MODULES,
    EXPECTED_PAIRS,
    EXPECTED_RUNTIMES,
    EXPECTED_SOURCES,
    INITIAL_HISTORY_RECORD_DIGEST,
    MAX_EVIDENCE_BYTES,
    MAX_REGISTER_BLOB_BYTES,
    MAX_REGISTER_SCHEMA_BLOB_BYTES,
    REGISTER_V2_REL,
    REGISTER_V2_SCHEMA_REL,
    REQUIRED_EVIDENCE_PATHS,
    ERROR_SCHEMA_ID,
    ReviewIssue,
    ReviewLoadError,
    _ANCHOR_RE,
    _DATE_RE,
    _GitFailure,
    _RevisionBlobStore,
    _add,
    _check_repo_relative_file,
    _evidence_heading_anchors,
    _load_strict_json,
    _parse_date,
    _read_canonical_repo_bytes,
    _read_file_snapshot,
    _reject_nonlocal_refs,
    _resolve_repo_root,
    _strict_utf8,
    _validate_bounded_tree,
    _validate_epoch_register,
)

RESULT_SCHEMA_ID = "specaudit.ctf.governance.review-result.v1"
RESULT_SCHEMA_VERSION = 1
GOVERNED_HISTORY_ID = "attributed-review-history-v1"
REPORT_SCHEMA_ID = "specaudit.ctf.governance.review-result-report.v1"

RESULT_SCHEMA_REL = "governance/schema/review-result.v1.schema.json"
EXECUTION_SOURCE_SCHEMA_ID = "specaudit.ctf.governance.executed-result-source.v1"
EXECUTION_SOURCE_PATH = re.compile(
    r"^governance/reviews/executed/([0-9]{4}-[0-9]{2}-[0-9]{2})\.[a-z0-9-]+\.json$"
)

# Independently pinned bytes: the closed review-result schema as committed.
CANONICAL_RESULT_SCHEMA_SHA256 = (
    "sha256:f0e5e93aed839f964b43f15f00554a2765ff1eea7dd5a88182da6c6512efde55"
)

# The v1 genesis inspected revision from the committed attributed history.
# Result epochs anchor their runtime roster to the register at this revision.
GENESIS_INSPECTED_REVISION = "7499dd12cdc87efc93d7a53d51b5dd785a27221d"
GENESIS_RECORDED_ON = date(2026, 10, 18)
# Full-population v1 cycles must be dated on or after the latest governed
# class due date (modules, 182-day cadence from 2026-10-13). Earlier dated
# results fail closed as cycle-too-early, so recurrence stays false before
# genuine future cycles. Frozen v1 policy: a change needs a later version.
MIN_CYCLE_REVIEWED_ON = date(2027, 4, 13)

REQUIREMENTS = ("integrity", "coverage", "complete")

MAX_RESULT_BYTES = 1024 * 1024
MAX_RESULT_NODES = 40_000
MAX_RESULT_STRING_BYTES = 1024 * 1024
MAX_RESULT_SCHEMA_BYTES = 64 * 1024

EXECUTED_BASIS = "executed-check"
OUTCOME_VALUES = frozenset({"pass", "fail"})


@dataclass(frozen=True)
class ReviewResultReport:
    """Complete executed-review-result verification outcome."""

    requirement: str
    as_of: date
    result_path: str
    result_sha256: str | None
    register_revision: int | None
    register_sha256: str | None
    result_schema_sha256: str | None
    integrity_ok: bool
    coverage_ok: bool
    cycle_complete_ok: bool
    epoch_validated: bool
    entities_expected: int
    entities_observed: int
    sources_expected: int
    sources_observed: int
    modules_expected: int
    modules_observed: int
    runtimes_expected: int
    runtimes_observed: int
    pairs_expected: int
    pairs_observed: int
    passes: int
    failures: int
    next_due_source: str | None
    next_due_runtime: str | None
    next_due_module: str | None
    queue_next_review_on: str | None
    cycle_reviewed_on: str | None
    epoch_reviewed_on: str | None
    due_provenance: str
    checks: tuple[Mapping[str, Any], ...]
    unknown_outcomes: tuple[str, ...]
    limitations: tuple[str, ...]
    issues: tuple[ReviewIssue, ...]

    @property
    def ok(self) -> bool:
        if self.requirement == "integrity":
            return self.integrity_ok
        if self.requirement == "coverage":
            return self.coverage_ok
        if self.requirement == "complete":
            return self.cycle_complete_ok
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA_ID,
            "requirement": self.requirement,
            "as_of": self.as_of.isoformat(),
            "ok": self.ok,
            "integrity_ok": self.integrity_ok,
            "coverage_ok": self.coverage_ok,
            "cycle_complete_ok": self.cycle_complete_ok,
            "result_path": self.result_path,
            "result_sha256": self.result_sha256,
            "register_revision": self.register_revision,
            "register_sha256": self.register_sha256,
            "result_schema_sha256": self.result_schema_sha256,
            "counts": {
                "epoch_validated": self.epoch_validated,
                "entities_expected": self.entities_expected,
                "entities_observed": self.entities_observed,
                "sources_expected": self.sources_expected,
                "sources_observed": self.sources_observed,
                "modules_expected": self.modules_expected,
                "modules_observed": self.modules_observed,
                "runtimes_expected": self.runtimes_expected,
                "runtimes_observed": self.runtimes_observed,
                "pairs_expected": self.pairs_expected,
                "pairs_observed": self.pairs_observed,
                "passes": self.passes,
                "failures": self.failures,
                "issues": len(self.issues),
            },
            "next_due": {
                "source": self.next_due_source,
                "runtime": self.next_due_runtime,
                "module": self.next_due_module,
                "queue_next_review_on": self.queue_next_review_on,
                # Provenance: these are the revision-bound epoch
                # register's dues at inspected_revision, not a
                # post-cycle projection. They predate the cycle when
                # the epoch was not advanced (epoch_reviewed_on !=
                # cycle_reviewed_on); a complete cycle advances the
                # epoch so they lie after the cycle date.
                "provenance": self.due_provenance,
                "cycle_reviewed_on": self.cycle_reviewed_on,
                "epoch_reviewed_on": self.epoch_reviewed_on,
            },
            "checks": [dict(check) for check in self.checks],
            "unknown_outcomes": list(self.unknown_outcomes),
            "limitations": list(self.limitations),
            "issues": [issue.as_dict() for issue in self.issues],
        }


def load_result_schema() -> tuple[Mapping[str, Any], str]:
    """Load the canonical closed review-result schema.

    There is no path override: the bytes are traversed from the anchored
    repository root with no-follow semantics for every component and must
    match the independently pinned canonical digest exactly.
    """

    data = _read_canonical_repo_bytes(
        RESULT_SCHEMA_REL,
        label="review-result schema",
        max_bytes=MAX_RESULT_SCHEMA_BYTES,
        expected_sha256=CANONICAL_RESULT_SCHEMA_SHA256,
    )
    raw = _strict_utf8(data, label="review-result schema")
    schema = _load_strict_json(raw, label="review-result schema")
    _validate_bounded_tree(schema, label="review-result schema")
    _reject_nonlocal_refs(schema)
    try:
        jsonschema.Draft7Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        raise ReviewLoadError(f"invalid review-result schema: {exc.message}") from exc
    if schema.get("$id", "").endswith("review-result.v1.schema.json") is False:
        raise ReviewLoadError("review-result schema has an unexpected $id")
    if schema.get("title") != RESULT_SCHEMA_ID:
        raise ReviewLoadError("review-result schema title must be " + RESULT_SCHEMA_ID)
    return schema, CANONICAL_RESULT_SCHEMA_SHA256


def load_result(
    path: Path | str,
) -> tuple[Mapping[str, Any], str, str]:
    """Load a result file through strict parsing and the closed schema.

    The result file itself is an explicit caller-selected input: it is
    opened boundedly with no-follow semantics and no repository-custody
    claim. The schema is always the pinned canonical one.
    """

    schema, schema_sha256 = load_result_schema()
    result_file = Path(path)
    snapshot = _read_file_snapshot(
        result_file, label="review result", max_bytes=MAX_RESULT_BYTES
    )
    raw = _strict_utf8(snapshot.data, label="review result")
    document = _load_strict_json(raw, label="review result")
    if not isinstance(document, dict):
        raise ReviewLoadError("review result must be a JSON object")
    _validate_bounded_tree(
        document,
        label="review result",
        max_nodes=MAX_RESULT_NODES,
        max_total_string_bytes=MAX_RESULT_STRING_BYTES,
    )
    try:
        validator = jsonschema.Draft7Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except jsonschema.SchemaError as exc:
        raise ReviewLoadError(f"invalid review-result schema: {exc.message}") from exc
    except Exception as exc:
        raise ReviewLoadError(
            f"review-result schema validation failed closed: {type(exc).__name__}: {exc}"
        ) from exc
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        raise ReviewLoadError(
            f"review result schema error at {location}: {error.message}"
        )
    if document.get("schema") != RESULT_SCHEMA_ID:
        raise ReviewLoadError("review result has an unexpected schema id")
    if document.get("schema_version") != RESULT_SCHEMA_VERSION:
        raise ReviewLoadError("review result has an unexpected schema version")
    if document.get("governed_history_id") != GOVERNED_HISTORY_ID:
        raise ReviewLoadError("review result has an unexpected governed history id")
    return document, snapshot.sha256, schema_sha256


def _codes(report: ReviewResultReport) -> set[str]:
    return {issue.code for issue in report.issues}


def _parse_execution_source(data: bytes) -> Mapping[str, Any]:
    """Validate the separate, revision-bound per-pair result source.

    The cycle summary is a caller-selected file. Its executed rows count only
    when they exactly reproduce a new Git blob with this closed shape and
    pair-specific details. This proves record custody, not reviewer identity
    or the truth of a human check.
    """
    raw = _strict_utf8(data, label="executed result source")
    source = _load_strict_json(raw, label="executed result source")
    if not isinstance(source, dict):
        raise ReviewLoadError("executed result source must be a JSON object")
    _validate_bounded_tree(
        source,
        label="executed result source",
        max_nodes=MAX_RESULT_NODES,
        max_total_string_bytes=MAX_RESULT_STRING_BYTES,
    )
    schema, _ = load_result_schema()
    source_schema = {
        "$schema": schema["$schema"],
        "$ref": "#/definitions/execution_source",
        "definitions": schema["definitions"],
    }
    validator = jsonschema.Draft7Validator(
        source_schema, format_checker=jsonschema.FormatChecker()
    )
    first = next(validator.iter_errors(source), None)
    if first is not None:
        location = ".".join(str(part) for part in first.absolute_path) or "$"
        raise ReviewLoadError(
            f"executed result source schema error at {location}: {first.message}"
        )
    return source


def verify_result(
    document: Mapping[str, Any],
    *,
    as_of: date,
    result_path: str,
    result_sha256: str | None,
    result_schema_sha256: str | None,
    requirement: str = "complete",
    repo_root: Path | str | None = None,
    blob_store: _RevisionBlobStore | None = None,
) -> ReviewResultReport:
    """Reconcile one executed-review-result cycle against revision-bound state.

    The cycle's evidence and authoritative register resolve from offline
    local Git objects at the cycle's exact ``inspected_revision``. No
    caller-supplied register is accepted and the working tree is never
    consulted for evidence. The epoch runtime roster is anchored to the
    register at the pinned genesis inspected revision, so coordinated
    substitutions that preserve every count still fail. Missing
    commits/paths, ambiguous or non-blob entries, decode/parse failures,
    oversized blobs, digest differences, premature cycle dates, and
    unsupported positive claims all fail closed. A missing git executable
    or an unusable repository root raises :class:`ReviewLoadError`.
    """

    if requirement not in REQUIREMENTS:
        raise ValueError(f"unknown requirement: {requirement}")
    root = _resolve_repo_root(repo_root)
    store = blob_store if blob_store is not None else _RevisionBlobStore(root)
    if store.repo_root != root:
        raise ReviewLoadError(
            f"blob store is rooted at {store.repo_root}, not {root}"
        )
    issues: list[ReviewIssue] = []
    anchor_cache: dict[tuple[str, str], set[str] | str] = {}

    # Immutable envelope identity: schema, schema_version, and the exact
    # governed history id are anchored together with the pinned genesis
    # record digest. Only a later explicit protocol version may change them.
    if (
        document.get("schema") != RESULT_SCHEMA_ID
        or document.get("schema_version") != RESULT_SCHEMA_VERSION
        or document.get("governed_history_id") != GOVERNED_HISTORY_ID
    ):
        _add(
            issues, "integrity", "history-identity-mismatch", "$",
            "the result envelope (schema, schema_version, "
            "governed_history_id) does not match the anchored "
            "review-result identity",
        )
    if document.get("governed_record_digest") != INITIAL_HISTORY_RECORD_DIGEST:
        _add(
            issues, "integrity", "history-digest-mismatch",
            "governed_record_digest",
            "the governed record digest does not bind the independently "
            "pinned v1 genesis record; the cycle reconciles against no "
            "known history",
        )

    reviewed = _parse_date(
        document.get("reviewed_on"), path="result.reviewed_on", issues=issues
    )
    recorded = _parse_date(
        document.get("recorded_on"), path="result.recorded_on", issues=issues
    )
    if reviewed is not None and recorded is not None and reviewed > recorded:
        _add(
            issues, "integrity", "recorded-before-reviewed", "result",
            "reviewed_on is later than recorded_on; every cycle needs "
            "recorded_on >= reviewed_on",
        )
    if reviewed is not None and reviewed > as_of:
        _add(
            issues, "integrity", "review-in-future", "result.reviewed_on",
            f"review date {reviewed.isoformat()} is later than as-of "
            f"{as_of.isoformat()}",
        )
    if recorded is not None and recorded > as_of:
        _add(
            issues, "integrity", "recorded-in-future", "result.recorded_on",
            f"record date {recorded.isoformat()} is later than as-of "
            f"{as_of.isoformat()}",
        )
    if reviewed is not None and reviewed < MIN_CYCLE_REVIEWED_ON:
        _add(
            issues, "integrity", "cycle-too-early", "result.reviewed_on",
            f"cycle review date {reviewed.isoformat()} precedes the latest "
            f"governed due date {MIN_CYCLE_REVIEWED_ON.isoformat()} "
            "(source/runtime 2027-01-11, module 2027-04-13); schema/result "
            "v1 defines only full-population cycles, so recurrence stays "
            "false before genuine future cycles",
        )
    reviewer = document.get("reviewer")
    if not isinstance(reviewer, str) or not reviewer.strip():
        _add(
            issues, "integrity", "reviewer-missing", "result.reviewer",
            "reviewer attribution must be a nonempty string",
        )
    inspected = document.get("inspected_revision")
    inspected_valid = (
        isinstance(inspected, str) and len(inspected) == 40
        and all(char in "0123456789abcdef" for char in inspected)
    )
    if inspected_valid and inspected == GENESIS_INSPECTED_REVISION:
        _add(
            issues, "integrity", "cycle-revision-reused",
            "result.inspected_revision",
            "the cycle binds the exact genesis inspected revision with new "
            "dates but no new revision-bound state: a relabeled replay, "
            "not a new executed cycle",
        )
    if not inspected_valid:
        _add(
            issues, "integrity", "inspected-revision-invalid",
            "result.inspected_revision",
            "inspected revision must be a 40-hex checkout revision",
        )
        inspected = None

    # --- revision-bound evidence -------------------------------------
    evidence = document.get("evidence", [])
    seen_evidence_paths: set[str] = set()
    bound_blobs: dict[str, bytes] = {}
    if isinstance(evidence, list):
        for index, entry in enumerate(evidence):
            epath = f"result.evidence[{index}]"
            if not isinstance(entry, dict):
                _add(
                    issues, "integrity", "evidence-entry-invalid", epath,
                    "evidence entry must be a mapping",
                )
                continue
            rel_text = entry.get("path")
            relative = _check_repo_relative_file(
                rel_text, allowed_suffixes=EVIDENCE_SUFFIXES
            )
            if relative is None:
                _add(
                    issues, "integrity", "invalid-evidence-path", epath,
                    "evidence path must be a bounded repo-relative "
                    ".md/.yaml/.json path",
                )
                continue
            if rel_text in seen_evidence_paths:
                _add(
                    issues, "integrity", "duplicate-evidence-path", epath,
                    f"duplicate evidence path {rel_text!r}",
                )
                continue
            seen_evidence_paths.add(rel_text)
            if inspected is None:
                continue
            try:
                blob = store.read_blob(
                    inspected, str(rel_text), max_bytes=MAX_EVIDENCE_BYTES
                )
            except _GitFailure as exc:
                _add(issues, "integrity", exc.code, epath, (
                    f"revision-bound evidence {rel_text} at {inspected}: {exc}"
                ))
                continue
            bound_blobs[str(rel_text)] = blob
            blob_sha256 = "sha256:" + hashlib.sha256(blob).hexdigest()
            if entry.get("sha256") != blob_sha256:
                _add(
                    issues, "integrity", "evidence-bytes-mismatch", epath,
                    f"evidence bytes differ for {rel_text}: recorded "
                    f"{entry.get('sha256')!r} does not match the "
                    f"revision-bound blob {blob_sha256}",
                )
            if entry.get("byte_length") != len(blob):
                _add(
                    issues, "integrity", "evidence-bytes-mismatch", epath,
                    f"evidence byte length differs for {rel_text}: recorded "
                    f"{entry.get('byte_length')!r} vs revision-bound "
                    f"{len(blob)}",
                )
        for required in REQUIRED_EVIDENCE_PATHS:
            if required not in seen_evidence_paths:
                _add(
                    issues, "integrity", "evidence-binding-missing", "result",
                    f"required evidence binding is missing: {required}",
                )
    else:
        _add(
            issues, "integrity", "evidence-entry-invalid", "result.evidence",
            "evidence must be a list",
        )

    # A different commit with the old register and old Markdown headings is
    # still a replay. Require a NEW, date-named, revision-bound JSON source
    # containing the actual pair-specific dated result rows. The caller's
    # summary rows must reproduce that source exactly; merely relabeling old
    # trigger metadata or creating an empty commit cannot establish a cycle.
    execution_source_path = document.get("execution_source")
    source_match = (
        EXECUTION_SOURCE_PATH.fullmatch(execution_source_path)
        if isinstance(execution_source_path, str)
        else None
    )
    if source_match is None:
        _add(
            issues, "integrity", "execution-source-path-invalid",
            "result.execution_source",
            "execution source must be a dated JSON file under "
            "governance/reviews/executed/",
        )
    elif reviewed is not None and source_match.group(1) != reviewed.isoformat():
        _add(
            issues, "integrity", "execution-source-date-mismatch",
            "result.execution_source",
            "execution source filename date must equal cycle reviewed_on",
        )
    if source_match is not None:
        if execution_source_path not in seen_evidence_paths:
            _add(
                issues, "integrity", "execution-source-unbound",
                "result.execution_source",
                "execution source needs its own sha256/length evidence binding",
            )
        source_bytes = bound_blobs.get(execution_source_path)
        if source_bytes is None:
            _add(
                issues, "integrity", "execution-source-unavailable",
                "result.execution_source",
                "execution source is not a readable revision-bound Git blob",
            )
        else:
            try:
                source = _parse_execution_source(source_bytes)
            except (ReviewLoadError, UnicodeDecodeError, ValueError) as exc:
                _add(
                    issues, "integrity", "execution-source-invalid",
                    "result.execution_source", str(exc),
                )
            else:
                if (
                    source.get("schema") != EXECUTION_SOURCE_SCHEMA_ID
                    or source.get("reviewed_on") != document.get("reviewed_on")
                    or source.get("reviewer") != document.get("reviewer")
                    or source.get("results") != document.get("results")
                ):
                    _add(
                        issues, "integrity", "execution-source-mismatch",
                        "result.execution_source",
                        "the revision-bound dated result source and the "
                        "caller-selected cycle summary disagree",
                    )
        try:
            store.read_blob(
                GENESIS_INSPECTED_REVISION,
                execution_source_path,
                max_bytes=MAX_EVIDENCE_BYTES,
            )
        except _GitFailure as exc:
            if exc.code != "evidence-path-missing":
                _add(
                    issues, "integrity", "execution-source-genesis-unavailable",
                    "result.execution_source",
                    f"cannot establish that the source is new: {exc}",
                )
        else:
            _add(
                issues, "integrity", "execution-source-reused",
                "result.execution_source",
                "the execution source already existed at the pinned "
                "genesis revision; a new cycle needs new dated results",
            )

    # --- genesis roster anchor ----------------------------------------
    # The genesis epoch is the historical runtime-roster anchor for every
    # v1 result epoch, exactly as in the history verifier. Without it the
    # result epoch cannot be trusted, so the cycle fails closed.
    genesis_anchor: frozenset[str] | None = None
    try:
        genesis_register_bytes = store.read_blob(
            GENESIS_INSPECTED_REVISION, REGISTER_V2_REL,
            max_bytes=MAX_REGISTER_BLOB_BYTES,
        )
        genesis_schema_bytes = store.read_blob(
            GENESIS_INSPECTED_REVISION, REGISTER_V2_SCHEMA_REL,
            max_bytes=MAX_REGISTER_SCHEMA_BLOB_BYTES,
        )
    except _GitFailure as exc:
        _add(
            issues, "integrity", "genesis-anchor-unavailable", "genesis",
            f"the genesis anchor register cannot be resolved: {exc}",
        )
        genesis_register_bytes = b""
        genesis_schema_bytes = b""
    if genesis_register_bytes and genesis_schema_bytes:
        genesis_epoch = _validate_epoch_register(
            genesis_register_bytes,
            genesis_schema_bytes,
            rpath="genesis",
            issues=issues,
            recorded=GENESIS_RECORDED_ON,
            expected_entity_roster=None,
        )
        if genesis_epoch is not None:
            genesis_anchor = frozenset(genesis_epoch.expected)

    # --- revision-bound epoch register --------------------------------
    epoch = None
    if inspected is not None and REGISTER_V2_REL in bound_blobs:
        register_bytes = bound_blobs[REGISTER_V2_REL]
        if len(register_bytes) > MAX_REGISTER_BLOB_BYTES:
            _add(
                issues, "integrity", "evidence-oversized", "result.register",
                f"epoch register blob exceeds {MAX_REGISTER_BLOB_BYTES} bytes",
            )
        else:
            schema_bytes = bound_blobs.get(REGISTER_V2_SCHEMA_REL)
            if schema_bytes is None and REGISTER_V2_SCHEMA_REL in seen_evidence_paths:
                # The schema blob read failed above; the failure is
                # already recorded against its evidence entry.
                pass
            elif schema_bytes is None:
                _add(
                    issues, "integrity", "register-schema-unavailable",
                    "result.register",
                    "the epoch register schema blob is not bound by this cycle",
                )
            elif len(schema_bytes) > MAX_REGISTER_SCHEMA_BLOB_BYTES:
                _add(
                    issues, "integrity", "register-schema-unavailable",
                    "result.register",
                    "the epoch register schema blob exceeds its size cap",
                )
            elif genesis_anchor is None:
                _add(
                    issues, "integrity", "register-epoch-unavailable",
                    "result.register",
                    "the genesis roster anchor is unavailable, so the cycle "
                    "epoch cannot be reconciled against its population",
                )
            else:
                epoch = _validate_epoch_register(
                    register_bytes,
                    schema_bytes,
                    rpath="result",
                    issues=issues,
                    recorded=recorded,
                    expected_entity_roster=genesis_anchor,
                )
    elif inspected is not None:
        _add(
            issues, "integrity", "register-epoch-unavailable", "result.register",
            "the epoch register blob is not bound by this cycle, so the "
            "cycle cannot be reconciled against its own population",
        )

    # --- cycle/epoch consistency ---------------------------------------
    # The frozen MIN_CYCLE_REVIEWED_ON gate alone would let a cycle dated
    # just after the latest governed due verify complete against a stale
    # epoch that still records 2026-10-13 with dues 2027-01-11/2027-04-13.
    # v1 defines only full-population cycles, so the revision-bound epoch
    # at the cycle's own inspected_revision must record the cycle itself:
    # every entity's epoch reviewed_on must equal the cycle reviewed_on.
    # This fails closed on a stale epoch; it never invents operation and
    # never advances the register — a genuine future cycle must commit an
    # updated register at the same revision. Dues then follow as
    # reviewed_on plus the frozen per-class cadence (already validated).
    if epoch is not None and reviewed is not None:
        epoch_reviewed_values = {
            info.get("reviewed_on") for info in epoch.expected.values()
        }
        if (
            len(epoch_reviewed_values) != 1
            or next(iter(epoch_reviewed_values)) != reviewed.isoformat()
        ):
            sample = sorted(epoch_reviewed_values)[:3]
            _add(
                issues, "integrity", "epoch-cycle-mismatch", "result",
                f"cycle reviewed_on {reviewed.isoformat()} does not match "
                f"the revision-bound epoch register currentness "
                f"(epoch reviewed_on values {sample!r}); the epoch at the "
                "cycle revision must record the cycle date itself, or the "
                "cycle reconciles against already-overdue obligations",
            )

    # --- heading anchors from revision-bound Markdown ------------------
    anchors: dict[str, set[str]] = {}
    if inspected is not None:
        for rel_text in sorted(seen_evidence_paths):
            if not rel_text.endswith(".md"):
                continue
            blob = bound_blobs.get(rel_text)
            if blob is None:
                continue
            cache_key = (inspected, rel_text)
            cached = anchor_cache.get(cache_key)
            if isinstance(cached, str):
                _add(
                    issues, "integrity", "evidence-decode-failed",
                    "result.evidence",
                    f"evidence document {rel_text} cannot be read: {cached}",
                )
                continue
            if cached is None:
                try:
                    parsed = _evidence_heading_anchors(
                        blob.decode("utf-8", errors="strict")
                    )
                except (UnicodeDecodeError, ReviewLoadError, ValueError) as exc:
                    anchor_cache[cache_key] = str(exc)
                    _add(
                        issues, "integrity", "evidence-decode-failed",
                        "result.evidence",
                        f"evidence document {rel_text} cannot be read: {exc}",
                    )
                    continue
                anchor_cache[cache_key] = parsed
                cached = parsed
            anchors[rel_text] = cached

    # --- results reconciled to the cycle's own epoch -------------------
    results = document.get("results", [])
    if not isinstance(results, list):
        _add(
            issues, "integrity", "result-invalid", "result.results",
            "results must be a list",
        )
        results = []
    seen_pairs: set[tuple[str, str]] = set()
    expected_pairs: set[tuple[str, str]] = set()
    if epoch is not None:
        expected_pairs = {
            (entity, trigger)
            for entity, info in epoch.expected.items()
            for trigger in info["triggers"]
        }
    passes = 0
    failures = 0
    for index, item in enumerate(results):
        opath = f"result.results[{index}]"
        if not isinstance(item, dict):
            _add(
                issues, "integrity", "result-invalid", opath,
                "result must be a mapping",
            )
            continue
        entity = item.get("entity")
        trigger = item.get("trigger")
        pair = (
            (entity, trigger)
            if isinstance(entity, str) and isinstance(trigger, str)
            else None
        )
        if pair is not None:
            if pair in seen_pairs:
                _add(
                    issues, "integrity", "duplicate-pair", opath,
                    f"duplicate entity/trigger pair {entity!r} {trigger!r}",
                )
            seen_pairs.add(pair)
        basis = item.get("basis")
        if basis != EXECUTED_BASIS:
            _add(
                issues, "integrity", "invalid-basis", opath,
                f"basis {basis!r} is not an executed check: only "
                f"{EXECUTED_BASIS!r} evidences operation",
            )
        outcome = item.get("outcome")
        if outcome not in OUTCOME_VALUES:
            _add(
                issues, "integrity", "invalid-outcome", opath,
                f"outcome {outcome!r} is not a recognized executed outcome",
            )
        elif outcome == "pass":
            passes += 1
        else:
            failures += 1
        checked_via = item.get("checked_via")
        if checked_via not in CHECKED_VIA_VALUES:
            _add(
                issues, "integrity", "trigger-check-method-unknown", opath,
                f"checked_via {checked_via!r} is not a recognized check method",
            )
        if epoch is not None:
            info = epoch.expected.get(entity) if isinstance(entity, str) else None
            if info is None:
                if isinstance(entity, str):
                    _add(
                        issues, "integrity", "unknown-entity", opath,
                        f"unknown entity {entity!r}: not in this cycle's "
                        "revision-bound register population",
                    )
            elif trigger not in info["triggers"]:
                _add(
                    issues, "integrity", "unknown-trigger", opath,
                    f"unknown trigger {trigger!r} for {entity!r}",
                )
            else:
                # Mirror the history verifier: a row must reproduce the
                # epoch register's declared method and evidence for its
                # (entity, trigger), not merely name a known pair. A
                # mismatched method or an unrelated bound anchor is a
                # self-declared check, not a reconciled one.
                recorded_check = info["checks"].get(trigger, {})
                if checked_via != recorded_check.get("checked_via"):
                    _add(
                        issues, "integrity", "observation-mismatch", opath,
                        f"checked_via {checked_via!r} does not match the "
                        f"epoch register record for {entity} {trigger}",
                    )
                if item.get("evidence_ref") != recorded_check.get("evidence_ref"):
                    _add(
                        issues, "integrity", "observation-mismatch", opath,
                        "evidence_ref does not match the epoch register "
                        f"record for {entity} {trigger}",
                    )
        observed_on = _parse_date(
            item.get("observed_on"), path=f"{opath}.observed_on", issues=issues
        )
        if observed_on is not None and observed_on > as_of:
            _add(
                issues, "integrity", "observed-in-future", opath,
                f"result date {observed_on.isoformat()} is later than as-of "
                f"{as_of.isoformat()}",
            )
        if (
            observed_on is not None
            and reviewed is not None
            and observed_on != reviewed
        ):
            _add(
                issues, "integrity", "observed-date-mismatch", opath,
                "observed_on must equal the cycle reviewed_on: dated results "
                "share one executed cycle date",
            )
        evidence_ref = item.get("evidence_ref")
        if not isinstance(evidence_ref, str) or evidence_ref.count("#") != 1:
            _add(
                issues, "integrity", "invalid-evidence-ref", opath,
                "evidence reference must be repo-relative Markdown path#anchor",
            )
            continue
        if any(
            unicodedata.category(char) in {"Cc", "Cf", "Cs"}
            for char in evidence_ref
        ):
            _add(
                issues, "integrity", "invalid-evidence-ref", opath,
                "evidence reference contains a control, format, or "
                "surrogate character",
            )
            continue
        rel_text, anchor = evidence_ref.split("#", 1)
        relative = _check_repo_relative_file(rel_text, allowed_suffixes=(".md",))
        if relative is None or _ANCHOR_RE.fullmatch(anchor) is None:
            _add(
                issues, "integrity", "invalid-evidence-ref", opath,
                "evidence reference must be a bounded repo-relative "
                "Markdown path#anchor",
            )
            continue
        if rel_text not in seen_evidence_paths:
            _add(
                issues, "integrity", "evidence-ref-unbound", opath,
                f"evidence reference {rel_text!r} is not bound by this "
                "cycle's revision-bound evidence: a pass without bound "
                "evidence is self-declared success",
            )
            continue
        available = anchors.get(rel_text)
        if available is None:
            _add(
                issues, "integrity", "evidence-decode-failed", opath,
                f"evidence document {rel_text} has no readable "
                "revision-bound anchors",
            )
            continue
        if anchor not in available:
            _add(
                issues, "integrity", "evidence-anchor-missing", opath,
                f"heading anchor {anchor!r} does not exist in the "
                f"revision-bound {rel_text}",
            )
    if len(seen_pairs) > EXPECTED_PAIRS:
        _add(
            issues, "integrity", "extra-pair", "result.results",
            f"cycle holds {len(seen_pairs)} distinct pairs, more than the "
            f"governed {EXPECTED_PAIRS}",
        )

    if epoch is not None:
        missing_pairs = expected_pairs - seen_pairs
        if missing_pairs:
            by_entity: dict[str, list[str]] = {}
            for entity, trigger in sorted(missing_pairs):
                by_entity.setdefault(entity, []).append(trigger)
            for entity in sorted(by_entity):
                if entity not in {pair[0] for pair in seen_pairs}:
                    _add(
                        issues, "integrity", "missing-entity", "result",
                        f"authoritative entity {entity!r} has no results "
                        f"(missing triggers {sorted(by_entity[entity])!r})",
                    )
                else:
                    _add(
                        issues, "integrity", "missing-trigger", "result",
                        f"entity {entity!r} is missing triggers "
                        f"{sorted(by_entity[entity])!r}",
                    )
            sample = sorted(missing_pairs)[:6]
            _add(
                issues, "coverage", "coverage-incomplete", "result",
                f"cycle covers {len(seen_pairs)} of {len(expected_pairs)} "
                f"authoritative pairs; sample missing={sample!r}",
            )

    integrity_ok = not any(issue.category == "integrity" for issue in issues)
    coverage_ok = integrity_ok and not any(
        issue.category == "coverage" for issue in issues
    )

    record_checks = (
        document.get("record_checks", [])
        if isinstance(document.get("record_checks"), list)
        else []
    )
    checks: list[dict[str, Any]] = []
    for check in record_checks:
        if isinstance(check, dict):
            checks.append(
                {
                    "result_id": document.get("result_id"),
                    "check": check.get("check"),
                    "result": check.get("result"),
                    "detail": check.get("detail"),
                }
            )
    unknown_outcomes: list[str] = []
    for item in (
        document.get("unknown_outcomes", [])
        if isinstance(document.get("unknown_outcomes"), list)
        else []
    ):
        if isinstance(item, str) and item not in unknown_outcomes:
            unknown_outcomes.append(item)
    limitations: list[str] = []
    for item in (
        document.get("limitations", [])
        if isinstance(document.get("limitations"), list)
        else []
    ):
        if isinstance(item, str) and item not in limitations:
            limitations.append(item)

    asserts = document.get("asserts", {})
    if isinstance(asserts, dict):
        if asserts.get("integrity_ok") is True and not integrity_ok:
            _add(
                issues, "integrity", "unsupported-positive-outcome",
                "result.asserts",
                "the cycle asserts integrity while recomputed integrity fails",
            )
        if asserts.get("coverage_ok") is True and not coverage_ok:
            _add(
                issues, "integrity", "unsupported-positive-outcome",
                "result.asserts",
                "the cycle asserts full coverage while recomputed coverage fails",
            )
        for check in record_checks:
            if (
                isinstance(check, dict)
                and check.get("result") == "pass"
                and not integrity_ok
            ):
                _add(
                    issues, "integrity", "unsupported-positive-outcome",
                    "result.asserts",
                    f"record check {check.get('check')!r} reports pass while "
                    "recomputed integrity fails",
                )
                break
    integrity_ok = not any(issue.category == "integrity" for issue in issues)
    coverage_ok = integrity_ok and not any(
        issue.category == "coverage" for issue in issues
    )

    # Completion (v1): integrity plus full one-to-one coverage with valid
    # cycle dates. Fail outcomes do not block completion: the protocol
    # verifies that the operation was executed with evidence, not that
    # every check passed. A cycle asserting completion without meeting
    # these terms fails integrity as an unsupported positive.
    cycle_complete_ok = integrity_ok and coverage_ok
    if isinstance(asserts, dict) and asserts.get("cycle_complete_ok") is True:
        if not cycle_complete_ok:
            _add(
                issues, "integrity", "unsupported-positive-outcome",
                "result.asserts",
                "the cycle asserts a completed executed cycle while no "
                "completed cycle is established",
            )
    if not cycle_complete_ok:
        _add(
            issues, "complete", "cycle-incomplete", "result",
            "no completed executed cycle is established: a future cycle "
            "must bind dated executed-check results one-to-one to all "
            f"{EXPECTED_PAIRS} governed pairs with revision-bound evidence",
        )
    integrity_ok = not any(issue.category == "integrity" for issue in issues)
    coverage_ok = integrity_ok and not any(
        issue.category == "coverage" for issue in issues
    )
    if any(issue.category in {"integrity", "coverage"} for issue in issues):
        cycle_complete_ok = False

    # Report expected counts from the validated cycle epoch. Each v1 epoch
    # must carry the same exact governed roster/trigger policy, while its
    # revision and due dates advance with history. The reported dues are
    # the epoch register's dues at inspected_revision, not a post-cycle
    # projection: they predate the cycle when the epoch was not advanced.
    # cycle_reviewed_on / epoch_reviewed_on make that provenance explicit
    # next to cycle_complete_ok.
    cycle_reviewed_on = reviewed.isoformat() if reviewed is not None else None
    if epoch is not None:
        _epoch_reviewed_values = {
            info.get("reviewed_on") for info in epoch.expected.values()
        }
        if len(_epoch_reviewed_values) == 1:
            _only = next(iter(_epoch_reviewed_values))
            epoch_reviewed_on: str | None = (
                _only if isinstance(_only, str) else None
            )
        else:
            epoch_reviewed_on = None
        pairs_expected = sum(
            len(info["triggers"]) for info in epoch.expected.values()
        )
        register_revision_value = epoch.document.get("register_revision")
        register_revision = (
            register_revision_value
            if isinstance(register_revision_value, int)
            else None
        )
        register_sha256_value: str | None = epoch.sha256
        entities_expected = len(epoch.expected)
        sources_expected = epoch.class_counts["source"]
        modules_expected = epoch.class_counts["module"]
        runtimes_expected = epoch.class_counts["runtime"]
        next_due_source = epoch.dues["source"]
        next_due_runtime = epoch.dues["runtime"]
        next_due_module = epoch.dues["module"]
        queue_next = epoch.queue_next
    else:
        pairs_expected = 0
        register_revision = None
        register_sha256_value = None
        entities_expected = 0
        sources_expected = 0
        modules_expected = 0
        runtimes_expected = 0
        next_due_source = None
        next_due_runtime = None
        next_due_module = None
        queue_next = None
        epoch_reviewed_on = None
    due_provenance = "epoch-dues-at-inspected-revision"

    latest_entities = {entity for entity, _trigger in seen_pairs}
    observed_sources = sorted(
        {name for name in latest_entities if name.startswith("source:")}
    )
    observed_modules = sorted(
        {name for name in latest_entities if name.startswith("module:")}
    )
    observed_runtimes = sorted(
        {name for name in latest_entities if name.startswith("runtime:")}
    )

    checks_sorted = tuple(
        sorted(
            checks,
            key=lambda entry: (str(entry.get("check"))),
        )
    )
    return ReviewResultReport(
        requirement=requirement,
        as_of=as_of,
        result_path=result_path,
        result_sha256=result_sha256,
        register_revision=register_revision,
        register_sha256=register_sha256_value,
        result_schema_sha256=result_schema_sha256,
        integrity_ok=integrity_ok,
        coverage_ok=coverage_ok,
        cycle_complete_ok=cycle_complete_ok,
        epoch_validated=epoch is not None,
        entities_expected=entities_expected or EXPECTED_ENTITIES,
        entities_observed=len(latest_entities),
        sources_expected=sources_expected or EXPECTED_SOURCES,
        sources_observed=len(observed_sources),
        modules_expected=modules_expected or EXPECTED_MODULES,
        modules_observed=len(observed_modules),
        runtimes_expected=runtimes_expected or EXPECTED_RUNTIMES,
        runtimes_observed=len(observed_runtimes),
        pairs_expected=pairs_expected or EXPECTED_PAIRS,
        pairs_observed=len(seen_pairs),
        passes=passes,
        failures=failures,
        next_due_source=next_due_source,
        next_due_runtime=next_due_runtime,
        next_due_module=next_due_module,
        queue_next_review_on=queue_next,
        cycle_reviewed_on=cycle_reviewed_on,
        epoch_reviewed_on=epoch_reviewed_on,
        due_provenance=due_provenance,
        checks=checks_sorted,
        unknown_outcomes=tuple(sorted(unknown_outcomes)),
        limitations=tuple(sorted(limitations)),
        issues=tuple(sorted(set(issues))),
    )


def _iso_date(value: str) -> date:
    if _DATE_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Executed review-result verifier (revision-bound)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="verify a review-result file")
    check.add_argument("--result", type=Path, required=True)
    check.add_argument("--as-of", type=_iso_date, required=True)
    check.add_argument("--require", choices=REQUIREMENTS, required=True)
    check.add_argument("--format", choices=("json",), default="json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fail-closed review-result check: 0 satisfied, 1 gaps, 2 invalid."""

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.require not in REQUIREMENTS:
            raise ValueError(f"unknown requirement: {args.require}")
        # No --register or --result-schema override exists: the cycle is
        # reconciled against its own revision-bound register, and the
        # schema is always the pinned canonical bytes.
        document, result_sha256, result_schema_sha256 = load_result(args.result)
        report = verify_result(
            document,
            as_of=args.as_of,
            result_path=str(args.result),
            result_sha256=result_sha256,
            result_schema_sha256=result_schema_sha256,
            requirement=args.require,
        )
    except (ReviewLoadError, ValueError) as exc:
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
                "review-result verification failed closed: "
                f"{type(exc).__name__}: {exc}"
            ),
        }
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), allow_nan=False, indent=2, sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
