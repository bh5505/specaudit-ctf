"""Causal tests for the revision-bound attributed review-history verifier.

The committed 2026-10-13 import validates clean for integrity and full
coverage while recurrence stays unestablished. Each mutation breaks its
own invariant: removed entities/triggers, duplicate pairs, unknown
identities, changed evidence bytes, broken chains, altered pinned
history, replayed cycles, retimed historical copies, backdated
successors, renamed envelopes, substitute registers/schemas, non-finite
numbers, and missing/wrong Git revisions/blobs all fail closed.

Isolation: no test writes or replaces a tracked file in this shared
worktree. Mutations run on tmp history copies; causal historical-file
transitions run in synthetic tmp Git repositories. A tripwire test
asserts the tracked review files are byte-identical before and after.
"""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from markdown_it import MarkdownIt

import governance.reviews as reviews
from governance.reviews import (
    EXPECTED_ENTITIES,
    EXPECTED_MODULES,
    EXPECTED_PAIRS,
    EXPECTED_RUNTIMES,
    EXPECTED_SOURCES,
    HISTORY_ID,
    INITIAL_HISTORY_RECORD_DIGEST,
    REVIEW_SCHEMA_ID,
    ReviewLoadError,
    _RevisionBlobStore,
    _canonical_digest,
    load_history,
    load_review_schema,
    verify_history,
)

ROOT = Path(__file__).resolve().parents[1]
COMMITTED_HISTORY = ROOT / "governance" / "reviews" / "2026-10-13.attributed.json"
COMMITTED_RAW = COMMITTED_HISTORY.read_bytes()
FIXED_AS_OF = date(2026, 10, 18)
GENESIS_REV = "7499dd12cdc87efc93d7a53d51b5dd785a27221d"
GENESIS_REVIEWED = "2026-10-13"
GENESIS_RECORDED = "2026-10-18"
REPORT_SCHEMA = "specaudit.ctf.governance.review-verification-report.v1"
ERROR_SCHEMA = "specaudit.ctf.governance.validation-error.v1"

REGISTER_REL = "governance/register.v2.yaml"
EVIDENCE_MD_REL = "docs/governance/source-verification-2026-10-13.md"
REGISTER_SCHEMA_REL = "governance/schema/register.v2.schema.json"
REVIEW_SCHEMA_REL = "governance/schema/review-evidence.v1.schema.json"
TRACKED_REVIEW_FILES = (
    ROOT / REGISTER_REL,
    ROOT / EVIDENCE_MD_REL,
    ROOT / REGISTER_SCHEMA_REL,
    ROOT / REVIEW_SCHEMA_REL,
    COMMITTED_HISTORY,
)
TRACKED_BASELINE = {path: path.read_bytes() for path in TRACKED_REVIEW_FILES}
# The suite scrubs PATH per test: resolve git and the real PATH once here at
# import, per the tests/conftest.py convention (absolute *_BIN / own PATH).
_TEST_GIT_BIN = shutil.which("git")
_REAL_PATH = os.environ.get("PATH", "")


@pytest.fixture(scope="module")
def history_document() -> dict[str, Any]:
    return json.loads(COMMITTED_RAW.decode("utf-8"))


@pytest.fixture(scope="module")
def register_expected() -> dict[str, dict[str, set[str]]]:
    """Independently derived population: entity -> class + trigger set."""

    doc = yaml.safe_load((ROOT / REGISTER_REL).read_text())
    expected: dict[str, dict[str, set[str]]] = {}
    for row in doc["modules"]:
        expected[f"module:{row['id']}"] = {
            "class": "module",
            "triggers": set(row["currentness"]["triggers"]),
        }
    for row in doc["sources"]:
        expected[f"source:{row['id']}"] = {
            "class": "source",
            "triggers": set(row["currentness"]["triggers"]),
        }
    for row in doc["runtime"]:
        expected[f"runtime:{row['capability_id']}"] = {
            "class": "runtime",
            "triggers": set(row["currentness"]["triggers"]),
        }
    return expected


def _copy_history(history_document: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(history_document)


def _write_tmp(tmp_path: Path, document: dict[str, Any], name: str = "history.json") -> Path:
    target = tmp_path / name
    target.write_text(json.dumps(document, allow_nan=False, sort_keys=True), encoding="utf-8")
    return target


def _run_cli(
    history: Path, *, require: str, as_of: str = "2026-10-18", extra: tuple[str, ...] = ()
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PATH"] = _REAL_PATH
    return subprocess.run(
        [sys.executable, "-m", "governance.reviews", "check",
         "--history", str(history), "--as-of", as_of, "--require", require, *extra],
        capture_output=True, text=True, cwd=str(ROOT), env=env,
    )


def _codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


def _verify(
    document,
    *,
    require="integrity",
    as_of=FIXED_AS_OF,
    repo_root=None,
    store=None,
):
    return verify_history(
        document, as_of=as_of,
        history_path="<test-history>", history_sha256="sha256:" + "0" * 64,
        review_schema_sha256=None, requirement=require,
        repo_root=repo_root, blob_store=store,
    )


def _chained_record(
    history_document: dict[str, Any],
    *,
    record_id: str,
    reviewed_on: str,
    recorded_on: str,
    observed_on: str | None = None,
    basis: str | None = None,
    inspected_revision: str | None = None,
    asserts_recurrence: bool = False,
) -> dict[str, Any]:
    """Append a correctly hash-linked successor to a history copy."""

    document = _copy_history(history_document)
    first = document["records"][0]
    replay = copy.deepcopy(first)
    replay["record_id"] = record_id
    replay["reviewed_on"] = reviewed_on
    replay["recorded_on"] = recorded_on
    replay["predecessor_digest"] = _canonical_digest(first)
    replay["asserts"] = {
        "integrity_ok": True, "coverage_ok": True,
        "recurring_operation_ok": asserts_recurrence,
    }
    for obs in replay["observations"]:
        if observed_on is not None:
            obs["observed_on"] = observed_on
        if basis is not None:
            obs["basis"] = basis
    if inspected_revision is not None:
        replay["inspected_revision"] = inspected_revision
    document["records"] = [first, replay]
    return document


# ---------------------------------------------------------------------------
# Positive: the real committed artifact
# ---------------------------------------------------------------------------

def test_committed_artifact_reconciles_full_population(
    history_document, register_expected
) -> None:
    assert EXPECTED_SOURCES == 109
    assert EXPECTED_MODULES == 29
    assert EXPECTED_RUNTIMES == 227
    assert EXPECTED_ENTITIES == 365
    assert EXPECTED_PAIRS == 1095
    assert len(register_expected) == 365
    assert sum(len(v["triggers"]) for v in register_expected.values()) == 1095
    assert sum(1 for e in register_expected if e.startswith("source:")) == 109
    assert sum(1 for e in register_expected if e.startswith("module:")) == 29
    assert sum(1 for e in register_expected if e.startswith("runtime:")) == 227

    # Immutable envelope identity is anchored, not merely shaped.
    assert history_document["schema"] == REVIEW_SCHEMA_ID
    assert history_document["schema_version"] == 1
    assert history_document["history_id"] == HISTORY_ID == "attributed-review-history-v1"

    record = history_document["records"][0]
    assert record["reviewed_on"] == GENESIS_REVIEWED
    assert record["recorded_on"] == GENESIS_RECORDED
    assert record["recorded_on"] >= record["reviewed_on"]
    assert record["inspected_revision"] == GENESIS_REV
    assert record["reviewer"] == "specaudit-ctf-maintainers"
    assert record["predecessor_digest"] is None
    assert record["asserts"] == {
        "integrity_ok": True, "coverage_ok": True, "recurring_operation_ok": False,
    }
    observed = {(o["entity"], o["trigger"]) for o in record["observations"]}
    assert len(observed) == 1095
    assert len(record["observations"]) == 1095
    for entity, info in register_expected.items():
        for trigger in info["triggers"]:
            assert (entity, trigger) in observed
    for row in yaml.safe_load((ROOT / REGISTER_REL).read_text())["modules"]:
        for check in row["currentness"]["trigger_checks"]:
            match = next(
                o for o in record["observations"]
                if o["entity"] == f"module:{row['id']}" and o["trigger"] == check["trigger"]
            )
            assert match["checked_via"] == check["checked_via"]
            assert match["evidence_ref"] == check["evidence_ref"]
            assert match["basis"] == "historical-declaration"
            assert match["outcome"] == "reviewed"
            assert match["observed_on"] == GENESIS_REVIEWED
    limitations = " ".join(record["limitations"])
    assert "30 module rows" in limitations
    assert "29 modules" in limitations
    assert "did not exist on 2026-10-13" in limitations
    assert "recorded_on 2026-10-18" in limitations
    # Every observation cites the single bound Markdown evidence file.
    assert {
        o["evidence_ref"].split("#")[0] for o in record["observations"]
    } == {EVIDENCE_MD_REL}


def test_pinned_initial_digest_matches_committed_record(history_document) -> None:
    record = history_document["records"][0]
    canonical = json.dumps(
        record, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    assert "sha256:" + hashlib.sha256(canonical).hexdigest() == INITIAL_HISTORY_RECORD_DIGEST


def test_pristine_history_passes_integrity_and_coverage_but_not_recurrence(
    history_document,
) -> None:
    for require, expected_ok in (("integrity", True), ("coverage", True), ("recurrence", False)):
        report = _verify(history_document, require=require)
        assert report.integrity_ok is True
        assert report.coverage_ok is True
        assert report.recurring_operation_ok is False
        assert report.ok is expected_ok
        assert report.entities_expected == 365
        assert report.entities_observed == 365
        assert report.pairs_expected == 1095
        assert report.pairs_observed == 1095
        assert report.sources_observed == 109
        assert report.modules_observed == 29
        assert report.runtimes_observed == 227
        assert report.register_revision == 2
    report = _verify(history_document, require="integrity")
    assert report.next_due_source == "2027-01-11"
    assert report.next_due_runtime == "2027-01-11"
    assert report.next_due_module == "2027-04-13"
    assert report.queue_next_review_on == "2027-01-11"
    assert report.as_dict()["schema"] == REPORT_SCHEMA
    # The register digest binds the revision-bound register bytes.
    register_entry = next(
        e for e in history_document["records"][0]["evidence"] if e["path"] == REGISTER_REL
    )
    assert report.register_sha256 == register_entry["sha256"]
    payload = report.as_dict()
    assert isinstance(payload["executed_checks"], list) and payload["executed_checks"]
    assert isinstance(payload["unknown_outcomes"], list) and payload["unknown_outcomes"]
    assert isinstance(payload["limitations"], list) and payload["limitations"]
    check_names = {c["check"] for c in payload["executed_checks"]}
    assert "register-reconciliation" in check_names
    assert "evidence-byte-binding" in check_names


def test_cli_reports_requirements_separately_and_deterministically() -> None:
    first = _run_cli(COMMITTED_HISTORY, require="integrity")
    assert first.returncode == 0
    assert first.stderr == ""
    payload = json.loads(first.stdout)
    assert payload["schema"] == REPORT_SCHEMA
    assert payload["ok"] is True
    assert payload["integrity_ok"] is True
    assert payload["coverage_ok"] is True
    assert payload["recurring_operation_ok"] is False

    second = _run_cli(COMMITTED_HISTORY, require="coverage")
    assert second.returncode == 0
    assert json.loads(second.stdout)["ok"] is True

    third = _run_cli(COMMITTED_HISTORY, require="recurrence")
    assert third.returncode == 1
    recurred = json.loads(third.stdout)
    assert recurred["ok"] is False
    assert recurred["recurring_operation_ok"] is False
    assert recurred["integrity_ok"] is True
    assert recurred["coverage_ok"] is True

    repeat = _run_cli(COMMITTED_HISTORY, require="integrity")
    assert repeat.stdout == first.stdout


def test_cli_help_preserves_argparse_contract() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "governance.reviews", "--help"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env={**os.environ, "PATH": _REAL_PATH},
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout.startswith("usage:")
    assert "Attributed review-history verifier" in completed.stdout


def test_review_schema_is_canonical_and_pinned() -> None:
    schema, digest = load_review_schema()
    assert digest == reviews.CANONICAL_REVIEW_SCHEMA_SHA256
    assert schema["title"] == REVIEW_SCHEMA_ID
    assert schema["properties"]["history_id"] == {"const": HISTORY_ID}
    assert "schema" in schema["required"] and "history_id" in schema["required"]
    # No override exists anywhere in the loader surface.
    assert tuple(inspect.signature(load_review_schema).parameters) == ()
    assert tuple(inspect.signature(load_history).parameters) == ("path",)


# ---------------------------------------------------------------------------
# Removed overrides: no caller-substituted register or schema
# ---------------------------------------------------------------------------

def test_register_and_schema_overrides_are_removed(tmp_path) -> None:
    target = _write_tmp(tmp_path, json.loads(COMMITTED_RAW.decode("utf-8")))
    for flag, value in (
        ("--register", "governance/register.v2.yaml"),
        ("--review-schema", "governance/schema/review-evidence.v1.schema.json"),
    ):
        completed = _run_cli(target, require="integrity", extra=(flag, value))
        assert completed.returncode == 2
        assert "unrecognized arguments" in completed.stderr
    # The parser offers no register/schema surface at all.
    assert "--register" not in reviews._parser().format_help()
    assert "--review-schema" not in reviews._parser().format_help()


# ---------------------------------------------------------------------------
# Strict parsing: unknown fields and non-finite numbers fail closed
# ---------------------------------------------------------------------------

def test_substitute_open_schema_cannot_smuggle_unknown_fields(tmp_path) -> None:
    document = json.loads(COMMITTED_RAW.decode("utf-8"))
    document["uninvited"] = True
    target = _write_tmp(tmp_path, document, name="extra.json")
    completed = _run_cli(target, require="integrity")
    assert completed.returncode == 2
    assert json.loads(completed.stderr)["schema"] == ERROR_SCHEMA
    with pytest.raises(ReviewLoadError):
        load_history(target)


@pytest.mark.parametrize("literal", ["1e999", "-1e999"])
def test_overflow_to_infinity_rejected_before_schema_validation(tmp_path, literal) -> None:
    raw = COMMITTED_RAW.decode("utf-8")
    assert '"byte_length": 16224' in raw
    poisoned = tmp_path / "nonfinite.json"
    poisoned.write_text(raw.replace('"byte_length": 16224', f'"byte_length": {literal}', 1))
    with pytest.raises(ReviewLoadError, match="non-finite"):
        load_history(poisoned)
    completed = _run_cli(poisoned, require="integrity")
    assert completed.returncode == 2
    assert json.loads(completed.stderr)["schema"] == ERROR_SCHEMA


def test_literal_nonfinite_and_duplicate_keys_rejected(tmp_path) -> None:
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"value": NaN}')
    with pytest.raises(ReviewLoadError):
        load_history(nonfinite)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema": 1, "schema": 2}')
    with pytest.raises(ReviewLoadError):
        load_history(duplicate)

    raw = COMMITTED_RAW.decode("utf-8")
    assert '"schema_version": 1\n}' in raw
    malformed = tmp_path / "malformed.json"
    malformed.write_text(raw.replace('"schema_version": 1\n}', '"schema_version": 1,\n}', 1))
    completed = _run_cli(malformed, require="integrity")
    assert completed.returncode == 2
    assert json.loads(completed.stderr)["schema"] == ERROR_SCHEMA
    with pytest.raises(ReviewLoadError):
        load_history(malformed)


def test_history_symlink_is_refused_without_custody_claim(tmp_path) -> None:
    link = tmp_path / "linked.json"
    link.symlink_to(COMMITTED_HISTORY)
    with pytest.raises(ReviewLoadError, match="must not be a symlink"):
        load_history(link)
    completed = _run_cli(link, require="integrity")
    assert completed.returncode == 2
    assert json.loads(completed.stderr)["schema"] == ERROR_SCHEMA


# ---------------------------------------------------------------------------
# Immutable envelope: history_id cannot change
# ---------------------------------------------------------------------------

def test_changed_history_id_fails_at_schema_and_code_layers(
    history_document, tmp_path
) -> None:
    renamed = _copy_history(history_document)
    renamed["history_id"] = "renamed-history"
    target = _write_tmp(tmp_path, renamed, name="renamed.json")
    with pytest.raises(ReviewLoadError):
        load_history(target)
    completed = _run_cli(target, require="integrity")
    assert completed.returncode == 2

    # Programmatic callers bypass the loader, so code enforces it too.
    report = _verify(renamed, require="integrity")
    assert report.integrity_ok is False
    assert "history-identity-mismatch" in _codes(report)

    report = _verify(_copy_history(history_document), require="integrity")
    assert "history-identity-mismatch" not in _codes(report)


# ---------------------------------------------------------------------------
# Classic causal mutations on tmp copies
# ---------------------------------------------------------------------------

def test_remove_one_entity_breaks_coverage(history_document, tmp_path) -> None:
    document = _copy_history(history_document)
    document["records"][0]["observations"] = [
        o for o in document["records"][0]["observations"] if o["entity"] != "source:SP-07"
    ]
    report = _verify(document, require="coverage")
    assert report.coverage_ok is False
    assert report.integrity_ok is False
    assert "missing-entity" in _codes(report)
    assert "coverage-incomplete" in _codes(report)
    assert report.entities_observed == 364
    assert report.pairs_observed == 1092
    target = _write_tmp(tmp_path, document)
    completed = _run_cli(target, require="coverage")
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["ok"] is False


def test_remove_one_trigger_breaks_coverage(history_document, tmp_path) -> None:
    document = _copy_history(history_document)
    victim = next(
        o for o in document["records"][0]["observations"]
        if o["entity"] == "runtime:nmap.scan"
    )
    document["records"][0]["observations"].remove(victim)
    report = _verify(document, require="coverage")
    assert report.coverage_ok is False
    assert "missing-trigger" in _codes(report)
    assert "coverage-incomplete" in _codes(report)
    assert report.entities_observed == 365
    assert report.pairs_observed == 1094
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="coverage").returncode == 1


def test_duplicate_pair_fails_integrity(history_document, tmp_path) -> None:
    document = _copy_history(history_document)
    document["records"][0]["observations"].append(
        copy.deepcopy(document["records"][0]["observations"][0])
    )
    report = _verify(document)
    assert report.integrity_ok is False
    assert "duplicate-pair" in _codes(report)
    target = _write_tmp(tmp_path, document)
    completed = _run_cli(target, require="integrity")
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["integrity_ok"] is False


@pytest.mark.parametrize("kind", ["entity", "trigger"])
def test_unknown_identity_fails_integrity(history_document, tmp_path, kind) -> None:
    document = _copy_history(history_document)
    probe = copy.deepcopy(document["records"][0]["observations"][0])
    if kind == "entity":
        probe["entity"] = "source:R99"
    else:
        probe["trigger"] = "bogus-trigger-never-declared"
    document["records"][0]["observations"].append(probe)
    report = _verify(document)
    assert report.integrity_ok is False
    assert (f"unknown-{kind}" in _codes(report))
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="integrity").returncode == 1


def test_changed_recorded_digest_fails_evidence_binding(history_document, tmp_path) -> None:
    document = _copy_history(history_document)
    document["records"][0]["evidence"][0]["sha256"] = "sha256:" + "0" * 64
    report = _verify(document)
    assert report.integrity_ok is False
    assert "evidence-bytes-mismatch" in _codes(report)
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="integrity").returncode == 1


def test_broken_chain_fails_integrity(history_document, tmp_path) -> None:
    document = _copy_history(history_document)
    document["records"][0]["predecessor_digest"] = "sha256:" + "0" * 64
    report = _verify(document)
    assert report.integrity_ok is False
    assert "genesis-predecessor-nonnull" in _codes(report)
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="integrity").returncode == 1


def test_altered_pinned_initial_history_fails(history_document, tmp_path) -> None:
    document = _copy_history(history_document)
    document["records"][0]["limitations"][0] += " (synthetic probe edit)"
    report = _verify(document)
    assert report.integrity_ok is False
    assert "initial-pin-mismatch" in _codes(report)
    target = _write_tmp(tmp_path, document)
    completed = _run_cli(target, require="integrity")
    assert completed.returncode == 1
    assert "initial-pin-mismatch" in {
        i["code"] for i in json.loads(completed.stdout)["issues"]
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("reviewed_on", "2026-10-19"),
        ("recorded_on", "2026-10-19"),
    ],
)
def test_future_record_dates_fail(history_document, tmp_path, field, value) -> None:
    document = _copy_history(history_document)
    document["records"][0][field] = value
    report = _verify(document)
    assert report.integrity_ok is False
    assert _codes(report) & {"review-in-future", "recorded-in-future", "observed-date-mismatch"}


def test_future_observation_fails(history_document, tmp_path) -> None:
    document = _copy_history(history_document)
    document["records"][0]["observations"][0]["observed_on"] = "2026-10-19"
    report = _verify(document)
    assert report.integrity_ok is False
    assert "observed-in-future" in _codes(report) or "observed-date-mismatch" in _codes(report)


def test_unsupported_positive_outcomes_fail(history_document, tmp_path) -> None:
    document = _copy_history(history_document)
    document["records"][0]["asserts"]["recurring_operation_ok"] = True
    report = _verify(document)
    assert report.integrity_ok is False
    assert "unsupported-positive-outcome" in _codes(report)
    assert report.recurring_operation_ok is False
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="integrity").returncode == 1

    document = _copy_history(history_document)
    document["records"][0]["observations"][0]["basis"] = "unknown"
    report = _verify(document)
    assert report.integrity_ok is False
    assert "outcome-basis-mismatch" in _codes(report)


# ---------------------------------------------------------------------------
# Recurrence stays negative without genuine executed-check operation
# ---------------------------------------------------------------------------

def test_replay_and_asof_advance_cannot_complete_a_cycle(history_document, tmp_path) -> None:
    for as_of in ("2026-10-18", "2027-06-01"):
        report = _verify(
            history_document, require="recurrence",
            as_of=date.fromisoformat(as_of),
        )
        assert report.recurring_operation_ok is False
        assert report.integrity_ok is True
        assert report.coverage_ok is True
    document = _chained_record(
        history_document,
        record_id="2026-10-13-attributed-replay",
        reviewed_on="2026-10-13",
        recorded_on="2026-10-13",
        observed_on="2026-10-13",
    )
    report = _verify(document, require="recurrence")
    assert report.integrity_ok is False  # same-day successor breaks strict chronology
    assert report.recurring_operation_ok is False
    assert "recurrence-not-established" in _codes(report)
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="recurrence").returncode == 1
    assert _run_cli(target, require="integrity").returncode == 1


@pytest.mark.parametrize(
    "reviewed_on,recorded_on",
    [
        ("2027-02-10", "2027-02-11"),  # retimed copy over a full span
        ("2026-10-23", "2026-10-24"),  # short-span date-only rewrite
    ],
)
def test_retimed_copies_never_complete_a_cycle(
    history_document, tmp_path, reviewed_on, recorded_on
) -> None:
    """A retimed deep copy of genesis is not an operated cycle.

    Retiming historical declarations to a new observed_on breaks the
    historical-epoch binding (observed_on must equal that entity's epoch
    reviewed_on), so integrity fails closed; recurrence stays false either
    way. v1 defines no executed-result protocol that could make a retimed
    copy operate.
    """

    document = _chained_record(
        history_document,
        record_id="2026-10-13-attributed-retimed",
        reviewed_on=reviewed_on,
        recorded_on=recorded_on,
        observed_on=reviewed_on,
        basis="historical-declaration",
    )
    report = _verify(document, require="recurrence", as_of=date(2027, 6, 1))
    assert report.integrity_ok is False
    assert report.recurring_operation_ok is False
    assert "historical-observed-mismatch" in _codes(report)
    assert "recurrence-not-established" in _codes(report)
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="recurrence", as_of="2027-06-01").returncode == 1
    assert _run_cli(target, require="integrity", as_of="2027-06-01").returncode == 1


def test_unknown_basis_rewrite_loses_coverage(history_document) -> None:
    document = _chained_record(
        history_document,
        record_id="2027-02-10-unknown-rewrite",
        reviewed_on="2027-02-10",
        recorded_on="2027-02-11",
        observed_on="2027-02-10",
        basis="unknown",
    )
    for obs in document["records"][1]["observations"]:
        obs["outcome"] = "unknown"
    report = _verify(document, require="recurrence", as_of=date(2027, 6, 1))
    assert report.recurring_operation_ok is False
    assert "coverage-unknown-outcome" in _codes(report)


def test_same_revision_executed_basis_is_still_a_replay(history_document, tmp_path) -> None:
    """Flipping every basis to executed-check on the same revision is a replay.

    The bytes are not newly evidenced: the inspected revision is unchanged,
    so no operated cycle is established even though the basis claims work.
    """

    document = _chained_record(
        history_document,
        record_id="2027-02-10-replayed-checks",
        reviewed_on="2027-02-10",
        recorded_on="2027-02-11",
        observed_on="2027-02-10",
        basis="executed-check",
    )
    report = _verify(document, require="recurrence", as_of=date(2027, 6, 1))
    assert report.integrity_ok is True
    assert report.coverage_ok is True
    assert report.recurring_operation_ok is False
    assert "recurrence-not-established" in _codes(report)
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="recurrence", as_of="2027-06-01").returncode == 1


# ---------------------------------------------------------------------------
# Strict cross-record chronology is integrity
# ---------------------------------------------------------------------------

def test_backdated_successor_reviewed_on_fails(history_document, tmp_path) -> None:
    document = _chained_record(
        history_document,
        record_id="2026-10-01-backdated-review",
        reviewed_on="2026-10-01",
        recorded_on="2026-10-20",
        observed_on="2026-10-01",
    )
    report = _verify(document, as_of=date(2026, 10, 21))
    assert report.integrity_ok is False
    assert "review-chronology-regression" in _codes(report)
    assert "cross-record-chronology" in _codes(report)
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="integrity", as_of="2026-10-21").returncode == 1


def test_backdated_successor_recorded_on_fails(history_document, tmp_path) -> None:
    document = _chained_record(
        history_document,
        record_id="2026-10-20-misrecorded",
        reviewed_on="2026-10-20",
        recorded_on="2026-10-18",
        observed_on="2026-10-20",
    )
    report = _verify(document, as_of=date(2026, 10, 21))
    assert report.integrity_ok is False
    assert "record-chronology-regression" in _codes(report)
    assert "recorded-before-reviewed" in _codes(report)
    target = _write_tmp(tmp_path, document)
    assert _run_cli(target, require="integrity", as_of="2026-10-21").returncode == 1


def test_successor_review_before_predecessor_record_fails(history_document) -> None:
    document = _chained_record(
        history_document,
        record_id="2026-10-15-overlapping-review",
        reviewed_on="2026-10-15",
        recorded_on="2026-10-19",
        observed_on="2026-10-15",
    )
    report = _verify(document, as_of=date(2026, 10, 21))
    assert report.integrity_ok is False
    assert "cross-record-chronology" in _codes(report)
    assert "review-chronology-regression" not in _codes(report)
    assert "record-chronology-regression" not in _codes(report)


# ---------------------------------------------------------------------------
# Revision-bound history in synthetic Git repositories
# ---------------------------------------------------------------------------

def _git(repo: Path, *args: str) -> str:
    if _TEST_GIT_BIN is None:
        pytest.skip("git executable unavailable")
    completed = subprocess.run(
        [_TEST_GIT_BIN, "-C", str(repo), *args],
        capture_output=True, text=True, check=True, timeout=120,
    )
    return completed.stdout.strip()


def _commit_all(repo: Path, message: str, *, allow_empty: bool = False) -> str:
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=gov-test", "-c", "user.email=gov-test@example.invalid",
         "commit", "-qm", message, *(["--allow-empty"] if allow_empty else []))
    return _git(repo, "rev-parse", "HEAD")


def _cloned_repo(tmp_path: Path) -> Path:
    """Clone the checkout into tmp: an isolated synthetic repository.

    The clone is fully offline (local path source) and carries every
    committed object, including the pinned genesis inspected revision, so
    the byte-exact genesis record keeps resolving while new synthetic
    epochs are committed on top. Nothing is written to the shared
    worktree.
    """

    if _TEST_GIT_BIN is None:
        pytest.skip("git executable unavailable")
    repo = tmp_path / "synth-repo"
    completed = subprocess.run(
        [_TEST_GIT_BIN, "clone", "-q", str(ROOT), str(repo)],
        capture_output=True, text=True, timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    return repo


def _real_blobs() -> dict[str, bytes]:
    return {
        REGISTER_REL: (ROOT / REGISTER_REL).read_bytes(),
        EVIDENCE_MD_REL: (ROOT / EVIDENCE_MD_REL).read_bytes(),
        REGISTER_SCHEMA_REL: (ROOT / REGISTER_SCHEMA_REL).read_bytes(),
    }


def _successor_for_blobs(
    history_document: dict[str, Any],
    revision: str,
    blobs: dict[str, bytes],
    *,
    record_id: str,
    reviewed_on: str,
    recorded_on: str,
    basis: str | None = None,
    asserts_recurrence: bool = False,
    digest_blobs: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Append a correctly chained successor bound to synthetic epoch bytes.

    The genesis record stays byte-exact (its pin and chain head hold); only
    the appended record references the synthetic revision. ``digest_blobs``
    optionally supplies different bytes for the recorded digests, to prove
    a stale or tampered binding mismatches the revision-bound blobs.
    """

    document = copy.deepcopy(history_document)
    genesis = document["records"][0]
    successor = copy.deepcopy(genesis)
    successor["record_id"] = record_id
    successor["reviewed_on"] = reviewed_on
    successor["recorded_on"] = recorded_on
    successor["inspected_revision"] = revision
    successor["predecessor_digest"] = _canonical_digest(genesis)
    successor["asserts"] = {
        "integrity_ok": True, "coverage_ok": True,
        "recurring_operation_ok": asserts_recurrence,
    }
    claimed = digest_blobs if digest_blobs is not None else blobs
    for entry in successor["evidence"]:
        data = claimed[entry["path"]]
        entry["sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
        entry["byte_length"] = len(data)
    for obs in successor["observations"]:
        obs["observed_on"] = reviewed_on
        if basis is not None:
            obs["basis"] = basis
    document["records"] = [genesis, successor]
    return document


def _register_bytes_with_duplicate_module() -> bytes:
    text = (ROOT / REGISTER_REL).read_text(encoding="utf-8")
    assert "\n- id: AUD-02\n" in text
    assert text.count("\n- id: AUD-01\n") == 1
    return text.replace("\n- id: AUD-02\n", "\n- id: AUD-01\n", 1).encode("utf-8")


def test_revision_bound_evidence_survives_working_tree_edit_and_new_commit(
    history_document, tmp_path
) -> None:
    """Working-tree edits neither invalidate nor replace revision history."""

    repo = _cloned_repo(tmp_path)
    report = _verify(history_document, repo_root=repo)
    assert report.integrity_ok is True
    assert report.coverage_ok is True
    assert report.recurring_operation_ok is False
    assert _codes(report) == {"recurrence-not-established"}

    # Uncommitted working-tree edits are invisible to revision-bound reads.
    blobs = _real_blobs()
    (repo / EVIDENCE_MD_REL).write_bytes(blobs[EVIDENCE_MD_REL] + b"\n<!-- drift -->\n")
    (repo / REGISTER_REL).write_bytes(blobs[REGISTER_REL] + b"\n# drift\n")
    report = _verify(history_document, repo_root=repo)
    assert report.integrity_ok is True
    assert report.coverage_ok is True

    # So is a later commit: history stays bound to its inspected revision.
    rev_b = _commit_all(repo, "drift")
    assert rev_b != GENESIS_REV
    report = _verify(history_document, repo_root=repo)
    assert report.integrity_ok is True
    assert report.coverage_ok is True
    assert report.recurring_operation_ok is False


def test_unknown_revision_fails_closed(history_document, tmp_path) -> None:
    repo = _cloned_repo(tmp_path)
    document = _successor_for_blobs(
        history_document, "0" * 40, _real_blobs(),
        record_id="2027-02-10-unknown-rev",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "revision-unknown" in _codes(report)


def test_non_commit_revision_fails_closed(history_document, tmp_path) -> None:
    repo = _cloned_repo(tmp_path)
    blob_rev = _git(repo, "rev-parse", f"HEAD:{REGISTER_REL}")
    assert len(blob_rev) == 40 and blob_rev != GENESIS_REV
    document = _successor_for_blobs(
        history_document, blob_rev, _real_blobs(),
        record_id="2027-02-10-blob-rev",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "revision-not-commit" in _codes(report)


def test_stale_revision_with_changed_bytes_fails(history_document, tmp_path) -> None:
    """A binding recorded against older bytes mismatches the new revision."""

    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()
    (repo / EVIDENCE_MD_REL).write_bytes(blobs[EVIDENCE_MD_REL] + b"\n<!-- later edit -->\n")
    rev_b = _commit_all(repo, "later edit")
    document = _successor_for_blobs(
        history_document, rev_b, blobs,
        record_id="2027-02-10-stale-binding",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    assert document["records"][1]["evidence"][0]["path"] == EVIDENCE_MD_REL
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "evidence-bytes-mismatch" in _codes(report)


def test_missing_path_at_revision_fails(history_document, tmp_path) -> None:
    repo = _cloned_repo(tmp_path)
    (repo / EVIDENCE_MD_REL).unlink()
    rev_b = _commit_all(repo, "drop evidence")
    document = _successor_for_blobs(
        history_document, rev_b, _real_blobs(),
        record_id="2027-02-10-missing-path",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "evidence-path-missing" in _codes(report)


def test_symlink_evidence_at_revision_is_refused(history_document, tmp_path) -> None:
    """A parent/symlink substitution at the evidence path fails closed."""

    repo = _cloned_repo(tmp_path)
    target = repo / EVIDENCE_MD_REL
    target.unlink()
    target.symlink_to(repo / REGISTER_REL)
    rev_b = _commit_all(repo, "symlink evidence")
    document = _successor_for_blobs(
        history_document, rev_b, _real_blobs(),
        record_id="2027-02-10-symlink-evidence",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "evidence-non-blob" in _codes(report)


def test_oversized_blob_at_revision_is_refused(history_document, tmp_path) -> None:
    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()
    big = blobs[EVIDENCE_MD_REL] + b"x" * (reviews.MAX_EVIDENCE_BYTES + 1)
    (repo / EVIDENCE_MD_REL).write_bytes(big)
    rev_b = _commit_all(repo, "oversized evidence")
    edited = dict(blobs)
    edited[EVIDENCE_MD_REL] = big
    document = _successor_for_blobs(
        history_document, rev_b, edited,
        record_id="2027-02-10-oversized",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "evidence-oversized" in _codes(report)


def test_duplicate_register_identity_fails_semantic_validation(
    history_document, tmp_path
) -> None:
    """A caller-substituted register with duplicate ids never reconciles."""

    repo = _cloned_repo(tmp_path)
    edited = dict(_real_blobs())
    edited[REGISTER_REL] = _register_bytes_with_duplicate_module()
    (repo / REGISTER_REL).write_bytes(edited[REGISTER_REL])
    rev_b = _commit_all(repo, "duplicate module id")
    document = _successor_for_blobs(
        history_document, rev_b, edited,
        record_id="2027-02-10-duplicate-register",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "register-duplicate-id" in _codes(report)


def test_git_is_not_run_per_observation(history_document) -> None:
    """1095 observations sharing 3 evidence blobs need one fetch each."""

    store = _RevisionBlobStore(ROOT)
    report = _verify(history_document, store=store)
    assert report.integrity_ok is True
    assert store.fetches == 3
    # 1 revision-type check + 3 blobs x (ls-tree, size, read).
    assert store.git_calls <= 16


def test_empty_commit_relabel_never_establishes_recurrence(history_document, tmp_path) -> None:
    """An empty commit with relabeled executed-checks is still a replay.

    Schema/history v1 defines no independently verifiable executed-result
    protocol: byte-identical October evidence on a different/descendant
    empty commit, all 1,095 observations relabeled to executed-check,
    advanced dates, and copied pass declarations do not evidence operation.
    Recurrence stays false; asserting it true fails integrity as an
    unsupported positive. A future version must define and bind a closed
    executed-result artifact whose dated results reconcile one-to-one to
    all governed pairs.
    """

    repo = _cloned_repo(tmp_path)
    rev_b = _commit_all(repo, "second epoch", allow_empty=True)
    assert rev_b != GENESIS_REV
    document = _successor_for_blobs(
        history_document, rev_b, _real_blobs(),
        record_id="2027-01-15-relabeled-replay",
        reviewed_on="2027-01-15", recorded_on="2027-01-16",
        basis="executed-check",
        asserts_recurrence=False,
    )
    report = _verify(document, require="recurrence", as_of=date(2027, 1, 20), repo_root=repo)
    assert report.integrity_ok is True
    assert report.coverage_ok is True
    assert report.recurring_operation_ok is False
    assert report.ok is False
    assert report.record_count == 2
    assert report.pairs_observed == 1095
    assert "recurrence-not-established" in _codes(report)

    # The same construction on a descendant and on an unrelated commit also
    # stays negative: the revision being different, descendant, or unrelated
    # never evidences operation in v1.
    rev_c = _commit_all(repo, "third epoch", allow_empty=True)
    assert rev_c not in (GENESIS_REV, rev_b)
    descendant = _successor_for_blobs(
        history_document, rev_c, _real_blobs(),
        record_id="2027-01-15-relabeled-descendant",
        reviewed_on="2027-01-15", recorded_on="2027-01-16",
        basis="executed-check",
    )
    descendant_report = _verify(
        descendant, require="recurrence", as_of=date(2027, 1, 20), repo_root=repo
    )
    assert descendant_report.recurring_operation_ok is False

    fresh = tmp_path / "fresh-remote"
    fresh.mkdir()
    subprocess.run(
        [_TEST_GIT_BIN, "init", "-q", str(fresh)], check=True, timeout=120
    )
    subprocess.run(
        [_TEST_GIT_BIN, "-C", str(fresh), "-c", "user.name=gov-test",
         "-c", "user.email=gov-test@example.invalid", "commit", "-q",
         "--allow-empty", "-m", "unrelated"],
        check=True, timeout=120,
    )
    unrelated_rev = subprocess.run(
        [_TEST_GIT_BIN, "-C", str(fresh), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True, timeout=120,
    ).stdout.strip()
    assert len(unrelated_rev) == 40
    # An unrelated revision is not a known local object of the verifier root,
    # so integrity fails closed there; recurrence is still false.
    unrelated = _successor_for_blobs(
        history_document, unrelated_rev, _real_blobs(),
        record_id="2027-01-15-relabeled-unrelated",
        reviewed_on="2027-01-15", recorded_on="2027-01-16",
        basis="executed-check",
    )
    unrelated_report = _verify(
        unrelated, require="recurrence", as_of=date(2027, 1, 20), repo_root=repo
    )
    assert unrelated_report.integrity_ok is False
    assert unrelated_report.recurring_operation_ok is False

    # Asserting recurrence true on the relabeled replay is an unsupported
    # positive and fails integrity.
    claimed = _successor_for_blobs(
        history_document, rev_b, _real_blobs(),
        record_id="2027-01-15-relabeled-claimed",
        reviewed_on="2027-01-15", recorded_on="2027-01-16",
        basis="executed-check",
        asserts_recurrence=True,
    )
    claimed_report = _verify(
        claimed, require="integrity", as_of=date(2027, 1, 20), repo_root=repo
    )
    assert claimed_report.integrity_ok is False
    assert claimed_report.recurring_operation_ok is False
    assert "unsupported-positive-outcome" in _codes(claimed_report)


# ---------------------------------------------------------------------------
# Evidence references and promotion silence
# ---------------------------------------------------------------------------

def test_evidence_refs_resolve_independently(history_document) -> None:
    """Every observation citation names a real heading in its document."""

    refs = {
        o["evidence_ref"] for o in history_document["records"][0]["observations"]
    }
    assert len(refs) == 17
    assert all(ref.startswith(EVIDENCE_MD_REL + "#") for ref in refs)
    by_path: dict[str, set[str]] = {}
    for ref in refs:
        rel, anchor = ref.split("#", 1)
        by_path.setdefault(rel, set()).add(anchor)
    for rel, anchors in by_path.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        tokens = MarkdownIt("commonmark").parse(text)
        found: set[str] = set()
        for position, token in enumerate(tokens):
            if token.type != "heading_open":
                continue
            inline = tokens[position + 1]
            title = "".join(
                c.content for c in (inline.children or ())
                if c.type in {"text", "text_special", "code_inline"}
            )
            slug = "".join(
                ch for ch in title.lower() if ch.isalnum() or ch in {" ", "-", "_"}
            ).replace(" ", "-")
            if slug:
                found.add(slug)
        assert anchors <= found, (rel, sorted(anchors - found))


def test_no_promotion_or_w2_language_in_observations(history_document) -> None:
    blob = json.dumps(history_document["records"][0]["observations"])
    assert "promotion" not in blob
    assert "admitted" not in blob
    assert "W2" not in json.dumps(history_document["records"][0]["record_checks"])


# ---------------------------------------------------------------------------
# Finding 2: closed local Git environment (isolated regressions)
# ---------------------------------------------------------------------------

def test_ambient_git_env_cannot_redirect_result(history_document, tmp_path, monkeypatch) -> None:
    """Ambient GIT_* repository/object/config vars cannot change the result."""

    repo = _cloned_repo(tmp_path)
    evil = tmp_path / "evil-repo"
    subprocess.run(
        [_TEST_GIT_BIN, "init", "-q", str(evil)], check=True, timeout=120
    )
    subprocess.run(
        [_TEST_GIT_BIN, "-C", str(evil), "-c", "user.name=gov-test",
         "-c", "user.email=gov-test@example.invalid", "commit", "-q",
         "--allow-empty", "-m", "evil"],
        check=True, timeout=120,
    )
    bad_config = tmp_path / "bad-global-config"
    bad_config.write_text("[[[invalid\n", encoding="utf-8")
    empty_objects = tmp_path / "empty-objects"
    empty_objects.mkdir()
    monkeypatch.setenv("GIT_DIR", str(evil / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(evil))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(empty_objects))
    monkeypatch.setenv("GIT_INDEX_FILE", str(evil / "index"))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(repo))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(bad_config))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(bad_config))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.pager")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")
    # A bad global config would break git if honored (fatal: bad config
    # line); a GIT_DIR redirect would resolve the wrong revision. The closed
    # environment ignores all of them: the pinned genesis still reconciles.
    report = _verify(history_document, repo_root=repo)
    assert report.integrity_ok is True
    assert report.coverage_ok is True
    assert report.recurring_operation_ok is False
    assert report.pairs_observed == 1095


def test_local_replace_ref_cannot_rewrite_evidence(history_document, tmp_path) -> None:
    """A local refs/replace entry cannot rewrite the exact commit's evidence."""

    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()
    evil_md = blobs[EVIDENCE_MD_REL] + b"\n<!-- evil replace -->\n"
    (repo / EVIDENCE_MD_REL).write_bytes(evil_md)
    rev_evil = _commit_all(repo, "evil evidence")
    assert rev_evil != GENESIS_REV
    _git(repo, "replace", GENESIS_REV, rev_evil)
    try:
        # Without --no-replace-objects the replacement is visible...
        shown = subprocess.run(
            [_TEST_GIT_BIN, "-C", str(repo), "ls-tree", GENESIS_REV,
             "--", EVIDENCE_MD_REL],
            capture_output=True, check=True, timeout=120,
        ).stdout
        shown_oid = shown.split(b"\t")[0].split(b" ")[2]
        original_oid = subprocess.run(
            [_TEST_GIT_BIN, "-C", str(repo), "hash-object", "--stdin"],
            input=blobs[EVIDENCE_MD_REL], capture_output=True, check=True, timeout=120,
        ).stdout.strip()
        replacement_oid = subprocess.run(
            [_TEST_GIT_BIN, "-C", str(repo), "hash-object", "--stdin"],
            input=evil_md, capture_output=True, check=True, timeout=120,
        ).stdout.strip()
        assert shown_oid == replacement_oid
        assert shown_oid != original_oid
        # ...but the verifier resolves the exact commit without replacement,
        # so the pinned genesis still reconciles byte-exactly.
        report = _verify(history_document, repo_root=repo)
        assert report.integrity_ok is True
        assert report.coverage_ok is True
        assert report.pairs_observed == 1095
    finally:
        _git(repo, "replace", "-d", GENESIS_REV)


def test_missing_promisor_blob_fails_without_fetch(history_document, tmp_path) -> None:
    """A missing promisor blob fails closed without a fetch/upload-pack."""

    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()
    blob_hash = _git(repo, "rev-parse", f"{GENESIS_REV}:{REGISTER_REL}")
    assert len(blob_hash) == 40
    git_dir = Path(_git(repo, "rev-parse", "--git-dir"))
    if not git_dir.is_absolute():
        git_dir = repo / git_dir
    obj_path = git_dir / "objects" / blob_hash[:2] / blob_hash[2:]
    assert obj_path.is_file()
    saved = obj_path.read_bytes()
    # Point the promisor at this same checkout's objects via a tmp bare
    # remote that does hold the blob: a lazy fetch would succeed, so the
    # verifier's failure proves it never fetched.
    promisor = tmp_path / "promisor.git"
    subprocess.run(
        [_TEST_GIT_BIN, "clone", "-q", "--bare", str(ROOT), str(promisor)],
        check=True, timeout=180,
    )
    _git(repo, "config", "extensions.partialClone", "origin")
    _git(repo, "config", "remote.origin.promisor", "true")
    _git(repo, "config", "remote.origin.partialCloneFilter", "blob:none")
    origin_url = _git(repo, "config", "remote.origin.url")
    _git(repo, "config", "remote.origin.url", str(promisor))
    obj_path.unlink()
    try:
        # The verifier runs first while the blob is still missing locally:
        # with GIT_NO_LAZY_FETCH=1 it must fail closed instead of fetching
        # the blob from the promisor.
        document = _successor_for_blobs(
            history_document, GENESIS_REV, blobs,
            record_id="2027-02-10-promisor-missing",
            reviewed_on="2027-02-10", recorded_on="2027-02-11",
        )
        report = _verify(document, repo_root=repo, as_of=date(2027, 6, 1))
        assert report.integrity_ok is False
        assert "evidence-path-missing" in _codes(report)
        assert report.recurring_operation_ok is False
        # Control: without the lazy-fetch guard the same blob is fetchable
        # from the tmp promisor, so the failure above proves no fetch or
        # upload-pack invocation happened in the verifier path.
        control = subprocess.run(
            [_TEST_GIT_BIN, "-C", str(repo), "cat-file", "-s", blob_hash],
            capture_output=True, text=True, timeout=30,
        )
        assert control.returncode == 0, control.stderr
        assert control.stdout.strip() == str(len(blobs[REGISTER_REL]))
    finally:
        obj_path.write_bytes(saved)
        subprocess.run(
            [_TEST_GIT_BIN, "-C", str(repo), "config", "remote.origin.url", origin_url],
            check=True, timeout=120,
        )
        subprocess.run(
            [_TEST_GIT_BIN, "-C", str(repo), "config", "--unset",
             "extensions.partialClone"], check=False, timeout=120,
        )
        subprocess.run(
            [_TEST_GIT_BIN, "-C", str(repo), "config", "--unset",
             "remote.origin.promisor"], check=False, timeout=120,
        )
        subprocess.run(
            [_TEST_GIT_BIN, "-C", str(repo), "config", "--unset",
             "remote.origin.partialCloneFilter"], check=False, timeout=120,
        )


# ---------------------------------------------------------------------------
# Finding 3: exact epoch trigger semantics and latest-record counts
# ---------------------------------------------------------------------------

def _register_text_with_mutation(mutation) -> bytes:
    import yaml as _yaml

    doc = _yaml.safe_load((ROOT / REGISTER_REL).read_text(encoding="utf-8"))
    mutation(doc)
    return _yaml.safe_dump(doc, sort_keys=True).encode("utf-8")


def _commit_register_variant(repo: Path, mutated: bytes, message: str) -> str:
    (repo / REGISTER_REL).write_bytes(mutated)
    return _commit_all(repo, message)


def _history_for_register_mutation(
    history_document: dict[str, Any],
    tmp_path: Path,
    mutation,
    *,
    entity_renames: tuple[tuple[str, str], ...] = (),
) -> tuple[dict[str, Any], Path]:
    """Commit one register mutation and bind a complete successor to it."""

    tmp_path.mkdir(parents=True, exist_ok=True)
    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()
    mutated = _register_text_with_mutation(mutation)
    edited = dict(blobs)
    edited[REGISTER_REL] = mutated
    revision = _commit_register_variant(repo, mutated, "mutated epoch register")
    document = _successor_for_blobs(
        history_document,
        revision,
        edited,
        record_id="2027-02-10-register-mutation",
        reviewed_on="2027-02-10",
        recorded_on="2027-02-11",
        basis="executed-check",
    )
    successor = document["records"][1]
    for old, new in entity_renames:
        for observation in successor["observations"]:
            if observation["entity"] == old:
                observation["entity"] = new
    return document, repo


@pytest.mark.parametrize(
    ("section", "old", "new", "prefix", "code"),
    (
        ("modules", "AUD-01", "AUD-99", "module", "register-module-roster-mismatch"),
        ("sources", "SP-46", "SP-47", "source", "register-source-roster-mismatch"),
        ("sources", "SD01", "SD1", "source", "register-source-roster-mismatch"),
    ),
)
def test_epoch_rejects_equal_count_source_and_module_substitutions(
    history_document, tmp_path, section, old, new, prefix, code
) -> None:
    """Exact authorities reject identities that preserve all population counts."""

    def substitute(doc) -> None:
        row = next(item for item in doc[section] if item["id"] == old)
        row["id"] = new

    document, repo = _history_for_register_mutation(
        history_document,
        tmp_path,
        substitute,
        entity_renames=((f"{prefix}:{old}", f"{prefix}:{new}"),),
    )
    report = _verify(document, repo_root=repo, as_of=date(2027, 2, 12))
    assert report.integrity_ok is False
    assert code in _codes(report)
    assert len(document["records"][1]["observations"]) == EXPECTED_PAIRS


def test_epoch_rejects_runtime_row_inventory_and_anchor_substitutions(
    history_document, tmp_path
) -> None:
    """Runtime rows must match both their inventory and the pinned genesis roster."""

    old = "ad-pathfinder.list_datasources"
    new = "ad-pathfinder.unknown"

    def row_only(doc) -> None:
        row = next(item for item in doc["runtime"] if item["capability_id"] == old)
        row["capability_id"] = new
        row["action"] = "unknown"

    document, repo = _history_for_register_mutation(
        history_document,
        tmp_path / "row-only",
        row_only,
        entity_renames=((f"runtime:{old}", f"runtime:{new}"),),
    )
    report = _verify(document, repo_root=repo, as_of=date(2027, 2, 12))
    assert report.integrity_ok is False
    assert "register-runtime-inventory-mismatch" in _codes(report)

    def coordinated(doc) -> None:
        row_only(doc)
        inventory_ids = doc["runtime_inventory"]["capability_ids"]
        inventory_ids[inventory_ids.index(old)] = new
        inventory_ids.sort()

    coordinated_document, coordinated_repo = _history_for_register_mutation(
        history_document,
        tmp_path / "coordinated",
        coordinated,
        entity_renames=((f"runtime:{old}", f"runtime:{new}"),),
    )
    coordinated_report = _verify(
        coordinated_document,
        repo_root=coordinated_repo,
        as_of=date(2027, 2, 12),
    )
    assert coordinated_report.integrity_ok is False
    assert "register-runtime-inventory-mismatch" not in _codes(coordinated_report)
    assert "register-runtime-roster-mismatch" in _codes(coordinated_report)


def test_epoch_rejects_runtime_inventory_count_and_order_drift(
    history_document, tmp_path
) -> None:
    """The embedded runtime inventory is counted and canonically ordered."""

    def bad_count(doc) -> None:
        doc["runtime_inventory"]["expected_count"] = EXPECTED_RUNTIMES - 1

    document, repo = _history_for_register_mutation(
        history_document, tmp_path / "count", bad_count
    )
    report = _verify(document, repo_root=repo, as_of=date(2027, 2, 12))
    assert "register-runtime-inventory-count-mismatch" in _codes(report)

    def bad_order(doc) -> None:
        ids = doc["runtime_inventory"]["capability_ids"]
        ids[0], ids[1] = ids[1], ids[0]

    ordered_document, ordered_repo = _history_for_register_mutation(
        history_document, tmp_path / "order", bad_order
    )
    ordered_report = _verify(
        ordered_document, repo_root=ordered_repo, as_of=date(2027, 2, 12)
    )
    assert "register-runtime-inventory-not-canonical" in _codes(ordered_report)


def test_epoch_rejects_internally_consistent_cadence_policy_change(
    history_document, tmp_path
) -> None:
    """Rewriting every source due cannot silently postpone the v1 cadence."""

    def postpone_sources(doc) -> None:
        doc["currentness_queue"]["source_cadence_days"] = 365
        for row in doc["sources"]:
            reviewed = date.fromisoformat(row["currentness"]["reviewed_on"])
            row["currentness"]["review_due_on"] = (
                reviewed + timedelta(days=365)
            ).isoformat()

    document, repo = _history_for_register_mutation(
        history_document, tmp_path, postpone_sources
    )
    report = _verify(document, repo_root=repo, as_of=date(2027, 2, 12))
    assert report.integrity_ok is False
    assert "register-cadence-unexpected" in _codes(report)


def test_next_due_is_earliest_in_valid_staggered_epoch(
    history_document, tmp_path
) -> None:
    """A later row deadline never hides the earlier next class obligation."""

    def stagger_one_source(doc) -> None:
        row = next(item for item in doc["sources"] if item["id"] == "R01")
        row["currentness"]["reviewed_on"] = "2026-10-14"
        row["currentness"]["review_due_on"] = "2027-01-12"

    document, repo = _history_for_register_mutation(
        history_document, tmp_path, stagger_one_source
    )
    report = _verify(document, repo_root=repo, as_of=date(2027, 2, 12))
    assert report.integrity_ok is True
    assert report.coverage_ok is True
    assert report.next_due_source == "2027-01-11"
    assert report.queue_next_review_on == "2027-01-11"


def test_epoch_requires_exact_trigger_sets(history_document, tmp_path) -> None:
    """One removed trigger/check/observation (1,094) fails closed."""

    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()

    def drop_source_trigger(doc) -> None:
        row = next(r for r in doc["sources"] if r["id"] == "R01")
        row["currentness"]["triggers"].remove("link-or-availability-change")
        row["currentness"]["trigger_checks"] = [
            c for c in row["currentness"]["trigger_checks"]
            if c["trigger"] != "link-or-availability-change"
        ]

    mutated = _register_text_with_mutation(drop_source_trigger)
    edited = dict(blobs)
    edited[REGISTER_REL] = mutated
    rev_b = _commit_register_variant(repo, mutated, "drop one source trigger")
    document = _successor_for_blobs(
        history_document, rev_b, edited,
        record_id="2027-02-10-removed-trigger",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    # Drop the matching observation too so the history claims 1,094 pairs.
    victim = next(
        o for o in document["records"][1]["observations"]
        if o["entity"] == "source:R01" and o["trigger"] == "link-or-availability-change"
    )
    document["records"][1]["observations"].remove(victim)
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "register-trigger-set-unexpected" in _codes(report)
    assert report.recurring_operation_ok is False


def test_epoch_rejects_duplicate_and_orphan_checks(history_document, tmp_path) -> None:
    """Duplicate checks (other fields differ) and orphans both fail."""

    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()

    def duplicate_module_check(doc) -> None:
        row = next(r for r in doc["modules"] if r["id"] == "AUD-01")
        first = copy.deepcopy(row["currentness"]["trigger_checks"][0])
        first["checked_via"] = "primary-source-review"
        first["evidence_ref"] = (
            "docs/governance/source-verification-2026-10-13.md#module-architecture-review"
        )
        row["currentness"]["trigger_checks"].append(first)

    mutated = _register_text_with_mutation(duplicate_module_check)
    edited = dict(blobs)
    edited[REGISTER_REL] = mutated
    rev_b = _commit_register_variant(repo, mutated, "duplicate module check")
    document = _successor_for_blobs(
        history_document, rev_b, edited,
        record_id="2027-02-10-duplicate-check",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "register-duplicate-check" in _codes(report)

    repo2 = _cloned_repo(tmp_path / "second")
    blobs2 = _real_blobs()

    def orphan_runtime_check(doc) -> None:
        row = doc["runtime"][0]
        row["currentness"]["trigger_checks"].append(
            {
                "trigger": "bogus-trigger-never-declared",
                "checked_via": "architecture-review",
                "evidence_ref": (
                    "docs/governance/source-verification-2026-10-13.md"
                    "#runtime-reconciliation-review"
                ),
            }
        )

    mutated2 = _register_text_with_mutation(orphan_runtime_check)
    edited2 = dict(blobs2)
    edited2[REGISTER_REL] = mutated2
    rev_c = _commit_register_variant(repo2, mutated2, "orphan runtime check")
    document2 = _successor_for_blobs(
        history_document, rev_c, edited2,
        record_id="2027-02-10-orphan-check",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report2 = _verify(document2, repo_root=repo2)
    assert report2.integrity_ok is False
    assert "register-orphan-check" in _codes(report2)


def test_counts_describe_latest_record_not_union(history_document, tmp_path) -> None:
    """A latest-record gap stays visible when the predecessor was complete."""

    repo = _cloned_repo(tmp_path)
    document = _successor_for_blobs(
        history_document, GENESIS_REV, _real_blobs(),
        record_id="2027-02-10-latest-gap",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    victim = next(
        o for o in document["records"][1]["observations"]
        if o["entity"] == "runtime:nmap.scan"
    )
    document["records"][1]["observations"].remove(victim)
    # Repair the predecessor digest chain is unnecessary: _successor_for_blobs
    # already chained correctly; only the latest record loses one pair.
    report = _verify(document, require="coverage", repo_root=repo)
    assert report.coverage_ok is False
    assert report.integrity_ok is False
    assert "coverage-incomplete" in _codes(report)
    # Unioning the complete genesis (1,095) would hide the gap; the report
    # must describe the latest record (1,094).
    assert report.pairs_observed == 1094
    assert report.entities_observed == 365


# ---------------------------------------------------------------------------
# Finding 4: epoch currentness dates, cadence, historical observed_on
# ---------------------------------------------------------------------------

def test_epoch_rejects_invalid_calendar_date(history_document, tmp_path) -> None:
    """2026-02-30 is shape-valid but not a real calendar date.

    The epoch register schema enforces it via Draft7 FormatChecker
    (register-schema-violation); the semantic calendar parser
    (register-invalid-date) is the second closed layer. Either layer
    failing closed satisfies the invalid-calendar requirement.
    """

    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()

    def bad_calendar(doc) -> None:
        doc["sources"][0]["currentness"]["reviewed_on"] = "2026-02-30"

    mutated = _register_text_with_mutation(bad_calendar)
    edited = dict(blobs)
    edited[REGISTER_REL] = mutated
    rev_b = _commit_register_variant(repo, mutated, "invalid calendar date")
    document = _successor_for_blobs(
        history_document, rev_b, edited,
        record_id="2027-02-10-bad-calendar",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo, as_of=date(2027, 6, 1))
    assert report.integrity_ok is False
    assert _codes(report) & {"register-schema-violation", "register-invalid-date"}


def test_epoch_rejects_inverted_and_future_windows(history_document, tmp_path) -> None:
    """reviewed_on < review_due_on and reviewed_on <= recorded_on are enforced."""

    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()

    def inverted(doc) -> None:
        row = next(r for r in doc["sources"] if r["id"] == "R01")
        row["currentness"]["reviewed_on"] = "2027-01-11"
        row["currentness"]["review_due_on"] = "2026-10-13"

    mutated = _register_text_with_mutation(inverted)
    edited = dict(blobs)
    edited[REGISTER_REL] = mutated
    rev_b = _commit_register_variant(repo, mutated, "inverted window")
    document = _successor_for_blobs(
        history_document, rev_b, edited,
        record_id="2027-02-10-inverted-window",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "register-window-inverted" in _codes(report)

    repo2 = _cloned_repo(tmp_path / "future")
    blobs2 = _real_blobs()

    def future(doc) -> None:
        row = next(r for r in doc["sources"] if r["id"] == "R01")
        row["currentness"]["reviewed_on"] = "2027-03-01"

    mutated2 = _register_text_with_mutation(future)
    edited2 = dict(blobs2)
    edited2[REGISTER_REL] = mutated2
    rev_c = _commit_register_variant(repo2, mutated2, "future reviewed_on")
    document2 = _successor_for_blobs(
        history_document, rev_c, edited2,
        record_id="2027-02-10-future-window",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report2 = _verify(document2, repo_root=repo2)
    assert report2.integrity_ok is False
    assert "register-window-future" in _codes(report2)


def test_epoch_enforces_due_cadence_and_queue_next(history_document, tmp_path) -> None:
    """Each due must equal reviewed_on plus class cadence; queue is earliest due."""

    repo = _cloned_repo(tmp_path)
    blobs = _real_blobs()

    def bad_due(doc) -> None:
        row = next(r for r in doc["sources"] if r["id"] == "R01")
        row["currentness"]["review_due_on"] = "2027-01-12"

    mutated = _register_text_with_mutation(bad_due)
    edited = dict(blobs)
    edited[REGISTER_REL] = mutated
    rev_b = _commit_register_variant(repo, mutated, "bad due cadence")
    document = _successor_for_blobs(
        history_document, rev_b, edited,
        record_id="2027-02-10-bad-cadence",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report = _verify(document, repo_root=repo)
    assert report.integrity_ok is False
    assert "register-due-cadence-mismatch" in _codes(report)

    repo2 = _cloned_repo(tmp_path / "queue")
    blobs2 = _real_blobs()

    def bad_queue(doc) -> None:
        doc["currentness_queue"]["next_review_on"] = "2027-04-13"

    mutated2 = _register_text_with_mutation(bad_queue)
    edited2 = dict(blobs2)
    edited2[REGISTER_REL] = mutated2
    rev_c = _commit_register_variant(repo2, mutated2, "bad queue next")
    document2 = _successor_for_blobs(
        history_document, rev_c, edited2,
        record_id="2027-02-10-bad-queue",
        reviewed_on="2027-02-10", recorded_on="2027-02-11",
    )
    report2 = _verify(document2, repo_root=repo2)
    assert report2.integrity_ok is False
    assert "register-queue-next-mismatch" in _codes(report2)


def test_historical_observed_on_must_match_epoch_reviewed(history_document) -> None:
    """A retimed historical observed_on breaks the epoch binding."""

    document = _copy_history(history_document)
    document["records"][0]["observations"][0]["observed_on"] = "2026-10-14"
    report = _verify(document)
    assert report.integrity_ok is False
    assert "historical-observed-mismatch" in _codes(report)


# ---------------------------------------------------------------------------
# Finding 5: non-blocking canonical read (POSIX FIFO regression)
# ---------------------------------------------------------------------------

def test_canonical_repo_read_refuses_fifo_without_hanging(tmp_path, monkeypatch) -> None:
    """A FIFO at the final component is refused promptly (POSIX-only)."""

    import os as _os

    if _os.name != "posix" or not hasattr(_os, "mkfifo"):
        pytest.skip("POSIX FIFO test requires os.mkfifo")
    root = tmp_path / "fifo-root"
    target_dir = root / "governance" / "schema"
    target_dir.mkdir(parents=True)
    fifo = target_dir / "review-evidence.v1.schema.json"
    _os.mkfifo(fifo)
    monkeypatch.setattr(reviews, "REPOSITORY_ROOT", root)
    outcome: dict[str, Any] = {}

    def attempt() -> None:
        try:
            reviews._read_canonical_repo_bytes(
                "governance/schema/review-evidence.v1.schema.json",
                label="review schema",
                max_bytes=reviews.MAX_REVIEW_SCHEMA_BYTES,
                expected_sha256=reviews.CANONICAL_REVIEW_SCHEMA_SHA256,
            )
        except Exception as exc:  # noqa: BLE001 - the assertion inspects it
            outcome["error"] = exc
        else:
            outcome["error"] = None

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "canonical read hung on a FIFO"
    assert isinstance(outcome.get("error"), reviews.ReviewLoadError)


def test_shared_worktree_tracked_files_untouched() -> None:
    """Tripwire: mutation tests must not touch tracked review files."""

    for path, baseline in TRACKED_BASELINE.items():
        assert path.read_bytes() == baseline, f"tracked file modified: {path}"
