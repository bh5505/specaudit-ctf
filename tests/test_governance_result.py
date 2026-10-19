"""Causal tests for the revision-bound executed-review-result verifier.

The committed tree ships no result artifact: the v1 history verdict
(integrity and coverage true, recurrence false) is preserved, and the
U-GOV.d protocol defines what a genuine future cycle must prove without
fabricating one. Each mutation of a synthetic cycle breaks its own
invariant: removed/duplicated/extra pairs, wrong entities/triggers/bases,
date and digest tampering, unbound evidence, premature cycle dates,
reused genesis revisions, broken history bindings, substitute schemas,
non-finite numbers, and missing/wrong Git revisions/blobs all fail
closed, while a well-formed future cycle in a synthetic repository
verifies complete (execution with evidence, not greenness: fail
outcomes do not block completion).

Isolation: no test writes or replaces a tracked file in this shared
worktree. Cycle documents are tmp files; epoch variants are committed
only in a synthetic module-scoped clone. A tripwire test asserts the
tracked governance files are byte-identical before and after.
"""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml

import governance.result as result_mod
from governance.result import (
    EXPECTED_ENTITIES,
    EXPECTED_PAIRS,
    GENESIS_INSPECTED_REVISION,
    GOVERNED_HISTORY_ID,
    INITIAL_HISTORY_RECORD_DIGEST,
    MIN_CYCLE_REVIEWED_ON,
    RESULT_SCHEMA_ID,
    ReviewLoadError,
    _RevisionBlobStore,
    load_result,
    load_result_schema,
    verify_result,
)
from governance.reviews import verify_history

ROOT = Path(__file__).resolve().parents[1]
COMMITTED_HISTORY = ROOT / "governance" / "reviews" / "2026-10-13.attributed.json"
COMMITTED_RAW = COMMITTED_HISTORY.read_bytes()

REGISTER_REL = "governance/register.v2.yaml"
EVIDENCE_MD_REL = "docs/governance/source-verification-2026-10-13.md"
REGISTER_SCHEMA_REL = "governance/schema/register.v2.schema.json"
REVIEW_SCHEMA_REL = "governance/schema/review-evidence.v1.schema.json"
RESULT_SCHEMA_REL = "governance/schema/review-result.v1.schema.json"
REVIEWS_MODULE_REL = "governance/reviews.py"
RESULT_MODULE_REL = "governance/result.py"
SYNTH_EXTRA_REL = "docs/governance/synthetic-cycle-evidence-ugd.md"
SYNTH_EXECUTION_REL = (
    "governance/reviews/executed/2027-04-14.synthetic-cycle.json"
)

TRACKED_RESULT_FILES = (
    ROOT / REGISTER_REL,
    ROOT / EVIDENCE_MD_REL,
    ROOT / REGISTER_SCHEMA_REL,
    ROOT / REVIEW_SCHEMA_REL,
    ROOT / RESULT_SCHEMA_REL,
    ROOT / REVIEWS_MODULE_REL,
    ROOT / RESULT_MODULE_REL,
    COMMITTED_HISTORY,
)
TRACKED_BASELINE = {path: path.read_bytes() for path in TRACKED_RESULT_FILES}
# The suite scrubs PATH per test: resolve git and the real PATH once here at
# import, per the tests/conftest.py convention (absolute *_BIN / own PATH).
_TEST_GIT_BIN = shutil.which("git")
_REAL_PATH = os.environ.get("PATH", "")

CYCLE_REVIEWED = "2027-04-14"
CYCLE_RECORDED = "2027-04-15"
CYCLE_AS_OF = date(2027, 4, 16)
REPORT_SCHEMA = "specaudit.ctf.governance.review-result-report.v1"
ERROR_SCHEMA = "specaudit.ctf.governance.validation-error.v1"


@pytest.fixture(scope="module")
def synth_repo(tmp_path_factory) -> Path:
    """One isolated synthetic repository cloned from this checkout.

    The clone is fully offline (local path source) and carries every
    committed object, including the pinned genesis inspected revision, so
    the genesis roster anchor keeps resolving while synthetic cycle
    epochs are committed on top. Nothing is written to the shared
    worktree. Tests share the clone but each commits its own variant and
    verifies against its own revision.
    """

    if _TEST_GIT_BIN is None:
        pytest.skip("git executable unavailable")
    repo = tmp_path_factory.mktemp("synth-result-repo") / "repo"
    completed = subprocess.run(
        [_TEST_GIT_BIN, "clone", "-q", str(ROOT), str(repo)],
        capture_output=True, text=True, timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    # A clone carries only committed bytes, so mirror the still-untracked
    # U-GOV.d protocol files into the clone worktree (never committed
    # there, never written to the shared worktree). The verifier and its
    # pinned schema load from the worktree-anchored checkout root, while
    # evidence and register bytes keep resolving from clone Git objects.
    for rel in (RESULT_MODULE_REL, RESULT_SCHEMA_REL):
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / rel).read_bytes())
    return repo


def _git(repo: Path, *args: str) -> str:
    if _TEST_GIT_BIN is None:
        pytest.skip("git executable unavailable")
    completed = subprocess.run(
        [_TEST_GIT_BIN, "-C", str(repo), *args],
        capture_output=True, text=True, check=True, timeout=120,
    )
    return completed.stdout.strip()


def _real_blobs() -> dict[str, bytes]:
    return {
        REGISTER_REL: (ROOT / REGISTER_REL).read_bytes(),
        EVIDENCE_MD_REL: (ROOT / EVIDENCE_MD_REL).read_bytes(),
        REGISTER_SCHEMA_REL: (ROOT / REGISTER_SCHEMA_REL).read_bytes(),
        SYNTH_EXECUTION_REL: _source_blob((ROOT / REGISTER_REL).read_bytes()),
    }


def _commit_variant(
    repo: Path,
    message: str,
    *,
    updates: dict[str, bytes] | None = None,
    new_files: dict[str, bytes] | None = None,
    deletions: tuple[str, ...] = (),
    allow_empty: bool = False,
) -> str:
    """Reset the worktree to pristine bytes, apply one variant, commit it."""

    blobs = _real_blobs()
    for rel, data in blobs.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((updates or {}).get(rel, data))
    (repo / SYNTH_EXTRA_REL).unlink(missing_ok=True)
    for rel, data in (new_files or {}).items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for rel in deletions:
        (repo / rel).unlink()
    _git(repo, "add", "-A")
    _git(
        repo, "-c", "user.name=gov-result-test",
        "-c", "user.email=gov-result-test@example.invalid",
        "commit", "-qm", message, *(["--allow-empty"] if allow_empty else []),
    )
    return _git(repo, "rev-parse", "HEAD")


def _pairs_from_register(register_bytes: bytes) -> list[tuple[str, str, str, str]]:
    """Independently derived population: (entity, trigger, via, ref)."""

    doc = yaml.safe_load(register_bytes.decode("utf-8"))
    pairs: list[tuple[str, str, str, str]] = []
    for row in doc["modules"]:
        for check in row["currentness"]["trigger_checks"]:
            pairs.append((
                f"module:{row['id']}", check["trigger"],
                check["checked_via"], check["evidence_ref"],
            ))
    for row in doc["sources"]:
        for check in row["currentness"]["trigger_checks"]:
            pairs.append((
                f"source:{row['id']}", check["trigger"],
                check["checked_via"], check["evidence_ref"],
            ))
    for row in doc["runtime"]:
        for check in row["currentness"]["trigger_checks"]:
            pairs.append((
                f"runtime:{row['capability_id']}", check["trigger"],
                check["checked_via"], check["evidence_ref"],
            ))
    return pairs


def _result_rows(
    register_bytes: bytes,
    *,
    reviewed_on: str = CYCLE_REVIEWED,
    basis: str = "executed-check",
    fail_pairs: set[tuple[str, str]] = frozenset(),
    ref_overrides: dict[tuple[str, str], str] | None = None,
) -> list[dict[str, str]]:
    return [
        {
            "entity": entity,
            "trigger": trigger,
            "basis": basis,
            "outcome": "fail" if (entity, trigger) in fail_pairs else "pass",
            "observed_on": reviewed_on,
            "checked_via": via,
            "evidence_ref": (ref_overrides or {}).get((entity, trigger), ref),
            "detail": (
                f"Synthetic dated review result for {entity} / {trigger}; "
                "fixture only, not an actual campaign review."
            ),
        }
        for entity, trigger, via, ref in _pairs_from_register(register_bytes)
    ]


def _source_blob(
    register_bytes: bytes,
    *,
    reviewed_on: str = CYCLE_REVIEWED,
    fail_pairs: set[tuple[str, str]] = frozenset(),
    ref_overrides: dict[tuple[str, str], str] | None = None,
) -> bytes:
    return json.dumps(
        {
            "schema": result_mod.EXECUTION_SOURCE_SCHEMA_ID,
            "reviewed_on": reviewed_on,
            "reviewer": "synthetic-cycle-prover",
            "results": _result_rows(
                register_bytes,
                reviewed_on=reviewed_on,
                fail_pairs=fail_pairs,
                ref_overrides=ref_overrides,
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _result_for_blobs(
    blobs: dict[str, bytes],
    revision: str,
    *,
    result_id: str = "2027-04-14-executed-cycle",
    reviewed_on: str = CYCLE_REVIEWED,
    recorded_on: str = CYCLE_RECORDED,
    basis: str = "executed-check",
    fail_pairs: set[tuple[str, str]] = frozenset(),
    ref_overrides: dict[tuple[str, str], str] | None = None,
    asserts_complete: bool = True,
    asserts_integrity: bool = True,
    asserts_coverage: bool = True,
) -> dict[str, Any]:
    """Build one well-formed synthetic cycle bound to the given blobs."""

    pairs = _pairs_from_register(blobs[REGISTER_REL])
    assert len(pairs) == EXPECTED_PAIRS
    evidence = [
        {
            "path": path,
            "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            "byte_length": len(data),
        }
        for path, data in sorted(blobs.items())
    ]
    results = _result_rows(
        blobs[REGISTER_REL], reviewed_on=reviewed_on, basis=basis,
        fail_pairs=fail_pairs, ref_overrides=ref_overrides,
    )
    return {
        "schema": RESULT_SCHEMA_ID,
        "schema_version": 1,
        "result_id": result_id,
        "governed_history_id": GOVERNED_HISTORY_ID,
        "governed_record_digest": INITIAL_HISTORY_RECORD_DIGEST,
        "reviewed_on": reviewed_on,
        "recorded_on": recorded_on,
        "reviewer": "synthetic-cycle-prover",
        "inspected_revision": revision,
        "evidence": evidence,
        "execution_source": SYNTH_EXECUTION_REL,
        "results": results,
        "record_checks": [
            {
                "check": "result-reconciliation",
                "result": "pass",
                "detail": (
                    "synthetic cycle: 365 entities and 1095 "
                    "entity/trigger pairs reconciled against the "
                    "revision-bound register epoch."
                ),
            },
            {
                "check": "evidence-byte-binding",
                "result": "pass",
                "detail": (
                    "synthetic cycle: evidence files re-hashed from "
                    "revision-bound blobs and bound by sha256 and length."
                ),
            },
        ],
        "unknown_outcomes": [
            "upstream-unchanged-unproven: executed checks are attributed "
            "records and machine re-derivations; they do not prove any "
            "upstream did not change after review.",
        ],
        "limitations": [
            "synthetic-fixture: this cycle exists only in an isolated "
            "synthetic repository for verifier testing; it evidences no "
            "real operation and completes no governed recurrence.",
            "attribution-is-evidence-not-authentication: the recorded "
            "reviewer does not authenticate who performed the checks.",
        ],
        "asserts": {
            "integrity_ok": asserts_integrity,
            "coverage_ok": asserts_coverage,
            "cycle_complete_ok": asserts_complete,
        },
    }


def _verify(
    document,
    *,
    require="complete",
    as_of=CYCLE_AS_OF,
    repo_root=None,
    store=None,
):
    return verify_result(
        document, as_of=as_of,
        result_path="<test-result>", result_sha256="sha256:" + "0" * 64,
        result_schema_sha256=None, requirement=require,
        repo_root=repo_root, blob_store=store,
    )


def _codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


def _write_tmp(tmp_path: Path, document: dict[str, Any], name: str = "result.json") -> Path:
    target = tmp_path / name
    target.write_text(json.dumps(document, allow_nan=False, sort_keys=True), encoding="utf-8")
    return target


def _run_cli(
    result: Path, *, require: str, as_of: str = "2027-04-16",
    extra: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PATH"] = _REAL_PATH
    return subprocess.run(
        [sys.executable, "-m", "governance.result", "check",
         "--result", str(result), "--as-of", as_of, "--require", require, *extra],
        capture_output=True, text=True, cwd=str(ROOT), env=env,
    )


def _run_cli_in(
    repo: Path, result: Path, *, require: str, as_of: str = "2027-04-16",
    extra: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    """Run the CLI with a synthetic repository as its checkout.

    The verifier anchors its schema and Git reads at its own repository
    root, so pointing the import path and working directory at the
    synthetic clone makes the CLI resolve synthetic cycle revisions.
    An exit 0 against a synthetic-only revision proves the clone copy
    was used: the real checkout knows no such object.
    """

    env = dict(os.environ)
    env["PATH"] = _REAL_PATH
    env["PYTHONPATH"] = str(repo) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    return subprocess.run(
        [sys.executable, "-m", "governance.result", "check",
         "--result", str(result), "--as-of", as_of, "--require", require, *extra],
        capture_output=True, text=True, cwd=str(repo), env=env,
    )


def _payload_codes(payload: dict[str, Any]) -> set[str]:
    return {issue["code"] for issue in payload["issues"]}


# ---------------------------------------------------------------------------
# No fabricated executed results: the tree ships protocol, not operation
# ---------------------------------------------------------------------------

def test_no_tracked_result_artifact_ships() -> None:
    """The committed tree holds the protocol but no executed cycle."""

    assert sorted(p.name for p in (ROOT / "governance" / "reviews").iterdir()) == [
        "2026-10-13.attributed.json"
    ]
    assert list((ROOT / "governance").rglob("*.result.json")) == []
    raw = COMMITTED_RAW.decode("utf-8")
    assert "executed-check" not in raw
    assert "cycle_complete_ok" not in raw
    assert "review-result" not in raw


def test_v1_history_verdict_is_preserved() -> None:
    """The v1 history still reconciles with recurrence false."""

    document = json.loads(COMMITTED_RAW.decode("utf-8"))
    for require, expected_ok in (
        ("integrity", True), ("coverage", True), ("recurrence", False),
    ):
        report = verify_history(
            document, as_of=date(2026, 10, 18),
            history_path="<committed>", history_sha256=None,
            review_schema_sha256=None, requirement=require,
        )
        assert report.integrity_ok is True
        assert report.coverage_ok is True
        assert report.recurring_operation_ok is False
        assert report.ok is expected_ok


def test_result_schema_is_canonical_and_pinned() -> None:
    schema, digest = load_result_schema()
    assert digest == result_mod.CANONICAL_RESULT_SCHEMA_SHA256
    assert schema["title"] == RESULT_SCHEMA_ID
    assert schema["properties"]["governed_history_id"] == {
        "const": GOVERNED_HISTORY_ID
    }
    assert schema["properties"]["results"]["items"] == {
        "$ref": "#/definitions/result"
    }
    assert schema["definitions"]["result"]["properties"]["basis"] == {
        "const": "executed-check"
    }
    assert schema["additionalProperties"] is False
    # No override exists anywhere in the loader surface.
    assert tuple(inspect.signature(load_result_schema).parameters) == ()
    assert tuple(inspect.signature(load_result).parameters) == ("path",)


# ---------------------------------------------------------------------------
# Positive: a well-formed future cycle verifies complete
# ---------------------------------------------------------------------------

def test_valid_future_cycle_verifies_complete(synth_repo, tmp_path) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch with new dated result source")
    assert rev != GENESIS_INSPECTED_REVISION
    document = _result_for_blobs(_real_blobs(), rev)
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is True
    assert report.coverage_ok is True
    assert report.cycle_complete_ok is True
    assert report.as_dict()["counts"]["epoch_validated"] is True
    assert report.entities_expected == 365 == EXPECTED_ENTITIES
    assert report.entities_observed == 365
    assert report.pairs_expected == 1095 == EXPECTED_PAIRS
    assert report.pairs_observed == 1095
    assert report.sources_observed == 109
    assert report.modules_observed == 29
    assert report.runtimes_observed == 227
    assert report.passes == 1095
    assert report.failures == 0
    assert report.next_due_source == "2027-01-11"
    assert report.next_due_runtime == "2027-01-11"
    assert report.next_due_module == "2027-04-13"
    assert report.queue_next_review_on == "2027-01-11"
    assert report.register_revision == 2
    assert report.as_dict()["schema"] == REPORT_SCHEMA
    check_names = {c["check"] for c in report.as_dict()["checks"]}
    assert {"result-reconciliation", "evidence-byte-binding"} <= check_names

    for require in ("integrity", "coverage", "complete"):
        assert _verify(document, require=require, repo_root=synth_repo).ok is True
    target = _write_tmp(tmp_path, document)
    for require in ("integrity", "coverage", "complete"):
        completed = _run_cli_in(synth_repo, target, require=require)
        assert completed.returncode == 0, completed.stderr
        payload = json.loads(completed.stdout)
        assert payload["ok"] is True
        assert payload["cycle_complete_ok"] is True
    repeat = _run_cli_in(synth_repo, target, require="complete")
    assert repeat.stdout == _run_cli_in(synth_repo, target, require="complete").stdout


def test_empty_commit_relabel_of_old_evidence_is_not_an_executed_cycle(
    synth_repo,
) -> None:
    """A new SHA and 1095 relabeled rows are not new review results."""

    _commit_variant(
        synth_repo, "restore base with synthetic source", allow_empty=True,
    )
    (synth_repo / SYNTH_EXECUTION_REL).unlink()
    _git(synth_repo, "add", "-A")
    _git(
        synth_repo, "-c", "user.name=gov-result-test",
        "-c", "user.email=gov-result-test@example.invalid",
        "commit", "-qm", "remove synthetic result source",
    )
    _git(
        synth_repo, "-c", "user.name=gov-result-test",
        "-c", "user.email=gov-result-test@example.invalid",
        "commit", "-qm", "empty successor", "--allow-empty",
    )
    empty_revision = _git(synth_repo, "rev-parse", "HEAD")
    document = _result_for_blobs(
        _real_blobs(), empty_revision,
        asserts_complete=False, asserts_integrity=False,
        asserts_coverage=False,
    )
    report = _verify(document, repo_root=synth_repo)
    assert report.cycle_complete_ok is False
    assert "execution-source-unavailable" in _codes(report)


def test_summary_rows_must_match_new_revision_bound_result_source(synth_repo) -> None:
    revision = _commit_variant(synth_repo, "bound result source")
    document = _result_for_blobs(
        _real_blobs(), revision,
        asserts_complete=False, asserts_integrity=False,
        asserts_coverage=False,
    )
    document["results"][0]["outcome"] = "fail"
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "execution-source-mismatch" in _codes(report)


def test_fail_outcomes_do_not_block_completion(synth_repo) -> None:
    """Completion verifies execution with evidence, not greenness."""

    blobs = _real_blobs()
    failed = {("source:R01", "upstream-revision-change"),
              ("module:AUD-01", "criteria-or-threat-change")}
    blobs[SYNTH_EXECUTION_REL] = _source_blob(
        blobs[REGISTER_REL], fail_pairs=failed,
    )
    rev = _commit_variant(
        synth_repo, "cycle epoch with findings",
        updates={SYNTH_EXECUTION_REL: blobs[SYNTH_EXECUTION_REL]},
    )
    document = _result_for_blobs(
        blobs, rev, fail_pairs=failed,
    )
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is True
    assert report.coverage_ok is True
    assert report.cycle_complete_ok is True
    assert report.passes == 1093
    assert report.failures == 2


def test_cli_help_and_no_register_override(tmp_path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "governance.result", "--help"],
        capture_output=True, text=True, cwd=str(ROOT),
        env={**os.environ, "PATH": _REAL_PATH},
    )
    assert completed.returncode == 0
    assert "Executed review-result verifier" in completed.stdout

    rev_hint = GENESIS_INSPECTED_REVISION
    document = _result_for_blobs(_real_blobs(), rev_hint,
                                 asserts_complete=False,
                                 asserts_integrity=False,
                                 asserts_coverage=False)
    target = _write_tmp(tmp_path, document)
    refused = _run_cli(target, require="complete",
                       extra=("--register", "governance/register.v2.yaml"))
    assert refused.returncode == 2
    assert "unrecognized arguments" in refused.stderr
    assert "--register" not in result_mod._parser().format_help()


# ---------------------------------------------------------------------------
# Pair mutations: missing, duplicate, extra, wrong trigger/basis
# ---------------------------------------------------------------------------

def test_missing_pair_breaks_coverage(synth_repo, tmp_path) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch gap", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    victim = next(
        o for o in document["results"]
        if o["entity"] == "runtime:nmap.scan"
    )
    document["results"].remove(victim)
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert report.coverage_ok is False
    assert report.cycle_complete_ok is False
    assert "missing-trigger" in _codes(report)
    assert "coverage-incomplete" in _codes(report)
    assert report.entities_observed == 365
    assert report.pairs_observed == 1094
    target = _write_tmp(tmp_path, document)
    completed = _run_cli_in(synth_repo, target, require="coverage")
    assert completed.returncode == 1
    assert "coverage-incomplete" in _payload_codes(json.loads(completed.stdout))


def test_missing_entity_breaks_coverage(synth_repo) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch entity gap", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    document["results"] = [
        o for o in document["results"] if o["entity"] != "source:SP-07"
    ]
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "missing-entity" in _codes(report)
    assert "coverage-incomplete" in _codes(report)
    assert report.entities_observed == 364
    assert report.pairs_observed == 1092


def test_duplicate_pair_fails_integrity(synth_repo, tmp_path) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch duplicate", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    document["results"].append(copy.deepcopy(document["results"][0]))
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert report.cycle_complete_ok is False
    assert "duplicate-pair" in _codes(report)
    target = _write_tmp(tmp_path, document)
    completed = _run_cli_in(synth_repo, target, require="integrity")
    assert completed.returncode == 1
    assert "duplicate-pair" in _payload_codes(json.loads(completed.stdout))


def test_extra_unknown_pair_fails_integrity(synth_repo, tmp_path) -> None:
    """An 1,096th pair must be a duplicate or an unknown identity."""

    rev = _commit_variant(synth_repo, "cycle epoch extra", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    probe = copy.deepcopy(document["results"][0])
    probe["entity"] = "source:R99"
    document["results"].append(probe)
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "unknown-entity" in _codes(report)
    target = _write_tmp(tmp_path, document)
    completed = _run_cli_in(synth_repo, target, require="integrity")
    assert completed.returncode == 1
    assert "unknown-entity" in _payload_codes(json.loads(completed.stdout))


def test_wrong_trigger_fails_integrity(synth_repo) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch wrong trigger", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    document["results"][0]["trigger"] = "bogus-trigger-never-declared"
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "unknown-trigger" in _codes(report)
    assert report.cycle_complete_ok is False


def test_nonexecuted_basis_is_rejected(synth_repo, tmp_path) -> None:
    """Only executed-check evidences operation; the loader refuses the rest."""

    rev = _commit_variant(synth_repo, "cycle epoch wrong basis", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
        basis="historical-declaration",
    )
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "invalid-basis" in _codes(report)
    assert report.cycle_complete_ok is False
    target = _write_tmp(tmp_path, document)
    refused = _run_cli(target, require="integrity")
    assert refused.returncode == 2
    assert json.loads(refused.stderr)["schema"] == ERROR_SCHEMA
    with pytest.raises(ReviewLoadError):
        load_result(target)


# ---------------------------------------------------------------------------
# Date tampering and premature cycles
# ---------------------------------------------------------------------------

def test_observed_date_tampering_fails(synth_repo) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch retimed", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    document["results"][0]["observed_on"] = "2027-04-15"
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "observed-date-mismatch" in _codes(report)


def test_inverted_and_future_cycle_dates_fail(synth_repo) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch misdated", allow_empty=True)
    inverted = _result_for_blobs(
        _real_blobs(), rev, reviewed_on="2027-04-14", recorded_on="2027-04-13",
        asserts_complete=False, asserts_integrity=False, asserts_coverage=False,
    )
    report = _verify(inverted, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "recorded-before-reviewed" in _codes(report)

    timely = _result_for_blobs(_real_blobs(), rev)
    report = _verify(timely, repo_root=synth_repo, as_of=date(2027, 4, 14))
    assert report.integrity_ok is False
    assert "recorded-in-future" in _codes(report)


@pytest.mark.parametrize(
    "reviewed_on,recorded_on",
    [
        ("2026-10-19", "2026-10-20"),  # just after the v1 import record
        ("2027-01-11", "2027-01-12"),  # source/runtime due, module due unmet
    ],
)
def test_premature_cycle_dates_stay_incomplete(synth_repo, reviewed_on, recorded_on) -> None:
    """No full-population cycle completes before the latest class due date.

    Schema/result v1 defines only full-population cycles, so even the
    source/runtime due date (2027-01-11) is insufficient while the module
    due date (2027-04-13) is unmet. Recurrence stays false before genuine
    future cycles.
    """

    assert MIN_CYCLE_REVIEWED_ON == date(2027, 4, 13)
    rev = _commit_variant(synth_repo, f"premature epoch {reviewed_on}", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, reviewed_on=reviewed_on, recorded_on=recorded_on,
        asserts_complete=False, asserts_integrity=False, asserts_coverage=False,
    )
    report = _verify(document, repo_root=synth_repo, as_of=date(2027, 6, 1))
    assert report.integrity_ok is False
    assert report.cycle_complete_ok is False
    assert "cycle-too-early" in _codes(report)


def test_reused_genesis_revision_is_a_replay(synth_repo) -> None:
    """New dates on the exact genesis revision evidence no new operation."""

    document = _result_for_blobs(
        _real_blobs(), GENESIS_INSPECTED_REVISION,
        asserts_complete=False, asserts_integrity=False, asserts_coverage=False,
    )
    report = _verify(document, repo_root=synth_repo, as_of=date(2027, 6, 1))
    assert report.integrity_ok is False
    assert report.cycle_complete_ok is False
    assert "cycle-revision-reused" in _codes(report)


# ---------------------------------------------------------------------------
# Evidence and hash tampering; self-declared success without evidence
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["sha256", "byte_length"])
def test_evidence_hash_tampering_fails(synth_repo, tmp_path, field) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch hash-tampered", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    if field == "sha256":
        document["evidence"][0]["sha256"] = "sha256:" + "0" * 64
    else:
        document["evidence"][0]["byte_length"] += 1
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert report.cycle_complete_ok is False
    assert "evidence-bytes-mismatch" in _codes(report)
    target = _write_tmp(tmp_path, document)
    completed = _run_cli_in(synth_repo, target, require="integrity")
    assert completed.returncode == 1
    assert "evidence-bytes-mismatch" in _payload_codes(json.loads(completed.stdout))


def test_self_declared_success_without_evidence_fails(synth_repo) -> None:
    """A pass whose evidence is unbound or anchorless is self-declared."""

    rev = _commit_variant(synth_repo, "cycle epoch unbound", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    document["results"][0]["evidence_ref"] = (
        "docs/governance/unbound-evidence-ugd.md#unbound-anchor"
    )
    document["results"][1]["evidence_ref"] = (
        EVIDENCE_MD_REL + "#no-such-heading-in-evidence"
    )
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert report.cycle_complete_ok is False
    assert "evidence-ref-unbound" in _codes(report)
    assert "evidence-anchor-missing" in _codes(report)


def test_stale_binding_after_evidence_edit_fails(synth_repo) -> None:
    """A binding recorded against older bytes mismatches the new revision."""

    blobs = _real_blobs()
    edited_md = blobs[EVIDENCE_MD_REL] + b"\n<!-- later edit -->\n"
    rev = _commit_variant(
        synth_repo, "later evidence edit",
        updates={EVIDENCE_MD_REL: edited_md},
    )
    document = _result_for_blobs(
        blobs, rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "evidence-bytes-mismatch" in _codes(report)


def test_missing_and_symlink_evidence_fail_closed(synth_repo) -> None:
    blobs = _real_blobs()
    rev_missing = _commit_variant(
        synth_repo, "drop evidence", deletions=(EVIDENCE_MD_REL,),
    )
    missing = _result_for_blobs(
        blobs, rev_missing, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    report = _verify(missing, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "evidence-path-missing" in _codes(report)

    target = synth_repo / EVIDENCE_MD_REL
    target.unlink(missing_ok=True)
    target.symlink_to(synth_repo / REGISTER_REL)
    _git(synth_repo, "add", "-A")
    _git(
        synth_repo, "-c", "user.name=gov-result-test",
        "-c", "user.email=gov-result-test@example.invalid",
        "commit", "-qm", "symlink evidence",
    )
    rev_link = _git(synth_repo, "rev-parse", "HEAD")
    # Restore pristine bytes for later tests sharing this clone.
    (synth_repo / EVIDENCE_MD_REL).unlink(missing_ok=True)
    (synth_repo / EVIDENCE_MD_REL).write_bytes(blobs[EVIDENCE_MD_REL])
    linked = _result_for_blobs(
        blobs, rev_link, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    linked_report = _verify(linked, repo_root=synth_repo)
    assert linked_report.integrity_ok is False
    assert "evidence-non-blob" in _codes(linked_report)


def test_new_evidence_file_is_supported(synth_repo) -> None:
    """Genuine new evidence binds exactly like the carried-forward files."""

    blobs = dict(_real_blobs())
    new_md = (
        b"# Synthetic cycle evidence\n\n"
        b"Second-cycle field notes for three re-checked pairs.\n"
    )
    blobs[SYNTH_EXTRA_REL] = new_md
    first_pairs = [
        (entity, trigger) for entity, trigger, _, _ in
        _pairs_from_register(blobs[REGISTER_REL])[:3]
    ]
    overrides = {
        pair: SYNTH_EXTRA_REL + "#synthetic-cycle-evidence"
        for pair in first_pairs
    }
    blobs[SYNTH_EXECUTION_REL] = _source_blob(
        blobs[REGISTER_REL], ref_overrides=overrides,
    )
    rev = _commit_variant(
        synth_repo, "cycle with new evidence",
        updates={SYNTH_EXECUTION_REL: blobs[SYNTH_EXECUTION_REL]},
        new_files={SYNTH_EXTRA_REL: new_md},
    )
    document = _result_for_blobs(blobs, rev, ref_overrides=overrides)
    assert len(document["evidence"]) == 5
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is True
    assert report.coverage_ok is True
    assert report.cycle_complete_ok is True


# ---------------------------------------------------------------------------
# History binding and unsupported positives
# ---------------------------------------------------------------------------

def test_history_binding_tampering_fails(synth_repo, tmp_path) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch unbound history", allow_empty=True)
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    document["governed_record_digest"] = "sha256:" + "0" * 64
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert "history-digest-mismatch" in _codes(report)

    renamed = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    renamed["governed_history_id"] = "renamed-history"
    target = _write_tmp(tmp_path, renamed)
    with pytest.raises(ReviewLoadError):
        load_result(target)
    assert _run_cli(target, require="integrity").returncode == 2
    stray = _verify(renamed, repo_root=synth_repo)
    assert stray.integrity_ok is False
    assert "history-identity-mismatch" in _codes(stray)


def test_unsupported_positive_claims_fail(synth_repo, tmp_path) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch claimed", allow_empty=True)
    document = _result_for_blobs(_real_blobs(), rev)
    document["results"] = [
        o for o in document["results"]
        if o["entity"] != "source:SP-07"
    ]
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert report.cycle_complete_ok is False
    assert "unsupported-positive-outcome" in _codes(report)
    assert "missing-entity" in _codes(report)
    target = _write_tmp(tmp_path, document)
    completed = _run_cli_in(synth_repo, target, require="integrity")
    assert completed.returncode == 1
    assert "unsupported-positive-outcome" in _payload_codes(
        json.loads(completed.stdout))
    recurred = _run_cli_in(synth_repo, target, require="complete")
    assert recurred.returncode == 1
    assert json.loads(recurred.stdout)["ok"] is False


# ---------------------------------------------------------------------------
# Epoch substitution, revision failures, bounds, and strict parsing
# ---------------------------------------------------------------------------

def test_coordinated_runtime_substitution_rejected(synth_repo) -> None:
    """Row plus inventory swaps that preserve every count still fail.

    The epoch is internally consistent, so only the independently pinned
    genesis roster anchor catches the substitution.
    """

    old = "ad-pathfinder.list_datasources"
    doc = yaml.safe_load((ROOT / REGISTER_REL).read_text(encoding="utf-8"))
    row = next(item for item in doc["runtime"] if item["capability_id"] == old)
    row["action"] = "unknown"
    row["capability_id"] = "ad-pathfinder.unknown"
    ids = doc["runtime_inventory"]["capability_ids"]
    ids[ids.index(old)] = "ad-pathfinder.unknown"
    ids.sort()
    mutated = yaml.safe_dump(doc, sort_keys=True).encode("utf-8")
    edited = dict(_real_blobs())
    edited[REGISTER_REL] = mutated
    rev = _commit_variant(synth_repo, "coordinated runtime swap",
                          updates={REGISTER_REL: mutated})
    document = _result_for_blobs(edited, rev, asserts_complete=False,
                                 asserts_integrity=False,
                                 asserts_coverage=False)
    assert len(document["results"]) == EXPECTED_PAIRS
    report = _verify(document, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert report.cycle_complete_ok is False
    assert "register-runtime-roster-mismatch" in _codes(report)
    assert "register-runtime-inventory-mismatch" not in _codes(report)


def test_unknown_and_non_commit_revisions_fail_closed(synth_repo) -> None:
    blobs = _real_blobs()
    rev = _commit_variant(synth_repo, "cycle epoch bad rev", allow_empty=True)
    unknown = _result_for_blobs(
        blobs, "f" * 40, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    report = _verify(unknown, repo_root=synth_repo)
    assert report.integrity_ok is False
    assert report.cycle_complete_ok is False
    assert report.as_dict()["counts"]["epoch_validated"] is False
    assert "revision-unknown" in _codes(report)

    blob_rev = _git(synth_repo, "rev-parse", f"{rev}:{REGISTER_REL}")
    assert len(blob_rev) == 40 and blob_rev != GENESIS_INSPECTED_REVISION
    non_commit = _result_for_blobs(
        blobs, blob_rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    non_commit_report = _verify(non_commit, repo_root=synth_repo)
    assert non_commit_report.integrity_ok is False
    assert "revision-not-commit" in _codes(non_commit_report)


def test_git_is_not_run_per_result(synth_repo) -> None:
    """1095 results sharing four evidence blobs need one fetch per blob."""

    rev = _commit_variant(synth_repo, "cycle epoch call counts", allow_empty=True)
    document = _result_for_blobs(_real_blobs(), rev)
    store = _RevisionBlobStore(synth_repo)
    report = _verify(document, repo_root=synth_repo, store=store)
    assert report.cycle_complete_ok is True
    # Four cycle-epoch blobs + genesis register/schema anchor blobs.
    assert store.fetches == 6
    assert store.git_calls <= 30


def test_substitute_open_schema_cannot_smuggle_unknown_fields(tmp_path) -> None:
    rev = GENESIS_INSPECTED_REVISION
    document = _result_for_blobs(
        _real_blobs(), rev, asserts_complete=False,
        asserts_integrity=False, asserts_coverage=False,
    )
    document["uninvited"] = True
    target = _write_tmp(tmp_path, document, name="extra.json")
    completed = _run_cli(target, require="integrity")
    assert completed.returncode == 2
    assert json.loads(completed.stderr)["schema"] == ERROR_SCHEMA
    with pytest.raises(ReviewLoadError):
        load_result(target)


def test_overflow_to_infinity_rejected_before_schema_validation(tmp_path) -> None:
    document = _result_for_blobs(
        _real_blobs(), GENESIS_INSPECTED_REVISION,
        asserts_complete=False, asserts_integrity=False, asserts_coverage=False,
    )
    first_len = document["evidence"][0]["byte_length"]
    raw = json.dumps(document, allow_nan=False, sort_keys=True).replace(
        f'"byte_length": {first_len}', '"byte_length": 1e999', 1
    )
    poisoned = tmp_path / "nonfinite.json"
    poisoned.write_text(raw, encoding="utf-8")
    with pytest.raises(ReviewLoadError, match="non-finite"):
        load_result(poisoned)
    completed = _run_cli(poisoned, require="integrity")
    assert completed.returncode == 2
    assert json.loads(completed.stderr)["schema"] == ERROR_SCHEMA

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema": 1, "schema": 2}')
    with pytest.raises(ReviewLoadError):
        load_result(duplicate)


def test_result_symlink_is_refused_without_custody_claim(synth_repo, tmp_path) -> None:
    rev = _commit_variant(synth_repo, "cycle epoch symlink input", allow_empty=True)
    document = _result_for_blobs(_real_blobs(), rev)
    target = _write_tmp(tmp_path, document)
    link = tmp_path / "linked.json"
    link.symlink_to(target)
    with pytest.raises(ReviewLoadError, match="must not be a symlink"):
        load_result(link)
    completed = _run_cli(link, require="integrity")
    assert completed.returncode == 2
    assert json.loads(completed.stderr)["schema"] == ERROR_SCHEMA


def test_shared_worktree_tracked_files_untouched() -> None:
    """Tripwire: mutation tests must not touch tracked governance files."""

    for path, baseline in TRACKED_BASELINE.items():
        assert path.read_bytes() == baseline, f"tracked file modified: {path}"
