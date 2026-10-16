"""T03 vertical slice end-to-end under the containment guard.

The slice's machine check, exercised for real: reader_evidence acquisition
of the packet inputs, the reader_evidence.data_slices digest gate on the
pinned vulnify demo snapshot, one vulnify.lookup batch dispatched to a
guarded child (canary watched), self-study ledger rows, an evidence-chain
close, and instructor-KEY unreachability from the learner root.

Windows honest-partial: the trusted acquisition gate itself types
``platform-unsupported`` (no ``os.O_NOFOLLOW``), mirroring
tests/test_containment_suite.py; the lexical root-escape refusal for the
instructor KEY fires before the platform gate and is asserted on both
platforms.
"""

from __future__ import annotations

from datetime import date, datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys

import pytest

from attempt_ledger import append_row, summarize, verify_ledger
from containment.harness import run_case
from containment.profile import OperatorProfile
from evidence_chain import build_chain, verify_chain
from reader_evidence import AcquisitionError, acquire
from reader_evidence.data_slices import (DataSliceError, verify_slice_bytes,
                                         vulnify_demo_slice)

REPO_ROOT = Path(__file__).resolve().parents[1]
SLICE = REPO_ROOT / "challenges" / "qualification" / "t03-vertical-slice"
KEY = SLICE / "instructor" / "KEY.md"
CANARY = "INSTRUCTOR-CANARY-T03"
AS_OF = date(2026, 10, 13)
GATE_AT = datetime(2026, 10, 13, 12, 0, 0)
SUFFIXES = frozenset({".json", ".md", ".yaml", ".yml", ".txt"})
QUERY_IDS = ("CVE-2099-0001", "CVE-2099-0002", "CVE-2099-9999")


def _load_loader():
    # Loading a non-package module by path; never leave bytecode in the tree.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "t03_qualification_loader",
        REPO_ROOT / "challenges" / "qualification" / "loader.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loader = _load_loader()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture(scope="module")
def learner_env(tmp_path_factory):
    """Operator-staged learner packet inside an approved root, with the
    pinned demo slice bytes staged under inputs/ and the instructor KEY
    left OUTSIDE the root."""
    root = tmp_path_factory.mktemp("t03-slice")
    approved = root / "approved"
    scratch = root / "scratch"
    packet = approved / "packet"
    (packet / "inputs").mkdir(parents=True)
    (packet / "BRIEF.md").write_text(
        (SLICE / "README.md").read_text(encoding="utf-8"), encoding="utf-8")
    shutil.copyfile(SLICE / "inputs" / "assets.json",
                    packet / "inputs" / "assets.json")
    # Stage the pinned slice bytes; the digest gate below proves the staged
    # copy equals the pin byte-for-byte.
    pinned_path = REPO_ROOT / vulnify_demo_slice().pinned_path
    shutil.copyfile(pinned_path, packet / "inputs" / "demo-vulnerability-snapshot.json")
    profile = OperatorProfile(approved_root=str(approved),
                              scratch_root=str(scratch), canaries=(CANARY,))
    return {"root": root, "approved": approved, "scratch": scratch,
            "packet": packet, "profile": profile,
            "assets": packet / "inputs" / "assets.json",
            "staged_slice": packet / "inputs" / "demo-vulnerability-snapshot.json"}


def test_slice_declares_qualification_ready_and_stays_out_of_the_shipped_table() -> None:
    readme = (SLICE / "README.md").read_text(encoding="utf-8")
    assert "qualification-ready" in readme
    # The shipped-challenge table must not carry this slice.
    challenges_readme = (REPO_ROOT / "challenges" / "README.md").read_text(
        encoding="utf-8")
    table = challenges_readme.split("| Challenge |", 1)[1].split("Start with", 1)[0]
    assert "t03" not in table and "qualification-ready" not in table
    # The brief must carry the run snippet, not auto-run it.
    assert "run_case(" in readme and "validate.py --dir" in readme


def test_slice_inventory_shape() -> None:
    assets = json.loads((SLICE / "inputs" / "assets.json").read_text(encoding="utf-8"))
    assert len(assets["assets"]) == 5
    ids = {asset["cve_id"] for asset in assets["assets"]}
    assert ids == {"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-9999"}
    assert CANARY in KEY.read_text(encoding="utf-8")


def test_pinned_slice_digest_gate(learner_env) -> None:
    record = vulnify_demo_slice()
    pinned_bytes = (REPO_ROOT / record.pinned_path).read_bytes()
    # The repo pin verifies, and the staged copy is byte-identical to it.
    verify_slice_bytes(record, pinned_bytes)
    verify_slice_bytes(record, learner_env["staged_slice"].read_bytes())
    with pytest.raises(DataSliceError) as excinfo:
        verify_slice_bytes(record, pinned_bytes + b" ")
    assert excinfo.value.reason == "digest-mismatch"


def test_packet_inputs_acquired_under_the_containment_gate(learner_env) -> None:
    """POSIX: the trusted gate acquires and binds the packet inputs.
    Windows: the gate types platform-unsupported (no os.O_NOFOLLOW) -- the
    honest partial the containment suite documents; the child-side enforcer
    still polices reads, proven by the guarded case below."""
    if os.name == "nt":
        with pytest.raises(AcquisitionError) as excinfo:
            acquire(learner_env["assets"], approved_root=learner_env["approved"],
                    allowed_suffixes=SUFFIXES, max_bytes=1_048_576,
                    acquired_at=GATE_AT)
        assert excinfo.value.reason == "platform-unsupported"
        return
    for path in (learner_env["assets"], learner_env["staged_slice"]):
        record = acquire(path, approved_root=learner_env["approved"],
                         allowed_suffixes=SUFFIXES, max_bytes=1_048_576,
                         acquired_at=GATE_AT)
        assert record.sha256 == _digest(path.read_bytes())


def test_guarded_vulnify_lookup_resolves_the_pinned_slice(learner_env) -> None:
    """The containment-guarded machine check: the batch lookup runs in a
    guarded child against the staged pinned slice, zero denials, no canary
    leak; the custody receipt on stderr carries the per-query outcomes
    (mapped / near-miss / unknown-stays-unknown)."""
    case = run_case(
        learner_env["profile"], arm_id="vulnify", action="lookup",
        payload={"cve_ids": list(QUERY_IDS),
                 "bundle_path": str(learner_env["staged_slice"])},
    )
    assert case.outcome == "positive", case.detail
    assert not case.denials
    stdout = case.detail.get("stdout_tail", "")
    stderr = case.detail.get("stderr_tail", "")
    assert CANARY not in stdout and CANARY not in stderr
    receipt_line = next(line for line in reversed(stderr.splitlines())
                        if "vulnify.lookup-receipt.v1" in line)
    receipt = json.loads(receipt_line)
    assert receipt["bundle_sha256"] == hashlib.sha256(
        learner_env["staged_slice"].read_bytes()).hexdigest()
    queries = {row["cve_id"]: row["status"] for row in receipt["queries"]}
    assert queries == {"CVE-2099-0001": "matched", "CVE-2099-0002": "matched",
                       "CVE-2099-9999": "unmatched"}


def test_lookup_semantics_on_digest_gated_bytes() -> None:
    """The in-process statement of the same facts, on the digest gate: one
    mapped record, one near-miss record without technique enrichment, and
    one unknown that stays unknown."""
    from extension.arms.vulnify import reader

    record = vulnify_demo_slice()
    raw = (REPO_ROOT / record.pinned_path).read_bytes()
    verify_slice_bytes(record, raw)
    index = reader.load_bundle_bytes(raw)
    snapshot_sha = _digest(raw)
    mapped = reader.lookup(index, "CVE-2099-0001", snapshot_sha)
    near_miss = reader.lookup(index, "CVE-2099-0002", snapshot_sha)
    unknown = reader.lookup(index, "CVE-2099-9999", snapshot_sha)
    assert mapped["technique_mappings"] == [
        {"id": "T0001", "name": "Fake technique mapping"}]
    assert near_miss is not None and near_miss["technique_mappings"] is None
    assert unknown is None  # unknown stays unknown


def test_instructor_key_unreachable_from_the_learner_root(learner_env) -> None:
    """Direct acquisition of the KEY is typed-refused; a reader-mediated
    hostile case carrying the KEY is blocked before dispatch; the guarded
    outputs carry no canary; the learner packet has no canary bytes."""
    with pytest.raises(AcquisitionError) as excinfo:
        acquire(KEY, approved_root=learner_env["approved"],
                allowed_suffixes=SUFFIXES, max_bytes=1_048_576,
                acquired_at=GATE_AT)
    assert excinfo.value.reason == "root-escape"

    case = run_case(
        learner_env["profile"], arm_id="vulnify", action="lookup",
        payload={"feed": str(KEY), "cve_id": "CVE-2099-0001"},
        hostile="absolute-out-of-root", variant="hostile-instructor",
    )
    assert case.outcome == "blocked"
    assert case.reason == "root-escape"

    for path in learner_env["packet"].rglob("*"):
        if path.is_file():
            assert CANARY.encode("utf-8") not in path.read_bytes()


def test_ledger_rows_and_evidence_chain_close(learner_env) -> None:
    """The slice's dry-run bookkeeping: self-study ledger rows (completion
    plus a refusal), a verifying chain, and no seed-shaped adjudication."""
    assets_bytes = learner_env["assets"].read_bytes()
    slice_bytes = learner_env["staged_slice"].read_bytes()
    rows: tuple[dict, ...] = ()
    rows, head = append_row(rows, {
        "attempt_id": "t03-0001-guarded-lookup",
        "lane": "self-study",
        "subject": "t03-vertical-slice",
        "attempt_class": "completion",
        "outcome": "passed",
        "assistance": "none",
        "detail_digest": _digest(slice_bytes),
        "recorded_at": GATE_AT,
    })
    rows, head = append_row(rows, {
        "attempt_id": "t03-0002-key-acquisition",
        "lane": "self-study",
        "subject": "t03-vertical-slice",
        "attempt_class": "refusal",
        "outcome": "blocked",
        "assistance": "none",
        "detail_digest": _digest(assets_bytes),
        "recorded_at": GATE_AT,
    })
    assert verify_ledger(rows).ok
    counts = summarize(rows)
    assert counts["by_class"] == {"completion": 1, "refusal": 1}
    assert counts["by_lane"] == {"self-study": 2}

    chain = build_chain(
        [{"digest": _digest(assets_bytes), "locator": "packet/inputs/assets.json",
          "custody_note": "operator-staged learner packet entry"},
         {"digest": _digest(slice_bytes),
          "locator": "packet/inputs/demo-vulnerability-snapshot.json",
          "custody_note": "pinned demo slice bytes staged under the approved root"}],
        [{"digest": _digest(assets_bytes), "evidence_class": "observed"},
         {"digest": _digest(slice_bytes), "evidence_class": "observed"}],
        {"digest": _digest(b"t03 prioritization statement"),
         "author_role": "analyst", "statement_count": 1},
        {"digest": _digest(b"t03 machine check"),
         "reviewer": "machine-check", "original_score": "3-queries",
         "adjusted_score": None,
         "rationale": "machine consistency only; human review unstaffed",
         "decided_on": "2026-10-13"},
        {"digest": head, "conclusion": "t03 vertical slice machine check closed"},
    )
    assert verify_chain(chain, as_of=AS_OF).ok
    # No code path may count this close as calibrated review, seed-shaped or not.
    assert loader.is_human_calibration(chain) is False
