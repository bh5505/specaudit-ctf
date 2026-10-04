"""Operator session runs actual admitted actions and verifies retained bytes."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from exercise.__main__ import main as exercise_main
from exercise.operations import (
    READERS, SessionError, inventory, make_plan, read_plan, run,
    validate_plan, verify_run,
)
from exercise import operations


def test_full_synthetic_operation_and_portable_readback(tmp_path: Path) -> None:
    root = tmp_path / "run"
    result = run(root, make_plan())
    assert result["status"] == "complete"
    assert len(result["steps"]) == 9 + len(READERS)
    assert {step["id"] for step in result["steps"]} >= set(READERS)
    copied = tmp_path / "copied"
    shutil.copytree(root, copied)
    status = verify_run(copied)
    assert status["status"] == "complete" and status["unverified_partial_files"] == 0
    assert status["completed"] == status["planned"] == len(result["steps"])
    detailed = verify_run(copied, detailed=True)
    reader = next(row for row in detailed["steps"] if row["id"] == "reader-agentseal")
    assert reader["report"] and reader["assessment"]["type"] == "offline-adapter"
    detection = next(row for row in detailed["steps"] if row["id"] == "detection-review")
    assert detection["status"] == "complete"
    assert detection["assessment"]["result"]["stages"]["events_collected"]["state"] == "not_met"
    assert detection["assessment"]["result"]["retest_result"] == "unknown"


def test_editable_plan_remains_closed_and_binds_exact_input(tmp_path: Path) -> None:
    plan = make_plan(["detection-review", "reader-vulnify"])
    source = tmp_path / "plan.json"
    assert exercise_main(["plan", "--scenario", "detection-review", "--out", str(source)]) == 0
    prepared, raw = read_plan(source)
    assert prepared["steps"][0]["id"] == "detection-review" and raw == source.read_bytes()
    plan["steps"][0]["args"]["packet"]["case_id"] = "locally-edited-case"
    validate_plan(plan)
    plan["steps"][1]["args"]["bundle_path"] = "/tmp/operator-owned-input.json"
    with pytest.raises(SessionError, match="fixed"):
        validate_plan(plan)
    plan = make_plan(["reader-vulnify"])
    plan["steps"][0]["id"] = "http-target"
    with pytest.raises(SessionError, match="override"):
        validate_plan(plan)


def test_tamper_extra_entries_and_interrupted_run_are_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "run"
    run(root, make_plan(["range", "reader-agentseal"]))
    journal_path = root / "journal.json"
    journal = json.loads(journal_path.read_text())
    assert verify_run(root)["status"] == "complete"
    staged = root / journal["steps"][1]["inputs"][0]["path"]
    staged.write_bytes(staged.read_bytes() + b" ")
    with pytest.raises(SessionError, match="staged input bytes changed"):
        verify_run(root)
    staged.write_bytes(staged.read_bytes()[:-1])
    envelope = root / journal["steps"][1]["envelope"]["path"]
    envelope.write_bytes(envelope.read_bytes() + b" ")
    with pytest.raises(SessionError, match="envelope bytes changed"):
        verify_run(root)
    envelope.write_bytes(envelope.read_bytes()[:-1])
    extra = root / "unclaimed.txt"
    extra.write_text("untracked")
    with pytest.raises(SessionError, match="unrecorded"):
        verify_run(root)
    journal["steps"] = journal["steps"][:1]
    journal["state"] = "running"
    journal["status"] = "incomplete"
    journal_path.write_text(json.dumps(journal))
    partial = verify_run(root)
    assert partial["status"] == "incomplete" and partial["completed"] == 1
    assert partial["unverified_partial_files"] > 0


def test_report_rechecks_artifact_after_inventory_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    run(root, make_plan(["reader-agentseal"]))
    actual_verify = operations._verify

    def mutate_after_verify(path: Path) -> tuple[dict, dict]:
        result = actual_verify(path)
        claim = result[0]["steps"][0]["artifacts"][0]
        artifact = path / claim["path"]
        artifact.write_bytes(artifact.read_bytes() + b" ")
        return result

    monkeypatch.setattr(operations, "_verify", mutate_after_verify)
    with pytest.raises(SessionError, match="digest mismatch"):
        verify_run(root, detailed=True)


def test_ancestor_symlink_refused_before_readback(tmp_path: Path) -> None:
    root = tmp_path / "run"
    run(root, make_plan(["reader-agentseal"]))
    steps = root / "steps"
    steps.rename(root / "saved-steps")
    steps.symlink_to(root / "saved-steps", target_is_directory=True)
    with pytest.raises(SessionError, match="symlink"):
        verify_run(root)


def test_inventory_preserves_support_tiers_and_named_gaps() -> None:
    result = inventory()
    catalog = {row["id"]: row for row in result["catalog"]}
    assert len(catalog) == 68 and len(result["challenges"]) == 13
    assert "reader-agentseal" in catalog["agentseal"]["scenarios"]
    assert catalog["agentseal"]["tier"] == "research"
    assert catalog["http-probe"]["operational_state"] == "opt-in-local-target"
    assert "probe" in catalog["http-probe"]["admitted_actions"]
    assert catalog["http-probe"]["action_profiles"]
    assert any(row["operational_state"] == "methodology-only" for row in result["catalog"])
    assert sum(row["offline_packet"] for row in result["challenges"]) == 7
