"""Operator packet, custody and grading boundaries for shipped challenges."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from exercise_operator.__main__ import (
    FIXTURES, OperatorError, bounded_regular, contracts, grade, inventory,
    main, packet_materials, prepare, rehearse,
)

ROOT = Path(__file__).resolve().parents[1]


def test_packaged_contracts_and_public_vocabulary() -> None:
    corpus = contracts()
    originals = sorted((ROOT / "challenges").glob("*/artifacts/expected-findings.json"))
    assert len(corpus) == len(originals) == 13
    for original in originals:
        assert corpus[original.parents[1].name][1] == original.read_bytes()
    vocab = json.loads((ROOT / "exercise_operator/vocabulary.json").read_text())
    keys = [row["finding_key"] for row in vocab["candidates"]]
    assert len(keys) == len(set(keys))
    expected_keys = {row["finding_key"] for name in FIXTURES
                     for row in corpus[name][0]["findings"]}
    assert expected_keys < set(keys)


def test_inventory_classifies_lanes_and_cross_fixture_note() -> None:
    rows = {row["id"]: row for row in inventory()["challenges"]}
    assert len(rows) == 13
    assert sum(row["offline_packet"] for row in rows.values()) == 7
    assert [row["lane"] for row in rows.values()].count("live-service") == 5
    assert [row["lane"] for row in rows.values()].count("planted-code") == 1
    cross = rows["telecom-aws-02-iam-s3-misconfig"]
    assert "cross-fixture trace only" in cross["declared_fixtures"][1]
    assert cross["packet_fixtures"] == ["tf_iam_open", "tf_s3_public_access"]


def test_prepare_exports_only_public_inputs(tmp_path: Path) -> None:
    packet = tmp_path / "packet"
    prepare("telecom-aws-02-iam-s3-misconfig", packet)
    names = {str(path.relative_to(packet)) for path in packet.rglob("*") if path.is_file()}
    assert len(names) == 12
    assert "evidence/tf_s3_public_access/main.tf" in names
    assert not any("expected" in name or "solution" in name or "KEY" in name for name in names)
    assert json.loads((packet / "findings-template.json").read_text())["findings"] == []
    vocab = json.loads((packet / "candidate-vocabulary.json").read_text())
    assert all(set(row) == {"finding_key", "control"} for row in vocab["candidates"])
    manifest = json.loads((packet / "manifest.json").read_text())
    for entry in manifest["files"]:
        assert hashlib.sha256((packet / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    with pytest.raises(OperatorError, match="fresh"):
        prepare("telecom-aws-02-iam-s3-misconfig", packet)


def _learner_submission(path: Path, *, complete: bool = True) -> None:
    rows = [
        ("demo-s3-public-read-acl", "storage exposure: public ACL grant",
         "aws_s3_bucket.public_bucket sets acl public-read"),
        ("demo-s3-no-public-access-block", "storage exposure: account-level public guard absent",
         "main.tf has no public access block for public_bucket"),
        ("demo-s3-no-encryption", "data protection: encryption at rest absent",
         "main.tf lacks server-side encryption for public_bucket"),
    ]
    if not complete:
        rows = rows[:1]
    path.write_text(json.dumps({
        "track": "telecom-aws-01-reachability", "total": len(rows),
        "findings": [
            {"finding_key": key, "control": control, "severity": "high",
             "rationale": "Observed condition warrants review", "traces_to": trace}
            for key, control, trace in rows
        ],
    }))


def test_packet_bound_grade_and_rehash_tamper(tmp_path: Path) -> None:
    packet = tmp_path / "learner"
    prepare("telecom-aws-01-reachability", packet)
    found = tmp_path / "submitted.json"
    _learner_submission(found)
    passed = grade("telecom-aws-01-reachability", found, tmp_path / "pass", packet)
    assert passed["status"] == "passed" and passed["packet_binding"]["verified_files"] == 7
    assert (tmp_path / "pass/submission.json").read_bytes() == found.read_bytes()
    _learner_submission(found, complete=False)
    failed = grade("telecom-aws-01-reachability", found, tmp_path / "miss", packet)
    assert failed["status"] == "failed"
    assert len(json.loads((tmp_path / "miss/grade.json").read_text())["misses"]) == 2
    found.write_text('{"track":"x","track":"x"}')
    refused = grade("telecom-aws-01-reachability", found, tmp_path / "refusal", packet)
    assert refused["status"] == "refused"
    assert (tmp_path / "refusal/submission.json").read_bytes() == found.read_bytes()
    assert main(["grade", "telecom-aws-01-reachability", "--found", str(found),
                 "--packet", str(packet), "--out", str(tmp_path / "cli-refusal")]) == 2
    original = (packet / "manifest.json").read_text()
    (packet / "BRIEF.md").write_text("tampered")
    with pytest.raises(OperatorError, match="changed"):
        grade("telecom-aws-01-reachability", found, tmp_path / "tamper", packet)
    forged = json.loads(original)
    next(row for row in forged["files"] if row["path"] == "BRIEF.md")["sha256"] = hashlib.sha256(
        (packet / "BRIEF.md").read_bytes()
    ).hexdigest()
    (packet / "manifest.json").write_text(json.dumps(forged))
    with pytest.raises(OperatorError, match="differs from packaged source"):
        grade("telecom-aws-01-reachability", found, tmp_path / "forged", packet)
    (packet / "manifest.json").write_text(original)
    (packet / "BRIEF.md").write_bytes(dict(packet_materials(
        "telecom-aws-01-reachability", contracts()["telecom-aws-01-reachability"][0]
    ))["BRIEF.md"])
    (packet / "extra.txt").write_text("extraneous")
    with pytest.raises(OperatorError, match="inventory changed"):
        grade("telecom-aws-01-reachability", found, tmp_path / "extra", packet)


def test_refuses_packet_contamination_and_unbounded_inputs(tmp_path: Path) -> None:
    packet = tmp_path / "packet"
    prepare("telecom-aws-01-reachability", packet)
    with pytest.raises(OperatorError, match="outside"):
        grade("telecom-aws-01-reachability", packet / "findings-template.json",
              tmp_path / "inside", packet)
    submitted = tmp_path / "submission.json"
    _learner_submission(submitted)
    with pytest.raises(OperatorError, match="outside"):
        grade("telecom-aws-01-reachability", submitted, packet / "report", packet)
    linked_packet = tmp_path / "linked-packet"
    linked_packet.symlink_to(packet, target_is_directory=True)
    with pytest.raises(OperatorError, match="real directory"):
        grade("telecom-aws-01-reachability", submitted, tmp_path / "linked-report", linked_packet)
    link = tmp_path / "link.json"
    link.symlink_to(submitted)
    with pytest.raises(OperatorError, match="unreadable"):
        grade("telecom-aws-01-reachability", link, tmp_path / "link-report")
    submitted.write_bytes(b"{" + b"x" * 1_048_576 + b"}")
    with pytest.raises(OperatorError, match="bounded"):
        grade("telecom-aws-01-reachability", submitted, tmp_path / "huge")
    with pytest.raises(OperatorError, match="unsupported"):
        prepare("lab-web-01-dast-surface", tmp_path / "live")


@pytest.mark.parametrize("missing", ["O_NONBLOCK", "O_NOFOLLOW"])
def test_missing_portable_read_flags_refuse_cleanly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, missing: str
) -> None:
    submission = tmp_path / "submission.json"
    submission.write_text("{}")
    monkeypatch.delattr(os, missing, raising=False)
    with pytest.raises(OperatorError, match="bounded nofollow file reads unavailable"):
        bounded_regular(submission)


def test_rehearsal_custodies_full_roster_without_arms(tmp_path: Path) -> None:
    destination = tmp_path / "operator"
    report = rehearse(destination)
    assert report["status"] == "complete"
    envelope = json.loads((destination / "range-envelope.json").read_text())
    assert envelope["status"] == "complete"
    artifact = next(row for row in report["files"] if row["path"].startswith("artifacts/"))
    raw = (destination / artifact["path"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]
    range_doc = json.loads(raw)
    assert len(range_doc["fixtures"]) == 10
    assert all(row["arms"] == [] for row in range_doc["fixtures"])
    assert range_doc["live_aws"] is False
