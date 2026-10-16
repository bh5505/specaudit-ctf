"""Ledger wiring on the exercise-operator grade path (additive --ledger only)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from attempt_ledger import verify_ledger
from exercise_operator.__main__ import main as operator_main

KEY_HEX = bytes(range(32)).hex()


@pytest.fixture(autouse=True)
def _portable_read_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bounded read contract is POSIX-gated; zero-valued flags keep the
    guards satisfied on hosts without them, with behavior-identical reads."""
    for flag in ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
        if not hasattr(os, flag):
            monkeypatch.setattr(os, flag, 0, raising=False)


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


def _grade_args(found: Path, out: Path, ledger: Path, **flags: str) -> list[str]:
    args = ["grade", "telecom-aws-01-reachability", "--found", str(found),
            "--out", str(out), "--ledger", str(ledger),
            "--at", "2026-10-13T10:00:00"]
    for flag, value in flags.items():
        args.extend([flag, value])
    return args


def _rows(ledger: Path) -> list[dict]:
    return [json.loads(line) for line in ledger.read_text().splitlines()]


def test_grade_appends_completion_row_and_manifest_head(tmp_path: Path) -> None:
    found = tmp_path / "submitted.json"
    _learner_submission(found)
    ledger = tmp_path / "ledger.jsonl"
    out = tmp_path / "report"
    assert operator_main(_grade_args(found, out, ledger)) == 0
    rows = _rows(ledger)
    assert len(rows) == 1
    row = rows[0]
    assert row["lane"] == "fixture-backed"
    assert row["subject"] == "telecom-aws-01-reachability"
    assert row["attempt_class"] == "completion"
    assert row["outcome"] == "passed"
    assert row["assistance"] == "first-pass"
    assert row["prev_row_digest"] is None
    grade_bytes = (out / "grade.json").read_bytes()
    assert row["detail_digest"] == "sha256:" + hashlib.sha256(grade_bytes).hexdigest()
    assert verify_ledger(rows).ok
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["ledger_head_digest"] == row["row_digest"]


def test_failed_grade_is_a_completion_row_with_failed_outcome(tmp_path: Path) -> None:
    found = tmp_path / "submitted.json"
    _learner_submission(found, complete=False)
    ledger = tmp_path / "ledger.jsonl"
    out = tmp_path / "report"
    assert operator_main(_grade_args(found, out, ledger)) == 1
    rows = _rows(ledger)
    # A failed grade is a completed attempt with wrong findings, not a refusal.
    assert rows[0]["attempt_class"] == "completion"
    assert rows[0]["outcome"] == "failed"
    assert json.loads((out / "manifest.json").read_text())["ledger_head_digest"] == \
        rows[0]["row_digest"]


def test_second_grade_chains_onto_the_first(tmp_path: Path) -> None:
    found = tmp_path / "submitted.json"
    _learner_submission(found)
    ledger = tmp_path / "ledger.jsonl"
    assert operator_main(_grade_args(found, tmp_path / "one", ledger)) == 0
    # Same submission bytes, same triple: a legitimate retry, not a new attempt.
    assert operator_main(_grade_args(found, tmp_path / "two", ledger)) == 0
    rows = _rows(ledger)
    assert len(rows) == 2
    assert rows[1]["prev_row_digest"] == rows[0]["row_digest"]
    assert rows[1]["attempt_id"] == rows[0]["attempt_id"]
    assert verify_ledger(rows).ok


def test_grade_without_ledger_keeps_manifest_keys_unchanged(tmp_path: Path) -> None:
    found = tmp_path / "submitted.json"
    _learner_submission(found)
    out = tmp_path / "report"
    assert operator_main(["grade", "telecom-aws-01-reachability", "--found", str(found),
                          "--out", str(out)]) == 0
    manifest = json.loads((out / "manifest.json").read_text())
    # Regression guard: the manifest is byte-for-byte the pre-ledger schema.
    assert set(manifest) == {
        "schema", "command", "challenge", "lane", "status", "submission_sha256",
        "contract_sha256", "packet_binding", "files", "limitations"}
    assert "ledger_head_digest" not in manifest
    with pytest.raises(FileNotFoundError):
        (tmp_path / "ledger.jsonl").read_bytes()


def test_ledger_flags_require_the_ledger(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    found = tmp_path / "submitted.json"
    _learner_submission(found)
    for extra in (["--ledger-key-hex", KEY_HEX], ["--assistance", "assisted"],
                  ["--at", "2026-10-13T10:00:00"]):
        with pytest.raises(SystemExit) as exc:
            operator_main(["grade", "telecom-aws-01-reachability", "--found", str(found),
                           "--out", str(tmp_path / "unused"), *extra])
        assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        operator_main(["grade", "telecom-aws-01-reachability", "--found", str(found),
                       "--out", str(tmp_path / "unused"), "--ledger",
                       str(tmp_path / "ledger.jsonl")])
    assert exc.value.code == 2  # --at is required with --ledger
    assert "required" in capsys.readouterr().err


def test_malformed_findings_row_is_parse_failure(tmp_path: Path) -> None:
    found = tmp_path / "submitted.json"
    found.write_text('{"track":"x","track":"x"}')
    ledger = tmp_path / "ledger.jsonl"
    out = tmp_path / "report"
    assert operator_main(_grade_args(found, out, ledger)) == 2
    rows = _rows(ledger)
    assert rows[0]["attempt_class"] == "parse-failure"
    assert rows[0]["outcome"] == "refused"
    assert not (out / "grade.json").exists()
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["status"] == "refused"
    assert manifest["ledger_head_digest"] == rows[0]["row_digest"]


def test_keyed_grade_ledger(tmp_path: Path) -> None:
    found = tmp_path / "submitted.json"
    _learner_submission(found)
    ledger = tmp_path / "ledger.jsonl"
    assert operator_main(_grade_args(found, tmp_path / "report", ledger,
                                     **{"--ledger-key-hex": KEY_HEX})) == 0
    rows = _rows(ledger)
    assert "auth_tag" in rows[0]
    assert verify_ledger(rows, hmac_key=bytes.fromhex(KEY_HEX)).ok
    assert not verify_ledger(rows).ok  # keyed rows are refused without the key
