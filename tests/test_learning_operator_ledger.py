"""Ledger wiring on the learning-operator run path (additive --ledger only)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from extension.arms.learning_operator import SAMPLE_ACTIONS, ARM_ID, _sample
from extension.encode import mode_a_supported
from learning.operator import main as operator_main

KEY_HEX = bytes(range(32)).hex()
ATTEMPT_ID = "attempt-" + "0" * 64


@pytest.fixture(autouse=True)
def _portable_read_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bounded read contract is POSIX-gated; zero-valued flags keep the
    guards satisfied on hosts without them, with behavior-identical reads."""
    for flag in ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
        if not hasattr(os, flag):
            monkeypatch.setattr(os, flag, 0, raising=False)


def _write_request(path: Path, action: str) -> None:
    args = _sample(action) if action in SAMPLE_ACTIONS else {}
    path.write_text(json.dumps(
        {"arm_id": ARM_ID, "action": action, "args": args}, sort_keys=True, indent=2))


def _run_args(request: Path, artifact_dir: Path, ledger: Path, **flags: str) -> list[str]:
    args = ["run", "--request", str(request), "--attempt-id", ATTEMPT_ID,
            "--artifact-dir", str(artifact_dir), "--ledger", str(ledger),
            "--at", "2026-10-13T10:00:00"]
    for flag, value in flags.items():
        args.extend([flag, value])
    return args


def _rows(ledger: Path) -> list[dict]:
    return [json.loads(line) for line in ledger.read_text().splitlines()]


def test_valid_request_appends_completion_row(
        tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    if not mode_a_supported():
        pytest.skip("Mode A artifact custody is Unix-only; refusal paths cover this host")
    action = sorted(SAMPLE_ACTIONS)[0]
    request = tmp_path / "request.json"
    _write_request(request, action)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    ledger = tmp_path / "ledger.jsonl"
    assert operator_main(_run_args(request, artifacts, ledger)) == 0
    rows = _rows(ledger)
    assert len(rows) == 1
    row = rows[0]
    assert row["lane"] == "self-study"
    assert row["subject"] == action
    assert row["attempt_class"] == "completion"
    assert row["outcome"] == "dispatched"
    assert row["attempt_id"] == ATTEMPT_ID
    printed = capsys.readouterr().out
    assert printed.endswith("\n")
    assert row["detail_digest"] == "sha256:" + hashlib.sha256(
        printed[:-1].encode("utf-8")).hexdigest()
    assert json.loads(printed)["report"] is not None


def test_malformed_request_appends_parse_failure_row(tmp_path: Path) -> None:
    request = tmp_path / "request.json"
    raw = b'{"arm_id": "learning.operator", "action": '
    request.write_bytes(raw)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    ledger = tmp_path / "ledger.jsonl"
    assert operator_main(_run_args(request, artifacts, ledger)) == 2
    rows = _rows(ledger)
    assert rows[0]["attempt_class"] == "parse-failure"
    assert rows[0]["lane"] == "self-study"
    assert rows[0]["subject"] == "unknown"
    assert rows[0]["detail_digest"] == "sha256:" + hashlib.sha256(raw).hexdigest()


def test_shapeless_request_names_the_workflow(tmp_path: Path) -> None:
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"action": "workpaper_review", "args": {}}))
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    ledger = tmp_path / "ledger.jsonl"
    assert operator_main(_run_args(request, artifacts, ledger)) == 2
    rows = _rows(ledger)
    assert rows[0]["attempt_class"] == "parse-failure"
    assert rows[0]["subject"] == "workpaper_review"


def test_dispatch_refusal_appends_refusal_row(tmp_path: Path) -> None:
    request = tmp_path / "request.json"
    _write_request(request, "nonexistent-action")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    ledger = tmp_path / "ledger.jsonl"
    assert operator_main(_run_args(request, artifacts, ledger)) == 2
    rows = _rows(ledger)
    assert len(rows) == 1
    assert rows[0]["attempt_class"] == "refusal"
    assert rows[0]["subject"] == "nonexistent-action"
    assert rows[0]["outcome"] is None


def test_keyed_ledger_and_flag_coupling(tmp_path: Path) -> None:
    request = tmp_path / "request.json"
    _write_request(request, "nonexistent-action")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    ledger = tmp_path / "ledger.jsonl"
    assert operator_main(_run_args(request, artifacts, ledger,
                                   **{"--ledger-key-hex": KEY_HEX,
                                      "--assistance": "assisted"})) == 2
    rows = _rows(ledger)
    assert rows[0]["assistance"] == "assisted"
    assert "auth_tag" in rows[0]
    # Ledger flags without --ledger are a usage error, before any dispatch.
    with pytest.raises(SystemExit) as exc:
        operator_main(["run", "--request", str(request), "--attempt-id", ATTEMPT_ID,
                       "--artifact-dir", str(tmp_path / "unused"), "--at",
                       "2026-10-13T10:00:00"])
    assert exc.value.code == 2
    assert len(_rows(ledger)) == 1
