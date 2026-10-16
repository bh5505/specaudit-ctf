"""Ledger wiring on the exercise runner path (additive --ledger only).

Covers the pure lane → (attempt_class, outcome) mapping table over every
status/reason the runner can emit, the pure row builder, and the CLI
wiring (happy, refused, graded-failed, arms, fake-head, keyed, corrupt,
flag guards, and the no-flag byte-identical regression).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from attempt_ledger import ATTEMPT_CLASSES, append_row, verify_ledger
from exercise.__main__ import main as exercise_main
from exercise.ledger_wiring import (
    LedgerWiringError,
    append_document_rows,
    build_rows,
    map_outcome,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_06 = (
    ROOT
    / "challenges"
    / "telecom-aws-06-chain-rehearsal"
    / "artifacts"
    / "expected-findings.json"
)
CONTRACT_02 = (
    ROOT
    / "challenges"
    / "telecom-aws-02-iam-s3-misconfig"
    / "artifacts"
    / "expected-findings.json"
)
KEY_HEX = bytes(range(32)).hex()
AT = "2026-10-13T10:00:00"
_ATTEMPT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{7,127}\Z")


def _canonical(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=False).encode("utf-8")


# --- pure mapping table: every status/reason the runner can emit -------------


@pytest.mark.parametrize(
    ("lane", "section", "expected"),
    [
        # range lane (extension/range statuses as the runner reports them)
        ("range", {"status": "complete"}, ("completion", "range-matched")),
        ("range", {"status": "degraded"}, ("completion", "range-degraded")),
        ("range", {"status": "failed"}, ("completion", "range-failed")),
        ("range", {"status": "mystery"}, ("parse-failure", "unknown-status")),
        # grade lane
        ("grade", {"schema": "specaudit.ctf.grade.v1", "passed": True},
         ("completion", "graded-passed")),
        ("grade", {"schema": "specaudit.ctf.grade.v1", "passed": False},
         ("completion", "graded-failed")),
        ("grade", {"schema": "score.failed-to-grade", "passed": False,
                   "error": "unparsable"}, ("refusal", "refused")),
        # arms lane rows
        ("arms", {"arm_id": "a", "action": "b", "status": "complete"},
         ("completion", "complete")),
        ("arms", {"arm_id": "a", "action": "b", "status": "degraded"},
         ("completion", "degraded")),
        ("arms", {"status": "failed", "reason": "arm request must be a mapping"},
         ("parse-failure", "invalid-request")),
        ("arms", {"arm_id": "", "action": "", "status": "failed",
                  "reason": "arm_id and action are required"},
         ("parse-failure", "invalid-request")),
        ("arms", {"status": "failed",
                  "reason": "pre-dispatch contract error: no such arm"},
         ("refusal", "refused")),
        # envelope-backed failure: no reason is recorded on the row
        ("arms", {"arm_id": "no-such-arm", "action": "scan", "status": "failed",
                  "capability_id": None, "envelope_status": "failed"},
         ("crash", "invoke-failed")),
        ("arms", {"status": "confused"}, ("parse-failure", "unknown-status")),
        # battery lane rows (skip reasons exactly as _run_battery writes them)
        ("battery", {"arm_id": "m", "action": "a", "status": "skipped",
                     "reason": ("battery: WAPITI_DISPATCH_SCOPE is unset; "
                                "preset member skipped (arm it to include "
                                "this member)")},
         ("refusal", "skipped-unarmed")),
        ("battery", {"arm_id": "m", "action": "a", "status": "skipped",
                     "reason": ("battery: LAB_TARGET_HOST is unset; "
                                "target-facing member skipped (set it to the "
                                "operator-armed target host)")},
         ("refusal", "skipped-no-target")),
        ("battery", {"arm_id": "m", "action": "a", "status": "skipped",
                     "reason": "battery: arm is not installed"},
         ("setup-failure", "not-installed")),
        ("battery", {"arm_id": "m", "action": "a", "status": "skipped",
                     "reason": "battery: something else"},
         ("parse-failure", "unknown-skip-reason")),
        ("battery", {"arm_id": "m", "action": "a", "status": "failed",
                     "reason": "battery: member args left an unresolved {target}"},
         ("crash", "invoke-failed")),
        ("battery", {"arm_id": "m", "action": "a", "status": "complete"},
         ("completion", "complete")),
        # head lane: readiness mode
        ("head", {"head": "claude-code", "mode": "readiness", "status": "available"},
         ("completion", "ready")),
        ("head", {"head": "codex-cli", "mode": "readiness", "ready": False,
                  "status": "skipped"},
         ("setup-failure", "launcher-missing")),
        # head lane: executed, passing
        ("head", {"head": "fake", "mode": "executed", "status": "passed"},
         ("completion", "attempt-passed")),
        # head lane: executed, failed — every reason string the runners emit
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "fake-head driver exceeded 300s"},
         ("timeout", "head-timeout")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "head exceeded 900s timeout and was killed"},
         ("timeout", "head-timeout")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "head spawn failed: [WinError 2] the system cannot find"},
         ("setup-failure", "spawn-failed")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "fake-head driver exited 1: boom"},
         ("crash", "driver-crashed")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "driver was interrupted"},
         ("interruption", "interrupted")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "attempt stopped halfway"},
         ("interruption", "interrupted")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "process was killed"},
         ("crash", "killed")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "no tool calls were recorded; nothing is gradable"},
         ("abstention", "no-tool-calls")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "trace failed verification; the attempt is not gradable"},
         ("parse-failure", "trace-unverified")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "attempt documents unusable: bad schema"},
         ("parse-failure", "documents-unusable")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": ("live-service contract: the attempt lane "
                             "cannot grade it — its coverage doctrine "
                             "verifies run_range fixture touches")},
         ("refusal", "refused")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "attempt directory does not exist: x"},
         ("setup-failure", "missing-attempt-layout")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "attempt has no trace.ndjson: x"},
         ("setup-failure", "missing-attempt-layout")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "attempt has no found.json: x"},
         ("setup-failure", "missing-attempt-layout")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": ("verifying an attempt requires the trace key "
                             "in SPECAUDIT_CTF_MCP_TRACE_KEY (it is never "
                             "stored beside the trace)")},
         ("setup-failure", "missing-trace-key")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "claims lack tool evidence"},
         ("completion", "graded-failed")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "agent claims conflict with or lack verified trace evidence"},
         ("completion", "graded-failed")),
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "found-vs-expected grading failed"},
         ("completion", "graded-failed")),
        # an unrecognized failure with a nonzero recorded exit code
        ("head", {"mode": "executed", "status": "failed",
                  "spawn": {"exit_code": 137}},
         ("crash", "head-exited-nonzero")),
        # an unrecognized failure with no exit evidence: completed attempt
        ("head", {"mode": "executed", "status": "failed",
                  "reason": "something entirely new"},
         ("completion", "attempt-failed")),
        ("head", {"mode": "confused", "status": "failed"},
         ("parse-failure", "unknown-mode")),
        # run row
        ("run", {"status": "complete"}, ("completion", "run-complete")),
        ("run", {"status": "degraded"}, ("completion", "run-degraded")),
        ("run", {"status": "failed", "range": {"status": "failed"}},
         ("completion", "run-failed")),
        ("run", {"status": "failed", "range": {"status": "complete"},
                 "head": {"mode": "executed", "status": "failed",
                          "reason": "fake-head driver exceeded 300s"}},
         ("timeout", "run-failed")),
        ("run", {"status": "failed", "range": {"status": "complete"},
                 "battery": [{"arm_id": "m", "action": "a", "status": "skipped",
                              "reason": "battery: arm is not installed"}]},
         ("setup-failure", "run-failed")),
        ("run", {"status": "confused"}, ("parse-failure", "unknown-status")),
    ],
)
def test_mapping_table(lane: str, section: dict, expected: tuple[str, str]) -> None:
    assert map_outcome(lane, section) == expected
    # Every mapped class stays inside the ledger taxonomy.
    assert map_outcome(lane, section)[0] in ATTEMPT_CLASSES


def test_unknown_lane_is_a_wiring_error() -> None:
    with pytest.raises(ValueError, match="unknown ledger lane"):
        map_outcome("nope", {})


def test_timeout_wins_over_killed_for_the_real_head_reason() -> None:
    attempt_class, outcome = map_outcome(
        "head", {"mode": "executed", "status": "failed",
                 "reason": "head exceeded 900s timeout and was killed"})
    assert (attempt_class, outcome) == ("timeout", "head-timeout")


# --- pure row builder --------------------------------------------------------


def _minimal_document() -> dict:
    from exercise.runner import run_exercise

    return run_exercise()


def test_build_rows_for_minimal_run_is_range_plus_run() -> None:
    document = _minimal_document()
    rows = build_rows(document, assistance="first-pass", recorded_at=AT)
    assert [row["subject"] for row in rows] == ["range", "run"]
    for row in rows:
        assert row["lane"] == "operator-rehearsal"
        assert row["assistance"] == "first-pass"
        assert row["recorded_at"] == AT
        assert _ATTEMPT_ID.fullmatch(row["attempt_id"])
        assert row["attempt_class"] in ATTEMPT_CLASSES
    range_row, run_row = rows
    assert range_row["attempt_class"] == "completion"
    assert range_row["outcome"] == "range-matched"
    assert range_row["detail_digest"] == "sha256:" + hashlib.sha256(
        _canonical(document["range"])).hexdigest()
    assert range_row["attempt_id"] == "range-" + hashlib.sha256(
        _canonical(document["range"])).hexdigest()[:16]
    assert run_row["attempt_class"] == "completion"
    assert run_row["outcome"] == "run-complete"
    assert run_row["detail_digest"] == "sha256:" + hashlib.sha256(
        _canonical(document)).hexdigest()


def test_built_rows_are_valid_ledger_content() -> None:
    document = _minimal_document()
    document = dict(document)
    document["arms"] = [
        {"arm_id": "agent-wiz", "action": "list_tools", "status": "complete",
         "capability_id": "agent-wiz.list_tools", "envelope_status": "complete"},
    ]
    rows = build_rows(document, assistance="assisted", recorded_at=AT)
    subjects = [row["subject"] for row in rows]
    assert subjects == ["range", "arms:agent-wiz:list_tools", "run"]
    assert all(row["assistance"] == "assisted" for row in rows)
    chained: tuple = ()
    for row in rows:
        chained, _ = append_row(chained, row)
    assert verify_ledger(chained).ok


def test_grade_row_subject_prefers_the_challenge_then_track() -> None:
    document = _minimal_document()
    document = dict(document)
    document["challenge"] = "telecom-aws-06-chain-rehearsal"
    document["grading"] = {"schema": "specaudit.ctf.grade.v1", "track": "other",
                           "passed": True}
    rows = build_rows(document, assistance="first-pass", recorded_at=AT)
    assert [row["subject"] for row in rows] == [
        "range", "grade:telecom-aws-06-chain-rehearsal", "run"]
    assert rows[1]["lane"] == "fixture-backed"
    track_only = dict(document, challenge=None)
    rows = build_rows(track_only, assistance="first-pass", recorded_at=AT)
    assert rows[1]["subject"] == "grade:other"
    unbound = dict(document, challenge=None)
    unbound["grading"] = {"schema": "score.failed-to-grade", "passed": False}
    rows = build_rows(unbound, assistance="first-pass", recorded_at=AT)
    assert rows[1]["subject"] == "grade:unbound"


# --- CLI wiring --------------------------------------------------------------


def _rows(ledger: Path) -> list[dict]:
    return [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]


def test_cli_happy_path_appends_range_and_run_rows(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert exercise_main(
        ["--ledger", str(ledger), "--at", AT, "--out", str(tmp_path / "r.json")]
    ) == 0
    rows = _rows(ledger)
    assert [(row["subject"], row["attempt_class"], row["outcome"]) for row in rows] == [
        ("range", "completion", "range-matched"),
        ("run", "completion", "run-complete"),
    ]
    assert verify_ledger(rows).ok
    assert rows[-1]["attempt_class"] == "completion"


def test_no_flag_run_is_byte_identical(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plain_out = tmp_path / "plain.json"
    assert exercise_main(["--out", str(plain_out)]) == 0
    plain = capsys.readouterr().out
    ledger = tmp_path / "ledger.jsonl"
    ledgered_out = tmp_path / "ledgered.json"
    assert exercise_main(
        ["--ledger", str(ledger), "--at", AT, "--out", str(ledgered_out)]
    ) == 0
    ledgered = capsys.readouterr().out
    # The report document is unchanged with or without the flag; only the
    # stderr summary line (host-timestamped by nothing here, but printed
    # twice) may repeat.
    assert ledgered == plain
    assert json.loads(plain_out.read_text(encoding="utf-8")) == json.loads(
        ledgered_out.read_text(encoding="utf-8"))
    assert "ledger_head" not in plain


def test_failed_grade_is_a_completion_row(tmp_path: Path) -> None:
    contract = json.loads(CONTRACT_06.read_text(encoding="utf-8"))
    partial = dict(contract)
    partial["findings"] = contract["findings"][:2]
    partial["total"] = 2
    found = tmp_path / "partial.json"
    found.write_text(json.dumps(partial), encoding="utf-8")
    ledger = tmp_path / "ledger.jsonl"
    report = tmp_path / "report.json"
    assert exercise_main([
        "--challenge", "telecom-aws-06-chain-rehearsal",
        "--found", str(found), "--expected", str(CONTRACT_06),
        "--ledger", str(ledger), "--at", AT, "--out", str(report),
    ]) == 1
    document = json.loads(report.read_text(encoding="utf-8"))
    rows = _rows(ledger)
    grade_row = next(row for row in rows if row["subject"].startswith("grade:"))
    assert grade_row["subject"] == "grade:telecom-aws-06-chain-rehearsal"
    assert grade_row["lane"] == "fixture-backed"
    assert grade_row["attempt_class"] == "completion"
    assert grade_row["outcome"] == "graded-failed"
    # The detail digest covers exactly the grading section it classified.
    assert grade_row["detail_digest"] == "sha256:" + hashlib.sha256(
        _canonical(document["grading"])).hexdigest()
    run_row = rows[-1]
    assert run_row["subject"] == "run"
    assert run_row["attempt_class"] == "completion"
    assert run_row["outcome"] == "run-failed"
    assert run_row["detail_digest"] == "sha256:" + hashlib.sha256(
        _canonical(document)).hexdigest()
    assert verify_ledger(rows).ok


def test_refused_grade_is_a_refusal_row(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{nope", encoding="utf-8")
    ledger = tmp_path / "ledger.jsonl"
    assert exercise_main([
        "--found", str(broken), "--expected", str(CONTRACT_06),
        "--ledger", str(ledger), "--at", AT,
    ]) == 1
    rows = _rows(ledger)
    grade_row = next(row for row in rows if row["subject"].startswith("grade:"))
    assert grade_row["attempt_class"] == "refusal"
    assert grade_row["outcome"] == "refused"
    assert rows[-1]["attempt_class"] == "completion"  # run failed, not refused
    assert rows[-1]["outcome"] == "run-failed"
    assert verify_ledger(rows).ok


def test_arms_rows_record_each_invocation(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    arms = json.dumps([
        {"arm_id": "agent-wiz", "action": "list_tools", "args": {}},
        {"arm_id": "no-such-arm", "action": "scan", "args": {}},
    ])
    assert exercise_main(["--arms", arms, "--ledger", str(ledger), "--at", AT]) == 1
    rows = _rows(ledger)
    assert [(row["subject"], row["attempt_class"], row["outcome"])
            for row in rows] == [
        ("range", "completion", "range-matched"),
        ("arms:agent-wiz:list_tools", "completion", "complete"),
        ("arms:no-such-arm:scan", "crash", "invoke-failed"),
        ("run", "crash", "run-failed"),  # an arm failure crashes the run row
    ]
    assert verify_ledger(rows).ok


def test_fake_head_execution_appends_head_row(tmp_path: Path) -> None:
    """The ledgered head row must mirror the report's head lane exactly.

    The competent persona's outcome is host-dependent (its scripted tool
    work includes arm invokes that need installed binaries), so the
    expectations derive from the produced report; the pinned contract is
    that the head lane is classified honestly and the chain verifies.
    """
    ledger = tmp_path / "ledger.jsonl"
    attempt_dir = tmp_path / "attempt"
    report = tmp_path / "report.json"
    code = exercise_main([
        "--head-execute", "--head", "fake",
        "--attempt-dir", str(attempt_dir), "--expected", str(CONTRACT_02),
        "--ledger", str(ledger), "--at", AT, "--out", str(report),
    ])
    document = json.loads(report.read_text(encoding="utf-8"))
    assert code == (0 if document["ok"] else 1)
    rows = _rows(ledger)
    head_row = next(row for row in rows if row["subject"].startswith("head:"))
    assert head_row["subject"] == "head:fake"
    expected_class, expected_outcome = map_outcome("head", document["head"])
    assert (head_row["attempt_class"], head_row["outcome"]) == (
        expected_class, expected_outcome)
    run_row = rows[-1]
    assert (run_row["attempt_class"], run_row["outcome"]) == map_outcome(
        "run", document)
    assert verify_ledger(rows).ok


def test_keyed_ledger_round_trip(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert exercise_main(
        ["--ledger", str(ledger), "--at", AT, "--ledger-key-hex", KEY_HEX,
         "--assistance", "tuned"]
    ) == 0
    rows = _rows(ledger)
    assert all(row["auth_tag"] for row in rows)
    assert all(row["assistance"] == "tuned" for row in rows)
    assert verify_ledger(rows, hmac_key=bytes.fromhex(KEY_HEX)).ok
    assert not verify_ledger(rows).ok  # keyed rows are refused without the key


def test_second_run_chains_onto_the_first(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert exercise_main(["--ledger", str(ledger), "--at", AT]) == 0
    assert exercise_main(["--ledger", str(ledger), "--at", AT]) == 0
    rows = _rows(ledger)
    assert len(rows) == 4
    assert rows[2]["prev_row_digest"] == rows[1]["row_digest"]
    assert verify_ledger(rows).ok


def test_corrupt_ledger_fails_closed_without_appending(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert exercise_main(["--ledger", str(ledger), "--at", AT]) == 0
    capsys.readouterr()  # drop the first run's report from the buffer
    rows = _rows(ledger)
    rows[0]["subject"] = "tampered"
    ledger.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8")
    tampered = ledger.read_bytes()
    code = exercise_main(["--ledger", str(ledger), "--at", AT])
    assert code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "ok": False,
        "reason": "ledger-error",
        "error": payload["error"],
    }
    assert "fails verification" in payload["error"]
    assert ledger.read_bytes() == tampered, "a corrupt ledger must not be appended"


def test_truncated_ledger_without_retained_head_still_chains(tmp_path: Path) -> None:
    """The documented unkeyed limit: a shortened chain verifies as far as
    it goes, so a truncation without an out-of-band retained head is not
    detected — and the next run's rows still chain cleanly onto the tail."""
    ledger = tmp_path / "ledger.jsonl"
    assert exercise_main(["--ledger", str(ledger), "--at", AT]) == 0
    rows = _rows(ledger)
    ledger.write_text(json.dumps(rows[0], sort_keys=True) + "\n", encoding="utf-8")
    assert exercise_main(["--ledger", str(ledger), "--at", AT]) == 0
    assert verify_ledger(_rows(ledger)).ok


def test_ledger_flag_guards(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        exercise_main(["--ledger-key-hex", KEY_HEX])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        exercise_main(["--assistance", "assisted"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        exercise_main(["--at", AT])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        exercise_main(["--ledger", str(tmp_path / "ledger.jsonl")])
    assert exc.value.code == 2  # --at is required with --ledger
    with pytest.raises(SystemExit) as exc:
        exercise_main([
            "--ledger", str(tmp_path / "ledger.jsonl"), "--at", AT,
            "--ledger-key-hex", "nothex",
        ])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        exercise_main([
            "--ledger", str(tmp_path / "ledger.jsonl"),
            "--at", "2026-10-13T10:00:00+02:00",
        ])
    assert exc.value.code == 2  # naive times only


def test_battery_rows_all_ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Whatever the host's battery reports — skips on an unarmed host,
    a failed member on a broken one — every row must classify inside the
    taxonomy and the whole run must append and verify."""
    for env in ("SEMGREP_SCAN_ROOT", "WAPITI_DISPATCH_SCOPE",
                "NMAP_DISPATCH_SCOPE", "LAB_TARGET_HOST"):
        monkeypatch.delenv(env, raising=False)
    ledger = tmp_path / "ledger.jsonl"
    report = tmp_path / "report.json"
    code = exercise_main(
        ["--battery", "--ledger", str(ledger), "--at", AT, "--out", str(report)])
    document = json.loads(report.read_text(encoding="utf-8"))
    rows = _rows(ledger)
    assert code == (0 if document["ok"] else 1)
    battery_rows = [row for row in rows if row["subject"].startswith("battery:")]
    assert len(battery_rows) == len(document["battery"]) > 0
    for row, section in zip(battery_rows, document["battery"]):
        assert row["subject"] == f"battery:{section['arm_id']}"
        assert (row["attempt_class"], row["outcome"]) == map_outcome(
            "battery", section)
        assert row["attempt_class"] in ATTEMPT_CLASSES
    assert verify_ledger(rows).ok


def test_append_document_rows_requires_recorded_at(tmp_path: Path) -> None:
    with pytest.raises(LedgerWiringError, match="recording time"):
        append_document_rows(tmp_path / "ledger.jsonl", _minimal_document())


def test_missing_attempt_ledger_package_fails_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import builtins

    real_import = builtins.__import__

    def blocked(name: str, *args: object, **kwargs: object) -> object:
        if name == "attempt_ledger" or name.startswith("attempt_ledger."):
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", blocked)
    with pytest.raises(LedgerWiringError, match="attempt_ledger package unavailable"):
        append_document_rows(
            tmp_path / "ledger.jsonl", _minimal_document(), recorded_at=AT)
    assert not (tmp_path / "ledger.jsonl").exists()
