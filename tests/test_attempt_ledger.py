"""Chain integrity, taxonomy, identity, keyed auth and CLI for the attempt ledger."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from attempt_ledger import (
    LedgerError, VerificationResult, append_row, row_digest, summarize,
    verify_ledger,
)
from attempt_ledger.__main__ import main as ledger_main

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
DIGEST = "sha256:" + "0" * 64


def _content(**overrides) -> dict:
    row = {
        "attempt_id": "attempt-" + "a" * 8, "lane": "fixture-backed",
        "subject": "telecom-aws-01-reachability", "attempt_class": "completion",
        "outcome": "passed", "assistance": "first-pass", "detail_digest": DIGEST,
        "recorded_at": "2026-10-13T10:00:00",
    }
    row.update(overrides)
    return row


def _chain(*contents: dict, hmac_key: bytes | None = None):
    rows = ()
    heads = []
    for content in contents:
        rows, head = append_row(rows, content, hmac_key=hmac_key)
        heads.append(head)
    return rows, heads


def test_chain_integrity_and_in_place_tamper_detection() -> None:
    rows, heads = _chain(_content(), _content(attempt_id="attempt-bbbbbbbb", outcome="failed"),
                         _content(attempt_id="attempt-cccccccc", attempt_class="refusal",
                                  outcome=None))
    assert heads[-1] == rows[-1]["row_digest"]
    assert rows[1]["ledger_seq"] == 2
    assert rows[1]["prev_row_digest"] == rows[0]["row_digest"]
    assert rows[0]["prev_row_digest"] is None
    assert verify_ledger(rows) == VerificationResult(True, ())
    tampered = [dict(row) for row in rows]
    tampered[1]["subject"] = "rewritten-subject"
    result = verify_ledger(tampered)
    assert not result.ok and "row-digest-mismatch" in result.reasons
    resynched = [dict(row) for row in tampered]
    resynched[1]["row_digest"] = row_digest(resynched[1])
    result = verify_ledger(resynched)  # retargeting breaks the chain to row 3
    assert not result.ok and "prev-digest-mismatch" in result.reasons


def test_truncation_detected_only_against_retained_head() -> None:
    rows, heads = _chain(_content(), _content(attempt_id="attempt-bbbbbbbb", outcome="failed"))
    # Honest limit: without a retained head, a shortened chain verifies as far
    # as it goes -- truncation is invisible.
    assert verify_ledger(rows[:1]) == VerificationResult(True, ())
    # With the out-of-band head, the dropped tail is refused.
    result = verify_ledger(rows[:1], retained_head=heads[-1])
    assert not result.ok and result.reasons == ("head-mismatch",)
    assert verify_ledger(rows, retained_head=heads[-1]) == VerificationResult(True, ())
    empty: tuple = ()
    result = verify_ledger(empty, retained_head=heads[-1])
    assert not result.ok and "head-mismatch" in result.reasons


def test_append_refuses_stale_expected_head() -> None:
    rows, heads = _chain(_content(), _content(attempt_id="attempt-bbbbbbbb", outcome="failed"))
    with pytest.raises(LedgerError) as exc:
        append_row(rows, _content(attempt_id="attempt-cccccccc", attempt_class="refusal",
                                  outcome=None),
                   expected_head=heads[0])
    assert exc.value.reason == "head-mismatch"
    rows, head = append_row(rows, _content(attempt_id="attempt-cccccccc",
                                           attempt_class="refusal", outcome=None),
                            expected_head=heads[1])
    assert head == rows[-1]["row_digest"]


@pytest.mark.parametrize("override", [
    {"lane": "target-production"},
    {"attempt_class": "accepted"},
    {"assistance": "cheated"},
    {"detail_digest": "md5:0"},
    {"recorded_at": "2026-10-13T10:00:00+02:00"},
    {"recorded_at": "not-a-time"},
])
def test_taxonomy_and_field_refusals(override: dict) -> None:
    with pytest.raises(LedgerError) as exc:
        append_row((), _content(**override))
    assert exc.value.reason == "malformed"
    with pytest.raises(LedgerError):
        append_row((), _content(attempt_class="completion", outcome=None))
    with pytest.raises(LedgerError):
        append_row((), _content(schema="specaudit.ctf.attempt-ledger.v1"))
    with pytest.raises(LedgerError):
        append_row((), _content(row_digest=DIGEST))


def test_identity_reuse_conflict_vs_legitimate_retry() -> None:
    rows, _ = _chain(_content())
    # Same (attempt_class, assistance, lane): a retry is allowed.
    rows, _ = append_row(rows, _content(outcome="failed", detail_digest="sha256:" + "1" * 64))
    assert rows[1]["attempt_id"] == rows[0]["attempt_id"]
    # Same id with a different triple is refused.
    for override in ({"lane": "self-study"}, {"attempt_class": "refusal", "outcome": None},
                     {"assistance": "assisted"}):
        with pytest.raises(LedgerError) as exc:
            append_row(rows, _content(**override))
        assert exc.value.reason == "attempt-identity-conflict"


def test_keyed_auth_tags() -> None:
    rows, _ = _chain(_content(), _content(attempt_id="attempt-bbbbbbbb", outcome="failed"),
                     hmac_key=KEY)
    assert all("auth_tag" in row for row in rows)
    assert verify_ledger(rows, hmac_key=KEY) == VerificationResult(True, ())
    wrong = verify_ledger(rows, hmac_key=OTHER_KEY)
    assert not wrong.ok and "auth-tag-mismatch" in wrong.reasons
    unkeyed = verify_ledger(rows)
    assert not unkeyed.ok and "auth-tag-present-without-key" in unkeyed.reasons
    # A retagged row must break under the true key even with a rebuilt digest.
    retagged = [dict(row) for row in rows]
    retagged[0]["subject"] = "forged"
    retagged[0]["row_digest"] = row_digest(retagged[0])
    result = verify_ledger(retagged, hmac_key=KEY)
    assert not result.ok and "auth-tag-mismatch" in result.reasons
    missing = [dict(row) for row in rows]
    del missing[0]["auth_tag"]
    result = verify_ledger(missing, hmac_key=KEY)
    assert not result.ok and "auth-tag-missing" in result.reasons


def test_summarize_denominator_keeps_every_row() -> None:
    rows, _ = _chain(
        _content(),
        _content(attempt_id="attempt-bbbbbbbb", outcome="failed"),
        _content(attempt_id="attempt-cccccccc", attempt_class="refusal", outcome=None,
                 lane="self-study", assistance="none"),
        _content(attempt_id="attempt-dddddddd", attempt_class="timeout", outcome=None,
                 lane="self-study", assistance="none"),
        _content(attempt_id="attempt-eeeeeeee", attempt_class="abstention", outcome=None,
                 lane="live-service", assistance="held-out"),
    )
    summary = summarize(rows)
    assert summary["total"] == 5
    # Denominator is every row: failures, refusals, timeouts and abstentions
    # are retained, and lanes are counted separately, never merged.
    assert summary["by_class"] == {
        "abstention": 1, "completion": 2, "refusal": 1, "timeout": 1}
    assert summary["by_lane"] == {"fixture-backed": 2, "live-service": 1, "self-study": 2}
    assert summary["by_assistance"] == {"first-pass": 2, "held-out": 1, "none": 2}
    assert summary["numerators"]["completions"] == 2
    assert summary["numerators"]["completions_by_lane"] == {"fixture-backed": 2}
    assert summary["numerators"]["completions_by_assistance"] == {"first-pass": 2}


def test_summarize_refuses_invalid_rows() -> None:
    rows, _ = _chain(_content())
    broken = [dict(rows[0])]
    broken[0]["lane"] = "unheard-lane"
    with pytest.raises(LedgerError):
        summarize(broken)


def _record_args(ledger: Path, **overrides) -> list[str]:
    args = [
        "record", "--ledger", str(ledger), "--attempt-id", "attempt-" + "a" * 8,
        "--lane", "fixture-backed", "--subject", "telecom-aws-01-reachability",
        "--class", "completion", "--outcome", "passed", "--assistance", "first-pass",
        "--detail-digest", DIGEST, "--at", "2026-10-13T10:00:00",
    ]
    for flag, value in overrides.items():
        args.extend([flag, value])
    return args


def test_cli_record_verify_summarize_happy_path(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert ledger_main(_record_args(ledger, **{"--key-hex": KEY.hex()})) == 0
    assert ledger_main(_record_args(
        ledger, **{"--attempt-id": "attempt-" + "b" * 8, "--outcome": "failed",
                   "--key-hex": KEY.hex(), "--at": "2026-10-13T11:00:00"})) == 0
    assert ledger_main(["verify", "--ledger", str(ledger), "--key-hex", KEY.hex()]) == 0
    assert ledger_main(["verify", "--ledger", str(ledger)]) == 1  # keyed rows need the key
    capsys.readouterr()  # drain the record/verify outputs before the parsed one
    assert ledger_main(["summarize", "--ledger", str(ledger)]) == 0
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [row["ledger_seq"] for row in rows] == [1, 2]
    assert rows[1]["prev_row_digest"] == rows[0]["row_digest"]
    assert all("auth_tag" in row for row in rows)
    summary = json.loads(capsys.readouterr().out)
    assert summary["total"] == 2 and summary["numerators"]["completions"] == 2
    assert summary["by_class"] == {"completion": 2}
    head = rows[-1]["row_digest"]
    assert ledger_main(["verify", "--ledger", str(ledger), "--key-hex", KEY.hex(),
                        "--retained-head", head]) == 0
    assert ledger_main(["verify", "--ledger", str(ledger), "--key-hex", KEY.hex(),
                        "--retained-head", "sha256:" + "9" * 64]) == 1


def test_cli_record_fails_closed_on_corrupt_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert ledger_main(_record_args(ledger)) == 0
    original = ledger.read_bytes()
    lines = original.decode().splitlines()
    row = json.loads(lines[0])
    row["subject"] = "tampered"
    lines[0] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    ledger.write_text("\n".join(lines) + "\n")
    tampered = ledger.read_bytes()
    assert ledger_main(_record_args(
        ledger, **{"--attempt-id": "attempt-" + "b" * 8,
                   "--at": "2026-10-13T11:00:00"})) == 1
    assert ledger.read_bytes() == tampered  # no append after failed verification
    assert ledger_main(["verify", "--ledger", str(ledger)]) == 1
    truncated = original.decode().splitlines()[0]
    ledger.write_text(truncated)  # partial trailing line
    assert ledger_main(_record_args(
        ledger, **{"--attempt-id": "attempt-" + "b" * 8,
                   "--at": "2026-10-13T11:00:00"})) == 1
    assert ledger.read_text() == truncated


def test_cli_verify_detects_dropped_tail_only_with_retained_head(
        tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert ledger_main(_record_args(ledger)) == 0
    assert ledger_main(_record_args(
        ledger, **{"--attempt-id": "attempt-" + "b" * 8, "--outcome": "failed",
                   "--at": "2026-10-13T11:00:00"})) == 0
    head = json.loads(ledger.read_text().splitlines()[-1])["row_digest"]
    lines = ledger.read_text().splitlines()
    ledger.write_text(lines[0] + "\n")
    assert ledger_main(["verify", "--ledger", str(ledger)]) == 0
    capsys.readouterr()  # drain the unanchored verify output
    assert ledger_main(["verify", "--ledger", str(ledger),
                        "--retained-head", head]) == 1
    assert "head-mismatch" in json.loads(capsys.readouterr().out)["reasons"]


def test_detail_digest_binds_external_document() -> None:
    body = json.dumps({"grade": {"misses": []}}, sort_keys=True,
                      separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    rows, _ = _chain(_content(detail_digest=digest))
    assert rows[0]["detail_digest"] == digest
    assert verify_ledger(rows).ok
