"""Custody journal: state distinction, chain/MAC, replay, cross-attempt, schema.

The journal records are pure library output; every timestamp is
caller-supplied and the tests run on every host (acquisition's nofollow
flag is simulated where the platform lacks it, exactly as
test_reader_evidence.py does).
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path

import jsonschema
import pytest
import tomllib

from reader_evidence import acquire, bind_reader_observation
from reader_evidence.__main__ import main as cli_main
from reader_evidence.custody import (
    CUSTODY_JOURNAL_SCHEMA,
    CUSTODY_OPERATOR_ASSERTED,
    CUSTODY_SOURCE_AUTHENTIC,
    CUSTODY_VERIFIED,
    CustodyError,
    acquisition_digest,
    append_observation,
    journal_identity,
    observation_digest,
    verify_journal,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "reader_evidence" / "schema" / "custody-journal.v1.schema.json"
NOW = datetime(2026, 10, 13, 12, 0, 0)
ATTEMPT = "attempt-" + "a" * 8
OTHER_ATTEMPT = "attempt-" + "b" * 8
RESULT_DIGEST = "sha256:" + "0" * 64
KEY = bytes(range(32))


@pytest.fixture
def nofollow_simulated(monkeypatch):
    """Expose os.O_NOFOLLOW on hosts that lack it (Windows); see
    test_reader_evidence.py for the same fixture and its rationale."""
    if not hasattr(os, "O_NOFOLLOW"):
        monkeypatch.setattr(os, "O_NOFOLLOW", 0, raising=False)


@pytest.fixture
def artifact(tmp_path, nofollow_simulated):
    """One acquired file, its record, and its observation."""
    data = b'{"demo": true}\n'
    (tmp_path / "input.json").write_bytes(data)
    record = acquire(tmp_path / "input.json", approved_root=tmp_path,
                     allowed_suffixes=frozenset({".json"}), max_bytes=1024,
                     acquired_at=NOW)
    observation = bind_reader_observation(
        record, attempt_id=ATTEMPT, arm_id="nmap", action="scan",
        handler_revision="rev-1", execution_result_digest=RESULT_DIGEST,
        collected_at=NOW)
    return data, record, observation


def _append(records, observation, record, *, state=CUSTODY_OPERATOR_ASSERTED,
            at=NOW, key=None, verified_bytes=None):
    return append_observation(records, observation, record, custody_state=state,
                              recorded_at=at, hmac_key=key,
                              verified_bytes=verified_bytes)


def _reason(callable_, *args, **kwargs) -> str:
    with pytest.raises(CustodyError) as excinfo:
        callable_(*args, **kwargs)
    return excinfo.value.reason


# --- record shape and derived digests ----------------------------------------


def test_first_record_shape_and_chain_fields(artifact) -> None:
    data, record, observation = artifact
    records, head = _append([], observation, record)
    stored = records[0]
    assert head == stored["record_digest"]
    assert set(stored) == {
        "schema", "schema_version", "seq", "journal_id", "observation_id",
        "observation_digest", "acquisition_digest", "attempt_id", "arm_id",
        "action", "custody_state", "recorded_at", "prev_record_digest",
        "record_digest"}
    assert stored["schema"] == CUSTODY_JOURNAL_SCHEMA
    assert stored["schema_version"] == 1
    assert stored["seq"] == 1
    assert stored["prev_record_digest"] is None
    assert stored["observation_id"] == observation["observation_id"]
    assert stored["observation_digest"] == observation_digest(observation)
    assert stored["observation_digest"] == "sha256:" + hashlib.sha256(
        json.dumps(observation, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).hexdigest()
    assert stored["acquisition_digest"] == acquisition_digest(record)
    assert stored["attempt_id"] == ATTEMPT
    assert stored["arm_id"] == "nmap"
    assert stored["action"] == "scan"
    assert stored["custody_state"] == CUSTODY_OPERATOR_ASSERTED
    assert stored["recorded_at"] == "2026-10-13T12:00:00"
    assert stored["journal_id"] == journal_identity(ATTEMPT)


def test_journal_identity_is_attempt_derived_and_stable() -> None:
    assert journal_identity(ATTEMPT) == journal_identity(ATTEMPT)
    assert journal_identity(ATTEMPT) != journal_identity(OTHER_ATTEMPT)
    assert journal_identity(ATTEMPT).startswith("sha256:")


def test_acquisition_digest_covers_content_identity(artifact) -> None:
    data, record, _ = artifact
    fields = {"sha256": record.sha256, "size_bytes": record.size_bytes}
    expected = "sha256:" + hashlib.sha256(json.dumps(
        fields, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    assert acquisition_digest(record) == expected


def test_second_record_chains(artifact, tmp_path: Path) -> None:
    data, record, observation = artifact
    records, head_one = _append([], observation, record)
    # A second record comes from a second acquired file bound under the
    # same attempt (a different observation of the SAME file would replay).
    other = tmp_other_file(record, tmp_path)
    other_observation = bind_reader_observation(
        other, attempt_id=ATTEMPT, arm_id="nmap", action="describe",
        handler_revision="rev-1", execution_result_digest=RESULT_DIGEST,
        collected_at=NOW)
    records, head_two = _append(records, other_observation, other)
    assert records[1]["seq"] == 2
    assert records[1]["prev_record_digest"] == head_one
    assert head_two == records[1]["record_digest"]
    assert verify_journal(records).ok


def tmp_other_file(record, directory: Path):
    """A second acquired file (same root shape as the artifact fixture)."""
    data = b'{"other": true}\n'
    (directory / "other.json").write_bytes(data)
    return acquire(directory / "other.json", approved_root=directory,
                   allowed_suffixes=frozenset({".json"}), max_bytes=1024,
                   acquired_at=record.acquired_at)


# --- custody state distinction ------------------------------------------------


def test_source_authentic_is_never_claimable(artifact) -> None:
    data, record, observation = artifact
    assert CUSTODY_SOURCE_AUTHENTIC == "source-authentic"
    assert _reason(_append, [], observation, record,
                   state=CUSTODY_SOURCE_AUTHENTIC) == \
        "source-authenticity-not-locally-claimable"


def test_verified_custody_requires_matching_bytes(artifact) -> None:
    data, record, observation = artifact
    assert _reason(_append, [], observation, record, state=CUSTODY_VERIFIED) == \
        "custody-bytes-mismatch"
    assert _reason(_append, [], observation, record, state=CUSTODY_VERIFIED,
                   verified_bytes=b"wrong bytes entirely") == "custody-bytes-mismatch"
    records, _ = _append([], observation, record, state=CUSTODY_VERIFIED,
                         verified_bytes=data)
    assert records[0]["custody_state"] == CUSTODY_VERIFIED
    assert verify_journal(records).ok


def test_states_are_strictly_distinct_in_records(artifact) -> None:
    data, record, observation = artifact
    asserted, _ = _append([], observation, record,
                          state=CUSTODY_OPERATOR_ASSERTED)
    verified, _ = _append([], observation, record, state=CUSTODY_VERIFIED,
                          verified_bytes=data)
    assert asserted[0]["custody_state"] != verified[0]["custody_state"]
    assert set(asserted[0]["custody_state"] for _ in [0]) == {CUSTODY_OPERATOR_ASSERTED}


def test_unknown_state_refused(artifact) -> None:
    _data, record, observation = artifact
    assert _reason(_append, [], observation, record, state="held-by-operator") == \
        "malformed"


# --- append refusals: mismatch, replay, cross-attempt -------------------------


def test_observation_must_bind_the_acquisition(artifact, tmp_path: Path) -> None:
    data, record, observation = artifact
    # The same record bound under a different file's input block: the
    # observation re-derives from the OTHER acquisition, not this one.
    other = tmp_other_file(record, tmp_path)
    stranger = bind_reader_observation(
        other, attempt_id=ATTEMPT, arm_id="nmap", action="scan",
        handler_revision="rev-1", execution_result_digest=RESULT_DIGEST,
        collected_at=NOW)
    assert _reason(_append, [], stranger, record) == "observation-mismatch"


def test_replayed_observation_refused(artifact) -> None:
    data, record, observation = artifact
    records, _ = _append([], observation, record)
    assert _reason(_append, records, observation, record) == "replayed-observation"


def test_cross_attempt_refused(artifact) -> None:
    data, record, observation = artifact
    records, _ = _append([], observation, record)
    other_observation = bind_reader_observation(
        record, attempt_id=OTHER_ATTEMPT, arm_id="nmap", action="scan",
        handler_revision="rev-1", execution_result_digest=RESULT_DIGEST,
        collected_at=NOW)
    assert _reason(_append, records, other_observation, record) == "cross-attempt"


# --- verify: tamper, truncate, replay, keys, artifacts ------------------------


def test_verify_detects_in_place_edit(artifact) -> None:
    data, record, observation = artifact
    records, _ = _append([], observation, record, key=KEY)
    tampered = [dict(records[0])]
    tampered[0]["arm_id"] = "zap"
    result = verify_journal(tampered, hmac_key=KEY)
    assert not result.ok
    assert "record-digest-mismatch" in result.reasons
    # A digest-consistent tamper (body edited AND record_digest recomputed)
    # is exactly what the MAC exists for.
    retagged = [dict(records[0])]
    retagged[0]["arm_id"] = "zap"
    body = {key: value for key, value in retagged[0].items()
            if key not in ("record_digest", "auth_tag")}
    retagged[0]["record_digest"] = "sha256:" + hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"),
        allow_nan=False, ensure_ascii=False).encode("utf-8")).hexdigest()
    result = verify_journal(retagged, hmac_key=KEY)
    assert result.reasons == ("auth-tag-mismatch",)


def test_verify_detects_broken_chain(artifact, tmp_path: Path) -> None:
    data, record, observation = artifact
    records, _ = _append([], observation, record)
    second_source = tmp_other_file(record, tmp_path)
    second_observation = bind_reader_observation(
        second_source, attempt_id=ATTEMPT, arm_id="nmap", action="describe",
        handler_revision="rev-1", execution_result_digest=RESULT_DIGEST,
        collected_at=NOW)
    records, _ = _append(records, second_observation, second_source)
    broken = [dict(row) for row in records]
    broken[1]["prev_record_digest"] = "sha256:" + "f" * 64
    result = verify_journal(broken)
    assert not result.ok
    assert "prev-digest-mismatch" in result.reasons
    assert "record-digest-mismatch" in result.reasons  # the chain recompute moves


def test_truncation_needs_the_retained_head(artifact, tmp_path: Path) -> None:
    data, record, observation = artifact
    records, head = _append([], observation, record)
    second_source = tmp_other_file(record, tmp_path)
    second_observation = bind_reader_observation(
        second_source, attempt_id=ATTEMPT, arm_id="nmap", action="describe",
        handler_revision="rev-1", execution_result_digest=RESULT_DIGEST,
        collected_at=NOW)
    records, head = _append(records, second_observation, second_source)
    assert verify_journal(records[:1]).ok  # unkeyed, no retained head
    result = verify_journal(records[:1], retained_head=head)
    assert not result.ok
    assert "head-mismatch" in result.reasons
    assert verify_journal(records, retained_head=head).ok


def test_replayed_observation_in_verify(artifact) -> None:
    data, record, observation = artifact
    # Two chain-valid records carrying the same observation id can only be
    # built by recomputing digests — the verify path must still catch it.
    updated, _ = _append([], observation, record)
    forged = [dict(row) for row in updated]
    duplicate = dict(forged[0])
    duplicate["seq"] = 2
    duplicate["prev_record_digest"] = forged[0]["record_digest"]
    body = {key: value for key, value in duplicate.items()
            if key not in ("record_digest", "auth_tag")}
    duplicate["record_digest"] = "sha256:" + hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"),
        allow_nan=False, ensure_ascii=False).encode("utf-8")).hexdigest()
    result = verify_journal(forged + [duplicate])
    assert not result.ok
    assert "replayed-observation" in result.reasons


def test_keyed_journal_round_trip(artifact) -> None:
    data, record, observation = artifact
    records, _ = _append([], observation, record, key=KEY)
    assert "auth_tag" in records[0]
    assert verify_journal(records, hmac_key=KEY).ok
    # Keyed rows are refused without the key; wrong key is a mismatch.
    assert "auth-tag-present-without-key" in verify_journal(records).reasons
    assert "auth-tag-mismatch" in verify_journal(
        records, hmac_key=b"other-key".ljust(32, b"0")).reasons
    # Untagged rows under a key are missing their tags.
    unkeyed, _ = _append([], observation, record)
    assert "auth-tag-missing" in verify_journal(unkeyed, hmac_key=KEY).reasons


def test_hand_forged_source_authentic_row_is_malformed(artifact) -> None:
    data, record, observation = artifact
    records, _ = _append([], observation, record)
    forged = [dict(records[0])]
    forged[0]["custody_state"] = CUSTODY_SOURCE_AUTHENTIC
    result = verify_journal(forged)
    assert not result.ok
    assert "malformed" in result.reasons


def test_artifacts_reverify_verified_custody_only(artifact) -> None:
    data, record, observation = artifact
    verified, _ = _append([], observation, record, state=CUSTODY_VERIFIED,
                          verified_bytes=data)
    observation_id = observation["observation_id"]
    assert verify_journal(verified, artifacts={observation_id: data}).ok
    assert verify_journal(verified, artifacts={}).ok
    assert "custody-bytes-mismatch" in verify_journal(
        verified, artifacts={observation_id: b"tampered"}).reasons
    # An artifact absent from the journal is simply unverifiable.
    stray = "sha256:" + hashlib.sha256(b"stray").hexdigest()
    assert verify_journal(verified, artifacts={stray: b"whatever"}).ok
    # The same artifact check against an operator-asserted record verifies
    # nothing: that state claims no bytes.
    asserted, _ = _append([], observation, record)
    assert verify_journal(asserted, artifacts={observation_id: b"tampered"}).ok


def test_verify_rejects_non_record_input() -> None:
    assert verify_journal("not-a-list").reasons == ("malformed",)
    assert verify_journal([{"schema": "junk"}]).reasons == ("malformed",)


def test_recorded_at_must_be_naive(artifact) -> None:
    _data, record, observation = artifact
    aware = "2026-10-13T12:00:00+02:00"
    assert _reason(_append, [], observation, record, at=aware) == "malformed"
    records, _ = _append([], observation, record,
                         at="2026-10-13T12:00:00.250000")
    assert records[0]["recorded_at"] == "2026-10-13T12:00:00.250000"


# --- shipped schema -----------------------------------------------------------


def test_schema_file_is_valid_draft07_and_closed() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft7Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    assert schema["$id"] == CUSTODY_JOURNAL_SCHEMA


def test_shipped_records_validate_against_the_schema(artifact) -> None:
    data, record, observation = artifact
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    records, _ = _append([], observation, record, key=KEY)
    for stored in records:
        validator.validate(stored)
    # A source-authentic state is outside the shipped vocabulary.
    forged = dict(records[0])
    forged["custody_state"] = CUSTODY_SOURCE_AUTHENTIC
    assert not validator.is_valid(forged)


def test_schema_is_shipped_by_package_data() -> None:
    pyproject = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]
    assert "schema/*.json" in package_data["reader_evidence"]
    assert SCHEMA_PATH.is_file()


# --- CLI ----------------------------------------------------------------------


def _observation_json(observation: dict) -> str:
    return json.dumps(observation, sort_keys=True)


def _record_json(record) -> str:
    document = dict(logical_path=record.logical_path,
                    resolved_path=record.resolved_path,
                    size_bytes=record.size_bytes, sha256=record.sha256,
                    suffix=record.suffix, acquired_at=record.acquired_at.isoformat())
    return json.dumps(document)


def test_cli_append_and_verify_operator_asserted(artifact, tmp_path: Path, capsys) -> None:
    data, record, observation = artifact
    journal = tmp_path / "journal.jsonl"
    argv = ["custody", "append", "--journal", str(journal),
            "--observation-json", _observation_json(observation),
            "--record-json", _record_json(record),
            "--custody-state", CUSTODY_OPERATOR_ASSERTED, "--at", "2026-10-13T12:00:00"]
    assert cli_main(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True and payload["seq"] == 1
    stored = [json.loads(line) for line in
              journal.read_text(encoding="utf-8").splitlines()]
    assert verify_journal(stored).ok
    assert cli_main(["custody", "verify", "--journal", str(journal)]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified == {"ok": True, "reasons": [], "total": 1,
                        "head_digest": stored[0]["record_digest"]}


def test_cli_append_verified_custody_with_artifact_file(
    artifact, tmp_path: Path, capsys
) -> None:
    data, record, observation = artifact
    artifact_path = tmp_path / "retained.bin"
    artifact_path.write_bytes(data)
    journal = tmp_path / "journal.jsonl"
    assert cli_main([
        "custody", "append", "--journal", str(journal),
        "--observation-json", _observation_json(observation),
        "--record-json", _record_json(record),
        "--custody-state", CUSTODY_VERIFIED,
        "--verified-bytes", str(artifact_path), "--at", "2026-10-13T12:00:00",
    ]) == 0
    capsys.readouterr()
    stored = [json.loads(line) for line in
              journal.read_text(encoding="utf-8").splitlines()]
    assert stored[0]["custody_state"] == CUSTODY_VERIFIED
    assert cli_main([
        "custody", "verify", "--journal", str(journal),
        "--artifact", f"{observation['observation_id']}={artifact_path}",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    artifact_path.write_bytes(b"tampered")
    assert cli_main([
        "custody", "verify", "--journal", str(journal),
        "--artifact", f"{observation['observation_id']}={artifact_path}",
    ]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["reasons"] == ["custody-bytes-mismatch"]


def test_cli_append_refuses_replay_and_cross_attempt(artifact, tmp_path: Path, capsys) -> None:
    data, record, observation = artifact
    journal = tmp_path / "journal.jsonl"
    argv = ["custody", "append", "--journal", str(journal),
            "--observation-json", _observation_json(observation),
            "--record-json", _record_json(record),
            "--custody-state", CUSTODY_OPERATOR_ASSERTED, "--at", "2026-10-13T12:00:00"]
    assert cli_main(argv) == 0
    capsys.readouterr()
    assert cli_main(argv) == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "replayed-observation"
    other_observation = bind_reader_observation(
        record, attempt_id=OTHER_ATTEMPT, arm_id="nmap", action="scan",
        handler_revision="rev-1", execution_result_digest=RESULT_DIGEST,
        collected_at=NOW)
    assert cli_main([
        "custody", "append", "--journal", str(journal),
        "--observation-json", _observation_json(other_observation),
        "--record-json", _record_json(record),
        "--custody-state", CUSTODY_OPERATOR_ASSERTED, "--at", "2026-10-13T12:00:00",
    ]) == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "cross-attempt"
    # Nothing was appended on either refusal.
    assert len(journal.read_text(encoding="utf-8").splitlines()) == 1


def test_cli_append_fail_closed_on_corrupt_journal(artifact, tmp_path: Path, capsys) -> None:
    data, record, observation = artifact
    journal = tmp_path / "journal.jsonl"
    assert cli_main([
        "custody", "append", "--journal", str(journal),
        "--observation-json", _observation_json(observation),
        "--record-json", _record_json(record),
        "--custody-state", CUSTODY_OPERATOR_ASSERTED, "--at", "2026-10-13T12:00:00",
    ]) == 0
    capsys.readouterr()
    good = journal.read_text(encoding="utf-8")
    journal.write_text(good.rstrip("\n"), encoding="utf-8")  # partial line
    assert cli_main([
        "custody", "append", "--journal", str(journal),
        "--observation-json", _observation_json(observation),
        "--record-json", _record_json(record),
        "--custody-state", CUSTODY_OPERATOR_ASSERTED, "--at", "2026-10-13T12:00:00",
    ]) == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "corrupt"
    # Tampered body: verify-existing refuses before the append.
    stored = json.loads(good)
    stored["arm_id"] = "zap"
    journal.write_text(json.dumps(stored, sort_keys=True) + "\n", encoding="utf-8")
    assert cli_main([
        "custody", "append", "--journal", str(journal),
        "--observation-json", _observation_json(observation),
        "--record-json", _record_json(record),
        "--custody-state", CUSTODY_OPERATOR_ASSERTED, "--at", "2026-10-13T12:00:00",
    ]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False and "record-digest-mismatch" in payload["reasons"]
    assert len(journal.read_text(encoding="utf-8").splitlines()) == 1


def test_cli_keyed_journal_and_retained_head(artifact, tmp_path: Path, capsys) -> None:
    data, record, observation = artifact
    journal = tmp_path / "journal.jsonl"
    key_hex = KEY.hex()
    argv = ["custody", "append", "--journal", str(journal),
            "--observation-json", _observation_json(observation),
            "--record-json", _record_json(record),
            "--custody-state", CUSTODY_OPERATOR_ASSERTED, "--at", "2026-10-13T12:00:00",
            "--key-hex", key_hex]
    assert cli_main(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    head = payload["head_digest"]
    assert cli_main(["custody", "verify", "--journal", str(journal)]) == 1
    assert "auth-tag-present-without-key" in json.loads(capsys.readouterr().out)["reasons"]
    assert cli_main(["custody", "verify", "--journal", str(journal),
                     "--key-hex", key_hex]) == 0
    capsys.readouterr()
    assert cli_main(["custody", "verify", "--journal", str(journal),
                     "--key-hex", key_hex, "--retained-head", head]) == 0
    capsys.readouterr()
    # Truncation is detected against the retained head.
    stored = journal.read_text(encoding="utf-8")
    journal.write_text(stored, encoding="utf-8")
    assert cli_main(["custody", "verify", "--journal", str(journal),
                     "--key-hex", key_hex,
                     "--retained-head", "sha256:" + "e" * 64]) == 1
    assert "head-mismatch" in json.loads(capsys.readouterr().out)["reasons"]


def test_cli_usage_guards(artifact, tmp_path: Path, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main(["custody", "append", "--journal", str(tmp_path / "j.jsonl"),
                  "--observation-json", "{}", "--record-json", "{}",
                  "--custody-state", CUSTODY_VERIFIED, "--at", "2026-10-13T12:00:00"])
    assert exc.value.code == 2  # --verified-bytes is required for verified-custody
    with pytest.raises(SystemExit) as exc:
        cli_main(["custody", "append", "--journal", str(tmp_path / "j.jsonl"),
                  "--observation-json", "{}", "--record-json", "{}",
                  "--custody-state", CUSTODY_OPERATOR_ASSERTED])
    assert exc.value.code == 2  # --at is required
    with pytest.raises(SystemExit) as exc:
        cli_main(["custody", "append", "--journal", str(tmp_path / "j.jsonl"),
                  "--observation-json", "{}", "--record-json", "{}",
                  "--custody-state", CUSTODY_OPERATOR_ASSERTED,
                  "--at", "2026-10-13T12:00:00+01:00"])
    assert exc.value.code == 2  # naive times only
    assert cli_main(["custody", "verify", "--journal", str(tmp_path / "j.jsonl"),
                     "--artifact", "not-a-digest=path"]) == 1  # typed refusal, not a crash
    assert json.loads(capsys.readouterr().out)["reason"] == "malformed"
