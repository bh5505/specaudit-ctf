"""Causal tests for the reader_evidence trusted-side acquisition package.

Windows has no ``os.O_NOFOLLOW``, so ``acquire`` is typed-refused there by
design; the read-discipline tests run on every host by simulating the flag as
0 (symlink TOCTOU enforcement itself is covered by the unix-only tests), and
one win32-only test pins the platform refusal.
"""

from __future__ import annotations

import dataclasses
from datetime import date, datetime
import hashlib
import json
import os
from pathlib import Path
import sys

import jsonschema
import pytest

import reader_evidence
from reader_evidence import (
    AcquisitionError,
    AcquisitionRecord,
    DataSliceError,
    DirectoryManifest,
    ObservationError,
    acquire,
    acquire_directory,
    bind_directory_observation,
    bind_reader_observation,
    check_freshness,
    detections_demo_slice,
    require_upstream_admission,
    rule_lookup,
    synthetic_rule_index,
    verify_directory_unchanged,
    verify_reader_observation,
    verify_slice_bytes,
    verify_unchanged,
    vulnify_demo_slice,
)
from reader_evidence.__main__ import main as cli_main

REPO_ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 13, 12, 0, 0)
SUFFIXES = frozenset({".json"})
ATTEMPT = "attempt-" + "a" * 8
RESULT_DIGEST = "sha256:" + "0" * 64

unix_symlink = pytest.mark.skipif(sys.platform == "win32",
                                  reason="symlink creation needs a POSIX host")
real_nofollow = pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"),
                                   reason="needs the real os.O_NOFOLLOW")


@pytest.fixture
def nofollow_simulated(monkeypatch):
    """Expose os.O_NOFOLLOW on hosts that lack it (Windows).

    The flag value 0 keeps every read-discipline behavior (bounded read,
    pre/post fstat identity) exercisable here; genuine nofollow enforcement is
    pinned by the unix-only tests against the real flag, and the win32-only
    test below pins the platform refusal when the flag is absent.
    """
    if not hasattr(os, "O_NOFOLLOW"):
        monkeypatch.setattr(os, "O_NOFOLLOW", 0, raising=False)


@pytest.fixture
def root(tmp_path):
    (tmp_path / "input.json").write_bytes(b'{"demo": true}\n')
    return tmp_path


@pytest.fixture
def record(root, nofollow_simulated):
    return acquire(root / "input.json", approved_root=root, allowed_suffixes=SUFFIXES,
                   max_bytes=1024, acquired_at=NOW)


def _reason(callable_, *args, **kwargs):
    with pytest.raises(AcquisitionError) as excinfo:
        callable_(*args, **kwargs)
    return excinfo.value.reason


# --- acquisition: refusals that must fire on every host ----------------------


def test_missing_path_refused(root):
    assert _reason(acquire, root / "absent.json", approved_root=root,
                   allowed_suffixes=SUFFIXES, max_bytes=1024, acquired_at=NOW) == "missing-path"


def test_missing_root_refused(tmp_path):
    assert _reason(acquire, tmp_path / "input.json", approved_root=tmp_path / "no-such-root",
                   allowed_suffixes=SUFFIXES, max_bytes=1024, acquired_at=NOW) == "missing-path"


def test_suffix_refused_before_open(root):
    assert _reason(acquire, root / "input.json", approved_root=root,
                   allowed_suffixes=frozenset({".yaml"}), max_bytes=1024,
                   acquired_at=NOW) == "suffix-refused"


def test_traversal_refused(root):
    assert _reason(acquire, root / ".." / "escaped.json", approved_root=root,
                   allowed_suffixes=SUFFIXES, max_bytes=1024,
                   acquired_at=NOW) == "traversal-refused"


def test_absolute_outside_root_refused(root, tmp_path_factory):
    elsewhere = tmp_path_factory.mktemp("elsewhere") / "input.json"
    elsewhere.write_bytes(b"{}")
    assert _reason(acquire, elsewhere, approved_root=root, allowed_suffixes=SUFFIXES,
                   max_bytes=1024, acquired_at=NOW) == "root-escape"


@pytest.mark.skipif(sys.platform != "win32" or hasattr(os, "O_NOFOLLOW"),
                    reason="pins the typed refusal on hosts lacking os.O_NOFOLLOW")
def test_platform_unsupported_on_windows(root):
    assert _reason(acquire, root / "input.json", approved_root=root,
                   allowed_suffixes=SUFFIXES, max_bytes=1024,
                   acquired_at=NOW) == "platform-unsupported"


# --- acquisition: read discipline (runs everywhere via the simulated flag) ---


def test_acquire_happy_path(root, record):
    raw = (root / "input.json").read_bytes()
    assert record.logical_path.endswith("input.json")
    assert record.size_bytes == len(raw)
    assert record.sha256 == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert record.suffix == ".json"
    assert record.acquired_at == NOW
    assert Path(record.resolved_path).is_relative_to(root.resolve())


def test_acquire_dotdot_inside_root_allowed(root, nofollow_simulated):
    record = acquire(root / "sub" / ".." / "input.json", approved_root=root,
                     allowed_suffixes=SUFFIXES, max_bytes=1024, acquired_at=NOW)
    assert record.sha256.startswith("sha256:")


def test_oversized_refused(root, nofollow_simulated):
    assert _reason(acquire, root / "input.json", approved_root=root,
                   allowed_suffixes=SUFFIXES, max_bytes=4, acquired_at=NOW) == "oversized"


def test_zero_max_bytes_is_caller_error(root):
    with pytest.raises(ValueError):
        acquire(root / "input.json", approved_root=root, allowed_suffixes=SUFFIXES,
                max_bytes=0, acquired_at=NOW)


def test_changed_while_read_refused(root, nofollow_simulated, monkeypatch):
    real_read = os.read

    def flaky_read(fd, size):
        chunk = real_read(fd, size)
        return chunk + b"x" if chunk else chunk

    monkeypatch.setattr(os, "read", flaky_read)
    assert _reason(acquire, root / "input.json", approved_root=root,
                   allowed_suffixes=SUFFIXES, max_bytes=1024,
                   acquired_at=NOW) == "changed-while-read"


def test_tamper_same_size_is_digest_mismatch(root, record):
    (root / "input.json").write_bytes(b'{"demo": fals}\n')
    assert _reason(verify_unchanged, record, approved_root=root) == "digest-mismatch"


def test_grown_file_is_digest_mismatch(root, record):
    with (root / "input.json").open("ab") as stream:
        stream.write(b"tail")
    assert _reason(verify_unchanged, record, approved_root=root) == "digest-mismatch"


def test_truncated_file_refused(root, record):
    (root / "input.json").write_bytes(b'{"demo"')
    assert _reason(verify_unchanged, record, approved_root=root) == "truncated"


def test_verify_locator_traversal_refused(root, record):
    forged = dataclasses.replace(record, resolved_path=str(root / ".." / "input.json"))
    assert _reason(verify_unchanged, forged, approved_root=root) == "traversal-refused"


def test_verify_outside_root_refused(root, record, tmp_path_factory):
    forged = dataclasses.replace(record, resolved_path=str(tmp_path_factory.mktemp("x") / "f.json"))
    assert _reason(verify_unchanged, forged, approved_root=root) == "root-escape"


# --- acquisition: real nofollow enforcement (POSIX only) ---------------------


@unix_symlink
@real_nofollow
def test_symlink_final_component_refused(root):
    (root / "link.json").symlink_to(root / "input.json")
    assert _reason(acquire, root / "link.json", approved_root=root, allowed_suffixes=SUFFIXES,
                   max_bytes=1024, acquired_at=NOW) == "symlink-refused"


@unix_symlink
@real_nofollow
def test_symlink_parent_escape_refused(root, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    (outside / "input.json").write_bytes(b"{}")
    (root / "alias").symlink_to(outside)
    assert _reason(acquire, root / "alias" / "input.json", approved_root=root,
                   allowed_suffixes=SUFFIXES, max_bytes=1024,
                   acquired_at=NOW) == "root-escape"


@unix_symlink
@real_nofollow
def test_symlink_parent_inside_root_admitted(root):
    (root / "real").mkdir()
    (root / "real" / "input.json").write_bytes(b'{"demo": true}\n')
    (root / "alias").symlink_to(root / "real")
    record = acquire(root / "alias" / "input.json", approved_root=root,
                     allowed_suffixes=SUFFIXES, max_bytes=1024, acquired_at=NOW)
    assert record.sha256.startswith("sha256:")


@unix_symlink
@real_nofollow
def test_fifo_not_regular_refused(root):
    os.mkfifo(root / "pipe.json")
    assert _reason(acquire, root / "pipe.json", approved_root=root, allowed_suffixes=SUFFIXES,
                   max_bytes=1024, acquired_at=NOW) == "not-regular"


# --- directory manifests ------------------------------------------------------


@pytest.fixture
def tree(root):
    (root / "sub").mkdir()
    (root / "sub" / "b.json").write_bytes(b"{}")
    (root / "sub" / "a.json").write_bytes(b"[1]")
    (root / "z.yaml").write_bytes(b"k: v\n")
    return root


def _manifest(tree):
    return acquire_directory(tree, approved_root=tree, max_entries=64, max_total_bytes=4096,
                             max_depth=4, acquired_at=NOW)


def test_manifest_deterministic_and_mtime_blind(tree, nofollow_simulated):
    first = _manifest(tree)
    second = _manifest(tree)
    assert first == second
    assert [entry["relative_path"] for entry in first.entries] == [
        "input.json", "sub/a.json", "sub/b.json", "z.yaml"]
    os.utime(tree / "z.yaml", (0, 0))
    assert _manifest(tree) == first


def test_manifest_entry_cap(tree, nofollow_simulated):
    assert _reason(acquire_directory, tree, approved_root=tree, max_entries=2,
                   max_total_bytes=4096, max_depth=4,
                   acquired_at=NOW) == "entry-cap-exceeded"


def test_manifest_byte_cap(tree, nofollow_simulated):
    assert _reason(acquire_directory, tree, approved_root=tree, max_entries=64,
                   max_total_bytes=2, max_depth=4, acquired_at=NOW) == "byte-cap-exceeded"


def test_manifest_depth_cap(tree, nofollow_simulated):
    (tree / "sub" / "deeper").mkdir()
    (tree / "sub" / "deeper" / "leaf.json").write_bytes(b"{}")
    assert _reason(acquire_directory, tree, approved_root=tree, max_entries=64,
                   max_total_bytes=4096, max_depth=1,
                   acquired_at=NOW) == "depth-cap-exceeded"


def test_manifest_added_entry_named(tree, nofollow_simulated):
    manifest = _manifest(tree)
    (tree / "new.json").write_bytes(b"{}")
    with pytest.raises(AcquisitionError) as excinfo:
        verify_directory_unchanged(manifest, approved_root=tree)
    assert excinfo.value.reason == "digest-mismatch"
    assert "new.json" in str(excinfo.value)


def test_manifest_removed_entry_named(tree, nofollow_simulated):
    manifest = _manifest(tree)
    (tree / "z.yaml").unlink()
    with pytest.raises(AcquisitionError) as excinfo:
        verify_directory_unchanged(manifest, approved_root=tree)
    assert excinfo.value.reason == "digest-mismatch"
    assert "z.yaml" in str(excinfo.value)


def test_manifest_changed_entry_named(tree, nofollow_simulated):
    manifest = _manifest(tree)
    (tree / "sub" / "b.json").write_bytes(b'{"x": 1}\n')
    with pytest.raises(AcquisitionError) as excinfo:
        verify_directory_unchanged(manifest, approved_root=tree)
    assert excinfo.value.reason == "digest-mismatch"
    assert "sub/b.json" in str(excinfo.value)


@unix_symlink
@real_nofollow
def test_manifest_symlink_anywhere_refused(tree):
    (tree / "dodge.json").symlink_to(tree / "z.yaml")
    assert _reason(acquire_directory, tree, approved_root=tree, max_entries=64,
                   max_total_bytes=4096, max_depth=4, acquired_at=NOW) == "symlink-refused"


def test_manifest_root_not_a_directory(tree, record, nofollow_simulated):
    assert _reason(acquire_directory, tree / "z.yaml", approved_root=tree, max_entries=64,
                   max_total_bytes=4096, max_depth=4, acquired_at=NOW) == "not-regular"


# --- observations -------------------------------------------------------------


def _bind(record, action="lookup"):
    return bind_reader_observation(record, attempt_id=ATTEMPT, arm_id="vulnify", action=action,
                                   handler_revision="rev-1",
                                   execution_result_digest=RESULT_DIGEST, collected_at=NOW)


def test_bind_mints_stable_replay_identity(record):
    first = _bind(record)
    second = _bind(record)
    other = _bind(record, action="render")
    raw = (record.resolved_path and Path(record.resolved_path)).read_bytes()
    assert first == second
    assert first["observation_id"] != other["observation_id"]
    assert first["observation_id"] != "sha256:" + hashlib.sha256(raw).hexdigest()
    assert first["schema"] == "specaudit.ctf.reader-observation.v1"
    assert first["schema_version"] == 1
    assert first["custody"] == "operator-asserted-root"
    assert first["evidence_class"] == "declared"
    assert first["limitations"] == [
        "operator-asserted-root-not-verified-custody",
        "bytes-acquired-in-bounded-read-window-stability-reattested",
        "content-bound-unsigned",
        "locator-is-not-identity",
        "applicability-not-assessed",
    ]
    assert first["input"]["resolved_path"] == record.resolved_path


def test_bind_validates_strictly(record):
    with pytest.raises(ObservationError):
        bind_reader_observation(record, attempt_id="ATTEMPT-SHORT", arm_id="vulnify",
                                action="lookup", handler_revision="rev-1",
                                execution_result_digest=RESULT_DIGEST, collected_at=NOW)
    for override in ({"arm_id": ""}, {"action": "no\nnewlines"},
                     {"handler_revision": "x" * 257}):
        fields = dict(arm_id="vulnify", action="lookup", handler_revision="rev-1")
        fields.update(override)
        with pytest.raises(ObservationError):
            bind_reader_observation(record, attempt_id=ATTEMPT,
                                    execution_result_digest=RESULT_DIGEST, collected_at=NOW,
                                    **fields)
    with pytest.raises(ObservationError):
        bind_reader_observation(record, attempt_id=ATTEMPT, arm_id="vulnify", action="lookup",
                                handler_revision="rev-1", execution_result_digest="deadbeef",
                                collected_at=NOW)
    with pytest.raises(ObservationError):
        bind_reader_observation(record, attempt_id=ATTEMPT, arm_id="vulnify", action="lookup",
                                handler_revision="rev-1", execution_result_digest=RESULT_DIGEST,
                                collected_at=NOW.astimezone())


def test_verify_ok_then_replay_refused(record):
    observation = _bind(record)
    assert verify_reader_observation(observation, acquisition=record,
                                     seen_observation_ids=set()).ok
    result = verify_reader_observation(observation, acquisition=record,
                                       seen_observation_ids={observation["observation_id"]})
    assert not result.ok and "replayed" in result.reasons
    # The seen set is caller-owned: nothing stored module-side, so a fresh
    # empty set verifies the same document again.
    assert verify_reader_observation(observation, acquisition=record,
                                     seen_observation_ids=set()).ok


def test_verify_cross_attempt_splice_refused(record):
    observation = _bind(record)
    spliced = dict(observation)
    spliced["attempt_id"] = "attempt-bbbb2222"
    result = verify_reader_observation(spliced, acquisition=record,
                                       seen_observation_ids=set())
    assert not result.ok and "cross-attempt" in result.reasons


def test_verify_rebound_document_with_consistent_id_is_ok(record):
    """The acquisition carries no attempt identity; a fully consistent rebind
    under a fresh attempt verifies cleanly, while a swapped id is a splice."""
    rebound = bind_reader_observation(record, attempt_id="attempt-bbbb2222", arm_id="vulnify",
                                      action="lookup", handler_revision="rev-1",
                                      execution_result_digest=RESULT_DIGEST, collected_at=NOW)
    assert verify_reader_observation(rebound, acquisition=record,
                                     seen_observation_ids=set()).ok


def test_verify_document_mismatch_refused(root, record):
    observation = _bind(record)
    tampered = dict(observation)
    tampered["input"] = dict(observation["input"], sha256="sha256:" + "f" * 64)
    result = verify_reader_observation(tampered, acquisition=record, seen_observation_ids=set())
    assert not result.ok and result.reasons == ("document-mismatch",)
    retest = dict(observation, collected_at="2026-10-13T12:00:00.000000")
    result = verify_reader_observation(retest, acquisition=record, seen_observation_ids=set())
    assert not result.ok and "document-mismatch" in result.reasons


def test_verify_malformed_documents(record):
    assert verify_reader_observation([], acquisition=record,
                                     seen_observation_ids=set()).reasons == ("malformed",)
    observation = _bind(record)
    assert verify_reader_observation(dict(observation, schema="other.v1"),
                                     acquisition=record, seen_observation_ids=set()).reasons == (
        "malformed",)
    assert verify_reader_observation(dict(observation, extra=1),
                                     acquisition=record, seen_observation_ids=set()).reasons == (
        "malformed",)


def test_directory_observation_roundtrip(tree, nofollow_simulated):
    manifest = _manifest(tree)
    observation = bind_directory_observation(manifest, attempt_id=ATTEMPT, arm_id="vulnify",
                                             action="scan", handler_revision="rev-1",
                                             execution_result_digest=RESULT_DIGEST,
                                             collected_at=NOW)
    assert observation["input"]["manifest_digest"].startswith("sha256:")
    assert verify_reader_observation(observation, acquisition=manifest,
                                     seen_observation_ids=set()).ok
    (tree / "z.yaml").write_bytes(b"k: w\n")
    changed = _manifest(tree)
    result = verify_reader_observation(observation, acquisition=changed,
                                       seen_observation_ids=set())
    assert not result.ok and "document-mismatch" in result.reasons


def _load_schema():
    path = Path(reader_evidence.__file__).parent / "schema" / "reader-observation.v1.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_schema_accepts_minted_documents(record, tree, nofollow_simulated):
    schema = _load_schema()
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.validate(_bind(record), schema)
    manifest = _manifest(tree)
    jsonschema.validate(bind_directory_observation(manifest, attempt_id=ATTEMPT, arm_id="vulnify",
                                                   action="scan", handler_revision="rev-1",
                                                   execution_result_digest=RESULT_DIGEST,
                                                   collected_at=NOW), schema)


def test_schema_rejects_unknown_and_missing_fields(record):
    schema = _load_schema()
    observation = _bind(record)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(dict(observation, unexpected=1), schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(dict(observation, input=dict(observation["input"], extra=0)), schema)
    missing = {key: value for key, value in observation.items() if key != "custody"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(missing, schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(dict(observation, observation_id="md5:abc"), schema)


# --- data slices --------------------------------------------------------------


def test_vulnify_snapshot_pin_matches_shipped_file():
    record = vulnify_demo_slice()
    raw = (REPO_ROOT / record.pinned_path).read_bytes()
    verify_slice_bytes(record, raw)
    assert record.provenance == "first-party-synthetic-demo"
    # Admitted since the 2026-10-14 operator authorization; the scope is the
    # pinned first-party synthetic slice only (not the upstream database).
    assert record.upstream_admission == "admitted"
    assert record.as_of == "2026-10-13"
    assert record.review_due == "2027-01-11"
    assert (record.unknown_lookup_stays_unknown and record.stale_after_review_due
            and record.no_generation and record.no_mutation and record.no_hosted_fallback)


def test_slice_digest_gate_tamper(tmp_path):
    record = vulnify_demo_slice()
    raw = (REPO_ROOT / record.pinned_path).read_bytes()
    tampered = raw[:-1] + bytes([raw[-1] ^ 0x20])
    with pytest.raises(DataSliceError) as excinfo:
        verify_slice_bytes(record, tampered)
    assert excinfo.value.reason == "digest-mismatch"


def test_slice_freshness_boundary():
    record = detections_demo_slice()
    check_freshness(record, as_of=date.fromisoformat(record.review_due))
    with pytest.raises(DataSliceError) as excinfo:
        check_freshness(record, as_of=date(2027, 6, 1))
    assert excinfo.value.reason == "stale-slice"


def test_detections_fixture_pin_and_index():
    record = detections_demo_slice()
    raw = (REPO_ROOT / record.pinned_path).read_bytes()
    verify_slice_bytes(record, raw)
    index = synthetic_rule_index(raw)
    assert len(index) == 7
    assert {rule["rule_id"] for rule in index} == {f"DEMO-000{n}" for n in range(1, 8)}
    assert rule_lookup(index, rule_id="DEMO-0003")["severity"] == "high"
    with pytest.raises(DataSliceError) as excinfo:
        rule_lookup(index, rule_id="NOT-A-RULE")
    assert excinfo.value.reason == "unknown-lookup"
    with pytest.raises(ValueError):
        synthetic_rule_index(b'{"schema": "specaudit.ctf.detection-rules.v1", "rules": []}')


def test_upstream_admission_gate():
    # The admitted pair passes the gate; an unadmitted record still fails closed.
    require_upstream_admission(vulnify_demo_slice())
    require_upstream_admission(detections_demo_slice())
    unadmitted = dataclasses.replace(vulnify_demo_slice(), upstream_admission="not-admitted")
    with pytest.raises(DataSliceError) as excinfo:
        require_upstream_admission(unadmitted)
    assert excinfo.value.reason == "admission-required"


def test_package_never_imports_extension():
    package = Path(reader_evidence.__file__).parent
    for source in package.glob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert "from extension" not in text and "import extension" not in text, source.name


# --- CLI ----------------------------------------------------------------------


def test_cli_bind_and_verify_slice_happy(record, capsys):
    record_json = json.dumps({
        "logical_path": record.logical_path, "resolved_path": record.resolved_path,
        "size_bytes": record.size_bytes, "sha256": record.sha256, "suffix": record.suffix,
        "acquired_at": record.acquired_at.isoformat(),
    })
    assert cli_main(["bind", "--record-json", record_json, "--attempt-id", ATTEMPT,
                     "--arm", "vulnify", "--action", "lookup", "--handler-rev", "rev-1",
                     "--result-digest", RESULT_DIGEST, "--at", NOW.isoformat()]) == 0
    observation = json.loads(capsys.readouterr().out)["observation"]
    assert observation["schema"] == "specaudit.ctf.reader-observation.v1"
    assert cli_main(["verify-slice", "--which", "vulnify",
                     "--path", str(REPO_ROOT / vulnify_demo_slice().pinned_path),
                     "--as-of", "2026-10-13"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_cli_verify_slice_refusal(tmp_path, capsys):
    record = vulnify_demo_slice()
    raw = (REPO_ROOT / record.pinned_path).read_bytes()
    tampered = tmp_path / "snapshot.json"
    tampered.write_bytes(raw[:-1] + bytes([raw[-1] ^ 0x20]))
    assert cli_main(["verify-slice", "--which", "vulnify", "--path", str(tampered),
                     "--as-of", "2026-10-13"]) == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "digest-mismatch"


def test_cli_manifest_happy(tree, capsys, nofollow_simulated):
    assert cli_main(["manifest", "--path", str(tree), "--root", str(tree),
                     "--at", NOW.isoformat()]) == 0
    manifest = json.loads(capsys.readouterr().out)["manifest"]
    assert [entry["relative_path"] for entry in manifest["entries"]] == [
        "input.json", "sub/a.json", "sub/b.json", "z.yaml"]
    rebuilt = DirectoryManifest(manifest["resolved_path"], tuple(manifest["entries"]),
                                manifest["total_bytes"],
                                datetime.fromisoformat(manifest["acquired_at"]))
    verify_directory_unchanged(rebuilt, approved_root=tree)


@pytest.mark.skipif(not (sys.platform == "win32" and not hasattr(os, "O_NOFOLLOW")),
                    reason="acquire CLI must refuse cleanly on nofollow-less hosts")
def test_cli_acquire_platform_refusal(root, capsys):
    assert cli_main(["acquire", "--path", str(root / "input.json"), "--root", str(root),
                     "--at", NOW.isoformat()]) == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "platform-unsupported"


@real_nofollow
def test_cli_acquire_happy(root, capsys):
    assert cli_main(["acquire", "--path", str(root / "input.json"), "--root", str(root),
                     "--at", NOW.isoformat()]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True and payload["record"]["suffix"] == ".json"


def test_cli_usage_errors(root):
    with pytest.raises(SystemExit) as excinfo:
        cli_main(["acquire", "--path", str(root / "input.json"), "--root", str(root)])
    assert excinfo.value.code == 2
    with pytest.raises(SystemExit) as excinfo:
        cli_main(["bind", "--record-json", "{not json", "--attempt-id", ATTEMPT,
                  "--arm", "vulnify", "--action", "lookup", "--handler-rev", "rev-1",
                  "--result-digest", RESULT_DIGEST, "--at", NOW.isoformat()])
    assert excinfo.value.code == 2
    with pytest.raises(SystemExit) as excinfo:
        cli_main(["bind", "--record-json", '{"schema": false}', "--attempt-id", ATTEMPT,
                  "--arm", "vulnify", "--action", "lookup", "--handler-rev", "rev-1",
                  "--result-digest", RESULT_DIGEST, "--at", NOW.isoformat()])
    assert excinfo.value.code == 2
