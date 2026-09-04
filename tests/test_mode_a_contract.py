"""Mode-A attempt echo, artifact custody, and static capability manifests."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import jsonschema
import pytest

# Windows hosts: the seven admission-contract tests that assert a specific
# path error (absolute / does-not-exist / not-a-symlink / not-a-directory /
# must-be-empty) pass only once the Mode-A admission-reorder commit lands
# (agents/20260901-p1-mcp-bundle-surface; it is producer-locked and rides the
# locked-bundle rebuild PR). Before that reorder, the Unix-only gate shadows
# the path error on Windows -- those failures are the stacking signal, not
# regressions in this packet.

from extension.__main__ import main as invoke_main
from extension.contract import Result
from extension.encode import (
    mode_a_supported,
    ArtifactHandoffError,
    artifact_filename,
    bind_artifact_dir,
    encode_capability_manifest,
    encode_capability_manifests,
    encode_range_document,
)
from extension.envelopes import (
    MANIFEST_SCHEMA_ID,
    RESULT_SCHEMA_ID,
    gate_dispatch,
    parse_capability_manifest,
    parse_execution_result,
)
from extension.invoke_profiles import INVOKE_PROFILES, InvokeProfile
from extension.range import run_range
from extension.range.__main__ import main as range_main
from tests.test_cli_json_encode import _assert_execution_result, _stdout_json
from tests.test_range_lifecycle import apply_no_curated_tools

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SCHEMA_PATH = ROOT / "extension" / "schema" / "capability.manifest.v1.schema.json"
GOLDEN = ROOT / "tests" / "goldens" / "capability-manifest" / "agent-wiz.list_tools.json"
ATTEMPT_ID = "attempt-" + ("ab" * 32)


def _schema() -> dict[str, Any]:
    payload = json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _forbid_invoke(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []

    def forbidden(self: Any, arm_id: str, action: str, args: Any = None) -> Any:
        calls.append((arm_id, action))
        raise AssertionError("Extension.invoke ran")

    monkeypatch.setattr("extension.__main__.Extension.invoke", forbidden)
    return calls


def _forbid_range(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        raise AssertionError("run_range executed")

    # X4-PUB: run_range is resolved lazily from its defining module inside
    # dispatch_range, so the zero-execution seam is extension.range.runner
    # (the source the lazy `from` reads), not any CLI/dispatch re-export.
    monkeypatch.setattr("extension.range.runner.run_range", forbidden)
    return calls


def _fake_list_tools() -> Result:
    return Result(
        ok=True,
        arm_id="agent-wiz",
        action="list_tools",
        output={"read_actions": ["extract", "visualize"]},
        error=None,
    )


@pytest.fixture
def no_curated_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    apply_no_curated_tools(monkeypatch)


def test_invoke_echoes_attempt_id_on_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: _fake_list_tools(),
    )
    code = invoke_main(
        ["invoke", "agent-wiz", "list_tools", "--attempt-id", ATTEMPT_ID]
    )
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert code == 0
    assert payload["attempt_id"] == ATTEMPT_ID
    assert parsed.result is not None
    assert parsed.result.attempt_id == ATTEMPT_ID
    assert payload["status"] == "complete"
    assert payload["side_effects"] == ["local-read"]


def test_invoke_echoes_attempt_id_on_failure(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = invoke_main(
        ["invoke", "no-such-arm", "ping", "--attempt-id", ATTEMPT_ID]
    )
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert code == 2
    assert payload["attempt_id"] == ATTEMPT_ID
    assert payload["status"] == "failed"
    assert parsed.result is not None
    assert parsed.result.attempt_id == ATTEMPT_ID


def test_invalid_attempt_id_zero_dispatch(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = _forbid_invoke(monkeypatch)
    code = invoke_main(
        ["invoke", "agent-wiz", "list_tools", "--attempt-id", "attempt-not-hex"]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "invalid attempt id" in captured.err


@pytest.mark.parametrize(
    "value",
    [
        "attempt-" + ("A" * 64),
        "attempt-" + ("ab" * 31),
        "attempt-" + ("ab" * 32) + "c",
        "nope-" + ("ab" * 32),
        ATTEMPT_ID.upper(),
    ],
)
def test_invalid_attempt_id_shapes_fail_closed(
    value: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = _forbid_invoke(monkeypatch)
    code = invoke_main(["invoke", "agent-wiz", "list_tools", "--attempt-id", value])
    assert calls == []
    assert code == 2
    assert capsys.readouterr().out == ""


@pytest.mark.skipif(
    not mode_a_supported(),
    reason="Mode A custody writes are Unix-only (dirfd-bound 0600 digest "
    "files); the Windows host contract is fail-before-dispatch",
)
def test_artifact_bytes_hash_to_envelope_digest(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    fake = _fake_list_tools()
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(tmp_path),
        ]
    )
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert code == 0
    assert payload["status"] == "complete"
    assert payload["attempt_id"] == ATTEMPT_ID
    assert payload["side_effects"] == ["local-read"]
    assert payload["artifacts"]
    digest = payload["artifacts"][0]["digest"]
    written = tmp_path / artifact_filename(digest)
    blob = written.read_bytes()
    assert hashlib.sha256(blob).hexdigest() == digest.split(":", 1)[1]
    assert blob == _canonical_bytes(fake.output)
    assert payload["budget"]["spent"]["output_bytes"] == len(blob)
    pretty = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    assert payload["budget"]["spent"]["output_bytes"] != len(pretty)
    assert parsed.result is not None
    assert parsed.result.artifacts[0].digest == digest
    names = [path for path in tmp_path.iterdir() if path.name not in (".", "..")]
    assert names == [written]
    info = written.stat()
    assert stat.S_ISREG(info.st_mode)
    assert info.st_mode & 0o777 == 0o600


def test_missing_artifact_dir_fails_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_invoke(monkeypatch)
    missing = tmp_path / "absent"
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(missing),
        ]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert not missing.exists()
    assert captured.out == ""
    assert "does not exist" in captured.err


def test_relative_artifact_dir_fails_before_dispatch(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = _forbid_invoke(monkeypatch)
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            "relative/artifacts",
        ]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "absolute" in captured.err


def test_artifact_dir_file_fails_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_invoke(monkeypatch)
    target = tmp_path / "not-a-dir"
    target.write_text("nope\n", encoding="utf-8")
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(target),
        ]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "must be a directory" in captured.err


def test_symlink_artifact_dir_fails_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_invoke(monkeypatch)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(link),
        ]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "symlink" in captured.err
    assert list(real.iterdir()) == []


def test_artifact_dir_requires_attempt_id(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_invoke(monkeypatch)
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--artifact-dir",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "--artifact-dir requires --attempt-id" in captured.err
    assert list(tmp_path.iterdir()) == []


def test_non_empty_artifact_dir_rejected_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_invoke(monkeypatch)
    planted = tmp_path / "already-there"
    planted.write_text("not-empty\n", encoding="utf-8")
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "must be empty" in captured.err
    assert planted.read_text(encoding="utf-8") == "not-empty\n"
    assert list(tmp_path.iterdir()) == [planted]


@pytest.mark.skipif(
    not mode_a_supported(),
    reason="Mode A custody writes are Unix-only (dirfd-bound 0600 digest "
    "files); the Windows host contract is fail-before-dispatch",
)
def test_exclusive_collision_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    fake = _fake_list_tools()
    blob = _canonical_bytes(fake.output)
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    planted = tmp_path / artifact_filename(digest)

    def plant_then_result(self: Any, arm_id: str, action: str, args: Any = None) -> Result:
        planted.write_bytes(b"tampered-not-canonical")
        return fake

    monkeypatch.setattr("extension.__main__.Extension.invoke", plant_then_result)
    before_names = list(tmp_path.iterdir())
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(tmp_path),
        ]
    )
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert before_names == []
    assert code == 2
    assert payload["status"] != "complete"
    assert payload["status"] == "failed"
    assert payload["attempt_id"] == ATTEMPT_ID
    assert payload["artifacts"] == []
    assert payload["transport_ok"] is True
    assert "artifact handoff failed" in payload["limitations"]
    assert planted.read_bytes() == b"tampered-not-canonical"
    assert parsed.status == "failed"
    assert "unowned-evidence" in parsed.reasons
    assert parsed.result is not None
    assert parsed.result.transport_ok is True
    assert parsed.result.artifacts == ()


def test_mode_b_omits_attempt_id_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: _fake_list_tools(),
    )
    code = invoke_main(["invoke", "agent-wiz", "list_tools"])
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert code == 0
    assert "attempt_id" not in payload
    assert parsed.result is not None
    assert parsed.result.attempt_id is None
    assert payload["status"] == "complete"
    assert list(tmp_path.iterdir()) == []


def test_describe_stays_catalog_not_capability_manifest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert invoke_main(["describe", "agent-wiz"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["id"] == "agent-wiz"
    assert payload.get("schema") != MANIFEST_SCHEMA_ID
    assert payload.get("schema") != RESULT_SCHEMA_ID
    assert "default_off" not in payload
    assert "synthetic_only" not in payload


def test_agent_wiz_golden_matches_encoder_and_is_admitted() -> None:
    profile = INVOKE_PROFILES["agent-wiz.list_tools"]
    encoded = encode_capability_manifest(profile)
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert encoded == golden
    jsonschema.validate(instance=encoded, schema=_schema())
    parsed = parse_capability_manifest(encoded)
    assert parsed.schema_ok is True
    assert parsed.dispatch_allowed is False
    assert "default-off" in parsed.reasons
    enabled = parse_capability_manifest(encoded, enabled=True)
    assert enabled.dispatch_allowed is True
    assert enabled.manifest is not None
    assert enabled.manifest.capability_id == "agent-wiz.list_tools"
    assert enabled.manifest.tool.name == profile.tool_name
    assert enabled.manifest.tool.version == profile.tool_version
    assert enabled.manifest.tier == "maintained"
    assert enabled.manifest.kind == "arm"
    assert enabled.manifest.safety_class == "R0"
    assert enabled.manifest.side_effects == ("local-read",)
    assert enabled.manifest.protocols == ("cli-json",)
    assert enabled.manifest.default_off is True
    assert enabled.manifest.synthetic_only is True


def test_capability_manifests_are_deterministic_and_admitted() -> None:
    # 21 since commix.scan admission (2026-09-03): 10 static read
    # profiles + 11 scope-gated dispatch profiles.
    # 45 after the prowler read admission (hosted-endpoint discovery)
    # on top of semgrep CLI (2), GTI (12), and burp (9).
    assert len(INVOKE_PROFILES) == 45
    # Defense-in-depth for X5-PROMOTE: among the static policy profiles only
    # agent-wiz may be maintained; any second promotion is a reviewed,
    # deliberate change to this assertion, never a quiet drift.
    maintained = sorted(
        capability_id
        for capability_id, profile in INVOKE_PROFILES.items()
        if profile.tier == "maintained"
    )
    assert maintained == ["agent-wiz.list_tools"]
    for capability_id, profile in INVOKE_PROFILES.items():
        if profile.arm_id == "burp-mcp":
            # MCP read admission: dials the operator endpoint once armed,
            # so not synthetic-only.
            assert profile.safety_class == "R0"
            assert profile.side_effects == ("local-read",)
            assert profile.synthetic_only is False
        elif profile.arm_id in ("google-mcp-security", "prowler-mcp"):
            # Remote-read admission: R1 network-egress lookups.
            assert profile.safety_class == "R1"
            assert profile.side_effects == ("network-egress",)
            assert profile.synthetic_only is False
        elif profile.action == "list_tools":
            assert profile.safety_class == "R0"
            assert profile.side_effects == ("local-read",)
            assert profile.synthetic_only is True
        else:
            # Dispatch-class admission: R1, declared side effects,
            # default-off, and NOT synthetic-only (the operator arms a
            # real lab target through <ARM>_DISPATCH_SCOPE).
            assert profile.safety_class == "R1"
            assert profile.side_effects
            assert profile.default_off is True
            assert profile.synthetic_only is False
            assert profile.tier == "research"
    first = encode_capability_manifests()
    second = encode_capability_manifests()
    assert first == second
    assert set(first) == set(INVOKE_PROFILES)

    def spy(_manifest: Any) -> None:
        raise AssertionError("manifest encoder dispatched")

    for capability_id, profile in INVOKE_PROFILES.items():
        payload = first[capability_id]
        assert payload == encode_capability_manifest(profile)
        assert payload["schema"] == MANIFEST_SCHEMA_ID
        assert payload["capability_id"] == profile.capability_id
        assert payload["tool"] == {
            "name": profile.tool_name,
            "version": profile.tool_version,
        }
        assert payload["protocols"] == ["cli-json"]
        assert payload["tier"] == profile.tier
        if profile.arm_id == "agent-wiz":
            assert payload["tier"] == "maintained"
        assert payload["kind"] == "arm"
        assert payload["default_off"] is True
        if profile.arm_id == "burp-mcp":
            # MCP read manifests: R0 local-read, synthetic_only False
            # (they dial the operator-configured endpoint once armed).
            assert payload["safety_class"] == "R0"
            assert payload["side_effects"] == ["local-read"]
            assert payload["synthetic_only"] is False
        elif profile.arm_id in ("google-mcp-security", "prowler-mcp"):
            # Remote-read manifests: R1 network-egress lookups (including
            # its list_tools, which dials the endpoint).
            assert payload["safety_class"] == "R1"
            assert payload["side_effects"] == ["network-egress"]
            assert payload["synthetic_only"] is False
        elif profile.action == "list_tools":
            assert payload["safety_class"] == "R0"
            assert payload["side_effects"] == ["local-read"]
            assert payload["synthetic_only"] is True
        else:
            # Dispatch-class manifests carry their honest R1 truth.
            assert payload["safety_class"] == "R1"
            assert payload["side_effects"] == list(profile.side_effects)
            assert payload["synthetic_only"] is False
        assert payload["authorized_scope"] == list(profile.authorized_scope)
        assert payload["budget"]["timeout_ms"] == profile.timeout_ms
        assert payload["budget"]["max_output_bytes"] == profile.max_output_bytes
        assert payload["budget"]["max_tool_steps"] == profile.max_tool_steps
        assert payload["budget"]["max_spend"] == profile.max_spend
        assert payload["cleanup"]["required"] is False
        jsonschema.validate(instance=payload, schema=_schema())
        parsed = parse_capability_manifest(payload)
        assert parsed.schema_ok is True
        assert parsed.manifest is not None
        enabled = parse_capability_manifest(payload, enabled=True)
        assert enabled.dispatch_allowed is True
        gated = gate_dispatch(payload, dispatcher=spy)
        assert gated.dispatch_allowed is False


def test_forged_profile_is_not_manifest_authority() -> None:
    real = INVOKE_PROFILES["agent-wiz.list_tools"]
    forged = replace(real)
    assert forged == real
    assert forged is not real
    with pytest.raises(ValueError, match="authoritative"):
        encode_capability_manifest(forged)


@pytest.mark.skipif(
    not mode_a_supported(),
    reason="Mode A custody writes are Unix-only (dirfd-bound 0600 digest "
    "files); the Windows host contract is fail-before-dispatch",
)
def test_range_echoes_attempt_id_and_writes_artifact(
    no_curated_tools: None,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    code = range_main(
        ["--attempt-id", ATTEMPT_ID, "--artifact-dir", str(tmp_path)]
    )
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert payload["attempt_id"] == ATTEMPT_ID
    assert payload["status"] != "complete"
    assert parsed.result is not None
    assert parsed.result.attempt_id == ATTEMPT_ID
    assert payload["artifacts"]
    digest = payload["artifacts"][0]["digest"]
    blob = (tmp_path / artifact_filename(digest)).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == digest.split(":", 1)[1]
    assert payload["budget"]["spent"]["output_bytes"] == len(blob)
    assert code == 1


def test_range_invalid_attempt_id_zero_execution(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = _forbid_range(monkeypatch)
    code = range_main(["--attempt-id", "attempt-nope"])
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""


def test_range_missing_artifact_dir_zero_execution(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_range(monkeypatch)
    code = range_main(
        [
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(tmp_path / "missing"),
        ]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""


def test_range_symlink_artifact_dir_zero_execution(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_range(monkeypatch)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    code = range_main(
        ["--attempt-id", ATTEMPT_ID, "--artifact-dir", str(link)]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "symlink" in captured.err


def test_range_mode_b_omits_attempt_id(
    no_curated_tools: None,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    code = range_main([])
    payload = _stdout_json(capsys)
    _assert_execution_result(payload)
    assert "attempt_id" not in payload
    assert list(tmp_path.iterdir()) == []
    assert code == 1


@pytest.mark.skipif(
    not mode_a_supported(),
    reason="Mode A custody writes are Unix-only (dirfd-bound 0600 digest "
    "files); the Windows host contract is fail-before-dispatch",
)
def test_range_complete_encoder_artifact_bytes_match_digest(tmp_path: Path) -> None:
    inner = run_range(arm_ids=())
    sink = bind_artifact_dir(str(tmp_path), attempt_id=ATTEMPT_ID)
    assert sink is not None
    try:
        payload = encode_range_document(
            inner,
            started_at="2026-08-25T12:00:00Z",
            finished_at="2026-08-25T12:00:00Z",
            attempt_id=ATTEMPT_ID,
            artifact_dir=sink,
        )
    finally:
        sink.close()
    parsed = parse_execution_result(payload)
    assert payload["attempt_id"] == ATTEMPT_ID
    assert parsed.status == "complete"
    digest = payload["artifacts"][0]["digest"]
    written = tmp_path / artifact_filename(digest)
    blob = written.read_bytes()
    assert blob == _canonical_bytes(dict(inner))
    assert hashlib.sha256(blob).hexdigest() == digest.split(":", 1)[1]
    assert payload["budget"]["spent"]["output_bytes"] == len(blob)
    names = [path for path in tmp_path.iterdir() if path.name not in (".", "..")]
    assert names == [written]
    info = written.stat()
    assert stat.S_ISREG(info.st_mode)
    assert info.st_mode & 0o777 == 0o600


@pytest.mark.skipif(
    not mode_a_supported(),
    reason="Mode A custody writes are Unix-only (dirfd-bound 0600 digest "
    "files); the Windows host contract is fail-before-dispatch",
)
def test_range_exclusive_collision_fails_closed(tmp_path: Path) -> None:
    inner = run_range(arm_ids=())
    blob = _canonical_bytes(dict(inner))
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    sink = bind_artifact_dir(str(tmp_path), attempt_id=ATTEMPT_ID)
    assert sink is not None
    planted = tmp_path / artifact_filename(digest)
    planted.write_bytes(b"tamper")
    try:
        with pytest.raises(ArtifactHandoffError, match="artifact handoff failed") as excinfo:
            encode_range_document(
                inner,
                started_at="2026-08-25T12:00:00Z",
                finished_at="2026-08-25T12:00:00Z",
                attempt_id=ATTEMPT_ID,
                artifact_dir=sink,
            )
    finally:
        sink.close()
    envelope = excinfo.value.envelope
    parsed = parse_execution_result(envelope)
    assert envelope["status"] == "failed"
    assert envelope["attempt_id"] == ATTEMPT_ID
    assert envelope["artifacts"] == []
    assert envelope["transport_ok"] is True
    assert planted.read_bytes() == b"tamper"
    assert parsed.status == "failed"
    assert parsed.result is not None
    assert parsed.result.transport_ok is True
    assert parsed.result.artifacts == ()


def test_range_out_plus_artifact_dir_rejected_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_range(monkeypatch)
    out = tmp_path / "range-result.json"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    code = range_main(
        [
            "--out",
            str(out),
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(artifacts),
        ]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "--out" in captured.err
    assert not out.exists()
    assert list(artifacts.iterdir()) == []


def test_range_non_empty_artifact_dir_rejected_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_range(monkeypatch)
    (tmp_path / "stale").write_text("nope\n", encoding="utf-8")
    code = range_main(
        ["--attempt-id", ATTEMPT_ID, "--artifact-dir", str(tmp_path)]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "must be empty" in captured.err
    assert (tmp_path / "stale").read_text(encoding="utf-8") == "nope\n"


@pytest.mark.skipif(
    not mode_a_supported(),
    reason="Mode A custody writes are Unix-only (dirfd-bound 0600 digest "
    "files); the Windows host contract is fail-before-dispatch",
)
def test_artifact_dir_replacement_after_admission_does_not_redirect(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    original = tmp_path / "artifacts"
    original.mkdir()
    parked = tmp_path / "original-inode"

    def swap_then_result(
        self: Any, arm_id: str, action: str, args: Any = None
    ) -> Result:
        original.rename(parked)
        original.mkdir()
        (original / "trap").write_text("replacement\n", encoding="utf-8")
        return _fake_list_tools()

    monkeypatch.setattr("extension.__main__.Extension.invoke", swap_then_result)
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(original),
        ]
    )
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert code == 0
    assert payload["status"] == "complete"
    digest = payload["artifacts"][0]["digest"]
    name = artifact_filename(digest)
    delivered = parked / name
    blob = delivered.read_bytes()
    assert hashlib.sha256(blob).hexdigest() == digest.split(":", 1)[1]
    assert blob == _canonical_bytes(_fake_list_tools().output)
    assert not (original / name).exists()
    assert (original / "trap").read_text(encoding="utf-8") == "replacement\n"
    names = [path.name for path in parked.iterdir()]
    assert names == [name]
    info = delivered.stat()
    assert stat.S_ISREG(info.st_mode)
    assert info.st_mode & 0o777 == 0o600
    assert parsed.result is not None
    assert parsed.result.artifacts[0].digest == digest


@pytest.mark.skipif(
    not mode_a_supported(),
    reason="Mode A custody writes are Unix-only (dirfd-bound 0600 digest "
    "files); the Windows host contract is fail-before-dispatch",
)
def test_successful_handoff_writes_exactly_one_regular_0600_digest_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    fake = _fake_list_tools()
    monkeypatch.setattr(
        "extension.__main__.Extension.invoke",
        lambda self, arm_id, action, args=None: fake,
    )
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(tmp_path),
        ]
    )
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert code == 0
    assert payload["status"] == "complete"
    assert len(payload["artifacts"]) == 1
    digest = payload["artifacts"][0]["digest"]
    written = tmp_path / artifact_filename(digest)
    names = list(tmp_path.iterdir())
    assert names == [written]
    info = os.lstat(written)
    assert stat.S_ISREG(info.st_mode)
    assert not stat.S_ISLNK(info.st_mode)
    assert info.st_mode & 0o777 == 0o600
    blob = written.read_bytes()
    assert hashlib.sha256(blob).hexdigest() == digest.split(":", 1)[1]
    assert blob == _canonical_bytes(fake.output)
    assert parsed.result is not None
    assert parsed.result.artifacts[0].digest == digest


@pytest.mark.skipif(
    not mode_a_supported(),
    reason="Mode A custody writes are Unix-only (dirfd-bound 0600 digest "
    "files); the Windows host contract is fail-before-dispatch",
)
def test_handoff_failure_clears_artifact_claims_unowned_evidence(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    fake = _fake_list_tools()
    blob = _canonical_bytes(fake.output)
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    planted = tmp_path / artifact_filename(digest)

    def plant_then_result(
        self: Any, arm_id: str, action: str, args: Any = None
    ) -> Result:
        planted.write_bytes(b"collision-bytes")
        return fake

    monkeypatch.setattr("extension.__main__.Extension.invoke", plant_then_result)
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(tmp_path),
        ]
    )
    payload = _stdout_json(capsys)
    parsed = _assert_execution_result(payload)
    assert code == 2
    assert payload["status"] == "failed"
    assert payload["artifacts"] == []
    assert payload["transport_ok"] is True
    assert "artifact handoff failed" in payload["limitations"]
    assert "unowned-evidence" in parsed.reasons
    assert parsed.status == "failed"
    assert parsed.result is not None
    assert parsed.result.transport_ok is True
    assert parsed.result.artifacts == ()
    assert planted.read_bytes() == b"collision-bytes"


def test_unsupported_mode_a_platform_fails_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls = _forbid_invoke(monkeypatch)
    # Patch the support probe, not os.name: under Python 3.13+ pathlib picks
    # the concrete Path flavor from os.name dynamically, so poisoning os.name
    # makes every later Path() a WindowsPath and crashes on POSIX hosts
    # before the gate under test is reached.
    monkeypatch.setattr("extension.encode.mode_a_supported", lambda: False)
    code = invoke_main(
        [
            "invoke",
            "agent-wiz",
            "list_tools",
            "--attempt-id",
            ATTEMPT_ID,
            "--artifact-dir",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()
    assert calls == []
    assert code == 2
    assert captured.out == ""
    assert "Unix-only" in captured.err
    assert list(tmp_path.iterdir()) == []
