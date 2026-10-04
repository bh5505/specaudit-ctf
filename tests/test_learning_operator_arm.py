"""Six bounded operator workflows through actual admission and custody paths."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from extension.arms.learning_operator import ACTIONS, ARM_ID, _sample
from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.invoke_profiles import invoke_profile
from extension.mcp_server import McpServer
from extension.arms import learning_operator
from learning.operator import _parse_request, _read_report, _read_request_file
from tests.test_alt_head_mcp import _call, _content_json


@pytest.mark.parametrize("action", sorted(ACTIONS))
def test_all_samples_dispatch_and_mcp_with_real_assessments(action: str) -> None:
    args = _sample(action)
    local = dispatch_invoke(Extension(), arm_id=ARM_ID, action=action, args=args)
    assert local.exit_code == 0
    assert local.envelope["status"] == "complete"
    assert local.envelope["coverage"]["complete"] == [f"{ARM_ID}.{action}"]
    mcp = _call(McpServer(extension=Extension()), "invoke", {"id": ARM_ID, "action": action, "args": args})
    assert mcp["result"]["isError"] is False
    assert _content_json(mcp)["artifacts"] == local.envelope["artifacts"]
    result = Extension().invoke(ARM_ID, action, args).output
    assert result["request_args_sha256"] == hashlib.sha256(json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert result["assessment"]
    assert invoke_profile(ARM_ID, action).synthetic_only is False


def test_specific_outcomes_and_bounded_false_submission() -> None:
    ext = Extension()
    graph = ext.invoke(ARM_ID, "graph_path", _sample("graph_path")).output["assessment"]
    assert {path["verdict"] for path in graph["paths"]} == {"configured_candidate", "blocked", "unknown"}
    k8s = ext.invoke(ARM_ID, "k8s_review", _sample("k8s_review")).output["assessment"]
    assert {row["outcome"] for row in k8s["case_evaluations"]} == {"allowed-check-candidate", "blocked-permission", "unknown-prerequisite"}
    assert ext.invoke(ARM_ID, "workpaper_review", _sample("workpaper_review")).output["assessment"] == {"structurally_valid": True, "human_review_required": True, "errors": []}
    agent = _sample("agent_grade")
    agent["submission"]["assessments"][0]["classification"] = "rejected"
    assert ext.invoke(ARM_ID, "agent_grade", agent).output["assessment"]["passed"] is False
    assert ext.invoke(ARM_ID, "detection_review", _sample("detection_review")).output["assessment"]["stages"]["events_collected"]["state"] == "not_met"
    triage = ext.invoke(ARM_ID, "triage_evaluate", _sample("triage_evaluate")).output["assessment"]
    assert triage["evaluation_scope"] == "synthetic-format-fixture"
    assert triage["kind"] == "review-order-evaluation-only"


def test_invalid_hash_evidence_and_path_arguments_fail_closed() -> None:
    cases = []
    graph = _sample("graph_path")
    graph["graph_ndjson"] += " "
    cases.append(("graph_path", graph))
    k8s = _sample("k8s_review")
    k8s["capture"]["sha256"] = "0" * 64
    cases.append(("k8s_review", k8s))
    workpaper = _sample("workpaper_review")
    workpaper["evidence"]["evidence/gateway.json"] += " "
    cases.append(("workpaper_review", workpaper))
    triage = _sample("triage_evaluate")
    triage["ranking_json"] += " "
    cases.append(("triage_evaluate", triage))
    cases.append(("graph_path", {**_sample("graph_path"), "file": "/etc/passwd"}))
    cases.append(("detection_review", {**_sample("detection_review"), "provider_endpoint": "https://example.invalid"}))
    for action, args in cases:
        outcome = dispatch_invoke(Extension(), arm_id=ARM_ID, action=action, args=args)
        if action == "workpaper_review":
            # A structural mismatch is a completed assessment with explicit errors.
            assert outcome.exit_code == 0
            assessment = Extension().invoke(ARM_ID, action, args).output["assessment"]
            assert assessment["structurally_valid"] is False
            assert any("sha256" in error for error in assessment["errors"])
        else:
            assert outcome.exit_code != 0
            assert outcome.envelope["status"] == "failed"


def test_mode_a_local_cli_returns_verified_report(tmp_path: Path) -> None:
    for index, action in enumerate(sorted(ACTIONS)):
        request = tmp_path / f"{action}.json"
        sample = subprocess.run([sys.executable, "-m", "learning", "operator", "sample", action, "--out", str(request)], capture_output=True, text=True)
        assert sample.returncode == 0, sample.stderr
        directory = tmp_path / f"artifacts-{index}"
        directory.mkdir()
        run = subprocess.run([sys.executable, "-m", "learning", "operator", "run", "--request", str(request),
                              "--attempt-id", "attempt-" + f"{index+1:064x}", "--artifact-dir", str(directory)],
                             capture_output=True, text=True)
        assert run.returncode == 0, (action, run.stderr)
        output = json.loads(run.stdout)
        assert output["execution"]["status"] == "complete"
        assert output["report"]["workflow"] == action
        assert output["report"]["assessment"]
        assert len(list(directory.iterdir())) == 1


def test_operator_request_rejects_duplicates_and_non_json(tmp_path: Path) -> None:
    for content in ('{"arm_id":"learning-operator","arm_id":"learning-operator","action":"x","args":{}}',
                    '{"arm_id":"learning-operator","action":"x","args":{"bad":NaN}}',
                    '{"arm_id":"learning-operator","action":"x","args":{"bad":1e999}}',
                    '{"arm_id":"learning-operator","action":"x","args":{"bad":' + '[' * 65 + '0' + ']' * 65 + '}}'):
        request = tmp_path / "bad.json"
        request.write_text(content)
        result = subprocess.run([sys.executable, "-m", "learning", "operator", "run", "--request", str(request),
                                 "--attempt-id", "attempt-" + "a"*64, "--artifact-dir", str(tmp_path)],
                                capture_output=True, text=True)
        assert result.returncode == 2
        assert not result.stdout


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Unix operator file reads only")
def test_operator_request_refuses_symlink_fifo_and_directory_without_blocking(tmp_path: Path) -> None:
    regular = tmp_path / "request.json"
    regular.write_text('{"arm_id":"learning-operator","action":"list_tools","args":{}}')
    linked = tmp_path / "linked.json"
    linked.symlink_to(regular)
    fifo = tmp_path / "request.fifo"
    os.mkfifo(fifo)
    for path in (linked, fifo, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "learning", "operator", "run", "--request", str(path),
             "--attempt-id", "attempt-" + "a" * 64, "--artifact-dir", str(tmp_path)],
            capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 2
        assert not result.stdout
        assert "invalid operator request:" in result.stderr
    assert set(tmp_path.iterdir()) == {regular, linked, fifo}


def test_operator_request_rejects_mutation_and_missing_nofollow_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = tmp_path / "request.json"
    request.write_text('{}')
    real_fstat = os.fstat
    calls = 0

    def changed(fd: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        if calls == 2:
            request.write_text('{"modified":true}')
        return real_fstat(fd)

    monkeypatch.setattr(os, "fstat", changed)
    with pytest.raises(ValueError, match="changed while reading"):
        _read_request_file(request)
    monkeypatch.setattr(os, "fstat", real_fstat)
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    with pytest.raises(ValueError, match="nofollow"):
        _read_request_file(request)
    with pytest.raises(ValueError, match="nofollow"):
        _read_report(str(tmp_path), "sha256:" + "a" * 64)


def test_operator_request_strict_json_accepts_finite_numbers() -> None:
    raw = b'{"arm_id":"learning-operator","action":"list_tools","args":{"value":1e3}}'
    assert _parse_request(raw)["args"]["value"] == 1000.0


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Unix Mode A only")
def test_retained_report_refuses_symlink_and_fifo(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    artifact = tmp_path / ("sha256-" + "a" * 64)
    artifact.symlink_to(tmp_path / "other")
    with pytest.raises(OSError):
        _read_report(str(tmp_path), digest)
    artifact.unlink()
    os.mkfifo(artifact)
    with pytest.raises(ValueError, match="regular file"):
        _read_report(str(tmp_path), digest)


def test_budgets_and_unmanifested_provider_action(monkeypatch: pytest.MonkeyPatch) -> None:
    invoked = []
    monkeypatch.setattr(learning_operator, "_run", lambda action, args: invoked.append(action) or {})
    args = _sample("graph_path")
    args["graph_ndjson"] = "x" * 256_001
    outcome = dispatch_invoke(Extension(), arm_id=ARM_ID, action="graph_path", args=args)
    assert outcome.exit_code == 1 and outcome.envelope["status"] == "failed"
    assert invoked == []

    monkeypatch.setattr(learning_operator, "_run", lambda action, args: {"large": "x" * 256_001})
    result = Extension().invoke(ARM_ID, "graph_path", _sample("graph_path"))
    assert not result.ok and "result exceeds" in result.error

    outcome = dispatch_invoke(Extension(), arm_id=ARM_ID, action="provider_rank", args={"endpoint": "https://example.invalid"})
    assert outcome.exit_code != 0 and outcome.envelope["status"] == "failed"
    assert outcome.envelope["budget"]["spent"]["tool_steps"] == 0
