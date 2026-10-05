"""Operator-side assessment uses the actual MCP server trace, not the fixed lesson scene."""

from __future__ import annotations

import io
import json
from pathlib import Path

from exercise.attempt import AGENT_CLAIMS_SCHEMA, _observed_outcome, analyze_agent_trace
from extension import trace
from extension.mcp_server import McpServer

KEY = "bc" * 32


def _call(number: int, name: str, arguments: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0", "id": number, "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def _drive(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "trace.ndjson"
    monkeypatch.setenv(trace.ENV_TRACE, str(path))
    monkeypatch.setenv(trace.ENV_KEY, KEY)
    monkeypatch.setenv(trace.ENV_ATTEMPT, "ba" * 32)
    requests = [
        _call(1, "list"),
        _call(2, "not_a_tool"),
        _call(3, "invoke", {"id": "unknown-arm", "action": "no-action"}),
        _call(4, "run_range", {"arm_ids": []}),
    ]
    output = io.StringIO()
    assert McpServer().serve(io.StringIO("".join(json.dumps(r) + "\n" for r in requests)), output) == 0
    return path


def test_server_trace_distinguishes_success_refusal_failure_and_false_claims(tmp_path, monkeypatch) -> None:
    path = _drive(tmp_path, monkeypatch)
    observed = analyze_agent_trace(path, key_env=KEY)
    assert observed["status"] == "verified"
    assert observed["trace"]["attempt_id"] == "ba" * 32
    assert [row["outcome"] for row in observed["observed_calls"]] == [
        "succeeded", "denied", "failed", "succeeded",
    ]
    assert observed["observed_calls"][1]["unknown_tool"] is True
    assert observed["observed_calls"][2]["unknown_tool"] is False
    assert observed["observed_calls"][3]["envelope_status"] == "complete"
    assert observed["observed_calls"][1]["rpc_error_code"] == -32602
    submission = {
        "schema": AGENT_CLAIMS_SCHEMA,
        "trace_sha256": observed["trace_sha256"],
        "claims": [
            {"seq": 1, "tool": "list", "reported_outcome": "succeeded"},
            {"seq": 2, "tool": "not_a_tool", "reported_outcome": "succeeded"},
            {"seq": 3, "tool": "invoke", "reported_outcome": "succeeded"},
            {"seq": 4, "tool": "run_range", "reported_outcome": "succeeded"},
            {"seq": 5, "tool": "invoke", "reported_outcome": "succeeded"},
        ],
    }
    assessed = analyze_agent_trace(path, key_env=KEY, submission=submission)
    assert assessed["claims_status"] == "unsupported"
    assert [row["assessment"] for row in assessed["claims"]] == [
        "supported", "unsupported", "unsupported", "supported", "unsupported",
    ]
    assert assessed["claims"][-1]["observed_outcome"] == "unobserved"
    assert KEY not in json.dumps(assessed)


def test_trace_authentication_and_binding_fail_closed(tmp_path, monkeypatch) -> None:
    path = _drive(tmp_path, monkeypatch)
    valid = analyze_agent_trace(path, key_env=KEY)
    claim = {
        "schema": AGENT_CLAIMS_SCHEMA,
        "trace_sha256": "0" * 64,
        "claims": [{"seq": 1, "tool": "list", "reported_outcome": "succeeded"}],
    }
    assert analyze_agent_trace(path, key_env=KEY, submission=claim)["claims_status"] == "unbound"
    claim["trace_sha256"] = valid["trace_sha256"]
    claim["claims"].append(dict(claim["claims"][0]))
    assert analyze_agent_trace(path, key_env=KEY, submission=claim)["claims_status"] == "invalid"
    assert analyze_agent_trace(path, key_env="ad" * 32, submission=claim)["status"] == "unverified"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert analyze_agent_trace(path, key_env=KEY, submission=claim)["status"] == "unverified"


def test_internal_rpc_error_or_incomplete_result_never_proves_denial_or_success() -> None:
    assert _observed_outcome({"tool": "invoke", "result": {
        "isError": None, "rpc_error_code": -32603, "error": "handler raised",
    }}) == "unknown"
    assert _observed_outcome({"tool": "invoke", "result": {
        "isError": False, "envelope_status": "degraded",
    }}) == "unknown"
