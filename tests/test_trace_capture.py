"""Server-side attempt-trace capture: chain, fail-closed sink, verifier."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extension import trace
from extension.mcp_server import McpServer

KEY_HEX = "ab" * 32
KEY = bytes.fromhex(KEY_HEX)


def _call(rpc_id: int, tool: str, arguments: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def _drive(tmp_path: Path, requests: list[dict], env_extra: dict | None = None) -> Path:
    """Serve scripted requests through McpServer.serve with tracing on."""
    trace_path = tmp_path / "trace.ndjson"
    lines = [json.dumps(request) + "\n" for request in requests]
    import io

    inn = io.StringIO("".join(lines))
    out = io.StringIO()
    import os

    environment = {
        trace.ENV_TRACE: str(trace_path),
        trace.ENV_KEY: KEY_HEX,
        trace.ENV_ATTEMPT: "c0" * 32,
    }
    environment.update(env_extra or {})
    saved = {k: os.environ.pop(k, None) for k in environment}
    os.environ.update(environment)
    try:
        code = McpServer().serve(stdin=inn, stdout=out)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    assert code == 0
    return trace_path


def _init() -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    }


def test_records_every_tool_call_with_a_verifiable_chain(tmp_path: Path) -> None:
    trace_path = _drive(
        tmp_path,
        [
            _init(),
            _call(2, "list", {}),
            _call(3, "describe", {"id": "agent-wiz"}),
        ],
    )
    verification = trace.verify_trace(trace_path, KEY)
    assert verification.ok, verification.reasons
    assert verification.close_ok is True
    assert verification.attempt_id == "c0" * 32
    assert verification.tool_calls == 2
    kinds = [record.get("type") for record in verification.records]
    assert kinds == ["call", "call", "close"]
    first = verification.records[0]
    assert first["tool"] == "list"
    assert first["result"]["isError"] is False
    assert first["result"]["envelope_status"] is None


def test_untraced_methods_and_transport_noise_are_not_records(tmp_path: Path) -> None:
    trace_path = _drive(tmp_path, [_init(), {"jsonrpc": "2.0", "id": 2, "method": "ping"}])
    verification = trace.verify_trace(trace_path, KEY)
    assert verification.ok, verification.reasons
    assert verification.tool_calls == 0, "handshake/ping are not tool evidence"
    assert [r.get("type") for r in verification.records] == ["close"]


def test_wrong_key_fails_the_chain(tmp_path: Path) -> None:
    trace_path = _drive(tmp_path, [_init(), _call(2, "list", {})])
    other = trace.verify_trace(trace_path, bytes.fromhex("cd" * 32))
    assert other.ok is False
    assert any("digest chain" in reason for reason in other.reasons)


def test_tampered_record_fails_verification(tmp_path: Path) -> None:
    trace_path = _drive(tmp_path, [_init(), _call(2, "list", {})])
    raw = trace_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(raw[0])
    record["tool"] = "run_range"  # forged claim, same HMAC
    raw[0] = json.dumps(record)
    trace_path.write_text("\n".join(raw) + "\n", encoding="utf-8")
    verification = trace.verify_trace(trace_path, KEY)
    assert verification.ok is False
    assert any("digest chain" in reason for reason in verification.reasons)


def test_missing_close_record_is_a_failed_attempt(tmp_path: Path) -> None:
    trace_path = _drive(tmp_path, [_init(), _call(2, "list", {})])
    lines = trace_path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if '"close"' not in line]
    trace_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    verification = trace.verify_trace(trace_path, KEY)
    assert verification.ok is False
    assert any("close record" in reason for reason in verification.reasons)


def test_partial_trailing_line_fails(tmp_path: Path) -> None:
    trace_path = _drive(tmp_path, [_init(), _call(2, "list", {})])
    with trace_path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq": 9, "half')
    verification = trace.verify_trace(trace_path, KEY)
    assert verification.ok is False
    assert any("partial line" in reason or "valid JSON" in reason for reason in verification.reasons)


def test_unusable_sink_refuses_to_serve(tmp_path: Path, capsys) -> None:
    import io
    import os

    missing = tmp_path / "no" / "such" / "dir" / "trace.ndjson"
    saved = {
        trace.ENV_TRACE: os.environ.pop(trace.ENV_TRACE, None),
        trace.ENV_KEY: os.environ.pop(trace.ENV_KEY, None),
    }
    os.environ[trace.ENV_TRACE] = str(missing)
    os.environ[trace.ENV_KEY] = KEY_HEX
    try:
        code = McpServer().serve(stdin=io.StringIO(""), stdout=io.StringIO())
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    assert code == 1
    assert "trace sink unusable" in capsys.readouterr().err


def test_bad_key_refuses_to_serve(tmp_path: Path, capsys) -> None:
    import io
    import os

    saved = {
        trace.ENV_TRACE: os.environ.pop(trace.ENV_TRACE, None),
        trace.ENV_KEY: os.environ.pop(trace.ENV_KEY, None),
    }
    os.environ[trace.ENV_TRACE] = str(tmp_path / "trace.ndjson")
    os.environ[trace.ENV_KEY] = "not-hex"
    try:
        code = McpServer().serve(stdin=io.StringIO(""), stdout=io.StringIO())
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    assert code == 1
    assert "64 lowercase hex" in capsys.readouterr().err


def test_capture_off_is_unchanged(tmp_path: Path) -> None:
    import io
    import os

    saved = os.environ.pop(trace.ENV_TRACE, None)
    try:
        out = io.StringIO()
        code = McpServer().serve(
            stdin=io.StringIO(json.dumps(_init()) + "\n"), stdout=out
        )
        assert code == 0
        assert "protocolVersion" in out.getvalue()
        assert not (tmp_path / "trace.ndjson").exists()
    finally:
        if saved is not None:
            os.environ[trace.ENV_TRACE] = saved


def test_secret_shaped_arguments_are_redacted(tmp_path: Path) -> None:
    trace_path = _drive(
        tmp_path,
        [
            _init(),
            _call(
                2,
                "invoke",
                {
                    "id": "x",
                    "action": "y",
                    "args": {"api_key": "supersecret", "note": "hello"},
                },
            ),
        ],
    )
    verification = trace.verify_trace(trace_path, KEY)
    assert verification.ok, verification.reasons
    args = verification.records[0]["args"]
    # Keyword redaction scrubs key name AND value (same semantics as the
    # arm-side scrubber); non-secret strings pass through.
    assert "supersecret" not in args["args"]
    assert '"note": "hello"' in args["args"]
    assert "[redacted]" in args["args"]


def test_run_range_record_carries_the_fixture_roster(tmp_path: Path) -> None:
    trace_path = _drive(tmp_path, [_init(), _call(2, "run_range", {"arm_ids": []})])
    verification = trace.verify_trace(trace_path, KEY)
    assert verification.ok, verification.reasons
    result = verification.records[0]["result"]
    assert result["isError"] is False
    assert len(result["fixture_ids"]) == 10
    assert "tf_iam_open" in result["fixture_ids"]


def test_range_fixture_ids_come_from_the_manifest() -> None:
    roster = trace.range_fixture_ids()
    assert len(roster) == 10
    assert len(set(roster)) == len(roster)
    assert "tf_iam_open" in roster
