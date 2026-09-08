"""Unexpected arm failures stay inside the typed invoke boundary."""

from __future__ import annotations

import json

from extension.__main__ import main as cli_main
from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.mcp_server import McpServer


def _raise_hostile_error(*_args: object, **_kwargs: object) -> object:
    raise AttributeError("secret input at /operator/private/feed.json")


def _assert_failed_vulnify_lookup(payload: object) -> None:
    assert isinstance(payload, dict)
    capability = "vulnify.lookup"
    assert payload["status"] == "failed"
    assert payload["transport_ok"] is False
    assert payload["scope"]["touched"] == []
    assert payload["artifacts"] == []
    assert payload["coverage"] == {
        "attempted": [capability],
        "complete": [],
        "skipped": [],
        "unsupported": [],
        "failed": [capability],
        "required": [capability],
    }
    assert payload["limitations"] == ["invoke failed"]
    assert payload["budget"]["spent"]["output_bytes"] == 0
    assert payload["budget"]["spent"]["tool_steps"] == 0


def test_dispatch_turns_unexpected_arm_exception_into_failed_envelope(
    monkeypatch,
) -> None:
    monkeypatch.setattr(Extension, "invoke", _raise_hostile_error)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="vulnify",
        action="lookup",
        args={"feed": "/operator/private/feed.json", "cve_id": "CVE-1"},
    )

    assert outcome.exit_code == 1
    assert outcome.stderr_line == "invoke failed"
    assert outcome.envelope is not None
    _assert_failed_vulnify_lookup(outcome.envelope)
    rendered = json.dumps(outcome.envelope)
    assert "secret input" not in rendered
    assert "/operator/private" not in rendered


def test_cli_unexpected_arm_exception_has_no_traceback_or_input_echo(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(Extension, "invoke", _raise_hostile_error)
    code = cli_main(
        [
            "invoke",
            "vulnify",
            "lookup",
            '{"feed":"/operator/private/feed.json","cve_id":"CVE-1"}',
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 1
    _assert_failed_vulnify_lookup(payload)
    assert captured.err.strip() == "invoke failed"
    assert "Traceback" not in captured.err
    assert "/operator/private" not in captured.out + captured.err


def test_mcp_unexpected_arm_exception_is_a_tool_failure_without_input_echo(
    monkeypatch,
) -> None:
    monkeypatch.setattr(Extension, "invoke", _raise_hostile_error)
    response = McpServer().handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "invoke",
                "arguments": {
                    "id": "vulnify",
                    "action": "lookup",
                    "args": {
                        "feed": "/operator/private/feed.json",
                        "cve_id": "CVE-1",
                    },
                },
            },
        }
    )

    assert response is not None
    assert "error" not in response
    assert response["result"]["isError"] is True
    payload = json.loads(response["result"]["content"][0]["text"])
    _assert_failed_vulnify_lookup(payload)
    rendered = json.dumps(response)
    assert "secret input" not in rendered
    assert "/operator/private" not in rendered


def test_dispatch_turns_malformed_arm_result_into_failed_envelope(
    monkeypatch,
) -> None:
    monkeypatch.setattr(Extension, "invoke", lambda *_args, **_kwargs: None)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="vulnify",
        action="lookup",
        args={"feed": "/operator/private/feed.json", "cve_id": "CVE-1"},
    )
    assert outcome.exit_code == 1
    assert outcome.stderr_line == "invoke failed"
    _assert_failed_vulnify_lookup(outcome.envelope)


def test_cli_malformed_arm_result_is_a_typed_failure(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(Extension, "invoke", lambda *_args, **_kwargs: None)
    code = cli_main(
        [
            "invoke",
            "vulnify",
            "lookup",
            '{"feed":"/operator/private/feed.json","cve_id":"CVE-1"}',
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 1
    _assert_failed_vulnify_lookup(payload)
    assert captured.err.strip() == "invoke failed"
    assert "Traceback" not in captured.err
    assert "/operator/private" not in captured.out + captured.err


def test_mcp_malformed_arm_result_is_a_typed_tool_failure(monkeypatch) -> None:
    monkeypatch.setattr(Extension, "invoke", lambda *_args, **_kwargs: None)
    response = McpServer().handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "invoke",
                "arguments": {
                    "id": "vulnify",
                    "action": "lookup",
                    "args": {
                        "feed": "/operator/private/feed.json",
                        "cve_id": "CVE-1",
                    },
                },
            },
        }
    )

    assert response is not None
    assert "error" not in response
    assert response["result"]["isError"] is True
    payload = json.loads(response["result"]["content"][0]["text"])
    _assert_failed_vulnify_lookup(payload)
    assert "/operator/private" not in json.dumps(response)
