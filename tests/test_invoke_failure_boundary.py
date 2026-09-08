"""Unexpected arm failures stay inside the typed invoke boundary."""

from __future__ import annotations

import json

import pytest

from extension.__main__ import main as cli_main
from extension.contract import Extension, ExtensionError, Result
from extension.dispatch import dispatch_invoke
from extension.mcp_server import McpServer


def _raise_hostile_error(*_args: object, **_kwargs: object) -> object:
    raise AttributeError(
        "invalid JSON in secret input at /operator/private/feed.json"
    )


def _raise_hostile_extension_error(
    *_args: object, **_kwargs: object
) -> object:
    raise ExtensionError("secret input at /operator/private/feed.json")


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
    assert payload["budget"]["spent"]["tool_steps"] == 1


def _mcp_vulnify_lookup() -> dict:
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
    return response


def test_pre_dispatch_argument_failure_spends_no_tool_step() -> None:
    outcome = dispatch_invoke(
        Extension(),
        arm_id="vulnify",
        action="lookup",
        args_error=ExtensionError("invalid JSON arguments"),
    )
    assert outcome.exit_code == 2
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["budget"]["spent"]["tool_steps"] == 0


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
    response = _mcp_vulnify_lookup()

    assert response is not None
    assert "error" not in response
    assert response["result"]["isError"] is True
    payload = json.loads(response["result"]["content"][0]["text"])
    _assert_failed_vulnify_lookup(payload)
    rendered = json.dumps(response)
    assert "secret input" not in rendered
    assert "/operator/private" not in rendered


def test_invoked_extension_error_is_generic_across_direct_cli_and_mcp(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(Extension, "invoke", _raise_hostile_extension_error)
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

    code = cli_main(
        [
            "invoke",
            "vulnify",
            "lookup",
            '{"feed":"/operator/private/feed.json","cve_id":"CVE-1"}',
        ]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.strip() == "invoke failed"
    _assert_failed_vulnify_lookup(json.loads(captured.out))

    response = _mcp_vulnify_lookup()
    assert "error" not in response
    assert response["result"]["isError"] is True
    _assert_failed_vulnify_lookup(
        json.loads(response["result"]["content"][0]["text"])
    )
    rendered = json.dumps([outcome.envelope, captured.out, response])
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
    response = _mcp_vulnify_lookup()

    assert response is not None
    assert "error" not in response
    assert response["result"]["isError"] is True
    payload = json.loads(response["result"]["content"][0]["text"])
    _assert_failed_vulnify_lookup(payload)
    assert "/operator/private" not in json.dumps(response)


@pytest.mark.parametrize(
    "returned,expected_transport_ok,expected_limitation",
    [
        (
            Result(True, "agentseal", "analyze", {"value": "mismatch"}, None),
            True,
            "arm result identity did not match admitted capability",
        ),
        (
            Result(True, "vulnify", "lookup", None, None),
            True,
            "arm returned no owned evidence",
        ),
        (
            Result("false", "vulnify", "lookup", {"value": "bad bool"}, None),  # type: ignore[arg-type]
            False,
            "invoke failed",
        ),
        (
            Result(True, 7, "lookup", {"value": "bad id"}, None),  # type: ignore[arg-type]
            False,
            "invoke failed",
        ),
        (
            Result(True, "vulnify", [], {"value": "bad action"}, None),  # type: ignore[arg-type]
            False,
            "invoke failed",
        ),
        (
            Result(True, "vulnify", "lookup", {"value": "bad error"}, "error"),
            False,
            "invoke failed",
        ),
        (
            Result(False, "vulnify", "lookup", None, None),
            False,
            "invoke failed",
        ),
        (
            Result(False, "vulnify", "lookup", None, 7),  # type: ignore[arg-type]
            False,
            "invoke failed",
        ),
        (
            Result(True, "vulnify", "lookup", {"rows": {1, 2}}, None),
            False,
            "invoke failed",
        ),
        (
            Result(True, "vulnify", "lookup", {"value": object()}, None),
            False,
            "invoke failed",
        ),
        (
            Result(
                True,
                "vulnify",
                "lookup",
                {"nested": {1: "coerced-key"}},
                None,
            ),
            False,
            "invoke failed",
        ),
        (
            Result(True, "vulnify", "lookup", {"nested": (1, 2)}, None),
            False,
            "invoke failed",
        ),
        (
            Result(True, "vulnify", "lookup", {"value": float("nan")}, None),
            False,
            "invoke failed",
        ),
        (
            Result(
                False,
                "vulnify",
                "lookup",
                None,
                "secret input at /operator/private/feed.json",
            ),
            True,
            "required arm failed",
        ),
    ],
    ids=[
        "identity-mismatch",
        "unowned-evidence",
        "non-bool-ok",
        "non-string-id",
        "non-string-action",
        "success-with-error",
        "failure-without-error",
        "non-string-error",
        "set-output",
        "custom-object-output",
        "nested-non-string-output-key",
        "tuple-output",
        "non-finite-output",
        "hostile-error",
    ],
)
def test_admitted_envelope_owns_direct_cli_and_mcp_failure_signal(
    monkeypatch,
    capsys,
    returned: Result,
    expected_transport_ok: bool,
    expected_limitation: str | None,
) -> None:
    monkeypatch.setattr(Extension, "invoke", lambda *_args, **_kwargs: returned)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="vulnify",
        action="lookup",
        args={"feed": "/operator/private/feed.json", "cve_id": "CVE-1"},
    )
    assert outcome.exit_code == 1
    assert outcome.stderr_line == "invoke failed"
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["transport_ok"] is expected_transport_ok
    assert outcome.envelope["budget"]["spent"]["tool_steps"] == 1
    if expected_limitation is not None:
        assert expected_limitation in outcome.envelope["limitations"]

    code = cli_main(
        [
            "invoke",
            "vulnify",
            "lookup",
            '{"feed":"/operator/private/feed.json","cve_id":"CVE-1"}',
        ]
    )
    captured = capsys.readouterr()
    cli_payload = json.loads(captured.out)
    assert code == 1
    assert captured.err.strip() == "invoke failed"
    assert cli_payload["status"] == "failed"
    assert cli_payload["transport_ok"] is expected_transport_ok

    response = _mcp_vulnify_lookup()
    assert "error" not in response
    assert response["result"]["isError"] is True
    mcp_payload = json.loads(response["result"]["content"][0]["text"])
    assert mcp_payload["status"] == "failed"
    assert mcp_payload["transport_ok"] is expected_transport_ok

    rendered = json.dumps([outcome.envelope, cli_payload, response])
    assert "secret input" not in rendered
    assert "/operator/private" not in rendered


def test_dispatch_scope_failure_guidance_is_producer_owned_and_redacted(
    monkeypatch, capsys
) -> None:
    returned = Result(
        False,
        "nmap",
        "scan",
        None,
        "secret input at /operator/private/targets.txt",
    )
    monkeypatch.setattr(Extension, "invoke", lambda *_args, **_kwargs: returned)
    expected_line = (
        "invoke failed for nmap.scan; verify NMAP_DISPATCH_SCOPE arming and "
        "whether the request is outside the armed dispatch scope"
    )

    outcome = dispatch_invoke(
        Extension(),
        arm_id="nmap",
        action="scan",
        args={"target": "10.10.0.5"},
    )
    assert outcome.exit_code == 1
    assert outcome.stderr_line == expected_line
    assert outcome.envelope is not None

    code = cli_main(
        ["invoke", "nmap", "scan", '{"target":"10.10.0.5"}']
    )
    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.strip() == expected_line
    cli_payload = json.loads(captured.out)

    response = McpServer().handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "invoke",
                "arguments": {
                    "id": "nmap",
                    "action": "scan",
                    "args": {"target": "10.10.0.5"},
                },
            },
        }
    )
    assert response is not None and "error" not in response
    assert response["result"]["isError"] is True
    rendered = json.dumps([outcome.envelope, cli_payload, response])
    assert "secret input" not in rendered
    assert "/operator/private" not in rendered

    # The same producer-owned prompt remains non-causal when the actual defect
    # is an identity mismatch rather than an arming or scope refusal.
    mismatch = Result(
        True,
        "wrong-arm",
        "scan",
        {"value": "wrong identity"},
        None,
    )
    monkeypatch.setattr(Extension, "invoke", lambda *_args, **_kwargs: mismatch)
    mismatched = dispatch_invoke(
        Extension(),
        arm_id="nmap",
        action="scan",
        args={"target": "10.10.0.5"},
    )
    assert mismatched.exit_code == 1
    assert mismatched.stderr_line == expected_line
    assert mismatched.envelope is not None
    assert mismatched.envelope["limitations"] == [
        "arm result identity did not match admitted capability"
    ]
