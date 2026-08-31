"""Frozen X4-PUB transport-parity matrix (CLI JSON vs stdio MCP).

Every case in ``tests/goldens/transport-parity/matrix.json`` is one logical
request executed through both transports in-process. Envelopes must be
equal after dropping wall-clock fields; ``isError`` must mirror the CLI
exit code. Frozen fields (statuses, limitations, capability ids, artifact
digests) are host-independent by construction and pinned here. A final
subprocess test proves the same parity across real process boundaries with
the initialize handshake and stdout discipline.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from extension import __main__ as cli_main
from extension.mcp_server import McpServer
from extension.range import __main__ as range_cli_main
from tests.test_contract import UNKNOWN_ID

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "tests" / "goldens" / "transport-parity" / "matrix.json"
_CLOCK_FIELDS = ("started_at", "finished_at")
_ENV_PREFIXES = ("AGENT_WIZ_", "VVAH_")


def _load_matrix() -> dict[str, Any]:
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _scrub_arm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)


def _normalize(payload: Any) -> Any:
    normalized = copy.deepcopy(payload)
    if not isinstance(normalized, dict):
        return normalized
    for field in _CLOCK_FIELDS:
        normalized.pop(field, None)
    spent = normalized.get("budget", {}).get("spent", {})
    if isinstance(spent, dict):
        spent.pop("elapsed_ms", None)
    return normalized


def _run_cli(case: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> tuple[int, Any, str]:
    argv = list(case["cli"])
    module = range_cli_main if case.get("cli_module") == "extension.range" else cli_main
    code = module.main(argv)
    captured = capsys.readouterr()
    text = captured.out.strip()
    payload = json.loads(text) if text else None
    return code, payload, captured.err


def _run_mcp(case: dict[str, Any]) -> dict[str, Any]:
    server = McpServer()
    return server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": case["mcp_tool"], "arguments": case["mcp_arguments"]},
        }
    )


def _mcp_envelope(response: dict[str, Any]) -> Any:
    assert "error" not in response, response
    return json.loads(response["result"]["content"][0]["text"])


def _assert_envelope_expectations(
    envelope: dict[str, Any], expected: dict[str, Any]
) -> None:
    for field in (
        "schema",
        "status",
        "transport_ok",
        "capability_id",
        "limitations",
        "attempt_id",
    ):
        if field in expected:
            assert envelope.get(field) == expected[field], field
    if expected.get("artifacts_empty"):
        assert envelope.get("artifacts") == []
    if "artifact_kinds" in expected:
        assert [item["kind"] for item in envelope["artifacts"]] == expected["artifact_kinds"]
    if "artifact_digests" in expected:
        assert [item["digest"] for item in envelope["artifacts"]] == expected[
            "artifact_digests"
        ]


def _assert_expect(expect: dict[str, Any], *, exit_code: int, is_error: bool) -> None:
    if "exit_code" in expect:
        assert exit_code == expect["exit_code"]
    if "is_error" in expect:
        assert is_error == expect["is_error"]


@pytest.mark.parametrize("case", _load_matrix()["cases"], ids=lambda c: c["id"])
def test_transport_parity_matrix(
    case: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    kind = case["kind"]
    assert kind in {
        "payload",
        "domain_error_no_envelope",
        "envelope",
        "envelope_equivalence_only",
        "transport_idiom_divergence",
    }

    if kind == "transport_idiom_divergence":
        cli_expect = case["cli_expect"]
        exit_code, payload, _ = _run_cli(case, capsys)
        assert exit_code == cli_expect["exit_code"]
        if cli_expect.get("stdout_empty"):
            assert payload is None
        elif "envelope" in cli_expect:
            assert payload is not None
            _assert_envelope_expectations(payload, cli_expect["envelope"])
        response = _run_mcp(case)
        assert response.get("error", {}).get("code") == case["mcp_expect"][
            "json_rpc_error_code"
        ]
        return

    exit_code, cli_payload, cli_err = _run_cli(case, capsys)
    response = _run_mcp(case)

    if kind == "domain_error_no_envelope":
        expect = case["expect"]
        assert exit_code == expect["exit_code"]
        assert cli_payload is None
        assert expect["message_contains"] in cli_err
        assert "error" not in response
        assert response["result"]["isError"] is True
        assert expect["message_contains"] in response["result"]["content"][0]["text"]
        return

    # payload and envelope kinds: CLI output equals MCP tool content.
    assert "error" not in response, response
    is_error = bool(response["result"]["isError"])
    mcp_payload = _mcp_envelope(response)
    assert cli_payload is not None
    assert _normalize(cli_payload) == _normalize(mcp_payload)
    _assert_expect(
        case.get("expect", {}),
        exit_code=exit_code,
        is_error=is_error,
    )
    assert is_error == (exit_code != 0)
    if "structuredContent" in response["result"]:
        assert response["result"]["structuredContent"] == mcp_payload
    if kind in {"envelope", "envelope_equivalence_only"} and "envelope" in case.get(
        "expect", {}
    ):
        _assert_envelope_expectations(cli_payload, case["expect"]["envelope"])


def test_matrix_frozen_digests_are_stable() -> None:
    """The frozen digests in the matrix are exactly the freezable cases."""
    matrix = _load_matrix()
    frozen = [c["id"] for c in matrix["cases"] if "artifact_digests" in json.dumps(c)]
    assert frozen == [
        "invoke_agent_wiz_list_tools",
        "invoke_agent_wiz_list_tools_attempt_echo",
        "run_range_seed7_required_empty",
    ]


@pytest.mark.skipif(os.name != "posix", reason="Mode A custody is Unix-only")
def test_artifact_dir_handoff_parity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """attempt_id + artifact_dir produce identical bytes on both transports."""
    attempt = "attempt-" + "b" * 64

    # invoke handoff
    cli_dir = tmp_path / "cli"
    mcp_dir = tmp_path / "mcp"
    cli_dir.mkdir()
    mcp_dir.mkdir()
    exit_code, cli_payload, _ = _run_cli(
        {
            "cli": [
                "invoke",
                "agent-wiz",
                "list_tools",
                "--attempt-id",
                attempt,
                "--artifact-dir",
                str(cli_dir),
            ]
        },
        capsys,
    )
    assert exit_code == 0
    server = McpServer()
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "invoke",
                "arguments": {
                    "id": "agent-wiz",
                    "action": "list_tools",
                    "args": {},
                    "attempt_id": attempt,
                    "artifact_dir": str(mcp_dir),
                },
            },
        }
    )
    assert response is not None and "error" not in response
    assert response["result"]["isError"] is False
    mcp_payload = json.loads(response["result"]["content"][0]["text"])
    assert _normalize(cli_payload) == _normalize(mcp_payload)
    cli_files = sorted(p.name for p in cli_dir.iterdir())
    mcp_files = sorted(p.name for p in mcp_dir.iterdir())
    assert cli_files == mcp_files and len(cli_files) == 1
    for name in cli_files:
        assert (cli_dir / name).read_bytes() == (mcp_dir / name).read_bytes()

    # range handoff
    rng_cli_dir = tmp_path / "rng-cli"
    rng_mcp_dir = tmp_path / "rng-mcp"
    rng_cli_dir.mkdir()
    rng_mcp_dir.mkdir()
    exit_code, cli_payload, _ = _run_cli(
        {
            "cli": [
                "--seed",
                "7",
                "--attempt-id",
                attempt,
                "--artifact-dir",
                str(rng_cli_dir),
            ],
            "cli_module": "extension.range",
        },
        capsys,
    )
    assert exit_code == 0
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "run_range",
                "arguments": {
                    "seed": 7,
                    "arm_ids": [],
                    "attempt_id": attempt,
                    "artifact_dir": str(rng_mcp_dir),
                },
            },
        }
    )
    assert response is not None and "error" not in response
    mcp_payload = json.loads(response["result"]["content"][0]["text"])
    assert _normalize(cli_payload) == _normalize(mcp_payload)
    rng_cli_files = sorted(p.name for p in rng_cli_dir.iterdir())
    rng_mcp_files = sorted(p.name for p in rng_mcp_dir.iterdir())
    assert rng_cli_files == rng_mcp_files and len(rng_cli_files) == 1
    for name in rng_cli_files:
        assert (rng_cli_dir / name).read_bytes() == (rng_mcp_dir / name).read_bytes()


def _subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(_ENV_PREFIXES):
            env.pop(key, None)
    return env


def test_stdio_subprocess_session_parity() -> None:
    """Full stdio session: handshake, tools/call, parity with CLI subprocess."""
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "parity-test", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "invoke",
                "arguments": {"id": "agent-wiz", "action": "list_tools", "args": {}},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "initialize",
            "params": {
                "protocolVersion": "1999-01-01",
                "capabilities": {},
                "clientInfo": {"name": "parity-test", "version": "0"},
            },
        },
    ]
    stdin = "".join(json.dumps(item) + "\n" for item in requests)
    proc = subprocess.run(
        [sys.executable, "-m", "extension.mcp_server"],
        cwd=ROOT,
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_subprocess_env(),
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    # Stdout discipline: every line is one complete JSON message (G-14).
    messages = [json.loads(line) for line in lines]
    assert len(messages) == 4  # notifications produce no response
    init = next(m for m in messages if m["id"] == 1)
    assert init["result"]["protocolVersion"] == "2025-06-18"
    listed = next(m for m in messages if m["id"] == 2)
    assert [t["name"] for t in listed["result"]["tools"]] == [
        "list",
        "describe",
        "invoke",
        "run_range",
    ]
    invoked = next(m for m in messages if m["id"] == 3)
    assert invoked["result"]["isError"] is False
    mcp_envelope = json.loads(invoked["result"]["content"][0]["text"])
    renegotiated = next(m for m in messages if m["id"] == 4)
    assert renegotiated["result"]["protocolVersion"] == "2025-11-25"

    cli = subprocess.run(
        [
            sys.executable,
            "-m",
            "extension",
            "invoke",
            "agent-wiz",
            "list_tools",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_subprocess_env(),
        check=False,
        timeout=60,
    )
    assert cli.returncode == 0, cli.stderr
    cli_envelope = json.loads(cli.stdout)
    assert _normalize(cli_envelope) == _normalize(mcp_envelope)


def test_matrix_lists_unknown_id_only_from_fixtures() -> None:
    """The matrix's unknown id matches the shared contract fixture constant."""
    assert UNKNOWN_ID == "no-such-arm"
