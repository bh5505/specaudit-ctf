"""The deterministic fake head: a scripted stdio-MCP client.

Plays an agent attempting a challenge through the four-tool MCP
server, hermetically — no agent CLI, no API keys, no spend. It is both
the lane's end-to-end proof and its regression harness: the real heads
(claude-code, codex-cli) must grade through exactly the same attempt
path as the personas scripted here.

Personas (all derive their found document from the challenge contract
at runtime — nothing about the challenges is hard-coded):

- ``competent``: performs genuine tool work (initialize, tools/list,
  run_range, describe, two admitted invokes) and writes the contract
  as its found findings. Passes: its claims ride on a verified trace
  that covers the fixture roster.
- ``blind-zero``: performs the handshake and NOTHING else, then writes
  the same confident findings. Fails at the lane gate: zero recorded
  tool calls, the attempt is never graded.
- ``blind-irrelevant``: performs reconnaissance only (list, describe —
  both touch no fixture by definition), then writes the same findings.
  Fails at the evidence gate: every hit is demoted to ``unverified``.

The trace itself is written server-side by the MCP server this driver
spawns; the driver only sets up the attempt directory and speaks the
protocol. The trace key and attempt id are minted by the caller (the
runner, or a test) and arrive via the environment — they never sit in
the attempt directory.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
PERSONAS = ("competent", "blind-zero", "blind-irrelevant")


class FakeHeadError(RuntimeError):
    """The persona's tool work failed — the lane is broken, fail loudly."""


def _rpc(method: str, params: dict[str, Any], rpc_id: int) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}


def _persona_calls(persona: str) -> list[dict[str, Any]]:
    """The tools/call sequence per persona (handshake handled apart)."""
    if persona == "blind-zero":
        return []
    if persona == "blind-irrelevant":
        return [
            {"name": "list", "arguments": {}},
            {"name": "describe", "arguments": {"id": "agent-wiz"}},
        ]
    from extension.arms.attackstix.policy import demo_bundle_path

    return [
        {"name": "list", "arguments": {}},
        {"name": "describe", "arguments": {"id": "agent-wiz"}},
        # Lifecycle-only: complete on every host, no binaries needed —
        # and per the range doctrine it still runs every shipped
        # fixture, so this one call covers the roster.
        {"name": "run_range", "arguments": {"arm_ids": []}},
        {"name": "invoke", "arguments": {"id": "agent-wiz", "action": "list_tools"}},
        {
            "name": "invoke",
            "arguments": {
                "id": "attack-stix-data",
                "action": "technique",
                "args": {"bundle": str(demo_bundle_path()), "id": "T1530"},
            },
        },
    ]


def run_attempt(
    persona: str,
    *,
    expected_path: Path,
    attempt_dir: Path,
) -> dict[str, Any]:
    """Play the persona against a fresh server and write the attempt."""
    expected = json.loads(Path(expected_path).read_text(encoding="utf-8"))
    attempt_dir = Path(attempt_dir)
    attempt_dir.mkdir(parents=True, exist_ok=True)

    requests: list[dict[str, Any]] = [
        _rpc(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "specaudit-ctf-fake-head", "version": "1.0.0"},
            },
            1,
        )
    ]
    for index, call in enumerate(_persona_calls(persona), start=2):
        requests.append(_rpc("tools/call", call, index))

    payload = "".join(json.dumps(request) + "\n" for request in requests)
    proc = subprocess.run(
        [sys.executable, "-m", "extension.mcp_server"],
        input=payload,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        cwd=str(REPO_ROOT),
        check=False,
    )
    if proc.returncode != 0:
        raise FakeHeadError(
            f"MCP server exited {proc.returncode}: {proc.stderr.strip()[:500]}"
        )
    responses = [
        json.loads(line)
        for line in proc.stdout.splitlines()
        if line.strip()
    ]
    if len(responses) != len(requests):
        raise FakeHeadError(
            f"expected {len(requests)} responses, got {len(responses)}"
        )
    _assert_handshake(responses[0])
    if persona != "blind-zero":
        _assert_calls(persona, responses[1:])

    found_path = attempt_dir / "found.json"
    found_path.write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "persona": persona,
        "requests": len(requests),
        "responses_ok": True,
        "found": str(found_path),
    }


def _assert_handshake(response: dict[str, Any]) -> None:
    result = response.get("result")
    if not isinstance(result, dict) or "protocolVersion" not in result:
        raise FakeHeadError(f"initialize handshake failed: {response}")


def _assert_calls(persona: str, responses: list[dict[str, Any]]) -> None:
    """A persona that claims tool work must have SUCCEEDED at it."""
    for response in responses:
        result = response.get("result")
        if not isinstance(result, dict):
            raise FakeHeadError(f"transport error in {persona} call: {response}")
        if result.get("error") is not None:
            raise FakeHeadError(f"JSON-RPC error in {persona} call: {response}")
        if result.get("isError") is True:
            raise FakeHeadError(f"tool error in {persona} call: {response}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="exercise.fake_head",
        description=(
            "Deterministic scripted MCP client: plays an agent attempting "
            "a challenge so the head lane is provable hermetically."
        ),
    )
    parser.add_argument("--persona", choices=PERSONAS, required=True)
    parser.add_argument("--expected", required=True, help="challenge expected-findings contract")
    parser.add_argument("--attempt-dir", required=True, help="attempt directory (trace lands here)")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        summary = run_attempt(
            args.persona,
            expected_path=Path(args.expected),
            attempt_dir=Path(args.attempt_dir),
        )
    except FakeHeadError as exc:
        print(f"fake_head: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
