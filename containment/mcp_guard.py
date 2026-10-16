"""One guarded MCP stdio round trip against the repo's own server.

Spawns ``python -m containment.worker`` with job kind ``mcp-server`` (the
enforcer is installed before the server loop starts), speaks ONE ndjson
JSON-RPC sequence over the pipes -- ``initialize`` then a single
``tools/call`` -- and returns both responses plus every denial record the
child appended to the pipe. This is the surface an operator uses to run
the guarded MCP server: launch the worker child with the profile env and
talk stdio exactly like any MCP client.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
import json
import os
import subprocess
import threading
from typing import Any, Mapping

from containment.harness import _drain_denials, _spawn_worker, stop_case
from containment.profile import OperatorProfile

_PROTOCOL_VERSION = "2025-06-18"


@dataclass(frozen=True)
class GuardedMcpResult:
    """Both round-trip responses and the child's denial records."""

    initialize: Mapping[str, Any]
    response: Mapping[str, Any]
    denials: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    returncode: int | None = None


def guarded_call(
    profile: OperatorProfile,
    *,
    tool: str,
    arguments: Mapping[str, Any],
    timeout: float = 90.0,
) -> GuardedMcpResult:
    """Run one guarded MCP round trip (initialize + tools/call)."""
    denial_read, denial_write = os.pipe()
    proc = _spawn_worker(
        profile, {"kind": "mcp-server"}, denial_write_fd=denial_write,
        stdin_payload=None, close_stdin=False,
    )
    # The worker is waiting on its first stdin line (the job, already
    # written by _spawn_worker); the protocol follows on the same stream.
    watchdog = threading.Timer(timeout, stop_case, args=(proc,))
    watchdog.start()
    try:
        initialize = _round_trip(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "containment-guard", "version": "1.0.0"},
            },
        })
        response = _round_trip(proc, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool, "arguments": dict(arguments)},
        })
    finally:
        watchdog.cancel()
        with contextlib.suppress(OSError):
            proc.stdin.close()
    try:
        proc.wait(timeout=30.0)
    except subprocess.TimeoutExpired:
        stop_case(proc)
        proc.wait(timeout=30.0)
    denials = _drain_denials(denial_read)
    return GuardedMcpResult(initialize, response, denials, proc.returncode)


def _round_trip(proc: subprocess.Popen, request: Mapping[str, Any]) -> Mapping[str, Any]:
    line = json.dumps(dict(request), ensure_ascii=True).encode("ascii") + b"\n"
    proc.stdin.write(line)
    proc.stdin.flush()
    raw = proc.stdout.readline()
    if not raw:
        raise OSError("guarded MCP child closed stdout before responding")
    reply = json.loads(raw.decode("utf-8"))
    if not isinstance(reply, dict):
        raise OSError("guarded MCP child sent a non-object response")
    return reply


def invoke_arguments(
    *, entry_id: str, action: str, args: Mapping[str, Any]
) -> dict[str, Any]:
    """Shape an ``invoke`` tool call per the server's declared schema."""
    return {"id": entry_id, "action": action, "args": dict(args)}
