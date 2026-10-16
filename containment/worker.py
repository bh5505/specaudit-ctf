"""Guarded child entry point: ``python -m containment.worker``.

Startup contract
----------------

* The profile arrives as JSON text in ``CONTAINMENT_PROFILE_JSON``; the
  job arrives as one JSON line on stdin (except ``mcp-server``, whose
  stdin is the MCP ndjson transport: the job line is read first, the
  remaining stream is handed to the server loop unchanged).
* The denial pipe arrives as ``CONTAINMENT_DENIAL_FD`` (POSIX raw fd) or
  ``CONTAINMENT_DENIAL_HANDLE`` (Windows: an inheritable handle VALUE,
  converted back to an fd with ``msvcrt.open_osfhandle``; ``pass_fds`` is
  not supported on Windows).
* The enforcer is installed BEFORE any target code runs. The control
  canary (``"enforced": false``) is the one deliberate exception: it
  proves the canary operations succeed in an unpoliced child, so any
  denial observed under enforcement is attributable to the enforcer.

Result reporting: one final line ``CONTAINMENT-RESULT {json}`` on stdout
(arm output may precede it; the marker prefix is unambiguous). The
``mcp-server`` job prints nothing itself -- stdout is protocol.

Exit codes: 0 ok/held/control-ok, 3 blocked-before-dispatch (job refused
by worker admission), 4 arm-error (handler raised), 7 canary-escaped.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any, Mapping

RESULT_MARKER = "CONTAINMENT-RESULT "

EXIT_OK = 0
EXIT_BLOCKED = 3
EXIT_ARM_ERROR = 4
EXIT_CANARY_ESCAPED = 7


class _JobRefused(ValueError):
    """Malformed job or profile; the child refuses before dispatch."""


def _read_denial_fd() -> int | None:
    raw_fd = os.environ.get("CONTAINMENT_DENIAL_FD")
    if raw_fd is not None and raw_fd.strip():
        return int(raw_fd)
    raw_handle = os.environ.get("CONTAINMENT_DENIAL_HANDLE")
    if raw_handle is not None and raw_handle.strip():
        import msvcrt

        return msvcrt.open_osfhandle(int(raw_handle), os.O_WRONLY)
    return None


def _read_job(stream: Any) -> dict[str, Any]:
    """Read the one job line, then leave the rest of the stream alone
    (the mcp-server job's remaining stdin is MCP ndjson protocol)."""
    line = stream.readline()
    if isinstance(line, bytes):
        line = line.decode("utf-8")
    try:
        job = json.loads(line)
    except json.JSONDecodeError as exc:
        raise _JobRefused(f"job line is not JSON: {exc}") from exc
    if not isinstance(job, dict):
        raise _JobRefused("job must be a JSON object")
    return job


def _emit_result(payload: Mapping[str, Any]) -> None:
    sys.stdout.write(
        RESULT_MARKER
        + json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))
        + "\n"
    )
    sys.stdout.flush()


def _refused(message: str) -> None:
    _emit_result({"status": "blocked-before-dispatch", "error": message})


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _arm_spec_and_handler(arm_id: str) -> tuple[Any, Any]:
    from extension.contract import ArmSpec, _default_arms

    handler = _default_arms().get(arm_id)
    if handler is None:
        raise LookupError(f"unknown arm: {arm_id}")
    spec = ArmSpec(
        id=arm_id,
        protocols=("cli",),
        curated=True,
        tier="research",
        notes="containment probe",
    )
    return spec, handler


def _run_invoke(job: Mapping[str, Any], *, delay_seconds: float = 0.0) -> int:
    """invoke-arm / sleep-invoke: direct handler.invoke under the hook.

    Same construction as the governance integrity probes: the worker
    bypasses catalog/dispatch admission on purpose -- containment is
    rehearsed at the arm layer, not re-tested at the dispatch layer.
    """
    arm_id = job.get("arm_id")
    action = job.get("action")
    payload = job.get("payload", {})
    if not isinstance(arm_id, str) or not isinstance(action, str) \
            or not isinstance(payload, dict):
        _refused("job needs string arm_id/action and object payload")
        return EXIT_BLOCKED
    if delay_seconds:
        import time

        time.sleep(min(delay_seconds, 600.0))
    try:
        spec, handler = _arm_spec_and_handler(arm_id)
    except LookupError as exc:
        _refused(str(exc))
        return EXIT_BLOCKED
    try:
        result = handler.invoke(spec, action, dict(payload))
    except Exception:  # noqa: BLE001 - sanitized child boundary
        # Keep caller paths out of the result line: type name only.
        _emit_result({"status": "arm-error", "error": "handler-raised"})
        return EXIT_ARM_ERROR
    _emit_result({
        "status": "ok" if result.ok else "refused",
        "ok": bool(result.ok),
        "error": result.error if isinstance(result.error, str) else None,
    })
    return EXIT_OK


def _canary_attempts(profile: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
    """The four escape probes, in fixed order. Each callable either
    succeeds, raises an OS error, or (when policed) raises
    PermissionError from the enforcer."""
    scratch = Path(str(profile.get("scratch_root")))
    outside = _norm(str(Path(scratch).parent / "canary-outside-target"))

    def _socket_attempt() -> None:
        # Loopback, unprivileged port 1: refusal is local, no network.
        socket.create_connection(("127.0.0.1", 1), timeout=0.5).close()

    def _popen_attempt() -> None:
        subprocess.Popen([sys.executable, "-c", "pass"]).wait()

    def _write_attempt() -> None:
        with open(scratch / "w.txt", "w", encoding="utf-8") as handle:
            handle.write("canary")

    def _symlink_attempt() -> None:
        link = scratch / "canary-link"
        if link.exists() or link.is_symlink():
            if link.is_symlink() or link.is_file():
                link.unlink()
            else:
                link.rmdir()
        os.symlink(outside, str(link))

    return (
        ("socket", _socket_attempt),
        ("subprocess", _popen_attempt),
        ("write-open", _write_attempt),
        ("symlink", _symlink_attempt),
    )


def _run_canary(*, enforced: bool) -> int:
    profile = json.loads(os.environ["CONTAINMENT_PROFILE_JSON"])
    attempts = []
    escaped = False
    scratch = Path(str(profile.get("scratch_root")))
    for name, attempt in _canary_attempts(profile):
        try:
            attempt()
        except PermissionError:
            attempts.append({"name": name, "outcome": "PermissionError"})
            if not enforced:
                # A PermissionError in an UNPOLICED child means a hook
                # leaked into the control run: the control contract
                # itself has escaped.
                escaped = True
        except OSError as exc:
            attempts.append({"name": name, "outcome": type(exc).__name__})
        else:
            attempts.append({"name": name, "outcome": "ok"})
            if enforced:
                escaped = True
    if not enforced:
        # Control-mode arena restore: the probes ran unpoliced and may
        # have left artifacts in scratch; remove them so the parent's
        # byte-clean snapshots stay meaningful. The enforced child never
        # creates anything (every probe is denied before the OS).
        for artifact in ("w.txt", "canary-link"):
            candidate = scratch / artifact
            try:
                if candidate.is_symlink() or candidate.is_file():
                    candidate.unlink()
                elif candidate.is_dir():
                    candidate.rmdir()
            except OSError:
                pass
    if escaped:
        _emit_result({"status": "escaped", "attempts": attempts})
        print("canary-escaped", file=sys.stderr)
        return EXIT_CANARY_ESCAPED
    _emit_result({
        "status": "held" if enforced else "control",
        "attempts": attempts,
    })
    return EXIT_OK


def _run_mcp_server() -> int:
    from extension.mcp_server import McpServer

    code = McpServer().serve()
    return int(code) if isinstance(code, int) else EXIT_OK


def _run_range_cli() -> int:
    """``python -m extension.range`` with no path args, under the hook."""
    from extension.range.__main__ import main as range_main

    code = range_main([])
    _emit_result({"status": "range", "exit_code": int(code)})
    return EXIT_OK


def main() -> int:
    profile_text = os.environ.get("CONTAINMENT_PROFILE_JSON")
    if not profile_text:
        _refused("CONTAINMENT_PROFILE_JSON is required")
        return EXIT_BLOCKED
    try:
        profile = json.loads(profile_text)
    except json.JSONDecodeError as exc:
        _refused(f"profile json invalid: {exc}")
        return EXIT_BLOCKED
    if not isinstance(profile, dict):
        _refused("profile must be a JSON object")
        return EXIT_BLOCKED
    try:
        job = _read_job(sys.stdin)
    except _JobRefused as exc:
        _refused(str(exc))
        return EXIT_BLOCKED
    enforced = job.get("enforced", True)
    if enforced is True:
        # Install FIRST: before any target code (extension imports, arm
        # code, MCP loop) runs in this process.
        try:
            denial_fd = _read_denial_fd()
        except (OSError, ValueError):
            denial_fd = None
        from containment.enforcer import install

        install(profile, denial_fd)
    kind = job.get("kind")
    try:
        if kind in ("invoke-arm", "sleep-invoke"):
            delay = job.get("delay", 0)
            delay_seconds = min(max(float(delay), 0.0), 600.0)
            return _run_invoke(
                job, delay_seconds=delay_seconds if kind == "sleep-invoke" else 0.0
            )
        if kind == "canary":
            return _run_canary(enforced=bool(enforced))
        if kind == "mcp-server":
            return _run_mcp_server()
        if kind == "range-cli":
            return _run_range_cli()
    except (TypeError, ValueError) as exc:
        _refused(f"malformed job parameter: {exc}")
        return EXIT_BLOCKED
    _refused(f"unknown job kind: {kind!r}")
    return EXIT_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
