"""Dispatch-scoped curl transport for caller-selected HTTP headers."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
from typing import Any, Mapping

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..dispatch import authorize, log_dispatch, stamp
from ..mcp_client import redact
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    DISPATCH_ACTIONS,
    ENV_DISPATCH_SCOPE,
    MAX_OUTPUT_CHARS,
    TIMEOUT_SECONDS,
    argv_for,
    resolve_binary,
    target_refusal,
)

_SECRET_NAME_RE = re.compile(
    r"authorization|token|secret|key|password|cookie", re.IGNORECASE
)
_STATUS_RE = re.compile(r"^HTTP/\S+\s+(\d{3})(?:\s|$)")


class HttpProbeArm:
    """Specialized transport for catalog id http-probe."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def __init__(self, timeout: float = TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID and resolve_binary() is not None

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        binary = resolve_binary()
        if binary is None:
            raise NotInstalledError(spec.id)
        if action not in ALLOWED_ACTIONS and action not in DISPATCH_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on any tier "
                "(http-probe always reaches the network; 'probe' is scope-gated dispatch)",
            )

        payload = dict(args)
        refusal = target_refusal(payload)
        if refusal:
            return Result(False, spec.id, action, None, refusal)
        target = payload["url"].strip()
        headers = payload.get("headers", {})
        safe_headers, secret_masks = _masked_headers(headers)

        scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, target)
        if scope is None:
            return Result(False, spec.id, action, None, refusal)
        # Secret-bearing values have been reduced to safe_masks before the
        # dispatch audit point. log_dispatch itself records only scope/target.
        log_dispatch(ARM_ID, action, scope, target)

        cmd = argv_for(binary, action, payload)
        if cmd is None:
            return Result(
                False,
                spec.id,
                action,
                None,
                f"action {action!r} rejected by argv policy",
            )
        try:
            proc, overflowed = _run_bounded(cmd, self.timeout, MAX_OUTPUT_CHARS)
        except subprocess.TimeoutExpired:
            return Result(
                False,
                spec.id,
                action,
                None,
                f"{action} timed out after {self.timeout}s",
            )
        except OSError as exc:
            return Result(False, spec.id, action, None, redact(str(exc)))
        if overflowed:
            return Result(False, spec.id, action, None, "curl output exceeded capture cap")

        stdout = _decode(proc.stdout)
        stderr = _decode(proc.stderr)
        stdout = _scrub_values(stdout, secret_masks)
        stderr = _scrub_values(stderr, secret_masks)
        if proc.returncode != 0:
            detail = (stderr or stdout or f"{action} failed").strip()
            return Result(
                False,
                spec.id,
                action,
                None,
                redact(detail[-MAX_OUTPUT_CHARS:]),
            )

        parsed = _response(stdout[:MAX_OUTPUT_CHARS])
        if parsed is None:
            return Result(
                False,
                spec.id,
                action,
                None,
                "curl returned no parseable HTTP status",
            )
        status, body = parsed
        report = json.dumps(
            {
                "status": status,
                "headers": safe_headers,
                "body_head": redact(body[:4096]),
            },
            sort_keys=True,
        )
        return Result(
            True,
            spec.id,
            action,
            {"dispatch": stamp(scope, target), "output": report},
            None,
        )


def _run_bounded(
    cmd: list[str], timeout: float, maximum: int
) -> tuple[subprocess.CompletedProcess[bytes], bool]:
    """Drain both pipes concurrently, killing curl at a combined byte cap."""
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        shell=False,
        start_new_session=(os.name == "posix"),
    )
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    lock = threading.Lock()
    total = 0

    def drain(stream: Any, destination: bytearray) -> None:
        nonlocal total
        while True:
            try:
                chunk = stream.read(8192)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            with lock:
                remaining = maximum - total
                destination.extend(chunk[: max(0, remaining)])
                total += min(len(chunk), max(0, remaining))
                if len(chunk) > remaining:
                    overflow.set()
                    _kill_process_tree(process)
                    return

    threads = [
        threading.Thread(target=drain, args=(stream, destination), daemon=True)
        for stream, destination in zip((process.stdout, process.stderr), buffers)
    ]
    for thread in threads:
        thread.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_tree(process)
        process.wait()
        _finish_drains(process, threads)
        raise
    _finish_drains(process, threads)
    return (
        subprocess.CompletedProcess(cmd, returncode, bytes(buffers[0]), bytes(buffers[1])),
        overflow.is_set(),
    )


def _kill_process_tree(process: subprocess.Popen[Any]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        pass


def _finish_drains(process: subprocess.Popen[Any], threads: list[threading.Thread]) -> None:
    """Close inherited pipes and bound reader shutdown after curl exits."""
    for thread in threads:
        thread.join(timeout=0.25)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    for thread in threads:
        thread.join(timeout=0.25)


def _decode(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _masked_headers(headers: Mapping[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    secrets: dict[str, str] = {}
    for name, value in headers.items():
        if _SECRET_NAME_RE.search(name) or value.lower().startswith("bearer "):
            secrets[value] = value[:2] + "..." + str(len(value))
    # Mask every duplicate occurrence of a secret value, even when a caller
    # repeats it under an otherwise non-secret-looking header name.
    safe = {name: secrets.get(value, value) for name, value in headers.items()}
    return safe, secrets


def _scrub_values(text: str, masks: Mapping[str, str]) -> str:
    for value in sorted(masks, key=len, reverse=True):
        if value:
            text = text.replace(value, masks[value])
    return text


def _response(stdout: str) -> tuple[int, str] | None:
    """Split curl ``-D - -o -`` output, accepting informational blocks."""
    remaining = stdout
    status: int | None = None
    while remaining.startswith("HTTP/"):
        crlf = remaining.find("\r\n\r\n")
        lf = remaining.find("\n\n")
        candidates = [(idx, size) for idx, size in ((crlf, 4), (lf, 2)) if idx >= 0]
        if not candidates:
            return None
        end, separator_size = min(candidates)
        block = remaining[:end]
        match = _STATUS_RE.match(block.splitlines()[0] if block else "")
        if match is None:
            return None
        status = int(match.group(1))
        remaining = remaining[end + separator_size :]
        # Only an informational response can legitimately be followed by a
        # second HTTP header block. A normal response body may itself begin
        # with the bytes "HTTP/" and must remain body data.
        if not (100 <= status < 200 and remaining.startswith("HTTP/")):
            break
    if status is None:
        return None
    return status, remaining
