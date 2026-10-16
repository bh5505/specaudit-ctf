"""Bounded stdout/stderr capture for local CLI arms."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from typing import Any, BinaryIO


def run_bounded(
    cmd: list[str], timeout: float, maximum: int, *,
    input: str | None = None, env: dict[str, str] | None = None,
    cwd: str | None = None,
    stdout_file: BinaryIO | None = None, stderr_maximum: int | None = None,
) -> tuple[subprocess.CompletedProcess[str], bool]:
    """Stop the process group when the combined output reaches the byte cap.

    Return an explicit overflow flag: truncated output must never be accepted
    as a successful scan or parsed as a complete report.
    POSIX process groups cover descendants which retain the child's pipes;
    this does not confine processes that deliberately detach from that group.
    """
    if (timeout <= 0 or maximum <= 0 or
            (stderr_maximum is not None and stderr_maximum <= 0) or
            (input is not None and len(input.encode("utf-8")) > maximum)):
        raise ValueError("invalid subprocess timeout, output cap, or stdin size")
    if os.name != "posix":
        raise OSError("bounded subprocess capture requires POSIX process groups")
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(
        cmd, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
        start_new_session=True, env=env, cwd=cwd,
    )
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    lock = threading.Lock()
    total = 0
    counts = [0, 0]
    drain_errors: list[OSError] = []

    def drain(stream: Any, destination: bytearray, index: int) -> None:
        nonlocal total
        while True:
            try:
                chunk = os.read(stream.fileno(), 8192)
            except (OSError, ValueError) as exc:
                drain_errors.append(OSError(f"subprocess pipe read failed: {exc}"))
                _kill_process_tree(process)
                return
            if not chunk:
                return
            with lock:
                limit = (stderr_maximum if index == 1 and stderr_maximum is not None else maximum)
                remaining = min(limit - counts[index], maximum - total) if stdout_file is None else limit - counts[index]
                part = chunk[:max(0, remaining)]
                if index == 0 and stdout_file is not None:
                    try:
                        written = stdout_file.write(part)
                        if written != len(part):
                            raise OSError("subprocess output file short write")
                    except (OSError, ValueError) as exc:
                        drain_errors.append(OSError(f"subprocess output file write failed: {exc}"))
                        _kill_process_tree(process)
                        return
                else:
                    destination.extend(part)
                counts[index] += len(part)
                total += len(part)
                if len(chunk) > remaining:
                    overflow.set()
                    _kill_process_tree(process)
                    return

    threads = [
        threading.Thread(target=drain, args=(stream, buffer, index), daemon=True)
        for index, (stream, buffer) in enumerate(zip((process.stdout, process.stderr), buffers))
    ]
    for thread in threads:
        thread.start()
    writer_errors: list[OSError] = []

    def feed() -> None:
        if process.stdin is not None:
            try:
                process.stdin.write(input.encode("utf-8"))  # type: ignore[union-attr]
                process.stdin.close()
            except BrokenPipeError:
                pass
            except OSError as exc:
                writer_errors.append(exc)

    writer = threading.Thread(target=feed, daemon=True) if input is not None else None
    if writer is not None:
        writer.start()
    try:
        returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        for thread in threads + ([writer] if writer is not None else []):
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads + ([writer] if writer is not None else [])):
            _kill_process_tree(process)
            for thread in threads:
                thread.join(timeout=0.25)
            raise subprocess.TimeoutExpired(cmd, timeout)
        if writer_errors or drain_errors:
            raise (writer_errors + drain_errors)[0]
    except subprocess.TimeoutExpired:
        _kill_process_tree(process)
        process.wait()
        raise
    finally:
        # A CLI arm is one bounded action; discard same-group background
        # children even when they closed inherited pipes before parent exit.
        _kill_process_tree(process)
        _finish_drains(process, threads)
        if process.stdin is not None and (writer is None or not writer.is_alive()):
            process.stdin.close()
    return (
        subprocess.CompletedProcess(
            cmd, returncode, buffers[0].decode("utf-8", "replace"),
            buffers[1].decode("utf-8", "replace"),
        ), overflow.is_set(),
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
    for thread in threads:
        thread.join(timeout=0.5)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                if not any(thread.is_alive() for thread in threads):
                    stream.close()
            except OSError:
                pass
    for thread in threads:
        thread.join(timeout=0.25)
