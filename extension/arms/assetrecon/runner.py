"""Hard wall/output bounds for isolated network and optional scanner workers."""
from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

from .model import Refusal
from .sources import decode


def run_worker(payload, timeout):
    if os.name != "posix":
        raise Refusal("bounded live workers require POSIX")
    if timeout <= 0.1:
        raise Refusal("insufficient worker deadline")
    payload = dict(payload, timeout=max(0.01, timeout - 0.1))
    argv = [sys.executable] + (["-S"] if sys.flags.no_site else []) + ["-m", "extension.arms.assetrecon.worker"]
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONSTARTUP", None)
    process = subprocess.Popen(argv,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True,
                               cwd=Path(__file__).resolve().parents[3], env=environment)
    try:
        process.stdin.write(json.dumps(payload).encode())
        process.stdin.close()
        chunks = []
        count = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refusal("worker deadline reached")
                if not selector.select(remaining):
                    raise Refusal("worker deadline reached")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
                if count > 1048576:
                    raise Refusal("worker output budget reached")
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if process.returncode != 0:
            raise Refusal("worker failed")
        result = decode(b"".join(chunks))
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise Refusal("provider or probe failed")
        return result
    except (OSError, subprocess.SubprocessError):
        raise Refusal("worker failed") from None
    finally:
        # Kill the entire worker session, including descendants holding pipes.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
