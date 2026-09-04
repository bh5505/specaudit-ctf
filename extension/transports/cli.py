"""Generic CLI transport."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)


class CliTransport:
    protocol = TRANSPORT_CLI

    def __init__(
        self,
        commands: Mapping[str, Sequence[str]] | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._commands = {key: list(value) for key, value in (commands or {}).items()}
        self.timeout = timeout

    def argv_for(self, spec: ArmSpec) -> list[str] | None:
        configured = self._commands.get(spec.id)
        if configured is not None:
            return list(configured)
        found = shutil.which(spec.id)
        if found:
            return [found]
        return None

    def installed(self, spec: ArmSpec) -> bool:
        argv = self.argv_for(spec)
        if argv is None:
            return False
        return _command_available(argv)

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        argv = self.argv_for(spec)
        if argv is None or not _command_available(argv):
            raise NotInstalledError(spec.id)
        payload = json.dumps(dict(args), separators=(",", ":"))
        cmd = [*argv, action, payload]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"timed out after {self.timeout}s: {exc}",
            )
        except OSError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=str(exc),
            )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=_decode_output(proc.stdout),
                error=detail,
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=_decode_output(proc.stdout),
            error=None,
        )


def _command_available(argv: Sequence[str]) -> bool:
    if not argv:
        return False
    head = argv[0]
    path = Path(head)
    if path.is_file():
        return True
    return shutil.which(head) is not None


def _decode_output(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return ""
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return stripped
