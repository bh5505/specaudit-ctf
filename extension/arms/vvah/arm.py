"""Vvah arm: doctor, estimate, scan, and remediation."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Mapping

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..bounded_capture import run_bounded
from ..mcp_client import redact
from .policy import (
    ACTION_TIMEOUTS,
    ALLOWED_ACTIONS,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    REPO_KEYS,
    TIMEOUT_SECONDS,
    USAGE,
    argv_for,
    contained_repo,
    resolve_binary,
)


class VvahArm:
    """Specialized transport for catalog id vvah."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def __init__(self, timeout: float = TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID and resolve_binary() is not None

    def _timeout_for(self, action: str) -> float:
        return ACTION_TIMEOUTS.get(action, self.timeout)

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        binary = resolve_binary()
        if binary is None:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"unsupported action {action!r}",
            )
        if action == "doctor":
            if payload:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error="vvah doctor takes no caller arguments (fixed argv)",
                )
            return self._run(
                spec, action, argv_for(binary, action, None), Path.cwd()
            )
        extra = {k: v for k, v in payload.items() if k not in REPO_KEYS}
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="vvah takes only args.repo (fixed argv)",
            )
        repo, refusal = contained_repo(payload.get("repo"))
        if repo is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        return self._run(
            spec,
            action,
            argv_for(binary, action, repo),
            repo,
        )

    def _list_tools(
        self, spec: ArmSpec, action: str, payload: dict
    ) -> Result:
        if payload:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="list_tools takes no caller arguments",
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={
                "actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "caveats": CAVEATS,
                "usage": USAGE,
            },
            error=None,
        )

    def _run(
        self,
        spec: ArmSpec,
        action: str,
        cmd: list[str],
        cwd: Path,
    ) -> Result:
        timeout = self._timeout_for(action)
        try:
            proc, overflowed = run_bounded(
                cmd,
                maximum=MAX_OUTPUT_CHARS,
                timeout=timeout,
                cwd=str(cwd),
            )
        except subprocess.TimeoutExpired:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"{action} timed out after {timeout}s",
            )
        except OSError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if overflowed:
            return Result(ok=False, arm_id=spec.id, action=action, output=None,
                          error="subprocess output exceeded capture cap")
        output: Any = _parse_output(proc.stdout)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"{action} failed").strip()
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=output,
                error=redact(detail[:MAX_OUTPUT_CHARS]),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=output,
            error=None,
        )


def _parse_output(stdout: str) -> Any:
    """Parse JSON tool output when valid; redacted raw text otherwise."""
    text = (stdout or "")[:MAX_OUTPUT_CHARS]
    stripped = text.strip()
    if stripped:
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    return redact(text)
