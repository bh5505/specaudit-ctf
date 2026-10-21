"""Wapiti DAST scan arm."""

from __future__ import annotations

import json
import subprocess
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
    ALLOWED_ACTIONS,
    ARM_ID,
    MAX_OUTPUT_CHARS,
    TIMEOUT_SECONDS,
    argv_for,
    resolve_binary,
    target_refusal,
)


class WapitiArm:
    """Specialized transport for catalog id wapiti.

    Upstream has no read-only mode; the single scan action runs the upstream scan.
    """

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
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                f"(supported: {sorted(ALLOWED_ACTIONS)})",
            )
        payload = dict(args)
        extra = {k: v for k, v in payload.items() if k != "url"}
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="wapiti scan takes only args.url (fixed argv)",
            )
        target, refusal = target_refusal(payload)
        if target is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        try:
            proc, overflowed = run_bounded(
                argv_for(binary, target),
                maximum=MAX_OUTPUT_CHARS,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"scan timed out after {self.timeout}s",
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
        report = {"output": output}
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "scan failed").strip()
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=report,
                error=redact(detail[:MAX_OUTPUT_CHARS]),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=report,
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
