"""Curated dark-moon arm: shell launcher only."""

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
from ..mcp_client import redact, redact_url_userinfo
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    TIMEOUT_SECONDS,
    argv_for,
    resolve_binary,
    session_id_refusal,
    target_refusal,
)


class DarkMoonArm:
    """Specialized transport for catalog id dark-moon.

    Wraps darkmoon.sh (or a wrapper). MCP tool names stay unbound.
    campaign/run execute against the operator-supplied target.
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
        payload = dict(args)
        if action in LIST_ACTIONS:
            if payload:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=f"{action} takes no arguments (fixed argv)",
                )
            return Result(
                ok=True,
                arm_id=spec.id,
                action=action,
                output={
                    "actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                    "caveats": CAVEATS,
                },
                error=None,
            )
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not supported "
                f"(available: {sorted(ALLOWED_ACTIONS | LIST_ACTIONS)})",
            )
        if action == "log":
            extra = {k: v for k, v in payload.items() if k != "session_id"}
            if extra:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=f"{ARM_ID} log takes only args.session_id (fixed argv)",
                )
            refusal = session_id_refusal(payload)
            if refusal:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
                )
        if action in ("campaign", "run"):
            extra = {k: v for k, v in payload.items() if k != "target"}
            if extra:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=f"{ARM_ID} {action} takes only args.target (fixed argv)",
                )
            refusal = target_refusal(payload)
            if refusal:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
                )
        cmd = argv_for(binary, action, payload)
        if cmd is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} rejected by argv policy",
            )
        try:
            proc, overflowed = run_bounded(
                cmd,
                maximum=MAX_OUTPUT_CHARS,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"{action} timed out after {self.timeout}s",
            )
        except OSError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(redact_url_userinfo(str(exc), str(payload.get("target", "")))),
            )
        if overflowed:
            return Result(ok=False, arm_id=spec.id, action=action, output=None,
                          error="subprocess output exceeded capture cap")
        target = str(payload.get("target", ""))
        output: Any = _parse_output(redact_url_userinfo(proc.stdout, target))
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"{action} failed").strip()
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=output,
                error=redact(redact_url_userinfo(detail[:MAX_OUTPUT_CHARS], target)),
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
