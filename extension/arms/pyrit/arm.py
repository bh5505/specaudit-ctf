"""Curated pyrit arm: first-party pyrit_scan, scope-gated scan."""

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
from ..dispatch import authorize, load_scope, log_dispatch, stamp
from ..mcp_client import redact
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    CAVEATS,
    DISPATCH_ACTIONS,
    ENV_DISPATCH_SCOPE,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    TIMEOUT_SECONDS,
    argv_for,
    canonical_host,
    resolve_binary,
    scenario_refusal,
    target_refusal,
)


def _with_caveat(message: str | None) -> str:
    text = message or "refused"
    if CAVEATS and CAVEATS not in text:
        return f"{text} Caveat: {CAVEATS}"
    return text


class PyritArm:
    """Specialized transport for catalog id pyrit.

    Wraps first-party pyrit_scan only. list_scenarios is a local read;
    scan is dispatch-class and refused until PYRIT_DISPATCH_SCOPE names
    the target host.
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
            scope, _ = load_scope(ENV_DISPATCH_SCOPE)
            return Result(
                ok=True,
                arm_id=spec.id,
                action=action,
                output={
                    "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                    "dispatch_actions": sorted(DISPATCH_ACTIONS),
                    "dispatch_armed": scope is not None,
                    "caveats": CAVEATS,
                },
                error=None,
            )
        if action not in ALLOWED_ACTIONS and action not in DISPATCH_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                f"(read: {sorted(ALLOWED_ACTIONS | LIST_ACTIONS)}; "
                f"dispatch: {sorted(DISPATCH_ACTIONS)})",
            )
        if action == "list_scenarios":
            if payload:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=f"{ARM_ID} list_scenarios takes no arguments (fixed argv)",
                )
        dispatch = action in DISPATCH_ACTIONS
        audit_target: str | None = None
        scope = None
        if dispatch:
            extra = {
                k: v
                for k, v in payload.items()
                if k not in ("scenario", "target")
            }
            if extra:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=f"{ARM_ID} scan takes only args.scenario and "
                    "args.target (fixed argv)",
                )
            refusal = scenario_refusal(payload)
            if refusal:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
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
            raw_target = str(payload["target"]).strip()
            audit_target = canonical_host(raw_target)
            scope, refusal = authorize(
                ENV_DISPATCH_SCOPE, action, audit_target
            )
            if scope is None:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=_with_caveat(refusal),
                )
            log_dispatch(ARM_ID, action, scope, audit_target)
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
            proc = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
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
                error=redact(str(exc)),
            )
        output: Any = _parse_output(proc.stdout)
        if dispatch and scope is not None:
            output = {"dispatch": stamp(scope, audit_target), "output": output}
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
