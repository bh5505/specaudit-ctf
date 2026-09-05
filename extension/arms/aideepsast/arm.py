"""Curated ai-deep-sast arm: skip-llm scan, dry-run index, gated AI scan."""

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
from ..dispatch import authorize, load_scope, log_dispatch, stamp
from ..mcp_client import redact
from .policy import (
    ACTION_TIMEOUTS,
    ALLOWED_ACTIONS,
    ARM_ID,
    ARMING,
    CAVEATS,
    DISPATCH_ACTIONS,
    ENV_DISPATCH_SCOPE,
    ENV_SEMGREP_CONFIG,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    TARGET_KEYS,
    TIMEOUT_SECONDS,
    argv_for,
    contained_semgrep_config,
    contained_target,
    resolve_binary,
    resolve_deepscan_binary,
    resolve_scan_root,
)


class AiDeepSastArm:
    """Specialized transport for catalog id ai-deep-sast."""

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
        if action not in ALLOWED_ACTIONS and action not in DISPATCH_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on any tier "
                "(list_tools/scan/dry_run read; ai_scan is scope-gated dispatch)",
            )
        extra = {k: v for k, v in payload.items() if k not in TARGET_KEYS}
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="ai-deep-sast takes only args.target (fixed argv)",
            )
        root, refusal = resolve_scan_root()
        if root is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        target, refusal = contained_target(payload.get("target"))
        if target is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        if action == "dry_run":
            deepscan = resolve_deepscan_binary()
            if deepscan is None:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error="deepscan binary not configured",
                )
            return self._run(
                spec, action, argv_for(deepscan, action, target), root, None
            )
        config, refusal = contained_semgrep_config()
        if config is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        dispatch = action in DISPATCH_ACTIONS
        scope = None
        audit = f"repo:{target}"
        if dispatch:
            scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, None)
            if scope is None:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=_with_caveat(refusal),
                )
            log_dispatch(ARM_ID, action, scope, audit)
        return self._run(
            spec,
            action,
            argv_for(binary, action, target, config),
            root,
            stamp(scope, audit) if dispatch and scope is not None else None,
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
                "arming": ARMING,
                "semgrep_config": ENV_SEMGREP_CONFIG,
            },
            error=None,
        )

    def _run(
        self,
        spec: ArmSpec,
        action: str,
        cmd: list[str],
        cwd: Path,
        dispatch_stamp: dict[str, str] | None,
    ) -> Result:
        timeout = self._timeout_for(action)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
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
        output: Any = _parse_output(proc.stdout)
        if dispatch_stamp is not None:
            output = {"dispatch": dispatch_stamp, "output": output}
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


def _with_caveat(message: str | None) -> str:
    text = message or "refused"
    if CAVEATS and CAVEATS not in text:
        return f"{text} Caveat: {CAVEATS}"
    return text


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
