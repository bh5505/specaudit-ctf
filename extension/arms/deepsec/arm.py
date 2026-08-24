"""Curated deepsec arm: Commander scan/process, workspace cwd, no positional path."""

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
    BLOCKED_ACTIONS,
    CAVEATS,
    DISPATCH_ACTIONS,
    ENV_DISPATCH_SCOPE,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    SCAN_KEYS,
    TIMEOUT_SECONDS,
    WORKSPACE_CONFIG_FAMILY,
    argv_for,
    contain_deepsec_root,
    project_id_refusal,
    resolve_binary,
    resolve_workspace,
)


class DeepsecArm:
    """Specialized transport for catalog id deepsec."""

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
        if action in BLOCKED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is blocked "
                "(init/sandbox/revalidate are operator-out-of-band)",
            )
        if action not in ALLOWED_ACTIONS and action not in DISPATCH_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on any tier "
                "(list_tools; scan is the unarmed matcher default; "
                "process is scope-gated dispatch)",
            )
        extra = {k: v for k, v in payload.items() if k not in SCAN_KEYS}
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="deepsec takes only args.project_id and args.root "
                "(fixed argv)",
            )
        workspace, refusal = resolve_workspace()
        if workspace is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        project_id: str | None = None
        if "project_id" in payload:
            pid_refusal = project_id_refusal(payload.get("project_id"))
            if pid_refusal:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=pid_refusal,
                )
            project_id = str(payload["project_id"]).strip()
        root: Path | None = None
        if "root" in payload:
            root, root_refusal = contain_deepsec_root(
                payload.get("root"), workspace
            )
            if root is None:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=root_refusal,
                )
        dispatch = action in DISPATCH_ACTIONS
        scope = None
        audit = f"repo:{root if root is not None else workspace}"
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
        cmd = argv_for(binary, action, project_id, root)
        return self._run(
            spec,
            action,
            cmd,
            workspace,
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
                "workspace_config": WORKSPACE_CONFIG_FAMILY,
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
