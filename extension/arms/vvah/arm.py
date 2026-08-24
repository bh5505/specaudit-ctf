"""Curated vvah arm: path-contained reads, s9 scan, dual-gated remediate."""

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
    ENV_ALLOW_REMEDIATE,
    ENV_DISPATCH_SCOPE,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    REPO_KEYS,
    TIMEOUT_SECONDS,
    argv_for,
    contained_repo,
    remediate_gate_refusal,
    resolve_binary,
    resolve_scan_root,
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
        if action not in ALLOWED_ACTIONS and action not in DISPATCH_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on any tier "
                "(list_tools/doctor/estimate read; scan and remediate are "
                "scope-gated dispatch; validate is not exposed)",
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
            root, refusal = resolve_scan_root()
            if root is None:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
                )
            return self._run(
                spec, action, argv_for(binary, action, None), root, None
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
        root, refusal = resolve_scan_root()
        if root is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
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
        dispatch = action in DISPATCH_ACTIONS
        scope = None
        audit = f"repo:{repo}"
        if action == "remediate":
            gate = remediate_gate_refusal()
            if gate:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=gate,
                )
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
            argv_for(binary, action, repo),
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
                "remediate_gate": f"{ENV_ALLOW_REMEDIATE}=1",
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
