"""Tier rules for the osmedeus arm. The scan -t argv is provisional pending upstream flag pinning."""

from __future__ import annotations

import json
import subprocess
from typing import Any, Mapping
from urllib import parse as urllib_parse

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..dispatch import authorize, log_dispatch, stamp
from ..mcp_client import redact
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    DISPATCH_ACTIONS,
    ENV_DISPATCH_SCOPE,
    MAX_OUTPUT_CHARS,
    TIMEOUT_SECONDS,
    target_refusal,
    argv_for,
    resolve_binary,
)


class OsmedeusArm:
    """Specialized transport for catalog id osmedeus."""

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
        if action not in ALLOWED_ACTIONS and action not in DISPATCH_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on any tier "
                "('assets' reads the local asset store; scan is scope-gated dispatch)",
            )
        payload = dict(args)
        dispatch = action in DISPATCH_ACTIONS
        target = self._target(action, payload)
        if isinstance(target, str) and target.startswith("REFUSAL:"):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=target[len("REFUSAL:"):],
            )
        scope = None
        if dispatch:
            scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, target)
            if scope is None:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
                )
            log_dispatch(ARM_ID, action, scope, target)
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
            output = {"dispatch": stamp(scope, target), "output": output}
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

    def _target(self, action: str, payload: dict) -> str | None:
        """Canonical dispatch target (None when scope-presence-only)."""
        if action == "scan":
            refusal = target_refusal(payload)
            if refusal:
                return "REFUSAL:" + refusal
            target = payload["target"].strip()
            parsed = urllib_parse.urlparse(
                target if "://" in target else "//" + target
            )
            return parsed.hostname or target
        return None


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
