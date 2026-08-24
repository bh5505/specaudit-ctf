"""Curated vuls arm: local report reads, dispatch-gated host scan."""

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
from ..dispatch import authorize, log_dispatch, stamp
from ..mcp_client import redact
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    BLOCKED_ACTIONS,
    DISPATCH_ACTIONS,
    ENV_DISPATCH_SCOPE,
    MAX_OUTPUT_CHARS,
    TIMEOUT_SECONDS,
    resolve_binary,
)


class VulsArm:
    """Specialized transport for catalog id vuls.

    Read tier: ``report`` / ``summary`` against the local results
    database with a fully fixed argv (no flags - some flags reach the
    network). Dispatch tier: ``scan``, authorized by
    VULS_DISPATCH_SCOPE presence (targets live in the vuls config, so
    the audit line records target=unknown). ``fetch`` is network egress
    and is on no tier.
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
        if action in BLOCKED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is blocked "
                "(network egress or interactive surface on no tier)",
            )
        if action in DISPATCH_ACTIONS:
            if dict(args):
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error="vuls scan takes no caller arguments (targets "
                    "come from the vuls config; arm with "
                    f"{ENV_DISPATCH_SCOPE})",
                )
            scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, None)
            if scope is None:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
                )
            log_dispatch(ARM_ID, action, scope, None)
            return self._run(spec, action, [binary, action], dispatch_stamp=stamp(scope, None))
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(local report and summary reads only)",
            )
        if dict(args):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="vuls report/summary take no caller arguments "
                "(fixed argv, no flags)",
            )
        return self._run(spec, action, [binary, action], dispatch_stamp=None)

    def _run(
        self,
        spec: ArmSpec,
        action: str,
        cmd: list[str],
        dispatch_stamp: dict[str, str] | None,
    ) -> Result:
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
