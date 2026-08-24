"""Curated zgrab2 arm: closed-module L7 grab, host on stdin, scope-gated."""

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
    MODULES,
    TIMEOUT_SECONDS,
    argv_for,
    extra_scan_keys,
    host_refusal,
    module_refusal,
    port_refusal,
    resolve_binary,
    stdin_and_auth_target,
)


def _with_caveat(message: str | None) -> str:
    text = message or "refused"
    if CAVEATS and CAVEATS not in text:
        return f"{text} Caveat: {CAVEATS}"
    return text


class Zgrab2Arm:
    """Specialized transport for catalog id zgrab2.

    list_modules is a static allowlist. scan feeds one host on stdin with
    a closed module set and optional --port. Dispatch is refused by
    default until ZGRAB2_DISPATCH_SCOPE names the target.
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
            return self._list_tools(spec, action, payload)
        if action in ALLOWED_ACTIONS:
            return self._list_modules(spec, action, payload)
        if action not in DISPATCH_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(list_tools/list_modules are reads; 'scan' is scope-gated dispatch)",
            )
        extra = extra_scan_keys(payload)
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="zgrab2 scan takes only args.target, args.module, "
                "optional args.port (fixed argv)",
            )
        for refusal in (
            host_refusal(payload),
            module_refusal(payload),
            port_refusal(payload),
        ):
            if refusal:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
                )
        stdin_host, auth_target = stdin_and_auth_target(str(payload["target"]))
        module = str(payload["module"]).strip()
        port = payload.get("port")
        scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, auth_target)
        if scope is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=_with_caveat(refusal),
            )
        log_dispatch(ARM_ID, action, scope, auth_target)
        try:
            proc = subprocess.run(
                argv_for(binary, module, port),
                input=f"{stdin_host}\n",
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
        stamped = {"dispatch": stamp(scope, auth_target), "output": output}
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"{action} failed").strip()
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=stamped,
                error=redact(detail[:MAX_OUTPUT_CHARS]),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=stamped,
            error=None,
        )

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        if payload:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="list_tools takes no arguments (fixed argv)",
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
                "modules": sorted(MODULES),
            },
            error=None,
        )

    def _list_modules(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        if payload:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="list_modules takes no arguments (fixed argv)",
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"modules": sorted(MODULES)},
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
