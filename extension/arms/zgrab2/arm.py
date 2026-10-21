"""zgrab2 arm: operator-selected module and target via separate argv/stdin."""

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
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    MODULES,
    TIMEOUT_SECONDS,
    argv_for,
    extra_scan_keys,
    host_refusal,
    module_refusal,
    options_refusal,
    port_refusal,
    resolve_binary,
    stdin_and_auth_target,
)


class Zgrab2Arm:
    """Specialized transport for catalog id zgrab2.

    list_modules supplies common examples. Scan feeds one target on stdin;
    the operator selects a module, optional port, and upstream argv options.
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
        if action == "list_modules":
            return self._list_modules(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                f"(supported: {sorted(ALLOWED_ACTIONS | LIST_ACTIONS)})",
            )
        extra = extra_scan_keys(payload)
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="zgrab2 scan takes args.target, args.module, optional args.port and args.options",
            )
        for refusal in (
            host_refusal(payload),
            module_refusal(payload),
            port_refusal(payload),
            options_refusal(payload),
        ):
            if refusal:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
                )
        stdin_host, _ = stdin_and_auth_target(str(payload["target"]))
        module = str(payload["module"]).strip()
        port = payload.get("port")
        try:
            proc, overflowed = run_bounded(
                argv_for(binary, module, port, payload.get("options")),
                input=f"{stdin_host}\n",
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
                error=redact(str(exc)),
            )
        if overflowed:
            return Result(ok=False, arm_id=spec.id, action=action, output=None,
                          error="subprocess output exceeded capture cap")
        output: Any = _parse_output(proc.stdout)
        report = {"output": output}
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"{action} failed").strip()
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

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        if payload:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="list_tools takes no arguments (fixed argv)",
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={
                "actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "caveats": CAVEATS,
                "modules": sorted(MODULES),
                "module_note": "common examples; any module accepted by the selected zgrab2 binary can be used",
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
            output={"modules": sorted(MODULES), "module_note": "common examples; any module accepted by the selected zgrab2 binary can be used"},
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
