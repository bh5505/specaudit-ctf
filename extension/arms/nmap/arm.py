"""Nmap arm: operator-supplied targets and options, XML on stdout."""

from __future__ import annotations

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
    MODES,
    TIMEOUT_SECONDS,
    argv_for,
    extra_scan_keys,
    host_refusal,
    mode_refusal,
    options_refusal,
    ports_refusal,
    resolve_binary,
)


class NmapArm:
    """Specialized transport for catalog id nmap.

    list_tools describes the supported actions. scan runs one
    nmap invocation with optional operator-supplied argv tokens and XML
    on stdout.
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
                error="nmap scan takes args.target and optional args.mode, "
                "args.ports, and args.options",
            )
        for refusal in (
            host_refusal(payload),
            mode_refusal(payload),
            ports_refusal(payload),
            options_refusal(payload),
        ):
            if refusal:
                return Result(
                    ok=False, arm_id=spec.id, action=action, output=None, error=refusal
                )
        target = str(payload["target"]).strip()
        mode = payload.get("mode")
        ports = payload.get("ports")
        options = payload.get("options")
        try:
            proc, overflowed = run_bounded(
                argv_for(binary, target, mode, ports, options),
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
        output = _parse_output(proc.stdout)
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
                "actions": sorted(LIST_ACTIONS | ALLOWED_ACTIONS),
                "caveats": CAVEATS,
                "modes": sorted(MODES),
                "options": "optional array of upstream nmap argv tokens",
            },
            error=None,
        )


def _parse_output(stdout: str) -> str:
    """Cap and keyword-redact the tool's text output.

    nmap emits XML (-oX -), which is free text under this arm's doctrine:
    every byte passes the redactor. There is deliberately no XML/JSON
    parser in this arm's trust path, so no structured path can bypass
    redaction.
    """
    return redact((stdout or "")[:MAX_OUTPUT_CHARS])
