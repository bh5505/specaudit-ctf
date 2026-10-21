"""Curated routersploit arm: operator-invoked module run."""

from __future__ import annotations

import json
import subprocess
import tempfile
from typing import Any, Mapping

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..bounded_capture import run_bounded
from ..mcp_client import redact, redact_values
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    RUN_KEYS,
    TIMEOUT_SECONDS,
    argv_for,
    extra_run_keys,
    module_refusal,
    options_refusal,
    port_refusal,
    resolve_binary,
    secret_values,
    target_refusal,
    username_refusal,
)


class RoutersploitArm:
    """Specialized transport for catalog id routersploit.

    Upstream non-interactive -m always executes the module.
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
                "(list_tools describes the supported actions; 'run' executes the selected module)",
            )
        extra = extra_run_keys(payload)
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="routersploit run takes args.module, args.target, and "
                "optional args.port, args.username, and args.options",
            )
        for refusal in (
            module_refusal(payload),
            target_refusal(payload),
            port_refusal(payload),
            username_refusal(payload),
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
        secrets = secret_values(payload)
        cmd = argv_for(binary, payload)
        if cmd is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="action 'run' rejected by argv policy",
            )
        try:
            # rsf.py opens routersploit.log in cwd; keep it off the clone.
            with tempfile.TemporaryDirectory() as tmp:
                proc, overflowed = run_bounded(
                    cmd,
                    cwd=tmp,
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
                error=_scrub(str(exc), secrets),
            )
        if overflowed:
            return Result(ok=False, arm_id=spec.id, action=action, output=None,
                          error="subprocess output exceeded capture cap")
        output: Any = _parse_output(proc.stdout, secrets)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"{action} failed").strip()
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=output,
                error=_scrub(detail[:MAX_OUTPUT_CHARS], secrets),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=output,
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
                "option_keys": sorted(RUN_KEYS),
                "options": (
                    "optional mapping of upstream module options "
                    "(for example password or other module keys) passed as "
                    "-s pairs; secret-named values are scrubbed from "
                    "reported results"
                ),
            },
            error=None,
        )


def _scrub(text: str, secrets: set[str]) -> str:
    """Keyword-redact text, scrubbing exact secret values first."""
    if secrets:
        text = redact_values(text, secrets)
    return redact(text)


def _parse_output(stdout: str, secrets: set[str]) -> Any:
    """Parse JSON tool output when valid; scrubbed raw text otherwise.

    Exact secret values are scrubbed before parsing so parsed structures
    never carry them either.
    """
    text = (stdout or "")[:MAX_OUTPUT_CHARS]
    if secrets:
        text = redact_values(text, secrets)
    stripped = text.strip()
    if stripped:
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    return redact(text)
