"""Curated routersploit arm: dispatch-only module run, scope-gated."""

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
    MODULE_RE,
    OPTION_KEYS,
    TIMEOUT_SECONDS,
    argv_for,
    canonical_target,
    extra_run_keys,
    module_refusal,
    port_refusal,
    resolve_binary,
    target_refusal,
    username_refusal,
)


def _with_caveat(message: str | None) -> str:
    text = message or "refused"
    if CAVEATS and CAVEATS not in text:
        return f"{text} Caveat: {CAVEATS}"
    return text


class RoutersploitArm:
    """Specialized transport for catalog id routersploit.

    Upstream non-interactive -m always executes the module. Dispatch is
    refused by default and authorized only by an armed
    ROUTERSPLOIT_DISPATCH_SCOPE containing the target host.
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
        if action not in DISPATCH_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(list_tools is the read surface; 'run' is scope-gated dispatch)",
            )
        extra = extra_run_keys(payload)
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="routersploit run takes only args.module, args.target, "
                "optional args.port and args.username (fixed argv)",
            )
        for refusal in (
            module_refusal(payload),
            target_refusal(payload),
            port_refusal(payload),
            username_refusal(payload),
        ):
            if refusal:
                return Result(
                    ok=False,
                    arm_id=spec.id,
                    action=action,
                    output=None,
                    error=refusal,
                )
        target = canonical_target(str(payload["target"]).strip())
        scope, refusal = authorize(ENV_DISPATCH_SCOPE, action, target)
        if scope is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=_with_caveat(refusal),
            )
        log_dispatch(ARM_ID, action, scope, target)
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
                proc = subprocess.run(
                    cmd,
                    cwd=tmp,
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
        stamped = {"dispatch": stamp(scope, target), "output": output}
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
                "module_pattern": MODULE_RE.pattern,
                "option_keys": list(OPTION_KEYS),
            },
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
