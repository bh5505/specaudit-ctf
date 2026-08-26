"""Curated agent-wiz arm: contained extract/visualize, gated OpenAI analyze."""

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
    EXTRACT_KEYS,
    FRAMEWORKS,
    INPUT_KEYS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    MISSING_OPENAI_CREDENTIAL,
    TIMEOUT_SECONDS,
    argv_analyze,
    argv_extract,
    argv_visualize,
    contained_path,
    framework_refusal,
    openai_key_present,
    resolve_binary,
    resolve_scan_root,
)


class AgentWizArm:
    """Specialized transport for catalog id agent-wiz."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def __init__(self, timeout: float = TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def installed(self, spec: ArmSpec) -> bool:
        # list_tools enumerates from the measured bundled/catalog source (see
        # _list_tools) and needs no external agent-wiz binary. Every other
        # action still requires one; that gate lives in invoke() below, not
        # here, so a caller cannot use "not installed" to skip past it.
        return spec.id == ARM_ID

    def _timeout_for(self, action: str) -> float:
        return ACTION_TIMEOUTS.get(action, self.timeout)

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
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
                "(list_tools/extract/visualize read; analyze is "
                "scope-gated dispatch)",
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
        if action == "extract":
            return self._extract(spec, action, binary, payload, root)
        if action == "visualize":
            return self._visualize(spec, action, binary, payload, root)
        return self._analyze(spec, action, binary, payload, root)

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
                "frameworks": sorted(FRAMEWORKS),
            },
            error=None,
        )

    def _extract(
        self,
        spec: ArmSpec,
        action: str,
        binary: str,
        payload: dict,
        root: Path,
    ) -> Result:
        extra = {k: v for k, v in payload.items() if k not in EXTRACT_KEYS}
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="agent-wiz extract takes only args.framework, "
                "args.directory, and args.output (fixed argv)",
            )
        fw_refusal = framework_refusal(payload.get("framework"))
        if fw_refusal:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=fw_refusal,
            )
        directory, refusal = contained_path(
            payload.get("directory"), what="directory", must_exist="dir"
        )
        if directory is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        output, refusal = contained_path(payload.get("output"), what="output")
        if output is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        framework = str(payload["framework"]).strip()
        return self._run(
            spec,
            action,
            argv_extract(binary, framework, directory, output),
            root,
            None,
        )

    def _visualize(
        self,
        spec: ArmSpec,
        action: str,
        binary: str,
        payload: dict,
        root: Path,
    ) -> Result:
        extra = {k: v for k, v in payload.items() if k not in INPUT_KEYS}
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="agent-wiz visualize takes only args.input (fixed argv)",
            )
        inp, refusal = contained_path(
            payload.get("input"), what="input", must_exist="file"
        )
        if inp is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        return self._run(spec, action, argv_visualize(binary, inp), root, None)

    def _analyze(
        self,
        spec: ArmSpec,
        action: str,
        binary: str,
        payload: dict,
        root: Path,
    ) -> Result:
        extra = {k: v for k, v in payload.items() if k not in INPUT_KEYS}
        if extra:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="agent-wiz analyze takes only args.input (fixed argv)",
            )
        inp, refusal = contained_path(
            payload.get("input"), what="input", must_exist="file"
        )
        if inp is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        if not openai_key_present():
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=MISSING_OPENAI_CREDENTIAL,
            )
        audit = f"graph:{inp}"
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
            argv_analyze(binary, inp),
            root,
            stamp(scope, audit),
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
