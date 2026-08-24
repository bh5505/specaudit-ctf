"""Curated checkov arm: fixed-argv offline IaC scan, fixture-contained."""

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
from ..mcp_client import redact
from .policy import (
    MAX_OUTPUT_CHARS,
    MAX_OUTPUT_ROWS,
    TIMEOUT_SECONDS,
    ALLOWED_ACTIONS,
    ARM_ID,
    argv_for,
    resolve_binary,
    resolve_scan_root,
)


class CheckovArm:
    """Specialized transport for catalog id checkov."""

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
        # Install gate first: uninstalled arms raise so callers (e.g. the
        # range runner) can distinguish "skipped" from a real refusal.
        binary = resolve_binary()
        if binary is None:
            raise NotInstalledError(spec.id)
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(only 'scan' runs, with fixed argv)",
            )
        if dict(args):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="checkov scan takes no caller arguments (fixed argv)",
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
        cmd = argv_for(binary, root)
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
                error=f"scan timed out after {self.timeout}s",
            )
        except OSError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "scan failed").strip()
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(detail[:MAX_OUTPUT_CHARS]),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=_parse_scan_output(proc.stdout),
            error=None,
        )


def _parse_scan_output(stdout: str) -> Any:
    """Parse checkov JSON output, row-capped; raw text on non-JSON."""
    stripped = stdout.strip()
    if not stripped:
        return ""
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return stripped[:MAX_OUTPUT_CHARS]
    if isinstance(data, dict):
        return _cap(data)
    if isinstance(data, list):
        return _cap(data)
    return data


def _cap(data: Any) -> Any:
    if isinstance(data, list) and len(data) > MAX_OUTPUT_ROWS:
        return data[:MAX_OUTPUT_ROWS]
    return data
