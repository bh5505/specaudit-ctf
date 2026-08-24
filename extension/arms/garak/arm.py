"""Curated garak arm: probe/detector listing and report reading only."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Mapping

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..mcp_client import redact
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ENV_REPORT_DIR,
    MAX_OUTPUT_CHARS,
    TIMEOUT_SECONDS,
    argv_for,
    report_dir,
    resolve_binary,
    target_bound,
)


class GarakArm:
    """Specialized transport for catalog id garak.

    Listing actions run the upstream binary with a fixed argv; the
    report action reads the newest JSONL report from GARAK_REPORT_DIR
    locally. Running probes against the bound target is not exposed.
    """

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def __init__(self, timeout: float = TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def installed(self, spec: ArmSpec) -> bool:
        return (
            spec.id == ARM_ID and resolve_binary() is not None and target_bound()
        )

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        # Install gate first: uninstalled arms raise so callers can
        # distinguish "skipped" from a real refusal.
        binary = resolve_binary()
        if binary is None or not target_bound():
            raise NotInstalledError(spec.id)
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(listing and report reading only; open-ended probe "
                "dispatch is blocked)",
            )
        if dict(args):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="garak actions take no caller arguments (fixed argv)",
            )
        if action == "report":
            return self._read_report(spec, action)
        cmd = argv_for(binary, action)
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
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"{action} failed").strip()
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
            output=redact(proc.stdout[:MAX_OUTPUT_CHARS]),
            error=None,
        )

    def _read_report(self, spec: ArmSpec, action: str) -> Result:
        path, refusal = report_dir()
        if path is None:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        reports = sorted(
            (p for p in path.glob("*.jsonl") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not reports:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"no report files (*.jsonl) in {ENV_REPORT_DIR}",
            )
        newest = reports[0]
        try:
            text = newest.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={
                "path": newest.name,
                "text": redact(text[:MAX_OUTPUT_CHARS]),
            },
            error=None,
        )
