"""Command arguments for the ai-deep-sast arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "ai-deep-sast"
ENV_BIN = "AI_DEEP_SAST_BIN"
ENV_DEEPSCAN_BIN = "AI_DEEP_SAST_DEEPSCAN_BIN"
ENV_SCAN_ROOT = "AI_DEEP_SAST_SCAN_ROOT"
ENV_SEMGREP_CONFIG = "AI_DEEP_SAST_SEMGREP_CONFIG"

ALLOWED_ACTIONS = frozenset({"scan", "dry_run", "ai_scan"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

TARGET_KEYS = frozenset({"target"})

TIMEOUT_SECONDS = 300.0
ACTION_TIMEOUTS: dict[str, float] = {}
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "scan uses --skip-llm; ai_scan uses the configured AI backend and may "
    "send data to that backend. AI_DEEP_SAST_SEMGREP_CONFIG is optional and "
    "may refer to a local or remote Semgrep ruleset. dry_run runs deepscan.py."
)


def _safe_resolve(raw: str, *, what: str = "path") -> tuple[Path | None, str | None]:
    if any(ord(ch) < 0x20 for ch in raw):
        return None, f"{what} contains control characters"
    try:
        return Path(raw).expanduser().resolve(), None
    except (ValueError, OSError):
        return None, f"{what} could not be resolved"


def resolve_binary() -> str | None:
    """Return the aideepsast.py path: AI_DEEP_SAST_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path, _ = _safe_resolve(explicit, what=ENV_BIN)
        if path is not None and path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("aideepsast.py") or shutil.which("aideepsast")


def resolve_deepscan_binary() -> str | None:
    """Return deepscan.py when configured; missing is a dry_run refusal, not uninstall."""
    explicit = os.environ.get(ENV_DEEPSCAN_BIN)
    if explicit:
        path, _ = _safe_resolve(explicit, what=ENV_DEEPSCAN_BIN)
        if path is not None and path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("deepscan.py") or shutil.which("deepscan")


def resolve_scan_root() -> tuple[Path | None, str | None]:
    """Select the command's working directory, defaulting to the caller's."""
    raw = os.environ.get(ENV_SCAN_ROOT, "").strip()
    if not raw:
        return Path.cwd(), None
    root, refusal = _safe_resolve(raw, what=ENV_SCAN_ROOT)
    if root is None:
        return None, refusal
    if not root.is_dir():
        return None, f"{ENV_SCAN_ROOT} is not a directory: {root}"
    return root, None


def contained_target(raw: object) -> tuple[Path | None, str | None]:
    if not isinstance(raw, str) or not raw.strip():
        return None, "ai-deep-sast actions require a path in args.target"
    text = raw.strip()
    if text.startswith("-"):
        return None, "target path must not be flag-shaped"
    path, refusal = _safe_resolve(text, what="target")
    if path is None:
        return None, refusal
    if not path.exists():
        return None, f"target path does not exist: {path}"
    return path, None


def contained_semgrep_config() -> tuple[str | None, str | None]:
    """Pass an optional operator-selected Semgrep config to the command."""
    raw = os.environ.get(ENV_SEMGREP_CONFIG, "").strip()
    if not raw:
        return None, None
    if raw.startswith("-"):
        return None, f"{ENV_SEMGREP_CONFIG} must not be flag-shaped"
    if any(ord(ch) < 0x20 for ch in raw):
        return None, f"{ENV_SEMGREP_CONFIG} contains control characters"
    return raw, None


def argv_for(
    binary: str,
    action: str,
    target: Path,
    semgrep_config: str | None = None,
) -> list[str]:
    if action == "scan":
        cmd = [binary, "--target", str(target), "--skip-llm"]
        if semgrep_config is not None:
            cmd.extend(["--semgrep-config", str(semgrep_config)])
        return cmd
    if action == "dry_run":
        return [binary, "--target", str(target), "--dry-run"]
    if action == "ai_scan":
        cmd = [binary, "--target", str(target)]
        if semgrep_config is not None:
            cmd.extend(["--semgrep-config", str(semgrep_config)])
        return cmd
    return [binary, action]
