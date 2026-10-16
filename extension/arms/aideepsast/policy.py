"""Path-contained rules for the ai-deep-sast arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "ai-deep-sast"
ENV_BIN = "AI_DEEP_SAST_BIN"
ENV_DEEPSCAN_BIN = "AI_DEEP_SAST_DEEPSCAN_BIN"
ENV_SCAN_ROOT = "AI_DEEP_SAST_SCAN_ROOT"
ENV_DISPATCH_SCOPE = "AI_DEEP_SAST_DISPATCH_SCOPE"
ENV_SEMGREP_CONFIG = "AI_DEEP_SAST_SEMGREP_CONFIG"

ALLOWED_ACTIONS = frozenset({"scan", "dry_run"})
DISPATCH_ACTIONS = frozenset({"ai_scan"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

TARGET_KEYS = frozenset({"target"})

TIMEOUT_SECONDS = 300.0
ACTION_TIMEOUTS: dict[str, float] = {}
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "--skip-llm scan is the safe default and requires a local "
    "AI_DEEP_SAST_SEMGREP_CONFIG inside the scan root (no registry p/ "
    "default). ai_scan runs local Foundation-Sec via llama-completion; "
    "frontier deepscan.py is not exposed beyond dry_run --dry-run."
)

ARMING = (
    f"set {ENV_DISPATCH_SCOPE}=localhost (any explicit non-blanket item); "
    f"containment is {ENV_SCAN_ROOT}"
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


def resolve_contained(raw: str | None, root_env: str) -> tuple[Path | None, str | None]:
    root_raw = os.environ.get(root_env, "").strip()
    if not root_raw:
        return None, f"{root_env} is required to contain filesystem paths"
    root, refusal = _safe_resolve(root_raw, what=root_env)
    if root is None:
        return None, refusal
    if not root.is_dir():
        return None, f"{root_env} is not a directory: {root}"
    if root == root.anchor or root.parent == root:
        return None, f"{root_env} must not be a filesystem root"
    if raw:
        candidate, refusal = _safe_resolve(raw, what="path")
        if candidate is None:
            return None, refusal
    else:
        candidate = root
    try:
        candidate.relative_to(root)
    except ValueError:
        return None, f"path must stay inside {root_env} (got {candidate}, base {root})"
    return candidate, None


def resolve_scan_root() -> tuple[Path | None, str | None]:
    return resolve_contained(None, ENV_SCAN_ROOT)


def contained_target(raw: object) -> tuple[Path | None, str | None]:
    if not isinstance(raw, str) or not raw.strip():
        return None, "ai-deep-sast actions require a path in args.target"
    text = raw.strip()
    if text.startswith("-"):
        return None, "target path must not be flag-shaped"
    path, refusal = resolve_contained(text, ENV_SCAN_ROOT)
    if path is None:
        return None, refusal
    if not path.exists():
        return None, f"target path does not exist: {path}"
    return path, None


_REGISTRY_CONFIGS = frozenset({"auto", "default"})
_REGISTRY_PREFIXES = ("p/", "r/", "registry://", "http://", "https://")


def contained_semgrep_config() -> tuple[Path | None, str | None]:
    """Local ruleset only; omitted or registry refs would pull Semgrep's registry."""
    raw = os.environ.get(ENV_SEMGREP_CONFIG, "").strip()
    if not raw:
        return None, (
            f"{ENV_SEMGREP_CONFIG} is required (local ruleset inside "
            f"{ENV_SCAN_ROOT}; no registry p/ default)"
        )
    if raw.startswith("-"):
        return None, f"{ENV_SEMGREP_CONFIG} must not be flag-shaped"
    lowered = raw.lower()
    if lowered in _REGISTRY_CONFIGS or lowered.startswith(_REGISTRY_PREFIXES):
        return None, (
            f"{ENV_SEMGREP_CONFIG} must be a local path inside {ENV_SCAN_ROOT}, "
            "not a registry ref"
        )
    path, refusal = resolve_contained(raw, ENV_SCAN_ROOT)
    if path is None:
        return None, refusal
    if not path.exists():
        return None, f"{ENV_SEMGREP_CONFIG} is not an existing path: {path}"
    return path, None


def argv_for(
    binary: str,
    action: str,
    target: Path,
    semgrep_config: Path | None = None,
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
