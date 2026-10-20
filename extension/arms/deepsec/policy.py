"""Operator-chosen workspace rules for the deepsec arm."""

from __future__ import annotations

import os
import re
from pathlib import Path

ARM_ID = "deepsec"
ENV_BIN = "DEEPSEC_BIN"
ENV_SCAN_ROOT = "DEEPSEC_SCAN_ROOT"

ALLOWED_ACTIONS = frozenset({"init", "scan", "process", "sandbox", "revalidate"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

SCAN_KEYS = frozenset({"project_id", "root"})

TIMEOUT_SECONDS = 120.0
# Long-action override only.
ACTION_TIMEOUTS: dict[str, float] = {"process": 600.0}
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "DEEPSEC_SCAN_ROOT selects the command's working directory; if unset, "
    "the current directory is used. scan writes matcher state. process is "
    "agentic, nondeterministic, and can cost thousands of dollars."
)

_FORBIDDEN_LAUNCHERS = frozenset({"npx", "pnpm", "npm", "yarn"})
_LAUNCHER_SUFFIXES = (".cmd", ".exe", ".bat", ".ps1")
_PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_WORKSPACE_CONFIGS = (
    "deepsec.config.ts",
    "deepsec.config.js",
    "deepsec.config.mjs",
    "deepsec.config.cjs",
)
WORKSPACE_CONFIG_FAMILY = "deepsec.config.ts or .js/.mjs/.cjs"


def _launcher_stem(path: Path) -> str:
    name = path.name.lower()
    for suffix in _LAUNCHER_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _is_forbidden_launcher(path: Path) -> bool:
    return _launcher_stem(path) in _FORBIDDEN_LAUNCHERS


def _safe_resolve(raw: str, *, what: str = "path") -> tuple[Path | None, str | None]:
    if any(ord(ch) < 0x20 for ch in raw):
        return None, f"{what} contains control characters"
    try:
        return Path(raw).expanduser().resolve(), None
    except (ValueError, OSError):
        return None, f"{what} could not be resolved"


def resolve_binary() -> str | None:
    """Return a real deepsec entrypoint; package-manager launchers are not installed."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path, _ = _safe_resolve(explicit, what=ENV_BIN)
        if path is not None and path.is_file() and not _is_forbidden_launcher(path):
            return str(path)
        return None
    import shutil

    found = shutil.which("deepsec")
    if found is None:
        return None
    path = Path(found)
    if _is_forbidden_launcher(path):
        return None
    return str(path)


def resolve_workspace(*, require_config: bool = True) -> tuple[Path | None, str | None]:
    """Resolve DEEPSEC_SCAN_ROOT as the operator-chosen workspace used for cwd."""
    raw = os.environ.get(ENV_SCAN_ROOT, "").strip()
    if not raw:
        root = Path.cwd()
    else:
        root, refusal = _safe_resolve(raw, what=ENV_SCAN_ROOT)
        if root is None:
            return None, refusal
    if not root.is_dir():
        return None, f"{ENV_SCAN_ROOT} is not a directory: {root}"
    if require_config and not any((root / name).is_file() for name in _WORKSPACE_CONFIGS):
        return None, (
            f"{ENV_SCAN_ROOT} must be a workspace containing "
            f"{WORKSPACE_CONFIG_FAMILY}"
        )
    return root, None


def contain_deepsec_root(
    raw: object, workspace: Path | None = None
) -> tuple[Path | None, str | None]:
    """Resolve the operator-chosen deepsec --root path.

    The operator is accountable for the target; no containment is enforced.
    ``workspace`` is accepted for backward compatibility and ignored.
    """
    if not isinstance(raw, str) or not raw.strip() or raw.strip().startswith("-"):
        return None, "deepsec --root must be a non-flag path"
    candidate, refusal = _safe_resolve(raw.strip(), what="deepsec --root")
    if candidate is None:
        return None, refusal
    return candidate, None


def project_id_refusal(raw: object) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return "deepsec --project-id must match [A-Za-z0-9._-]{1,64}"
    text = raw.strip()
    if text.startswith("-"):
        return "deepsec --project-id must not be flag-shaped"
    if not _PROJECT_ID_RE.match(text):
        return "deepsec --project-id must match [A-Za-z0-9._-]{1,64}"
    return None


def argv_for(
    binary: str,
    action: str,
    project_id: str | None,
    root: Path | None,
) -> list[str]:
    """Commander argv: subcommand only, no positional path."""
    cmd = [binary, action]
    if project_id:
        cmd.extend(["--project-id", project_id])
    if root is not None:
        cmd.extend(["--root", str(root)])
    return cmd
