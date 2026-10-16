"""Path-contained rules for the vvah arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "vvah"
ENV_BIN = "VVAH_BIN"
ENV_SCAN_ROOT = "VVAH_SCAN_ROOT"
ENV_DISPATCH_SCOPE = "VVAH_DISPATCH_SCOPE"
ENV_ALLOW_REMEDIATE = "VVAH_ALLOW_REMEDIATE"

ALLOWED_ACTIONS = frozenset({"doctor", "estimate"})
DISPATCH_ACTIONS = frozenset({"scan", "remediate"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

REPO_KEYS = frozenset({"repo"})

TIMEOUT_SECONDS = 600.0
ACTION_TIMEOUTS: dict[str, float] = {"remediate": 600.0}
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "Eleven-stage agentic pipeline; nondeterministic; may spend model tokens "
    "and egress. doctor live-probes configured backends (may spend tokens); "
    "estimate spends nothing. scan --stop-after s9 does not edit source; "
    "remediate does. cwd is the scan root."
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
    """Return the vvaharness binary path: VVAH_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path, _ = _safe_resolve(explicit, what=ENV_BIN)
        if path is not None and path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("vvaharness")


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


def contained_repo(raw: object) -> tuple[Path | None, str | None]:
    if not isinstance(raw, str) or not raw.strip():
        return None, "vvah actions require a repo path in args.repo"
    text = raw.strip()
    if text.startswith("-"):
        return None, "repo path must not be flag-shaped"
    path, refusal = resolve_contained(text, ENV_SCAN_ROOT)
    if path is None:
        return None, refusal
    if not path.is_dir():
        return None, f"repo path is not a directory: {path}"
    return path, None


def remediate_gate_refusal() -> str | None:
    if os.environ.get(ENV_ALLOW_REMEDIATE) != "1":
        return (
            f"action 'remediate' requires {ENV_ALLOW_REMEDIATE}=1 "
            f"and {ENV_DISPATCH_SCOPE}"
        )
    return None


def argv_for(binary: str, action: str, repo: Path | None) -> list[str]:
    if action == "doctor":
        return [binary, "doctor"]
    if action == "estimate":
        return [binary, "estimate", "--repo", str(repo)]
    if action == "scan":
        return [binary, "scan", "--repo", str(repo), "--stop-after", "s9"]
    if action == "remediate":
        return [binary, "remediate", "--repo", str(repo)]
    return [binary, action]
