"""Arguments and command assembly for the vvah arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "vvah"
ENV_BIN = "VVAH_BIN"

ALLOWED_ACTIONS = frozenset({"doctor", "estimate", "scan", "remediate"})
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

USAGE = "The operator chooses the repository. remediate edits source files."


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


def contained_repo(raw: object) -> tuple[Path | None, str | None]:
    if not isinstance(raw, str) or not raw.strip():
        return None, "vvah actions require a repo path in args.repo"
    text = raw.strip()
    if text.startswith("-"):
        return None, "repo path must not be flag-shaped"
    path, refusal = _safe_resolve(text, what="repo path")
    if path is None:
        return None, refusal
    if not path.is_dir():
        return None, f"repo path is not a directory: {path}"
    return path, None


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
