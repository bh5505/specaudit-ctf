"""Fixed-argv and scan-root rules for the checkov arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "checkov"
ENV_BIN = "CHECKOV_BIN"
ENV_SCAN_ROOT = "CHECKOV_SCAN_ROOT"

# The only action this arm runs. Every argument is fixed; callers pass
# no free-form args (an non-empty args dict is refused).
ALLOWED_ACTIONS = frozenset({"scan"})

# Offline first: --skip-download stops the policy-bundle download so a
# scan never egresses (the same doctrine as the semgrep inline rule
# pack). Operator docs still tell operators to pre-warm the bundle.
FIXED_ARGV_TAIL = (
    "--framework",
    "terraform",
    "-o",
    "json",
    "--skip-download",
)

TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_ROWS = 200
MAX_OUTPUT_CHARS = 200_000


def default_scan_root() -> Path:
    """Packaged synthetic range root: the only default scan target."""
    from ...range.runner import default_range_root

    return default_range_root()


def resolve_binary() -> str | None:
    """Return the checkov binary path: CHECKOV_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which(ARM_ID)


def resolve_scan_root() -> tuple[Path | None, str | None]:
    """Resolve and contain the scan root.

    The root must stay inside the packaged fixtures tree (the synthetic
    range). An operator-set CHECKOV_SCAN_ROOT outside that tree is the
    path blocklist firing: scanning arbitrary host directories is not
    what this arm is for.
    """
    base = default_scan_root().resolve()
    raw = os.environ.get(ENV_SCAN_ROOT)
    root = Path(raw).resolve() if raw else base
    if not root.is_dir():
        return None, f"scan root is not a directory: {root}"
    try:
        root.relative_to(base)
    except ValueError:
        return (
            None,
            "scan root must stay inside the packaged synthetic range "
            f"(got {root}, base {base})",
        )
    return root, None


def argv_for(binary: str, root: Path) -> list[str]:
    """Fixed argv; no caller-supplied fragment ever reaches it."""
    return [binary, "scan", "-d", str(root), *FIXED_ARGV_TAIL]
