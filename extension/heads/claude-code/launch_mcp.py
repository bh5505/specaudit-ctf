"""Run the MCP server with this clone first on sys.path."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _is_clone(path: Path) -> bool:
    return (path / "extension" / "mcp_server.py").is_file()


def _clone_root() -> Path:
    # This file, then SPECAUDIT_CTF_ROOT / CLAUDE_PROJECT_DIR — never cwd.
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if _is_clone(parent):
            return parent
    for key in ("SPECAUDIT_CTF_ROOT", "CLAUDE_PROJECT_DIR"):
        raw = os.environ.get(key, "").strip()
        if not raw:
            continue
        candidate = Path(raw).expanduser()
        if _is_clone(candidate):
            return candidate
    raise SystemExit(
        "specaudit-ctf clone not found; set SPECAUDIT_CTF_ROOT to the clone root"
    )


def main() -> int:
    root = str(_clone_root())
    if sys.path[:1] != [root]:
        sys.path.insert(0, root)
    from extension.mcp_server import main as mcp_main

    return mcp_main()


if __name__ == "__main__":
    raise SystemExit(main())
