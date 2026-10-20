"""Command arguments for the agent-wiz arm."""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "agent-wiz"
ENV_BIN = "AGENT_WIZ_BIN"
ENV_SCAN_ROOT = "AGENT_WIZ_SCAN_ROOT"
ENV_OPENAI_KEY = "OPENAI_API_KEY"

ALLOWED_ACTIONS = frozenset({"extract", "visualize", "analyze"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

EXTRACT_KEYS = frozenset({"framework", "directory", "output"})
INPUT_KEYS = frozenset({"input"})

TIMEOUT_SECONDS = 60.0
# Long-action override only.
ACTION_TIMEOUTS: dict[str, float] = {"analyze": 300.0}
MAX_OUTPUT_CHARS = 200_000

# Upstream argparse choices= list verbatim (src/repello_agent_wiz/cli.py).
FRAMEWORKS = frozenset({
    "agent_chat",
    "autogen",
    "crewai",
    "google_adk",
    "langgraph",
    "llama_index",
    "n8n",
    "openai_agents",
    "pydantic",
    "swarm",
})

CAVEATS = (
    "extract and visualize use local AST/HTML processing; analyze sends "
    "data to OpenAI. AGENT_WIZ_SCAN_ROOT selects the command's working directory."
)

MISSING_OPENAI_CREDENTIAL = "OpenAI credential env is unset"


def _safe_resolve(raw: str, *, what: str = "path") -> tuple[Path | None, str | None]:
    if any(ord(ch) < 0x20 for ch in raw):
        return None, f"{what} contains control characters"
    try:
        return Path(raw).expanduser().resolve(), None
    except (ValueError, OSError):
        return None, f"{what} could not be resolved"


def resolve_binary() -> str | None:
    """Return the agent-wiz binary path: AGENT_WIZ_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path, _ = _safe_resolve(explicit, what=ENV_BIN)
        if path is not None and path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("agent-wiz")


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


def contained_path(
    raw: object, *, what: str, must_exist: str | None = None
) -> tuple[Path | None, str | None]:
    if not isinstance(raw, str) or not raw.strip():
        return None, f"{what} is required"
    text = raw.strip()
    if text.startswith("-"):
        return None, f"{what} must not be flag-shaped"
    path, refusal = _safe_resolve(text, what=what)
    if path is None:
        return None, refusal
    if must_exist == "dir" and not path.is_dir():
        return None, f"{what} is not a directory: {path}"
    if must_exist == "file" and not path.is_file():
        return None, f"{what} is not an existing file: {path}"
    return path, None


def framework_refusal(raw: object) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return "extract requires args.framework"
    text = raw.strip()
    if text.startswith("-"):
        return "framework must not be flag-shaped"
    if text not in FRAMEWORKS:
        return f"framework {text!r} is not in the argparse choices"
    return None


def openai_key_present() -> bool:
    return bool(os.environ.get(ENV_OPENAI_KEY, "").strip())


def argv_extract(binary: str, framework: str, directory: Path, output: Path) -> list[str]:
    return [
        binary,
        "extract",
        "--framework",
        framework,
        "--directory",
        str(directory),
        "--output",
        str(output),
    ]


def argv_visualize(binary: str, inp: Path) -> list[str]:
    return [binary, "visualize", "--input", str(inp)]


def argv_analyze(binary: str, inp: Path) -> list[str]:
    return [binary, "analyze", "--input", str(inp)]
