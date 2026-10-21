"""Argument and process rules for the routersploit arm.

Non-interactive -m always calls command_run (never check). The operation
executes the selected module. The operator supplies the module, the target
expression, and any upstream module options; values for secret-named
options (and a password embedded in the target expression) are scrubbed
from reported results.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib import parse as urllib_parse

ARM_ID = "routersploit"
ENV_BIN = "ROUTERSPLOIT_BIN"

ALLOWED_ACTIONS = frozenset({"run"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

RUN_KEYS = frozenset({"module", "target", "port", "username", "options"})

TIMEOUT_SECONDS = 120.0
MAX_OUTPUT_CHARS = 200_000

SECRET_KEY_RE = re.compile(
    r"(token|password|passwd|secret|api[_-]?key|authorization|bearer|cookie)",
    re.IGNORECASE,
)
OPTION_KEY_MAX_LEN = 64

CAVEATS = (
    "Exploitation framework; non-interactive run always executes the module "
    "(command_run), not check. The operator chooses the module, the target "
    "expression, and any upstream module options (sent as -s pairs); "
    "secret-named option values are scrubbed from reported results."
)


def _safe_resolve(raw: str, *, what: str = "path") -> tuple[Path | None, str | None]:
    if any(ord(ch) < 0x20 for ch in raw):
        return None, f"{what} contains control characters"
    try:
        return Path(raw).expanduser().resolve(), None
    except (ValueError, OSError):
        return None, f"{what} could not be resolved"


def resolve_binary() -> str | None:
    """Return the binary path: ROUTERSPLOIT_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path, _ = _safe_resolve(explicit, what=ENV_BIN)
        if path is not None and path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("routersploit")


def extra_run_keys(payload: dict) -> frozenset[str]:
    return frozenset(payload) - RUN_KEYS


def module_refusal(payload: dict) -> str | None:
    raw = payload.get("module")
    if not isinstance(raw, str) or not raw.strip():
        return "run requires a module in args.module"
    module = raw.strip()
    if module.startswith("-"):
        return "module must not be flag-shaped"
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in module):
        return "module must be one argument without control characters"
    return None


def target_refusal(payload: dict) -> str | None:
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "run requires a target in args.target"
    target = raw.strip()
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in target):
        return "run target must be one argument without control characters"
    if target.startswith("-"):
        return "run target must not be flag-shaped"
    return None


def port_refusal(payload: dict) -> str | None:
    if "port" not in payload or payload["port"] is None:
        return None
    port = payload["port"]
    if isinstance(port, bool) or not isinstance(port, int):
        return "port must be an integer from 1 to 65535"
    if not 1 <= port <= 65535:
        return "port must be an integer from 1 to 65535"
    return None


def username_refusal(payload: dict) -> str | None:
    if "username" not in payload or payload["username"] is None:
        return None
    raw = payload["username"]
    if not isinstance(raw, str) or not raw:
        return "username must be a nonempty string"
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in raw):
        return "username must be one argument without control characters"
    return None


def options_refusal(payload: dict) -> str | None:
    if "options" not in payload or payload["options"] is None:
        return None
    options = payload["options"]
    if not isinstance(options, dict):
        return "run options must be a mapping of upstream option names to values"
    for key, value in options.items():
        if not isinstance(key, str) or not key:
            return "run option names must be nonempty strings"
        if len(key) > OPTION_KEY_MAX_LEN:
            return (
                f"run option names must be at most {OPTION_KEY_MAX_LEN} characters"
            )
        if any(ord(ch) < 33 or ord(ch) == 127 for ch in key):
            return "run option names must be one argument without control characters"
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            return f"run option {key!r} must be a string or number"
        if isinstance(value, str) and any(
            ord(ch) < 32 or ord(ch) == 127 for ch in value
        ):
            return f"run option {key!r} must not contain control characters"
    return None


def secret_values(payload: dict) -> set[str]:
    """Exact secret values to scrub from reported results.

    Values of secret-named upstream options, plus a password embedded in
    the operator-supplied target expression. Scrubbing is reporting-only:
    the values are still passed to upstream on argv.
    """
    found: set[str] = set()
    target = payload.get("target")
    if isinstance(target, str) and "@" in target and "://" in target:
        try:
            password = urllib_parse.urlsplit(target.strip()).password
        except ValueError:
            password = None
        if password:
            found.add(password)
    options = payload.get("options")
    if isinstance(options, dict):
        for key, value in options.items():
            if (
                isinstance(key, str)
                and SECRET_KEY_RE.search(key)
                and isinstance(value, (str, int, float))
                and not isinstance(value, bool)
            ):
                text = str(value)
                if text:
                    found.add(text)
    return found


def argv_for(binary: str, payload: dict) -> list[str] | None:
    """Fixed-shape argv: -m plus -s pairs for the target and module options.

    The subprocess runs without a shell, so operator-supplied values are
    single argv elements. Top-level port/username come first, then the
    options mapping in order; every entry is passed through verbatim.
    """
    module = payload.get("module")
    target = payload.get("target")
    if not isinstance(module, str) or not isinstance(target, str):
        return None
    cmd = [binary, "-m", module.strip(), "-s", f"target {target.strip()}"]
    port = payload.get("port")
    if port is not None:
        cmd.extend(["-s", f"port {int(port)}"])
    username = payload.get("username")
    if username is not None:
        cmd.extend(["-s", f"username {username}"])
    options = payload.get("options")
    if isinstance(options, dict):
        for key, value in options.items():
            cmd.extend(["-s", f"{key} {value}"])
    return cmd
