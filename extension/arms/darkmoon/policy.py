"""CLI rules for the dark-moon arm (shell launcher only)."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlparse

ARM_ID = "dark-moon"
ENV_BIN = "DARK_MOON_BIN"
ENV_DISPATCH_SCOPE = "DARK_MOON_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset({"log"})
DISPATCH_ACTIONS = frozenset({"campaign", "run"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 200_000

SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

CAVEATS = (
    "Autonomous multi-agent pentest; the MCP gateway still launches "
    "Nuclei/sqlmap/NetExec/etc. inside Docker (composite egress). "
    "Unknown MCP tool names are why this arm wraps the CLI, not MCP."
)


def session_id_refusal(payload: dict) -> str | None:
    raw = payload.get("session_id")
    if not isinstance(raw, str) or not raw.strip():
        return "log requires a session id in args.session_id"
    session_id = raw.strip()
    if session_id.startswith("-"):
        return "session_id must not be flag-shaped"
    if not SESSION_ID_RE.fullmatch(session_id):
        return "session_id must match [A-Za-z0-9_-]{1,64}"
    return None


def _parsed_hostname(target: str) -> str | None:
    """urlparse hostname, or None when missing or malformed (bad IPv6)."""
    try:
        parsed = urlparse(target if "://" in target else "//" + target)
        return parsed.hostname
    except ValueError:
        return None


def target_refusal(payload: dict) -> str | None:
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "campaign/run requires a target in args.target"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return "target contains control characters"
    if " " in target:
        return "target must be a hostname or http(s) URL"
    if target.startswith("-"):
        return "target must not be flag-shaped"
    if "://" in target:
        try:
            parsed = urlparse(target)
            host = parsed.hostname
        except ValueError:
            return "target must be an http(s) URL or hostname"
        if parsed.scheme not in ("http", "https") or not host:
            return "target must be an http(s) URL or hostname"
        # userinfo would sit on argv (TARGET: <raw>); never echo the secret.
        if (
            parsed.username is not None
            or parsed.password is not None
            or "@" in (parsed.netloc or "")
        ):
            return "target must not include URL userinfo"
        return None
    # Unbracketed IPv6 mangles under urlparse.
    if ":" in target and not target.startswith("["):
        return "IPv6 targets must be bracketed"
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.[]:")
    if not target or any(ch not in allowed for ch in target.lower()):
        return "target must be an http(s) URL or hostname"
    if _parsed_hostname(target) is None:
        return "target must be an http(s) URL or hostname"
    return None


def canonical_host(target: str) -> str:
    """Hostname used for authorize / audit; argv still carries the raw target.

    IPv6 is re-bracketed: target_in_scope mangles unbracketed literals.
    """
    host = _parsed_hostname(target) or target
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 6:
        return f"[{ip}]"
    return host


def resolve_binary() -> str | None:
    """Return the launcher path: DARK_MOON_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("darkmoon") or shutil.which("darkmoon.sh")


def argv_for(binary: str, action: str, payload: dict) -> list[str] | None:
    """Fixed argv per action; no caller-controlled fragment."""
    if action == "log":
        session_id = payload.get("session_id")
        if not isinstance(session_id, str) or not session_id.strip():
            return None
        return [binary, "--log", session_id.strip()]
    if action in DISPATCH_ACTIONS:
        target = payload.get("target")
        if not isinstance(target, str) or not target.strip():
            return None
        # Upstream: ./darkmoon.sh "TARGET: example.com" — one argv token.
        return [binary, f"TARGET: {target.strip()}"]
    return None
