"""Dispatch-only rules for the routersploit arm.

Non-interactive -m always calls command_run (never check). Default
unarmed. password is not an accepted -s key: it would sit in process
argv regardless of Result redaction.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib import parse as urllib_parse

ARM_ID = "routersploit"
ENV_BIN = "ROUTERSPLOIT_BIN"
ENV_DISPATCH_SCOPE = "ROUTERSPLOIT_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset()
DISPATCH_ACTIONS = frozenset({"run"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

OPTION_KEYS = ("target", "port", "username")
CLOSED_RUN_KEYS = frozenset({"module", "target", "port", "username"})

TIMEOUT_SECONDS = 120.0
MAX_OUTPUT_CHARS = 200_000

MODULE_RE = re.compile(
    r"^(exploits|scanners|creds|payloads|encoders|generic)/[a-z0-9_]+(/[a-z0-9_]+)*$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MODULE_MAX_LEN = 128

CAVEATS = (
    "Exploitation framework; non-interactive run always executes the module "
    "(command_run), not check. Default unarmed."
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
    return frozenset(payload) - CLOSED_RUN_KEYS


def module_refusal(payload: dict) -> str | None:
    raw = payload.get("module")
    if not isinstance(raw, str) or not raw.strip():
        return "run requires a module in args.module"
    module = raw.strip()
    if module.startswith("-"):
        return "module must not be flag-shaped"
    if len(module) > MODULE_MAX_LEN:
        return "module name is too long"
    if not MODULE_RE.match(module):
        return "module must match the closed module pattern"
    return None


def _parse_host(target: str) -> tuple[urllib_parse.ParseResult | None, str | None]:
    """Return (parsed, hostname). urlparse.hostname raises ValueError on
    malformed IPv6 (empty brackets, unclosed, IPv4-in-brackets)."""
    candidate = target if "://" in target else "//" + target
    try:
        parsed = urllib_parse.urlparse(candidate)
        host = parsed.hostname
    except ValueError:
        return None, None
    if not host:
        return None, None
    return parsed, host


def target_refusal(payload: dict) -> str | None:
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "run requires a target in args.target"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return "run target contains control characters"
    if " " in target:
        return "run target must be a hostname or http(s) URL"
    if target.startswith("-"):
        return "run target must not be flag-shaped"
    if "://" in target:
        parsed, host = _parse_host(target)
        if parsed is None or parsed.scheme not in ("http", "https") or not host:
            return "run target must be an http(s) URL or hostname"
        # userinfo would sit on argv like a password -s key.
        if (
            parsed.username is not None
            or parsed.password is not None
            or "@" in (parsed.netloc or "")
        ):
            return "run target must not include URL userinfo"
        return None
    # Unbracketed IPv6 mangles under urlparse; require brackets so the
    # audited target is the executed target.
    if ":" in target and not target.startswith("["):
        return "IPv6 targets must be bracketed"
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.[]:")
    if not target or any(ch not in allowed for ch in target.lower()):
        return "run target must be an http(s) URL or hostname"
    parsed, host = _parse_host(target)
    if parsed is None or not host:
        return "run target must be an http(s) URL or hostname"
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
    if not isinstance(raw, str) or not USERNAME_RE.match(raw):
        return "username must match [A-Za-z0-9._-]{1,64}"
    return None


def canonical_target(raw: str) -> str:
    """Hostname for authorize/log/stamp; IPv6 is bracketed."""
    _parsed, host = _parse_host(raw)
    if not host:
        return raw.strip()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 6:
        return f"[{ip}]"
    return host


def argv_for(binary: str, payload: dict) -> list[str] | None:
    """Fixed argv: -m/-s target|port|username only. No password."""
    module = payload.get("module")
    target = payload.get("target")
    if not isinstance(module, str) or not isinstance(target, str):
        return None
    cmd = [binary, "-m", module.strip(), "-s", f"target {target.strip()}"]
    port = payload.get("port")
    if port is not None:
        cmd.extend(["-s", f"port {int(port)}"])
    username = payload.get("username")
    if username:
        cmd.extend(["-s", f"username {username}"])
    return cmd
