"""Dispatch-only rules for the sniper arm.

Upstream sniper is a composite harness with no read-only mode. port and
discover are not allowlisted (port needs -p; discover is fleet-wide recon).
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from urllib import parse as urllib_parse

ARM_ID = "sniper"
ENV_BIN = "SNIPER_BIN"
ENV_DISPATCH_SCOPE = "SNIPER_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset()
DISPATCH_ACTIONS = frozenset({"scan"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MODES = frozenset({"normal", "stealth", "web", "fullportonly"})
CLOSED_SCAN_KEYS = frozenset({"target", "mode"})

TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "Scoping the named target does not bound 90+ sub-tools (nmap, nuclei, "
    "and others). Community sniper must run as root (EUID -ne 0 exits 1). "
    "Once armed, an in-scope -t still performs check_online telemetry "
    "(version + machine-id). Operators who accept composite egress, root, "
    "and telemetry arm SNIPER_DISPATCH_SCOPE; others leave unarmed."
)


def resolve_binary() -> str | None:
    """Return the binary path: SNIPER_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("sniper")


def extra_scan_keys(payload: dict) -> frozenset[str]:
    return frozenset(payload) - CLOSED_SCAN_KEYS


def mode_refusal(payload: dict) -> str | None:
    raw = payload.get("mode")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a mode in args.mode"
    mode = raw.strip()
    if mode.startswith("-"):
        return "mode must not be flag-shaped"
    if mode not in MODES:
        return f"mode must be one of {sorted(MODES)}"
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
        return "scan requires a target in args.target"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return "scan target contains control characters"
    if " " in target:
        return "scan target must be a hostname or http(s) URL"
    if target.startswith("-"):
        return "scan target must not be flag-shaped"
    if "://" in target:
        parsed, host = _parse_host(target)
        if parsed is None or parsed.scheme not in ("http", "https") or not host:
            return "scan target must be an http(s) URL or hostname"
        # userinfo would sit on argv like a password -s key.
        if (
            parsed.username is not None
            or parsed.password is not None
            or "@" in (parsed.netloc or "")
        ):
            return "scan target must not include URL userinfo"
        return None
    # Unbracketed IPv6 mangles under urlparse; require brackets so the
    # audited target is the executed target.
    if ":" in target and not target.startswith("["):
        return "IPv6 targets must be bracketed"
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.[]:")
    if not target or any(ch not in allowed for ch in target.lower()):
        return "scan target must be an http(s) URL or hostname"
    parsed, host = _parse_host(target)
    if parsed is None or not host:
        return "scan target must be an http(s) URL or hostname"
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


def argv_for(binary: str, target: str, mode: str) -> list[str]:
    """Fixed argv: sniper -t <target> -m <mode>. No -p/-fp/-o/-re/-f."""
    return [binary, "-t", target, "-m", mode]
