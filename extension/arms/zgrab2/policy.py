"""Tier rules for the zgrab2 arm: closed modules, host on stdin."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

ARM_ID = "zgrab2"
ENV_BIN = "ZGRAB2_BIN"
ENV_DISPATCH_SCOPE = "ZGRAB2_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset({"list_modules"})
DISPATCH_ACTIONS = frozenset({"scan"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

CLOSED_SCAN_KEYS = frozenset({"target", "module", "port"})

MODULES = frozenset({
    "http", "tls", "ssh", "dns", "ntp", "redis", "mysql", "postgres",
    "smtp", "imap", "pop3", "ftp", "telnet", "banner", "jarm",
    "mongodb", "mqtt",
})

TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "Application-layer handshake scanner; overlaps zdns for DNS but adds L7. "
    "Stdin is the input path."
)


def resolve_binary() -> str | None:
    """Return the binary path: ZGRAB2_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("zgrab2")


def extra_scan_keys(payload: dict) -> frozenset[str]:
    return frozenset(payload) - CLOSED_SCAN_KEYS


def module_refusal(payload: dict) -> str | None:
    raw = payload.get("module")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a module in args.module"
    module = raw.strip()
    if module.startswith("-"):
        return "module must not be flag-shaped"
    if module not in MODULES:
        return f"module must be one of {sorted(MODULES)}"
    return None


def host_refusal(payload: dict) -> str | None:
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a target in args.target"
    host = raw.strip()
    # stdin CSV treats extra comma fields as a port override.
    if any(ch in host for ch in ("\x00", "\r", "\n", " ", ",")):
        return "scan target must not contain spaces, commas, or control characters"
    if host.startswith("-"):
        return "scan target must not be flag-shaped"
    if "/" in host or "@" in host or "://" in host:
        return "scan target must be a hostname, IPv4, or IPv6 address"
    stdin_host = host.strip("[]")
    if stdin_host.startswith("-"):
        return "scan target must not be flag-shaped"
    try:
        ipaddress.ip_address(stdin_host)
        return None
    except ValueError:
        pass
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if not stdin_host or any(ch not in allowed for ch in stdin_host.lower()):
        return "scan target must be a hostname, IPv4, or IPv6 address"
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


def _is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def stdin_and_auth_target(raw: str) -> tuple[str, str]:
    """Unbracketed stdin host and bracketed IPv6 authorize/log/stamp target.

    Unbracketed IPv6 fails target_in_scope (urlparse hostname is the first
    hextet). Operators arm ZGRAB2_DISPATCH_SCOPE with the unbracketed
    literal; stdin is a host, not a URL.
    """
    stdin_host = raw.strip().strip("[]")
    if _is_ipv6(stdin_host):
        return stdin_host, f"[{ipaddress.ip_address(stdin_host)}]"
    return stdin_host, stdin_host


def argv_for(binary: str, module: str, port: int | None) -> list[str]:
    """Fixed argv: module plus optional --port. Host is never on argv."""
    cmd = [binary, module]
    if port is not None:
        cmd.extend(["--port", str(port)])
    return cmd
