"""Request input for the zgrab2 arm: module argv and target stdin."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

ARM_ID = "zgrab2"
ENV_BIN = "ZGRAB2_BIN"

ALLOWED_ACTIONS = frozenset({"list_modules", "scan"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

SCAN_KEYS = frozenset({"target", "module", "port", "options"})

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
    return frozenset(payload) - SCAN_KEYS


def module_refusal(payload: dict) -> str | None:
    raw = payload.get("module")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a module in args.module"
    module = raw.strip()
    if module.startswith("-"):
        return "module must not be flag-shaped"
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7f for ch in module):
        return "module must be one argv token without control characters"
    return None


def host_refusal(payload: dict) -> str | None:
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a target in args.target"
    host = raw.strip()
    # stdin CSV treats extra comma fields as a port override.
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7f for ch in host) or "," in host:
        return "scan target must not contain spaces, commas, or control characters"
    return None


def options_refusal(payload: dict) -> str | None:
    options = payload.get("options", [])
    if not isinstance(options, list) or any(
        not isinstance(option, str) or not option or
        any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in option)
        for option in options
    ):
        return "scan options must be an array of nonempty argv tokens without control characters"
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
    """Unbracketed stdin host and bracketed IPv6 display target.

    Stdin is a host, not a URL; IPv6 is shown bracketed for display
    while stdin carries the unbracketed literal.
    """
    stdin_host = raw.strip()
    if stdin_host.startswith("[") and stdin_host.endswith("]") and _is_ipv6(stdin_host[1:-1]):
        stdin_host = stdin_host[1:-1]
    if _is_ipv6(stdin_host):
        return stdin_host, f"[{ipaddress.ip_address(stdin_host)}]"
    return stdin_host, stdin_host


def argv_for(binary: str, module: str, port: int | None, options: list[str] | None = None) -> list[str]:
    """Separate argv: module, optional port, and operator options. Target stays on stdin."""
    cmd = [binary, module]
    if port is not None:
        cmd.extend(["--port", str(port)])
    cmd.extend(options or [])
    return cmd
