"""Tier rules for the nmap arm: closed flags, single host, XML on stdout.

The binary is never bundled (NPSL): this arm invokes a user-installed
``nmap`` only. The flag surface is a closed allowlist assembled by
:func:`argv_for` — caller-controlled argv is impossible by construction,
and targets are single hosts (CIDR-shaped targets are refused before the
dispatch scope is consulted; the shared scope check is host-granular).
"""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "nmap"
ENV_BIN = "NMAP_BIN"
ENV_DISPATCH_SCOPE = "NMAP_DISPATCH_SCOPE"

LIST_ACTIONS = frozenset({"list_tools", "tools/list"})
ALLOWED_ACTIONS = frozenset()  # no static read action beyond list_tools
DISPATCH_ACTIONS = frozenset({"scan"})

CLOSED_SCAN_KEYS = frozenset({"target", "mode", "ports"})

# Fixed per-mode flag sets. connect = TCP connect scan (no raw sockets,
# unprivileged); version = connect scan + service version detection.
# Deliberately absent: -sS/-O/--send-eth (raw sockets), -sU, -sC/--script
# (NSE is unsandboxed Lua), -A, -Pn, -D/-S/-e, -T5, --script-args.
MODES = {
    "connect": ("-sT",),
    "version": ("-sT", "-sV"),
}
TIMING_FLAG = "-T4"

# Port selection: an explicit list, or the top-100 default. A full-range
# port list is refused; name the ports you mean.
DEFAULT_TOP_PORTS = 100
MAX_PORTS = 128
MAX_PORT = 65535
MIN_PORT = 1

TIMEOUT_SECONDS = 180.0
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "Invokes the user's own nmap (NPSL; never bundled). Single-host "
    "targets only — CIDR/range targets are refused before scope. Fixed "
    "-T4 timing, connect/version modes only; no NSE scripts, OS detect, "
    "raw-socket, or decoy paths. XML lands on stdout, capped and "
    "keyword-redacted; dispatch defaults refused until NMAP_DISPATCH_SCOPE "
    "names the target."
)


def resolve_binary() -> str | None:
    """Return the binary path: NMAP_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("nmap")


def extra_scan_keys(payload: dict) -> frozenset[str]:
    return frozenset(payload) - CLOSED_SCAN_KEYS


def host_refusal(payload: dict) -> str | None:
    raw = payload.get("target")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a single-host target in args.target"
    host = raw.strip()
    if any(ch in host for ch in ("\x00", "\r", "\n", " ", ",", ";", "|", "&")):
        return "scan target must not contain spaces, commas, or control characters"
    if host.startswith("-"):
        return "scan target must not be flag-shaped"
    # CIDR/range targets are refused BEFORE the scope gate: the shared
    # target_in_scope check is host-granular and would only see the
    # network address of a CIDR target.
    stripped = host.strip("[]")
    if stripped.startswith("-"):
        return "scan target must not be flag-shaped"
    import ipaddress

    try:
        ipaddress.ip_address(stripped)
        return None
    except ValueError:
        pass
    bad = set(stripped) - set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    # Digit/dot/dash-only non-IP input is an nmap octet-range pattern
    # ("10.0.0.1-20"); refuse it while hyphenated hostnames stay valid.
    octet_range = stripped and set(stripped) <= set("0123456789.-") and "-" in stripped
    if "/" in host or "@" in host or "://" in host or bad or octet_range:
        return (
            "scan target must be a single hostname, IPv4, or IPv6 address "
            "(no CIDR, ranges, or URLs)"
        )
    return None


def mode_refusal(payload: dict) -> str | None:
    if "mode" not in payload or payload["mode"] is None:
        return None
    mode = payload["mode"]
    if not isinstance(mode, str) or mode not in MODES:
        return f"scan mode must be one of {sorted(MODES)} (fixed flag sets)"
    return None


def ports_refusal(payload: dict) -> str | None:
    if "ports" not in payload or payload["ports"] is None:
        return None
    ports = payload["ports"]
    if not isinstance(ports, list) or isinstance(ports, bool):
        return "scan ports must be a list of integers"
    if not ports:
        return "scan ports must not be empty (omit for the top-100 default)"
    if len(ports) > MAX_PORTS:
        return f"scan ports accept at most {MAX_PORTS} entries; name the ports you mean"
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int):
            return "scan ports must be a list of integers"
        if not (MIN_PORT <= port <= MAX_PORT):
            return f"scan port {port!r} is outside 1..65535"
    return None


def argv_for(binary: str, target: str, mode: str | None, ports: list[int] | None) -> list[str]:
    """Assemble the closed nmap argv: fixed flags, XML on stdout.

    The target is the only caller-derived token and host_refusal has
    already rejected flag-shaped, range, and CIDR inputs.
    """
    argv = [binary, *MODES[mode or "connect"], TIMING_FLAG, "-oX", "-"]
    if ports:
        argv += ["-p", ",".join(str(port) for port in ports)]
    else:
        argv += ["--top-ports", str(DEFAULT_TOP_PORTS)]
    argv.append(target)
    return argv
