"""Argument assembly for the nmap arm with XML on stdout.

The binary is never bundled (NPSL): this arm invokes a user-installed
``nmap`` only. The operator supplies the target expression and may provide
additional nmap arguments as separate argv tokens.
"""

from __future__ import annotations

import os
from pathlib import Path

ARM_ID = "nmap"
ENV_BIN = "NMAP_BIN"

LIST_ACTIONS = frozenset({"list_tools", "tools/list"})
ALLOWED_ACTIONS = frozenset({"scan"})

CLOSED_SCAN_KEYS = frozenset({"target", "mode", "ports", "options"})

# Convenient presets. ``options`` lets the operator use other upstream modes.
MODES = {
    "connect": ("-sT",),
    "version": ("-sT", "-sV"),
    "version-light": ("-sT", "-sV", "--version-light", "-Pn", "-n", "--unprivileged"),
}
TIMING_FLAG = "-T4"

# Port selection: an explicit list, or the top-100 default.
DEFAULT_TOP_PORTS = 100
MAX_PORTS = 128
MAX_PORT = 65535
MIN_PORT = 1

TIMEOUT_SECONDS = 180.0
MAX_OUTPUT_CHARS = 200_000

CAVEATS = (
    "Invokes the user's own nmap (NPSL; never bundled). The operator "
    "chooses the target and may pass upstream options as argv tokens. "
    "The arm requests XML on stdout for result capture."
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
        return "scan requires args.target"
    host = raw.strip()
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in host):
        return "scan target must be one argument without control characters"
    if host.startswith("-"):
        return "scan target must not be flag-shaped"
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


def options_refusal(payload: dict) -> str | None:
    options = payload.get("options")
    if options is None:
        return None
    if not isinstance(options, list) or not all(isinstance(item, str) for item in options):
        return "scan options must be a list of argv strings"
    if any(not item or "\x00" in item for item in options):
        return "scan options must be nonempty argv strings without NUL bytes"
    return None


def argv_for(binary: str, target: str, mode: str | None, ports: list[int] | None,
             options: list[str] | None = None) -> list[str]:
    """Assemble the nmap argv, requesting XML on stdout.

    ``host_refusal`` rejects a flag-shaped target; options are passed to
    nmap as argv tokens without shell interpolation.
    """
    if options is None:
        argv = [binary, *MODES[mode or "connect"], TIMING_FLAG, "-oX", "-"]
    else:
        argv = [binary, *MODES[mode]] if mode else [binary]
    if ":" in target:
        argv.insert(1, "-6")
        if target.startswith("[") and target.endswith("]"):
            target = target[1:-1]
    if ports:
        argv += ["-p", ",".join(str(port) for port in ports)]
    elif options is None:
        argv += ["--top-ports", str(DEFAULT_TOP_PORTS)]
    if options is not None:
        argv.extend(options)
        argv += ["-oX", "-"]
    argv.append(target)
    return argv
