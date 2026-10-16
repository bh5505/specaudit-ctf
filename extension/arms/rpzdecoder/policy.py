"""Exact-allowlist rules for the rpz-decoder read arm."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

ARM_ID = "rpz-decoder"

ENV_DIG_BIN = "RPZDECODER_DIG_BIN"
ENV_DISPATCH_SCOPE = "RPZDECODER_DISPATCH_SCOPE"
ENV_ZONE = "RPZDECODER_ZONE"
ENV_MASTER = "RPZDECODER_MASTER"

# Read tier: in-process decoding of an operator-supplied AXFR dump.
# Dispatch tier: fetch/status shell out to dig against the zone master.
ALLOWED_ACTIONS = frozenset({"decode"})
DISPATCH_ACTIONS = frozenset({"fetch", "status"})

TIMEOUT_SECONDS = 300.0
MAX_OUTPUT_CHARS = 200_000
SAMPLE_INDICATORS = 25
MAX_DUMP_BYTES = 512 * 1024 * 1024
DEFAULT_PORT = 53
ALLOWED_PORTS = frozenset({53, 5353})
DIG_QUERY_TIMEOUT = "+time=60"

# Zone-name pattern every catalogued master serves (<Policy>.rpz.threatstop.local).
ZONE_SUFFIX = ".rpz.threatstop.local"
_MASTER_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Vendor control names inside the zone: policy plumbing, not threat intel.
CONTROL_DOMAINS = frozenset(
    {
        "bad.threatstop.com",
        "vile.threatstop.com",
        "garden.threatstop.com",
        "unprotected.threatstop.com",
        "protected.threatstop.com",
    }
)

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "decode": frozenset({"dump", "outdir", "include_control", "zone"}),
    "fetch": frozenset({"outdir", "zone", "master", "keyfile", "port"}),
    "status": frozenset({"zone", "master", "port"}),
}

CAVEATS = (
    "ad-hoc, unscheduled: every fetch/status runs only when invoked",
    "fetch requires the dig binary and an operator-supplied TSIG key file",
    "the TSIG secret rides the dig argv transiently (host-scoped exposure)",
    "no zone data ships in the repo; defaults carry no account identifiers",
)

ARMING = (
    "pass args.dump (an existing AXFR dump) for decode, or args.keyfile "
    "(0600 two-line file: key name, then base64 secret) plus optionally "
    "args.zone/args.master (env RPZDECODER_ZONE/RPZDECODER_MASTER) for fetch"
)


def zone_refusal(zone: str) -> str | None:
    if not isinstance(zone, str) or not zone.strip():
        return "zone is required (args.zone or RPZDECODER_ZONE)"
    zone = zone.strip().rstrip(".")
    if zone.startswith("-"):
        return "zone must not be flag-shaped"
    if not zone.endswith(ZONE_SUFFIX):
        return f"zone must end with {ZONE_SUFFIX}"
    if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for ch in zone.lower()):
        return "zone contains invalid characters"
    return None


def master_refusal(master: str) -> str | None:
    if not isinstance(master, str) or not master.strip():
        return "master is required (args.master or RPZDECODER_MASTER)"
    master = master.strip()
    if not _MASTER_RE.match(master):
        return "master must be a dotted-quad IPv4 address"
    octets = [int(part) for part in master.split(".")]
    if any(octet > 255 for octet in octets):
        return "master octets must be 0-255"
    return None


def port_refusal(port: object) -> str | None:
    if port is None:
        return None
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    if not isinstance(port, int) or isinstance(port, bool):
        return "port must be 53 or 5353"
    if port not in ALLOWED_PORTS:
        return "port must be 53 or 5353"
    return None


def args_refusal(action: str, payload: dict) -> str | None:
    """Reject unknown keys and missing required keys per action."""
    allowed = ARG_KEYS.get(action)
    if allowed is None:
        return f"action {action!r} is not on the allowlist"
    unknown = sorted(set(payload) - allowed)
    if unknown:
        return f"unknown argument(s) for {action}: {', '.join(unknown)}"
    if action == "decode" and not _opt_str(payload.get("dump")):
        return "decode requires args.dump (path to an AXFR dump)"
    if action == "fetch" and not _opt_str(payload.get("keyfile")):
        return "fetch requires args.keyfile (0600 two-line TSIG key file)"
    if action == "fetch" and not _opt_str(payload.get("outdir")):
        return "fetch requires args.outdir (the decoded lists are written there)"
    return None


MAX_KEYFILE_BYTES = 64 * 1024


def keyfile_refusal(path: Path) -> str | None:
    """Fail-closed credential-file check: exists, bounded, 0600."""
    if not path.is_file():
        return f"keyfile not found: {path}"
    try:
        if path.stat().st_size > MAX_KEYFILE_BYTES:
            return f"keyfile exceeds {MAX_KEYFILE_BYTES} bytes"
        raw = path.read_bytes()
    except OSError as exc:
        return f"keyfile unreadable: {exc}"
    lines = [line for line in raw.decode("utf-8", errors="replace").splitlines() if line.strip()]
    if len(lines) < 2:
        return "keyfile must hold two lines: key name, then base64 secret"
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            return f"keyfile must be 0600 (found {mode:o})"
    return None


def resolve_dig() -> str | None:
    """Return the dig binary path: RPZDECODER_DIG_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_DIG_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("dig")


def _opt_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
