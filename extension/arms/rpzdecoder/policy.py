"""RPZ decoder argument and credential-file validation."""

from __future__ import annotations

import os
import re
import ipaddress
from pathlib import Path

ARM_ID = "rpz-decoder"

ENV_DIG_BIN = "RPZDECODER_DIG_BIN"
ENV_ZONE = "RPZDECODER_ZONE"
ENV_MASTER = "RPZDECODER_MASTER"

# Supported actions: decode is an in-process pass over an operator-supplied
# AXFR dump; fetch/status shell out to dig against the zone master.
ALLOWED_ACTIONS = frozenset({"decode", "fetch", "status"})

TIMEOUT_SECONDS = 300.0
MAX_OUTPUT_CHARS = 200_000
SAMPLE_INDICATORS = 25
MAX_DUMP_BYTES = 512 * 1024 * 1024
DEFAULT_PORT = 53
DIG_QUERY_TIMEOUT = "+time=60"

_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9_*-]{1,63}$")

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
    "the TSIG secret is transiently included in dig's command-line arguments",
    "no zone data ships in the repo; defaults carry no account identifiers",
)

USAGE = (
    "pass args.dump (an existing AXFR dump) for decode, or args.keyfile "
    "(two-line file: key name, then base64 secret) plus optionally "
    "args.zone/args.master (env RPZDECODER_ZONE/RPZDECODER_MASTER) for fetch"
)


def zone_refusal(zone: str) -> str | None:
    if not isinstance(zone, str) or not zone.strip():
        return "zone is required (args.zone or RPZDECODER_ZONE)"
    zone = zone.strip().rstrip(".")
    if zone.startswith("-"):
        return "zone must not be flag-shaped"
    if len(zone) > 253 or any(not _DNS_LABEL_RE.fullmatch(label) for label in zone.split(".")):
        return "zone must be a DNS name"
    return None


def master_refusal(master: str) -> str | None:
    if not isinstance(master, str) or not master.strip():
        return "master is required (args.master or RPZDECODER_MASTER)"
    master = master.strip()
    if master.startswith("-") or any(ord(ch) < 0x20 for ch in master):
        return "master must be a host name or IP address"
    try:
        ipaddress.ip_address(master)
    except ValueError:
        if len(master) > 253 or any(not _DNS_LABEL_RE.fullmatch(label) for label in master.rstrip(".").split(".")):
            return "master must be a host name or IP address"
    return None


def port_refusal(port: object) -> str | None:
    if port is None:
        return None
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    if not isinstance(port, int) or isinstance(port, bool):
        return "port must be an integer from 1 to 65535"
    if not 1 <= port <= 65535:
        return "port must be an integer from 1 to 65535"
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
        return "fetch requires args.keyfile (two-line TSIG key file)"
    if action == "fetch" and not _opt_str(payload.get("outdir")):
        return "fetch requires args.outdir (the decoded lists are written there)"
    return None


MAX_KEYFILE_BYTES = 64 * 1024


def keyfile_refusal(path: Path) -> str | None:
    """Check that the credential file can supply a key name and secret."""
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
