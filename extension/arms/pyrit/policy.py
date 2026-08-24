"""CLI rules for the pyrit arm (first-party pyrit_scan only)."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlparse

ARM_ID = "pyrit"
ENV_BIN = "PYRIT_BIN"
ENV_DISPATCH_SCOPE = "PYRIT_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset({"list_scenarios"})
DISPATCH_ACTIONS = frozenset({"scan"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_CHARS = 200_000

SCENARIO_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")

CAVEATS = (
    "Requires operator PyRIT config (~/.pyrit). Community MCP wrappers "
    "are unused. First-party pyrit_scan only."
)


def scenario_refusal(payload: dict) -> str | None:
    raw = payload.get("scenario")
    if not isinstance(raw, str) or not raw.strip():
        return "scan requires a scenario in args.scenario"
    scenario = raw.strip()
    if scenario.startswith("-"):
        return "scenario must not be flag-shaped"
    if not SCENARIO_RE.fullmatch(scenario):
        return "scenario must match [A-Za-z][A-Za-z0-9_.-]{0,63}"
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
        return "scan requires a target in args.target"
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
        # userinfo would sit on argv (--target <raw>); never echo the secret.
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
    """Return the pyrit_scan path: PYRIT_BIN, else PATH lookup."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        return None
    import shutil

    return shutil.which("pyrit_scan")


def argv_for(binary: str, action: str, payload: dict) -> list[str] | None:
    """Fixed argv frozen from first-party pyrit_scan --help (PyRIT 1.0.1).

    Docs: https://microsoft.github.io/PyRIT/1.0.1/scanner/pyrit-scan
    list_scenarios -> --list-scenarios; scan -> positional scenario --target NAME.
    """
    if action == "list_scenarios":
        return [binary, "--list-scenarios"]
    if action == "scan":
        scenario = payload.get("scenario")
        target = payload.get("target")
        if not isinstance(scenario, str) or not scenario.strip():
            return None
        if not isinstance(target, str) or not target.strip():
            return None
        return [binary, scenario.strip(), "--target", target.strip()]
    return None
