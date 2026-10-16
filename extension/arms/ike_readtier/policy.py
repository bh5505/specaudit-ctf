"""Closed input and target policy for the bounded IKE presence arm."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ..dispatch import load_scope, target_in_scope

ARM_ID = "ike-readtier"
ALLOWED_ACTIONS = frozenset({"probe"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})
ARG_KEYS = frozenset({"host", "ports", "timeout_ms"})
ENV_SCOPE = "IKE_READTIER_SCOPE"
DEFAULT_PORTS = (500,)
ALLOWED_PORT_SETS = ((500,), (500, 4500))
MIN_TIMEOUT_MS = 50
MAX_TIMEOUT_MS = 5_000
MAX_RESPONSE_BYTES = 65_535
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


def args_refusal(payload: dict[str, Any]) -> str | None:
    extra = sorted(set(payload) - ARG_KEYS)
    if extra:
        return f"probe rejects unexpected arguments: {', '.join(extra)}"
    for required in ("host", "timeout_ms"):
        if required not in payload:
            return f"probe requires explicit args.{required}"
    host = payload.get("host")
    if not isinstance(host, str) or not host.strip() or any(ord(ch) < 0x21 for ch in host):
        return "args.host must be one IP literal or hostname without whitespace"
    text = host.strip()
    try:
        ipaddress.ip_address(text)
    except ValueError:
        if not _HOST_RE.fullmatch(text) or ".." in text:
            return "args.host must be one IP literal or hostname"
    ports = payload.get("ports", list(DEFAULT_PORTS))
    if not isinstance(ports, list) or tuple(ports) not in ALLOWED_PORT_SETS or any(type(port) is not int for port in ports):
        return "args.ports must be exactly [500] or [500, 4500]"
    timeout = payload.get("timeout_ms")
    if type(timeout) is not int or not MIN_TIMEOUT_MS <= timeout <= MAX_TIMEOUT_MS:
        return f"args.timeout_ms must be an integer from {MIN_TIMEOUT_MS} through {MAX_TIMEOUT_MS}"
    return None


def authorize_host(host: str) -> str | None:
    scope, refusal = load_scope(ENV_SCOPE)
    if refusal:
        return refusal
    if scope is None:
        return f"probe is blocked by default; set {ENV_SCOPE} to explicit authorized targets"
    if not target_in_scope(host, scope):
        return f"args.host is outside {ENV_SCOPE}"
    return None
