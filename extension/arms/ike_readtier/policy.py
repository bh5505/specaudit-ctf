"""Request input for the IKE presence arm."""

from __future__ import annotations

import ipaddress
import re
from typing import Any


ARM_ID = "ike-readtier"
ALLOWED_ACTIONS = frozenset({"probe"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})
ARG_KEYS = frozenset({"host", "ports", "timeout_ms"})
DEFAULT_PORTS = (500,)
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
    if (not isinstance(ports, list) or not ports or
            any(type(port) is not int or not 1 <= port <= 65_535 for port in ports) or
            len(set(ports)) != len(ports)):
        return "args.ports must be a nonempty list of distinct UDP ports from 1 through 65535"
    timeout = payload.get("timeout_ms")
    if type(timeout) is not int or not MIN_TIMEOUT_MS <= timeout <= MAX_TIMEOUT_MS:
        return f"args.timeout_ms must be an integer from {MIN_TIMEOUT_MS} through {MAX_TIMEOUT_MS}"
    return None
