"""Closed input and target policy for the bounded SNMP read arm."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

from ..dispatch import load_scope, target_in_scope

ARM_ID = "snmp-readtier"
ALLOWED_ACTIONS = frozenset({"probe"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})
ARG_KEYS = frozenset({"host", "port", "community", "oids", "timeout_ms"})
ENV_SCOPE = "SNMP_READTIER_SCOPE"
DEFAULT_COMMUNITY = "public"
DEFAULT_PORT = 161
MIN_TIMEOUT_MS = 50
MAX_TIMEOUT_MS = 5_000
MAX_RESPONSE_BYTES = 65_535
OID_ALLOWLIST = {
    "sysDescr.0": ".1.3.6.1.2.1.1.1.0",
    "sysUpTime.0": ".1.3.6.1.2.1.1.3.0",
    "sysName.0": ".1.3.6.1.2.1.1.5.0",
}
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


def normalize_oid(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    for name, oid in OID_ALLOWLIST.items():
        if text.lower() == name.lower() or text == oid or text == oid.lstrip("."):
            return oid
    return None


def args_refusal(payload: dict[str, Any]) -> str | None:
    extra = sorted(set(payload) - ARG_KEYS)
    if extra:
        return f"probe rejects unexpected arguments: {', '.join(extra)}"
    for required in ("host", "community", "oids", "timeout_ms"):
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
    port = payload.get("port", DEFAULT_PORT)
    if type(port) is not int or not 1 <= port <= 65_535:
        return "args.port must be an integer from 1 through 65535"
    community = payload.get("community")
    if not isinstance(community, str) or not 1 <= len(community.encode("utf-8")) <= 64:
        return "args.community must be an explicit 1-64 byte UTF-8 string"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in community):
        return "args.community contains control characters"
    oids = payload.get("oids")
    if not isinstance(oids, list) or not 1 <= len(oids) <= len(OID_ALLOWLIST):
        return "args.oids must contain one to three allowed OIDs"
    normalized = [normalize_oid(value) for value in oids]
    if any(value is None for value in normalized) or len(set(normalized)) != len(normalized):
        return "args.oids contains an unknown or duplicate OID"
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
