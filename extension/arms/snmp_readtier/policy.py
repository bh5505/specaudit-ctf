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
ARG_KEYS = frozenset({
    "host", "port", "community", "oids", "timeout_ms", "user",
    "auth_protocol", "auth_password", "priv_protocol", "priv_password",
})
AUTH_PROTOCOLS = frozenset({"none", "md5", "sha", "sha256"})
PRIV_PROTOCOLS = frozenset({"none", "des", "aes128"})
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


def _utf8_size(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


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
    v3 = "user" in payload
    required_args = ("host", "oids", "timeout_ms") if v3 else ("host", "community", "oids", "timeout_ms")
    for required in required_args:
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
    if v3:
        user = payload.get("user")
        user_size = _utf8_size(user)
        if user_size is None or not 1 <= user_size <= 64:
            return "args.user must be a 1-64 byte UTF-8 string"
        if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in user):
            return "args.user contains control characters"
        auth = payload.get("auth_protocol", "none")
        privacy = payload.get("priv_protocol", "none")
        if not isinstance(auth, str) or auth.lower() not in AUTH_PROTOCOLS:
            return "args.auth_protocol must be one of none, md5, sha, sha256"
        if not isinstance(privacy, str) or privacy.lower() not in PRIV_PROTOCOLS:
            return "args.priv_protocol must be one of none, des, aes128"
        if auth.lower() != "none" and (_utf8_size(payload.get("auth_password")) in (None, 0)):
            return "args.auth_password must be non-empty UTF-8 when authentication is enabled"
        if privacy.lower() != "none" and (_utf8_size(payload.get("priv_password")) in (None, 0)):
            return "args.priv_password must be non-empty UTF-8 when privacy is enabled"
        if privacy.lower() != "none" and auth.lower() == "none":
            return "SNMPv3 privacy requires authentication"
    else:
        community = payload.get("community")
        community_size = _utf8_size(community)
        if community_size is None or not 1 <= community_size <= 64:
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
