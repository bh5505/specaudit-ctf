"""Two-tier dispatch: scope-bound opt-in for active actions.

Read-only is the default tier. Dispatch-class actions (exploit run,
scan launch, detonate, active scan) are refused unless the operator
armed the arm with an explicit ``<PREFIX>_DISPATCH_SCOPE`` naming the
authorized targets. Arming is scope-binding, not a boolean: blanket
values (``*``, ``0.0.0.0/0``, ``::/0``) are refused, so the flag
always encodes what is authorized and cannot be cargo-culted.

Every allowed dispatch writes a user-visible audit line to stderr and
is stamped on the Result so downstream documents carry provenance.
"""

from __future__ import annotations

import ipaddress
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib import parse as urllib_parse

# Scope expression: comma-separated items, each a CIDR, an IP literal,
# a hostname, or a URI prefix (scheme://...). No wildcards.
_BLANKET_VALUES = frozenset({"*", "0.0.0.0/0", "::/0"})
_MAX_ITEMS = 32


@dataclass(frozen=True)
class Scope:
    """A parsed dispatch scope: networks, hosts, and URI prefixes."""

    raw: str
    networks: tuple[str, ...]
    hosts: tuple[str, ...]
    uri_prefixes: tuple[str, ...]


def parse_scope(raw: str | None) -> tuple[Scope | None, str | None]:
    """Parse a scope expression; return (scope, refusal_reason).

    Blanket scopes and malformed items are refused - an armed arm must
    name its targets, never "everything".
    """
    if raw is None or not raw.strip():
        return None, "dispatch scope is required to arm dispatch actions"
    text = raw.strip()
    if any(ord(ch) < 0x20 for ch in text):
        return None, "dispatch scope contains control characters"
    items = [item.strip() for item in text.split(",")]
    if len(items) > _MAX_ITEMS:
        return None, f"dispatch scope has too many items (max {_MAX_ITEMS})"
    networks: list[str] = []
    hosts: list[str] = []
    prefixes: list[str] = []
    for item in items:
        if not item:
            return None, "dispatch scope has an empty item"
        lowered = item.lower()
        if lowered in _BLANKET_VALUES:
            return (
                None,
                f"dispatch scope {item!r} is a blanket scope; name explicit "
                "targets instead",
            )
        if "://" in item:
            prefixes.append(item.rstrip("/"))
            continue
        if _looks_like_cidr_or_ip(item):
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                return None, f"dispatch scope item is not a valid network: {item!r}"
            if net.prefixlen == 0:
                # Canonicalization variants (0::/0, netmask forms) must
                # not slip past the literal blanket check.
                return None, (
                    f"dispatch scope {item!r} is a blanket scope; name "
                    "explicit targets instead"
                )
            networks.append(str(net))
            continue
        if _valid_hostname(item):
            hosts.append(lowered)
            continue
        return None, f"dispatch scope item is not a CIDR, IP, hostname, or URI: {item!r}"
    return (
        Scope(
            raw=text,
            networks=tuple(networks),
            hosts=tuple(hosts),
            uri_prefixes=tuple(prefixes),
        ),
        None,
    )


def target_in_scope(target: str, scope: Scope) -> bool:
    """Return True when *target* is inside *scope*.

    A target may be an IP literal, a hostname, or a URL (its host is
    checked against networks/hosts; a URL also matches a URI prefix).
    Hostnames match exactly (no subdomain wildcarding).
    """
    if not target or not target.strip():
        return False
    candidate = target.strip()
    if "@" in candidate and "://" not in candidate:
        return False  # bare user@host discards userinfo silently; refuse
    try:
        parsed = urllib_parse.urlparse(
            candidate if "://" in candidate else "//" + candidate
        )
    except ValueError:
        # Malformed targets (bracketed IPv4, unmatched brackets, bad IPv6
        # URL forms) are out of scope by construction — containment is
        # False, never an unhandled crash on the security seam.
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    path = (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")
    if not host:
        return False
    for prefix in scope.uri_prefixes:
        head = urllib_parse.urlparse(prefix)
        if host == (head.hostname or "").lower().rstrip("."):
            # Scheme must match too: an https prefix must not authorize
            # plain-http targets on the same host.
            if head.scheme and head.scheme != parsed.scheme:
                continue
            # Scheme-relative prefix match on the normalized remainder.
            import posixpath

            tail = posixpath.normpath((head.path or "").strip("/"))
            candidate_tail = posixpath.normpath(path.strip("/"))
            if not tail or candidate_tail == tail or candidate_tail.startswith(
                tail + "/"
            ):
                return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        for net in scope.networks:
            if ip in ipaddress.ip_network(net):
                return True
    for allowed in scope.hosts:
        try:
            if ip is not None:
                if allowed and ip == ipaddress.ip_address(allowed):
                    return True
            elif host == allowed:
                return True
        except ValueError:
            if host == allowed:
                return True
    return False


def load_scope(env_name: str) -> tuple[Scope | None, str | None]:
    """Load the scope from an environment variable (None = unarmed)."""
    import os

    raw = os.environ.get(env_name)
    if raw is None or not raw.strip():
        return None, None
    return parse_scope(raw)


def unarmed_refusal(env_name: str, action: str) -> str:
    """Refusal for a dispatch action when the arm is not armed."""
    return (
        f"action {action!r} is a dispatch action (blocked by default). "
        f"Arm with {env_name}=<explicit targets> to enable; every dispatch "
        "is logged."
    )


def authorize(
    env_name: str, action: str, target: str | None
) -> tuple[Scope | None, str | None]:
    """Authorize one dispatch invocation.

    Returns (scope, None) when armed and the target is inside the
    scope, else (None, refusal). ``target`` may be None when the arm
    cannot extract one; the dispatch then proceeds on scope presence
    alone and the audit line records target=unknown.
    """
    scope, refusal = load_scope(env_name)
    if scope is None:
        if refusal is not None:
            return None, refusal
        return None, unarmed_refusal(env_name, action)
    if target is not None and not target_in_scope(target, scope):
        return None, f"target {target!r} is outside the armed dispatch scope"
    return scope, None


def log_dispatch(arm_id: str, action: str, scope: Scope, target: str | None) -> None:
    """Write the user-visible dispatch audit line to stderr."""
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(
        f"[dispatch] {stamp} arm={arm_id} action={action} "
        f"scope={scope.raw} target={target or 'unknown'}",
        file=sys.stderr,
        flush=True,
    )


def stamp(scope: Scope, target: str | None) -> dict[str, str]:
    """Result provenance stamp for an allowed dispatch."""
    return {"dispatch": "true", "scope": scope.raw, "target": target or "unknown"}


def _looks_like_cidr_or_ip(item: str) -> bool:
    if "/" in item:
        return True  # CIDR-shaped; validity checked by ip_network()
    parts = item.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return True  # IPv4 literal shaped
    return ":" in item  # IPv6-shaped


def _valid_hostname(item: str) -> bool:
    if not item or len(item) > 253:
        return False
    if item.isdigit():
        return False  # bare numbers are not hostnames
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if not all(ch in allowed for ch in item.lower()):
        return False
    lowered = item.lower()
    if lowered.startswith(("-", ".")) or lowered.endswith(("-", ".")):
        return False
    return ".." not in lowered
