"""RPZ AXFR decoder: raw indicator extraction from a zone dump.

Stdlib-only, in-process, fail-closed. The dump is the plain text a
``dig ... axfr`` run prints. Records outside the zone or outside the
IN class (the SOA/NS bookends, the dig TSIG trailer) are skipped;
in-zone records that are not usable indicators are counted into
explicit buckets (control, unparsed) rather than dropped silently,
and undecodable triggers never raise — they are counted so the
caller can see the residue. Zone data must be valid UTF-8; anything
else is a ZoneDecodeError, never a silent replacement decode.
"""

from __future__ import annotations

import json
from typing import Any

from .policy import CONTROL_DOMAINS

# Owner-side trigger branches, per the RPZ layout.
_IP_TRIGGERS: tuple[tuple[str, str], ...] = (
    (".rpz-ip", "ip"),
    (".rpz-nsip", "nsip"),
    (".rpz-client-ip", "client_ip"),
)
_IP_TRIGGER_SUFFIXES = tuple(branch for branch, _ in _IP_TRIGGERS)
_NAME_TRIGGER = ".rpz-nsdname"

_SKIP_TYPES = frozenset({"SOA", "NS", "TSIG", "RRSIG", "NSEC", "NSEC3"})


class ZoneDecodeError(ValueError):
    """The dump is not a decodable AXFR capture for the zone."""


def read_dump_bytes(raw: bytes, zone: str) -> str:
    """Strict-UTF8 decode with sanity guards; corruption is an error."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZoneDecodeError(f"dump is not valid UTF-8: {exc}") from exc
    if not text.strip():
        raise ZoneDecodeError("dump is empty")
    if f"{zone}." not in text:
        raise ZoneDecodeError(f"dump does not mention zone {zone}")
    return text


def decode_axfr(text: str, zone: str, include_control: bool = False) -> dict[str, Any]:
    """Decode one AXFR dump into raw indicator lists plus a report.

    Returns ``serial`` (zone SOA serial), ``counts`` (per trigger type
    and the control/unparsed/skipped residue), ``actions`` (rdata
    distribution), and the raw lists: ``ips`` as CIDR strings,
    ``domains`` as plain names, and ``ndjson`` lines pairing every
    indicator with its zone action. Vendor control names (the
    threatstop.com plumbing and canaries) are counted but kept out of
    the lists unless ``include_control`` is set.
    """
    zone_fqdn = f"{zone}."
    suffix = f".{zone_fqdn}"
    if zone_fqdn not in text:
        raise ZoneDecodeError(f"dump does not mention zone {zone}")
    serial: int | None = None
    counts = {
        "records": 0,
        "qname": 0,
        "ip": 0,
        "nsip": 0,
        "nsdname": 0,
        "client_ip": 0,
        "control": 0,
        "unparsed": 0,
        "skipped": 0,
    }
    actions: dict[str, int] = {}
    ips: list[str] = []
    domains: list[str] = []
    ndjson: list[str] = []

    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != "IN":
            continue
        owner, rtype = parts[0], parts[3]
        rdata = " ".join(parts[4:])
        if rtype == "SOA":
            if owner == zone_fqdn:
                # mname, rname, serial, refresh, retry, expire, minimum
                try:
                    serial = int(rdata.split()[2])
                except (IndexError, ValueError):
                    serial = None
            counts["skipped"] += 1
            continue
        if rtype in _SKIP_TYPES:
            counts["skipped"] += 1
            continue
        if not owner.endswith(suffix):
            continue
        counts["records"] += 1
        base = owner[: -len(suffix)].rstrip(".")
        action = _action_of(rtype, rdata)
        actions[action] = actions.get(action, 0) + 1

        is_control = _is_control(base)
        if is_control:
            counts["control"] += 1
            if not include_control:
                continue
        if base.endswith(_IP_TRIGGER_SUFFIXES):
            kind, branch = _ip_trigger_kind(base)
            cidr = _decode_ip_trigger(base, branch)
            if cidr is None:
                counts["unparsed"] += 1
                continue
            counts[kind] += 1
            ips.append(cidr)
            ndjson.append(_ndjson(kind, cidr, action))
        elif base.endswith(_NAME_TRIGGER):
            name = base[: -len(_NAME_TRIGGER)].rstrip(".")
            if not name:
                counts["unparsed"] += 1
                continue
            counts["nsdname"] += 1
            domains.append(name)
            ndjson.append(_ndjson("nsdname", name, action))
        elif not base:
            counts["unparsed"] += 1
        else:
            counts["qname"] += 1
            domains.append(base)
            ndjson.append(_ndjson("qname", base, action))

    return {
        "serial": serial,
        "counts": counts,
        "actions": dict(sorted(actions.items(), key=lambda kv: -kv[1])),
        "ips": ips,
        "domains": domains,
        "ndjson": ndjson,
    }


def _is_control(base: str) -> bool:
    lowered = base.lower()
    return lowered in CONTROL_DOMAINS or lowered.endswith(".threatstop.com")


def _ip_trigger_kind(base: str) -> tuple[str, str]:
    for branch, kind in _IP_TRIGGERS:
        if base.endswith(branch):
            return kind, branch
    return "ip", ".rpz-ip"


def _action_of(rtype: str, rdata: str) -> str:
    if rtype == "TXT":
        return "txt"
    if rtype in ("A", "AAAA"):
        return "local-data"
    if rtype != "CNAME":
        return rtype.lower()
    target = rdata.strip().rstrip(".").strip('"')
    lowered = target.lower()
    if lowered == "":
        return "nxdomain"
    if lowered == "*":
        return "nodata"
    if lowered == "rpz-passthru":
        return "passthru"
    if lowered == "rpz-drop":
        return "drop"
    if lowered == "rpz-tcp-only":
        return "tcp-only"
    return f"redirect:{target}"


def _decode_ip_trigger(base: str, branch: str) -> str | None:
    labels = base[: -len(branch)].split(".")
    if len(labels) < 2:
        return None
    try:
        prefix = int(labels[0])
    except ValueError:
        return None
    body = labels[1:]
    if all(label.isdigit() for label in body):
        return _decode_ipv4(body, prefix)
    if all(
        label == "zz"
        or (label and len(label) <= 4 and all(ch in "0123456789abcdefABCDEF" for ch in label))
        for label in body
    ):
        return _decode_ipv6(body, prefix)
    return None


def _decode_ipv4(labels: list[str], prefix: int) -> str | None:
    if not 1 <= prefix <= 32 or not 1 <= len(labels) <= 4:
        return None
    try:
        octets_rev = [int(label) for label in labels]
    except ValueError:
        return None
    if any(octet > 255 for octet in octets_rev):
        return None
    # Labels are the address octets reversed; least-significant octets
    # may be truncated for shorter prefixes — pad on the right.
    octets = list(reversed(octets_rev))
    while len(octets) < 4:
        octets.append(0)
    return f"{'.'.join(str(octet) for octet in octets)}/{prefix}"


def _decode_ipv6(labels: list[str], prefix: int) -> str | None:
    if not 1 <= prefix <= 128 or len(labels) > 32:
        return None
    if any(label == "zz" for label in labels):
        groups = _decode_ipv6_hextet(labels)
    else:
        groups = _decode_ipv6_nibble(labels)
    if groups is None:
        return None
    return f"{_format_ipv6(groups)}/{prefix}"


def _decode_ipv6_nibble(labels: list[str]) -> list[int] | None:
    """Single hex digits reversed; trailing nibbles are zero.

    Multi-char hex labels are NOT accepted here — a hextet-form trigger
    without its zz marker must land in the unparsed bucket, never be
    reinterpreted as nibbles (that would fabricate bogus CIDRs).
    """
    if any(len(label) != 1 for label in labels):
        return None
    try:
        nibbles_rev = [int(label, 16) for label in labels]
    except ValueError:
        return None
    if len(nibbles_rev) * 4 > 128:
        return None
    if any(nibble > 0xF for nibble in nibbles_rev):
        return None
    nibbles = list(reversed(nibbles_rev))
    while len(nibbles) < 32:
        nibbles.append(0)
    return [
        nibbles[i] * 4096 + nibbles[i + 1] * 256 + nibbles[i + 2] * 16 + nibbles[i + 3]
        for i in range(0, 32, 4)
    ]


def _decode_ipv6_hextet(labels: list[str]) -> list[int] | None:
    """draft-00 form: 16-bit groups reversed, one zz marks the zero run.

    ``48.zz.101.db8.2001`` decodes to 2001:db8:101::/48: the labels
    after ``zz`` are the leading hextets in reverse order, the labels
    before it are the trailing hextets in reverse order.
    """
    if labels.count("zz") != 1:
        return None
    split = labels.index("zz")
    try:
        head = [int(label, 16) for label in reversed(labels[split + 1 :])]
        tail = [int(label, 16) for label in reversed(labels[:split])]
    except ValueError:
        return None
    if any(group > 0xFFFF for group in head + tail):
        return None
    missing = 8 - len(head) - len(tail)
    if missing < 1:
        return None
    return head + [0] * missing + tail


def _format_ipv6(groups: list[int]) -> str:
    parts = [format(group, "x") for group in groups]
    best_start, best_len, cur_start, cur_len = -1, 0, -1, 0
    for index, part in enumerate(parts + ["x"]):
        if part == "0":
            if cur_start < 0:
                cur_start = index
            cur_len += 1
        else:
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
            cur_start, cur_len = -1, 0
    if best_len < 2:
        return ":".join(parts)
    head = ":".join(parts[:best_start])
    tail = ":".join(parts[best_start + best_len :])
    return f"{head}::{tail}"


def _ndjson(kind: str, value: str, action: str) -> str:
    return json.dumps({"type": kind, "value": value, "action": action})
