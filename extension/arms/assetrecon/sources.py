"""Source adapters emit the same typed observations; provider data is untrusted."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
import re
from dataclasses import dataclass
from datetime import datetime

from .model import Observation, Refusal, bounded_list, closed, normalize

# Live certificate-transparency responses for large telecom domains regularly
# exceed 1 MiB (optimum.com ~1.2 MiB, wowway.com ~1.4 MiB exact+wildcard). The
# 1 MiB cap made the governed `asset-recon ct/discover` path fail closed on such
# footprints, so the decode/fixture byte bound is raised to 16 MiB. The output
# budget (max_output_bytes=1 MiB) independently prunes what is echoed; this is
# only the read/parse admission bound.
MAX_FILE_BYTES = 16 * 1024 * 1024


def read_fixture(path):
    if not isinstance(path, str) or not os.path.isabs(path) or len(path) > 4096:
        raise Refusal("fixture requires absolute regular file")
    fd = None
    try:
        if os.path.islink(path):
            raise Refusal("fixture is not a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise Refusal("fixture is not a bounded regular file")
        chunks = []
        size = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_FILE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise Refusal("fixture exceeds byte limit")
        raw = b"".join(chunks)
        return decode(raw), hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeError, RecursionError, ValueError):
        raise Refusal("invalid or inaccessible fixture") from None
    finally:
        if fd is not None:
            os.close(fd)


def decode(raw):
    if len(raw) > MAX_FILE_BYTES:
        raise Refusal("source exceeds byte limit")
    # Bound nesting before the JSON decoder allocates recursive containers.
    depth = 0
    quoted = escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > 24:
                raise Refusal("source nesting limit")
        elif char in (93, 125):
            depth -= 1
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("invalid source JSON") from None


def attributes(row):
    output = {}
    for original, key in (("id", "record_id"), ("entry_timestamp", "observed_at"), ("timestamp", "observed_at"),
                          ("discovered_at", "observed_at"), ("not_before", "not_before"), ("not_after", "not_after"), ("ttl", "ttl"), ("port", "port"), ("transport", "transport")):
        if original not in row:
            continue
        value = row[original]
        if key == "record_id":
            if type(value) is int and value >= 0:
                value = str(value)
            if (not isinstance(value, str) or not 1 <= len(value) <= 128 or
                    not value.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in value)):
                raise Refusal("invalid provider record identifier")
        elif key == "transport":
            if value not in ("tcp", "udp"):
                raise Refusal("invalid service transport")
        elif key == "port":
            if type(value) is not int or not 1 <= value <= 65535:
                raise Refusal("invalid service port")
        elif key == "ttl":
            if type(value) is not int or not 0 <= value <= 2147483647:
                raise Refusal("invalid DNS TTL")
        else:
            if not isinstance(value, str) or len(value) > 40 or not re.fullmatch(r"[0-9TtZz:+. -]+", value):
                raise Refusal("invalid evidence timestamp")
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                raise Refusal("invalid evidence timestamp") from None
        output[key] = value
    return output


def observation(source, lk, left, relation, rk, right, metadata=None):
    return Observation(source, lk, normalize(lk, left), relation, rk, normalize(rk, right), attributes=metadata or {})


def crtsh(data):
    for row in bounded_list(data, 4000):
        if not isinstance(row, dict):
            raise Refusal("invalid CT record")
        names = row.get("name_value")
        if not isinstance(names, str) or len(names) > 16384:
            raise Refusal("invalid CT names")
        names = list(dict.fromkeys(("dns_pattern" if v.startswith("*.") else "domain", v.lower().rstrip(".")) for v in names.splitlines()))
        if not names or len(names) > 128:
            raise Refusal("invalid CT names")
        fingerprint = row.get("sha256") or row.get("fingerprint_sha256")
        metadata = attributes(row)
        if fingerprint:
            for kind, name in names:
                yield observation("crtsh", "certificate", fingerprint, "san", kind, name, metadata)
        else:
            # crt.sh JSON does not necessarily include a certificate digest.
            # A synthetic digest would falsely claim certificate-byte custody.
            anchor_kind, anchor_name = names[0]
            yield observation("crtsh", anchor_kind, anchor_name, "query_match", anchor_kind, anchor_name, metadata)
            for kind, name in names[1:]:
                yield observation("crtsh", anchor_kind, anchor_name, "co_certificate_name", kind, name, metadata)


def dns(data):
    for row in bounded_list(data, 4000):
        closed(row, ("name", "type", "value", "ttl", "timestamp"))
        metadata = attributes(row)
        rr = row.get("type")
        if rr in ("A", "AAAA"):
            address = normalize("ip", row.get("value"))
            if ipaddress.ip_address(address).version != (4 if rr == "A" else 6):
                raise Refusal("DNS address family mismatch")
            yield observation("dns", "domain", row.get("name"), "resolves_to", "ip", row.get("value"), metadata)
        elif rr == "PTR":
            yield observation("dns", "ip", row.get("name"), "ptr", "domain", row.get("value"), metadata)
        elif rr == "CNAME":
            yield observation("dns", "domain", row.get("name"), "cname", "domain", row.get("value"), metadata)
        else:
            raise Refusal("unsupported DNS record")


def certspotter(data):
    for row in bounded_list(data, 4000):
        if not isinstance(row, dict) or not isinstance(row.get("dns_names"), list):
            raise Refusal("invalid CertSpotter issuance")
        for name in bounded_list(row["dns_names"], 128):
            kind = "dns_pattern" if isinstance(name, str) and name.startswith("*.") else "domain"
            yield observation("certspotter", "certificate", row.get("cert_sha256"), "san", kind, name, attributes(row))


def registry(data):
    for row in bounded_list(data, 4000):
        closed(row, ("ip", "prefix", "asn", "organization"))
        asn = row.get("asn")
        if "ip" in row and "prefix" in row:
            address = ipaddress.ip_address(normalize("ip", row["ip"]))
            network = ipaddress.ip_network(normalize("network", row["prefix"]))
            if address.version != network.version or address not in network:
                raise Refusal("registry prefix does not contain IP")
        if "prefix" in row:
            yield observation("registry", "network", row["prefix"], "announced_by", "asn", asn)
        if "ip" in row:
            yield observation("registry", "ip", row["ip"], "announced_by", "asn", asn)
        if "organization" in row:
            yield observation("registry", "asn", asn, "registered_to", "organization", row["organization"])


def shodan(data):
    if isinstance(data, dict) and "matches" in data:
        data = data["matches"]
    elif isinstance(data, dict):
        data = [data]
    roots = bounded_list(data, 4000)
    def rows():
        for root in roots:
            if not isinstance(root, dict):
                raise Refusal("invalid Shodan record")
            yield root
            services = root.get("data", [])
            if isinstance(services, str):
                services = []  # Search matches carry a raw banner, not services.
            for service in bounded_list(services, 128):
                if not isinstance(service, dict):
                    raise Refusal("invalid Shodan service record")
                yield dict(service, ip_str=root.get("ip_str"))
    for row in rows():
        if not isinstance(row, dict):
            raise Refusal("invalid Shodan record")
        ip = normalize("ip", row.get("ip_str"))
        metadata = attributes(row)
        for name in bounded_list(row.get("hostnames", []), 128):
            yield observation("shodan", "ip", ip, "observed_hostname", "domain", name, metadata)
        ssl = row.get("ssl") or {}
        if not isinstance(ssl, dict):
            raise Refusal("invalid Shodan certificate")
        cert = ssl.get("cert") or {}
        if not isinstance(cert, dict):
            raise Refusal("invalid Shodan certificate")
        fp = cert.get("fingerprint", {})
        if isinstance(fp, dict) and "sha256" in fp:
            yield observation("shodan", "ip", ip, "served_certificate", "certificate", fp["sha256"], metadata)
        if row.get("asn") is not None:
            yield observation("shodan", "ip", ip, "announced_by", "asn", row["asn"], metadata)
        if isinstance(row.get("org"), str) and row["org"].strip():
            yield observation("shodan", "ip", ip, "observed_organization", "organization", row["org"], metadata)


@dataclass(frozen=True)
class Adapter:
    parse: object
    query_kinds: tuple[str, ...]
    endpoint: str


ADAPTERS = {
    "crtsh": Adapter(crtsh, ("domain",), "https://crt.sh/"),
    "dns": Adapter(dns, ("domain", "ip"), "https://dns.google/resolve"),
    "google": Adapter(dns, ("domain", "ip"), "https://dns.google/resolve"),
    "cloudflare": Adapter(dns, ("domain", "ip"), "https://cloudflare-dns.com/dns-query"),
    "certspotter": Adapter(certspotter, ("domain",), "https://api.certspotter.com/v1/issuances"),
    "registry": Adapter(registry, ("ip", "asn"), "https://stat.ripe.net/data/"),
    # shodan can also query a network (CIDR) via host/search net: filter; this
    # lets an ASN-seed discover expand announced-prefix network nodes down to
    # observed origin hosts instead of stalling at the network tier (P2).
    "shodan": Adapter(shodan, ("ip", "certificate", "network"), "https://api.shodan.io/"),
}
