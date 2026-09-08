"""Closed input types, exclusions and resource budgets shared by all sources."""
from __future__ import annotations

import ipaddress
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field


class Refusal(ValueError):
    """A constant, safe diagnostic; never interpolate untrusted text."""


def domain(value):
    if not isinstance(value, str) or len(value) > 254:
        raise Refusal("invalid domain")
    value = value.lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}", value):
        raise Refusal("invalid domain")
    return value


def normalize(kind, value):
    if isinstance(value, str):
        for env in ("SHODAN_API_KEY", "CERTSPOTTER_TOKEN"):
            secret = os.environ.get(env)
            if secret and len(secret) <= 4096 and any(form.lower() in value.lower() for form in (secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret))):
                raise Refusal("secret-bearing value omitted [REDACTED]")
    if kind == "domain":
        return domain(value)
    if kind == "domain_suffix":
        if not isinstance(value, str):
            raise Refusal("invalid domain suffix")
        value = value.lower().lstrip(".").rstrip(".")
        if re.fullmatch(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
            return value
        return domain(value)
    if kind == "dns_pattern":
        if not isinstance(value, str) or not value.startswith("*."):
            raise Refusal("invalid DNS pattern")
        base = value[2:].lower().rstrip(".")
        # Retain even a one-label wildcard suffix as certificate evidence;
        # it never becomes a live domain query or a blanket scope grant.
        if re.fullmatch(r"[a-z][a-z0-9-]{0,62}", base):
            return "*." + base
        return "*." + domain(base)
    if kind == "ip":
        if not isinstance(value, str) or "%" in value:
            raise Refusal("invalid IP")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise Refusal("invalid IP") from None
    if kind == "network":
        try:
            if not isinstance(value, str) or "%" in value:
                raise ValueError()
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise Refusal("invalid network") from None
    if kind == "certificate":
        if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            raise Refusal("certificate requires SHA256 hex")
        return value.lower()
    if kind == "asn":
        if isinstance(value, str) and re.fullmatch(r"AS[0-9]{1,10}", value):
            value = int(value[2:])
        if type(value) is not int or not 1 <= value <= 4294967295:
            raise Refusal("invalid ASN")
        return str(value)
    if kind == "organization":
        if (not isinstance(value, str) or not 1 <= len(value) <= 120 or
                not value.isprintable() or not value.strip()):
            raise Refusal("invalid organization")
        return value.strip()
    raise Refusal("unknown node type")


def closed(obj, keys):
    if not isinstance(obj, dict) or set(obj) - set(keys):
        raise Refusal("unknown or invalid fields")
    return obj


def bounded_list(value, maximum=64):
    if not isinstance(value, list) or len(value) > maximum:
        raise Refusal("invalid or oversized list")
    return value


DEFAULTS = dict(max_depth=3, max_nodes=500, max_edges=1000, max_requests=16,
                max_records=2000, max_output_bytes=262144, wall_seconds=30,
                min_interval_ms=250, retries=0)
CEILINGS = dict(max_depth=5, max_nodes=1000, max_edges=2000, max_requests=32,
                max_records=4000, max_output_bytes=1048576, wall_seconds=60,
                min_interval_ms=2000, retries=2)


class Budget:
    def __init__(self, values=None):
        values = closed({} if values is None else values, DEFAULTS)
        self.values = DEFAULTS | values
        for key, value in self.values.items():
            minimum = 0 if key in ("max_depth", "retries") else (4096 if key == "max_output_bytes" else 50 if key == "min_interval_ms" else 1)
            if type(value) is not int or not minimum <= value <= CEILINGS[key]:
                raise Refusal("invalid limit")
        self.deadline = time.monotonic() + self.values["wall_seconds"]
        self.requests = 0
        self.records = 0
        self.last_request = None

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Refusal("deadline reached")
        return remaining

    def request(self):
        self.remaining()
        if self.requests >= self.values["max_requests"]:
            raise Refusal("request budget reached")
        if self.last_request is not None:
            wait = self.values["min_interval_ms"] / 1000 - (time.monotonic() - self.last_request)
            if wait > 0:
                if wait >= self.remaining():
                    raise Refusal("pacing exceeds deadline")
                time.sleep(wait)
        self.requests += 1
        self.last_request = time.monotonic()

    def record(self):
        self.remaining()
        if self.records >= self.values["max_records"]:
            raise Refusal("record budget reached")
        self.records += 1


class Exclusions:
    def __init__(self, values=None):
        values = closed({} if values is None else values, ("domains", "networks"))
        self.domains = tuple(normalize("domain_suffix", v) for v in bounded_list(values.get("domains", [])))
        self.networks = tuple(ipaddress.ip_network(normalize("network", v))
                              for v in bounded_list(values.get("networks", [])))

    def denies(self, kind, value):
        if kind in ("domain", "dns_pattern"):
            value = value.removeprefix("*.")
            return any(value == d or value.endswith("." + d) for d in self.domains)
        if kind in ("ip", "network"):
            net = ipaddress.ip_network(value, strict=False)
            return any(net.version == n.version and net.overlaps(n) for n in self.networks)
        return False


def seeds(values, exclusions):
    values = closed({} if values is None else values, ("domains", "ips", "fingerprints", "asns", "networks", "domains_file", "targets_file"))
    output = []
    for plural, kind in (("domains", "domain"), ("ips", "ip"), ("fingerprints", "certificate"), ("asns", "asn")):
        for value in bounded_list(values.get(plural, []), 256 if plural == "ips" else 64):
            value = normalize(kind, value)
            if not exclusions.denies(kind, value) and (kind, value) not in output:
                output.append((kind, value))
    for value in bounded_list(values.get("networks", []), 16):
        network = ipaddress.ip_network(normalize("network", value))
        if network.num_addresses > 256:
            raise Refusal("seed network exceeds 256 address cap")
        for address in network:
            value = str(address)
            if not exclusions.denies("ip", value) and ("ip", value) not in output:
                output.append(("ip", value))
            if len(output) > 512:
                raise Refusal("seed expansion exceeds 512 nodes")
    return output


def live_value(kind, value):
    """Recorded documentation values are allowed offline, never sent live."""
    if kind == "ip":
        address = ipaddress.ip_address(value)
        return address.is_global and not address.is_multicast and not address.is_reserved and not getattr(address, "is_site_local", False)
    if kind == "domain":
        return not any(value == suffix or value.endswith("." + suffix) for suffix in
                       ("test", "invalid", "localhost", "local", "internal", "example", "example.com", "example.net", "example.org", "onion", "arpa"))
    if kind == "asn":
        number = int(value)
        return not (number == 23456 or 64496 <= number <= 65551 or 4200000000 <= number <= 4294967295)
    return kind == "certificate"


def pattern_covers(pattern, name):
    return pattern.startswith("*.") and name.endswith(pattern[1:]) and name.count(".") == pattern.count(".")


@dataclass(frozen=True)
class Observation:
    source: str
    left_kind: str
    left: str
    relation: str
    right_kind: str
    right: str
    classification: str = "observed"
    attributes: dict = field(default_factory=dict)
