"""Isolated fixed-destination collectors and explicit literal-target probes.

The parent kills this process group on its absolute deadline. Child resource
limits bound JSON allocation and optional scanner memory/CPU as well.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
try:
    import resource
except ModuleNotFoundError:  # pragma: no cover - exercised by Windows imports
    resource = None
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .model import Refusal, bounded_list, closed, live_value, normalize, pattern_covers
from .sources import ADAPTERS, MAX_FILE_BYTES, decode
from .probe_policy import validate_target
from .sanitize import safe_text


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Refusal("provider redirect refused")


def credential(value):
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or not value.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise Refusal("invalid provider credential")
    return value


def opaque_cursor(value):
    """Bound an opaque provider cursor without inventing a token grammar."""
    if (not isinstance(value, str) or not 1 <= len(value) <= 128 or
            not value.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in value)):
        raise Refusal("invalid pagination cursor")
    return value


def fetch(url, token=None, dns=False):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    headers = {"Accept": "application/dns-json" if dns else "application/json", "Accept-Encoding": "identity"}
    if token:
        headers["Authorization"] = "Bearer " + credential(token)
    request = urllib.request.Request(url, headers=headers)
    # Live CT responses for large telecom domains are multi-MiB and crt.sh is
    # slow/rate-limited; 8s socket timeout was too tight and made the governed
    # footprinting path fail on reads. 30s accommodates slow large responses.
    with opener.open(request, timeout=30) as response:
        if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
            raise Refusal("invalid provider response")
        raw = response.read(MAX_FILE_BYTES + 1)
    return decode(raw), hashlib.sha256(raw).hexdigest()


def collect(source, kind, value, variant=None):
    if source == "crtsh":
        query = value if variant == "exact" else "%." + value
        # crt.sh intermittently returns 502 / drops large responses. Retry with
        # linear backoff so a transient failure is absorbed in-process (P3);
        # bounded by the parent wall deadline, and sleep is wall-clock not CPU.
        attempts = 0
        while True:
            attempts += 1
            try:
                data, digest = fetch("https://crt.sh/?" + urllib.parse.urlencode({"q": query, "output": "json"}))
                break
            except (Refusal, TimeoutError, OSError):
                if attempts >= 3:
                    raise
                time.sleep(1.0 * attempts)
        for row in bounded_list(data, 4000):
            if not isinstance(row, dict) or not isinstance(row.get("name_value"), str) or len(row["name_value"]) > 16384:
                raise Refusal("invalid CT record")
            if not ct_names_bind(row["name_value"].splitlines(), value):
                raise Refusal("CT record does not bind query")
        return dict(ok=True, data=data, digest=digest, limitations=["CT index results are a snapshot; provider has no completeness guarantee"])
    if source == "certspotter":
        params = [("domain", value), ("include_subdomains", "true"),
                  ("match_wildcards", "true"), ("expand", "dns_names")]
        if variant:
            params.append(("after", variant))
        data, digest = fetch("https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(params), os.environ.get("CERTSPOTTER_TOKEN"))
        if not isinstance(data, list):
            raise Refusal("invalid CertSpotter page")
        cursor = None
        for row in data:
            if not isinstance(row, dict) or not isinstance(row.get("dns_names"), list):
                raise Refusal("invalid issuance")
            if not ct_names_bind(row["dns_names"], value):
                raise Refusal("issuance does not bind query")
            cursor = opaque_cursor(row.get("id"))
        return dict(ok=True, data=data, digest=digest, cursor=cursor,
                    limitations=["CT provider returns indexed unexpired issuances, not a complete current asset inventory"])
    if source in ("google", "cloudflare"):
        name = ipaddress.ip_address(value).reverse_pointer if kind == "ip" else value
        rr = "PTR" if kind == "ip" else variant
        endpoint = "https://dns.google/resolve" if source == "google" else "https://cloudflare-dns.com/dns-query"
        data, digest = fetch(endpoint + "?" + urllib.parse.urlencode({"name": name, "type": rr}), dns=True)
        if not isinstance(data, dict) or type(data.get("Status")) is not int or data["Status"] not in (0, 3) or data.get("TC") is not False:
            raise Refusal("DNS incomplete or failed")
        answers = data.get("Answer", [])
        question = data.get("Question")
        expected = {"A": 1, "AAAA": 28, "PTR": 12}[rr]
        if not isinstance(question, list) or len(question) != 1 or question[0].get("name", "").lower().rstrip(".") != name.lower().rstrip(".") or question[0].get("type") != expected:
            raise Refusal("DNS question does not bind request")
        answers = bounded_list(answers, 4000)
        if data["Status"] == 3 and answers:
            raise Refusal("NXDOMAIN contains contradictory answers")
        rows = []
        allowed_names = {name.lower().rstrip(".")}
        for _ in range(min(len(answers), 16)):
            for answer in answers:
                if answer.get("type") == 5 and answer.get("name", "").lower().rstrip(".") in allowed_names:
                    allowed_names.add(answer.get("data", "").lower().rstrip("."))
        for answer in answers:
            rrtype = {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR"}.get(answer.get("type"))
            if rrtype is None or answer.get("name", "").lower().rstrip(".") not in allowed_names or (rrtype != rr and rrtype != "CNAME"):
                raise Refusal("DNS answer does not bind request")
            if kind == "ip" and rrtype == "CNAME":
                continue  # RFC2317 aliases establish binding, not asset names.
            row = dict(name=value if rrtype == "PTR" else answer.get("name"), type=rrtype, value=answer.get("data"))
            if "TTL" in answer:
                row["ttl"] = answer["TTL"]
            rows.append(row)
        return dict(ok=True, data=rows, digest=digest, dns_status=data["Status"], limitations=[])
    if source == "registry":
        endpoint = "network-info" if kind == "ip" else ("as-overview" if variant == "overview" else "announced-prefixes")
        data, digest = fetch("https://stat.ripe.net/data/" + endpoint + "/data.json?" + urllib.parse.urlencode({"resource": value if kind == "ip" else "AS" + value}))
        if not isinstance(data, dict) or data.get("status") != "ok" or not isinstance(data.get("data"), dict):
            raise Refusal("registry failed")
        body = data["data"]
        if kind == "ip":
            asns = bounded_list(body.get("asns"), 64)
            if not asns:
                rows = []
            else:
                prefix = normalize("network", body.get("prefix"))
                address = ipaddress.ip_address(value)
                network = ipaddress.ip_network(prefix)
                if address.version != network.version or address not in network:
                    raise Refusal("registry prefix does not bind query")
                normalized_asns = []
                for asn in asns:
                    # RIPEstat network-info serializes ASNs as bare decimal
                    # strings (unlike our caller contract, which uses ints or
                    # AS-prefixed strings). Normalize that provider shape at
                    # the trust boundary, without widening seed inputs.
                    if isinstance(asn, str) and re.fullmatch(r"[0-9]{1,10}", asn):
                        asn = int(asn)
                    if type(asn) is not int:
                        raise Refusal("invalid registry ASN")
                    normalized_asns.append(int(normalize("asn", asn)))
                rows = [dict(ip=value, prefix=prefix, asn=asn) for asn in normalized_asns]
        elif variant == "overview":
            if str(body.get("resource", "")).removeprefix("AS") != value or not isinstance(body.get("holder"), str):
                raise Refusal("registry organization does not bind query")
            rows = [dict(asn=int(value), organization=body["holder"])]
        else:
            if str(body.get("resource", "")).removeprefix("AS") != value:
                raise Refusal("registry prefixes do not bind query")
            prefixes = bounded_list(body.get("prefixes"), 4000)
            rows = []
            for item in prefixes:
                if not isinstance(item, dict):
                    raise Refusal("invalid registry prefix")
                rows.append(dict(prefix=normalize("network", item.get("prefix")), asn=int(value)))
        return dict(ok=True, data=rows, digest=digest, limitations=[])
    if source == "shodan":
        key = credential(os.environ.get("SHODAN_API_KEY"))
        if not key:
            raise Refusal("Shodan credential unavailable")
        if kind == "ip":
            url = "https://api.shodan.io/shodan/host/" + value + "?" + urllib.parse.urlencode({"key": key})
        else:
            # certificate -> ssl.cert fingerprint search; network -> net: CIDR
            # search (lets an announced-prefix node expand to observed origin
            # hosts instead of stalling at the network tier).
            query = ("net:" if kind == "network" else "ssl.cert.fingerprint.sha256:") + value
            url = "https://api.shodan.io/shodan/host/search?" + urllib.parse.urlencode({"key": key, "query": query, "page": 1})
        data, digest = fetch(url)
        if not isinstance(data, dict):
            raise Refusal("invalid Shodan response")
        if kind == "ip":
            if normalize("ip", data.get("ip_str")) != value:
                raise Refusal("Shodan host response does not bind query")
        else:
            matches = bounded_list(data.get("matches"), 4000)
            total = data.get("total")
            if type(total) is not int or total < len(matches):
                raise Refusal("invalid Shodan search response")
            for match in matches:
                if not isinstance(match, dict):
                    raise Refusal("invalid Shodan search match")
                if kind == "certificate":
                    certificate = match.get("ssl", {}).get("cert", {}) if isinstance(match.get("ssl", {}), dict) else {}
                    fingerprint = certificate.get("fingerprint", {}) if isinstance(certificate, dict) else {}
                    if not isinstance(fingerprint, dict) or normalize("certificate", fingerprint.get("sha256")) != value:
                        raise Refusal("Shodan search result does not bind certificate query")
        limitations = ["Shodan snapshot is not proof of current service state"]
        if kind in ("certificate", "network") and isinstance(data, dict) and data.get("total", 0) > len(data.get("matches", [])):
            limitations.append("Shodan pagination not exhausted")
        return dict(ok=True, data=data, digest=digest, limitations=limitations)
    raise Refusal("unknown provider")


def ct_names_bind(names, root):
    for raw in bounded_list(names, 128):
        kind = "dns_pattern" if isinstance(raw, str) and raw.startswith("*.") else "domain"
        value = normalize(kind, raw)
        base = value.removeprefix("*.")
        if base == root or base.endswith("." + root) or (kind == "dns_pattern" and pattern_covers(value, root)):
            return True
    return False


def probe(target, timeout=8):
    deadline = time.monotonic() + timeout
    ip = target["ip"]
    port = target["port"]
    method = target["method"]
    if method in ("nmap", "zgrab2"):
        from ...contract import ArmSpec
        spec = ArmSpec(method, ("cli",), True, "Explicit bounded probe composition", "research")
        if method == "nmap":
            from ..nmap import NmapArm
            auth_target = "[" + ip + "]" if ":" in ip else ip
            result = NmapArm(timeout=timeout).invoke(spec, "scan", dict(target=auth_target, mode="version-light", ports=[port]))
        else:
            from ..zgrab2 import Zgrab2Arm
            result = Zgrab2Arm(timeout=timeout).invoke(spec, "scan", dict(target=ip, module=target.get("module", "banner"), port=port))
        if not result.ok or not isinstance(result.output, dict):
            raise Refusal("delegated scanner failed")
        raw = result.output.get("output")
        if method == "zgrab2" and isinstance(raw, dict):
            raw = json.dumps(raw)
        if not isinstance(raw, str) or not raw or len(raw) > 200000:
            raise Refusal("invalid scanner response")
        observations = []
        if method == "nmap":
            if "<!" in raw:
                raise Refusal("XML declarations refused")
            root = ET.fromstring(raw)
            for elem in root.findall(".//port")[:16]:
                state = elem.find("state")
                service = elem.find("service")
                item = {"port": port, "state": "open" if state is not None and state.get("state") == "open" else "not-open"}
                if service is not None and service.get("name") in ("http", "https", "ssh", "smtp", "ftp", "domain", "mysql", "postgresql", "imap", "pop3", "ssl", "unknown"):
                    item["service"] = service.get("name")
                if service is not None:
                    for field in ("product", "version", "extrainfo"):
                        if field in service.attrib:
                            item[field] = safe_text(service.get(field), 120)["preview"]
                observations.append(item)
        else:
            parsed = json.loads(raw.splitlines()[0])
            module = target.get("module", "banner")
            entry = parsed.get("data", {}).get(module, {})
            if entry.get("status") != "success":
                raise Refusal("zgrab2 protocol probe unsuccessful")
            item = {"protocol": module, "status": "responded"}
            if "result" in entry:
                summary = safe_text(json.dumps(entry["result"], sort_keys=True), 512)
                item["result_preview"] = summary["preview"]
                item["result_preview_truncated"] = summary["preview_truncated"]
            observations.append(item)
        if not observations:
            raise Refusal("scanner produced no observations")
        return dict(ok=True, observations=observations, bytes=len(raw), sha256=hashlib.sha256(raw.encode()).hexdigest(), content="[REDACTED]")
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM if method == "udp-hello" else socket.SOCK_STREAM) as sock:
        sock.settimeout(max(.001, deadline - time.monotonic()))
        sock.connect((ip, port))
        if method in ("tcp-hello", "udp-hello"):
            sock.settimeout(max(.001, deadline - time.monotonic()))
            sock.sendall(target.get("hello", "hello\r\n").encode("ascii"))
        if method == "tls" or target.get("url", "").startswith("https:"):
            context = ssl.create_default_context()
            # An IP certificate is verified for that exact explicit IP.
            sock.settimeout(max(.001, deadline - time.monotonic()))
            with context.wrap_socket(sock, server_hostname=target.get("host", ip)) as tls:
                if method == "tls":
                    cert = tls.getpeercert(binary_form=True)
                    return dict(ok=True, tls_version=tls.version(), certificate_sha256=hashlib.sha256(cert).hexdigest())
                return http_get(tls, target, deadline)
        if method == "http":
            return http_get(sock, target, deadline)
        if method == "tcp":
            return dict(ok=True, connected=True)
        sock.settimeout(max(.001, deadline - time.monotonic()))
        banner = sock.recv(4096)
        return dict(ok=True, bytes=len(banner), sha256=hashlib.sha256(banner).hexdigest(), **safe_text(banner), read_limit=4096)


def http_get(sock, target, deadline=None):
    deadline = deadline if deadline is not None else time.monotonic() + 8
    url = urllib.parse.urlsplit(target["url"])
    path = url.path or "/"
    request = ("GET " + path + " HTTP/1.0\r\nHost: " + url.netloc + "\r\nConnection: close\r\n\r\n").encode("ascii")
    sock.sendall(request)
    raw = b""
    complete = False
    read_limit = 16384
    while len(raw) < read_limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(4096, read_limit - len(raw)))
        except (TimeoutError, socket.timeout):
            break
        if not chunk:
            complete = True
            break
        raw += chunk
    if b"\r\n\r\n" not in raw:
        raise Refusal("HTTP headers incomplete within capture bound")
    first = raw.split(b"\r\n", 1)[0].split(b" ")
    if len(first) < 2 or first[0] not in (b"HTTP/1.0", b"HTTP/1.1") or len(first[1]) != 3 or not first[1].isdigit() or not 100 <= int(first[1]) <= 599:
        raise Refusal("invalid HTTP response")
    headers = {}
    for line in raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
        key, separator, value = line.partition(b":")
        if separator and key.lower() in (b"server", b"content-type", b"content-length"):
            headers[key.decode("ascii").lower()] = safe_text(value.strip(), 160)["preview"]
    body = safe_text(raw.split(b"\r\n\r\n", 1)[1], 512)
    return dict(ok=True, complete=complete, http_status=int(first[1]), headers=headers,
                body_preview=body["preview"], body_preview_truncated=body["preview_truncated"],
                capture_truncated=not complete, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                redirects_followed=0, read_limit=read_limit)


def validate_request(request):
    if not isinstance(request, dict) or request.get("operation") not in ("collect", "probe"):
        raise Refusal("unknown operation")
    if request.get("live") is not True:
        raise Refusal("explicit live true required")
    timeout = request.get("timeout", 8)
    # collect workers may need up to 30s for slow multi-MiB telecom CT reads.
    if type(timeout) not in (int, float) or not 0 < timeout <= 30:
        raise Refusal("invalid worker deadline")
    if request["operation"] == "collect":
        closed(request, ("operation", "live", "source", "kind", "value", "variant", "timeout"))
        source, kind = request.get("source"), request.get("kind")
        grants = os.environ.get("ASSET_RECON_PROVIDERS", "").split(",")
        allowed = set(ADAPTERS) - {"dns"}
        if source not in allowed or not set(grants) <= allowed or source not in grants or kind not in ADAPTERS[source].query_kinds:
            raise Refusal("invalid provider or query kind")
        value = normalize(kind, request.get("value"))
        if not live_value(kind, value):
            raise Refusal("live query value refused")
        variant = request.get("variant")
        if source in ("google", "cloudflare"):
            if variant not in (("A", "AAAA") if kind == "domain" else (None,)):
                raise Refusal("invalid DNS query variant")
        elif source == "registry":
            if variant not in (("prefixes", "overview") if kind == "asn" else (None,)):
                raise Refusal("invalid registry variant")
        elif source == "certspotter":
            if variant is not None:
                variant = opaque_cursor(variant)
        elif source == "crtsh":
            if variant not in ("exact", "subdomains"):
                raise Refusal("invalid CT query variant")
        elif variant is not None:
            raise Refusal("unexpected query variant")
        return dict(request, value=value)
    closed(request, ("operation", "live", "target", "timeout"))
    target, _, _ = validate_target(request.get("target"))
    return dict(request, target=target)


def execute(request):
    request = validate_request(request)
    if request["operation"] == "collect":
        return collect(request["source"], request["kind"], request["value"], request.get("variant"))
    return probe(request["target"], request.get("timeout", 8))


def _failure_reason(operation, exc):
    """Return a bounded category; never serialize exception text."""
    if operation != "probe":
        return None
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, ssl.SSLError):
        return "tls_refused"
    if isinstance(exc, Refusal):
        return "protocol_refused"
    if isinstance(exc, OSError):
        return "transport_error"
    return "internal_error"


def main():
    operation = None
    try:
        request = decode(sys.stdin.buffer.read(16385))
        operation = request.get("operation") if isinstance(request, dict) else None
        request = validate_request(request)
        if resource is None:
            raise Refusal("bounded live workers require POSIX")
        resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
        resource.setrlimit(resource.RLIMIT_CPU, (12, 12))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = execute(request)
        encoded = json.dumps(result).encode()
        if len(encoded) > 1048576:
            raise Refusal("worker output budget reached")
        sys.stdout.buffer.write(encoded)
    except Exception as exc:
        # Provider errors may contain URLs with API credentials. Only a closed
        # probe category crosses the worker boundary; details remain redacted.
        reason = _failure_reason(operation, exc)
        failure = {"ok": False, "error": "operation failed [REDACTED]"}
        if reason is not None:
            failure["reason"] = reason
        sys.stdout.write(json.dumps(failure, separators=(",", ":")))


if __name__ == "__main__":
    main()
