"""One closed probe admission policy shared by parent and isolated worker."""
from __future__ import annotations

import urllib.parse

from ..dispatch import authorize
from .model import Exclusions, Refusal, closed, live_value, normalize


def validate_target(target, exclusions=None):
    exclusions = exclusions if exclusions is not None else Exclusions()
    closed(target, ("ip", "port", "method", "url", "module", "hello", "host"))
    target = dict(target)
    ip = normalize("ip", target.get("ip"))
    if not live_value("ip", ip) or exclusions.denies("ip", ip):
        raise Refusal("probe requires permitted global unicast IP")
    target["ip"] = ip
    port = target.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise Refusal("invalid explicit probe port")
    method = target.get("method")
    if method not in ("tcp", "tls", "http", "tcp-hello", "udp-hello", "nmap", "zgrab2"):
        raise Refusal("unknown probe method")
    host = target.get("host")
    if "host" in target:
        host = normalize("domain", host)
        if method not in ("tls", "http") or not live_value("domain", host) or exclusions.denies("domain", host):
            raise Refusal("host requires an eligible explicit HTTP or TLS name")
        host_scope, _ = authorize("ASSET_RECON_PROBE_SCOPE", "probe", host)
        if host_scope is None:
            raise Refusal("explicit host requires independent scope grant")
        target["host"] = host
    if "hello" in target or method.endswith("-hello"):
        if method not in ("tcp-hello", "udp-hello") or target.get("hello", "hello\r\n") not in ("hello", "hello\n", "hello\r\n"):
            raise Refusal("only literal hello with optional newline is permitted")
    if method == "http":
        url = target.get("url")
        if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in url):
            raise Refusal("invalid explicit HTTP URL")
        try:
            parsed = urllib.parse.urlsplit(url)
            bound_host = normalize("domain", parsed.hostname) if host else normalize("ip", parsed.hostname)
            if (parsed.scheme not in ("http", "https") or parsed.username or
                    parsed.password or parsed.query or parsed.fragment or
                    parsed.path not in ("", "/") or bound_host != (host or ip) or
                    (parsed.port or (443 if parsed.scheme == "https" else 80)) != port):
                raise Refusal("URL must bind explicit host, port, and root path without credentials or query")
        except ValueError:
            raise Refusal("invalid bound HTTP URL") from None
    elif "url" in target:
        raise Refusal("URL requires HTTP method")
    if method == "zgrab2":
        if target.get("module", "banner") not in ("http", "tls", "banner"):
            raise Refusal("unsupported zgrab2 module")
    elif "module" in target:
        raise Refusal("module requires zgrab2")
    auth_target = "[" + ip + "]" if ":" in ip else ip
    scope, _ = authorize("ASSET_RECON_PROBE_SCOPE", "probe", auth_target)
    if scope is None:
        raise Refusal("ASSET_RECON_PROBE_SCOPE refuses target")
    if method in ("nmap", "zgrab2"):
        inner, _ = authorize("NMAP_DISPATCH_SCOPE" if method == "nmap" else "ZGRAB2_DISPATCH_SCOPE", "scan", auth_target)
        if inner is None:
            raise Refusal("existing arm scope refuses target")
    return target, scope, auth_target
