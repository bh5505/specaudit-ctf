"""Probe argument validation shared by parent and worker."""
from __future__ import annotations

import urllib.parse

from .model import Exclusions, Refusal, closed, normalize


def validate_target(target, exclusions=None):
    exclusions = exclusions if exclusions is not None else Exclusions()
    closed(target, ("ip", "port", "method", "url", "module", "hello", "host"))
    target = dict(target)
    ip = normalize("ip", target.get("ip"))
    if exclusions.denies("ip", ip):
        raise Refusal("probe target excluded by the request")
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
        if method not in ("tls", "http") or exclusions.denies("domain", host):
            raise Refusal("host requires an explicit HTTP or TLS name outside request exclusions")
        target["host"] = host
    if "hello" in target:
        hello = target["hello"]
        try:
            hello_bytes = hello.encode("utf-8") if isinstance(hello, str) else b""
        except UnicodeEncodeError:
            raise Refusal("hello must be valid UTF-8 text") from None
        if method not in ("tcp-hello", "udp-hello") or not isinstance(hello, str) or len(hello_bytes) > 4096:
            raise Refusal("hello must be text of at most 4096 UTF-8 bytes for a hello probe")
    if method == "http":
        url = target.get("url")
        if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in url):
            raise Refusal("invalid explicit HTTP URL")
        try:
            parsed = urllib.parse.urlsplit(url)
            bound_host = normalize("domain", parsed.hostname) if host else normalize("ip", parsed.hostname)
            if (parsed.scheme not in ("http", "https") or parsed.username or
                    parsed.password or parsed.fragment or
                    bound_host != (host or ip) or
                    (parsed.port or (443 if parsed.scheme == "https" else 80)) != port):
                raise Refusal("URL host and port must match the requested HTTP connection")
        except ValueError:
            raise Refusal("invalid bound HTTP URL") from None
    elif "url" in target:
        raise Refusal("URL requires HTTP method")
    if method == "zgrab2":
        if "module" in target and (not isinstance(target["module"], str) or not target["module"].strip()):
            raise Refusal("zgrab2 module must be a nonempty string")
    elif "module" in target:
        raise Refusal("module requires zgrab2")
    return target
