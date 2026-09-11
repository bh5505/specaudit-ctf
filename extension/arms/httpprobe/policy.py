"""Dispatch-only policy for the bounded curl-based HTTP probe arm.

curl is the selected transport because it ships on Kali lab images and modern
Windows. Redirects surface as data, never followed: the fixed argv omits -L.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from urllib import parse as urllib_parse

ARM_ID = "http-probe"
ENV_BIN = "HTTP_PROBE_BIN"
ENV_DISPATCH_SCOPE = "HTTP_PROBE_DISPATCH_SCOPE"

ALLOWED_ACTIONS = frozenset()
DISPATCH_ACTIONS = frozenset({"probe"})

TIMEOUT_SECONDS = 30.0
MAX_OUTPUT_CHARS = 200_000
MAX_HEADERS = 8
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
MAX_VALUE_LEN = 512
MAX_HEADER_BYTES = 8 * 1024
FORBIDDEN_NAMES = frozenset({"host", "content-length", "connection"})


def resolve_binary() -> str | None:
    """Return HTTP_PROBE_BIN when it is a file, else find curl on PATH."""
    explicit = os.environ.get(ENV_BIN)
    if explicit:
        path = Path(explicit)
        return str(path) if path.is_file() else None
    return shutil.which("curl")


def target_refusal(payload: dict) -> str | None:
    """Validate the closed request schema before scope authorization."""
    extra = [key for key in payload if key not in {"url", "headers"}]
    if extra:
        return f"http-probe probe rejects unknown argument {extra[0]!r}"

    raw = payload.get("url")
    if not isinstance(raw, str) or not raw.strip():
        return "probe requires a target URL in args.url"
    target = raw.strip()
    if "\x00" in target or "\r" in target or "\n" in target:
        return "probe target contains control characters"
    try:
        parsed = urllib_parse.urlparse(target)
        hostname = parsed.hostname
        parsed.port  # force malformed/non-numeric port validation
    except ValueError:
        return "probe target must be a well-formed http(s) URL"
    if parsed.scheme not in ("http", "https") or not hostname:
        return "probe target must be an http(s) URL"
    if parsed.username is not None or parsed.password is not None:
        return "probe target URL must not contain userinfo credentials"

    headers = payload.get("headers", {})
    if not isinstance(headers, dict):
        return "probe headers must be a dict[str, str]"
    if len(headers) > MAX_HEADERS:
        return f"probe headers exceed the maximum count of {MAX_HEADERS}"
    total = 0
    for name, value in headers.items():
        if not isinstance(name, str) or not HEADER_NAME_RE.fullmatch(name):
            return f"probe header name {name!r} must be an RFC token (1-64 letters, digits, or hyphens)"
        if name.lower() in FORBIDDEN_NAMES:
            return f"probe header {name!r} is forbidden because curl would duplicate or mangle it"
        if not isinstance(value, str):
            return f"probe header {name!r} value must be a string"
        if any(ch in value for ch in ("\x00", "\r", "\n")):
            return f"probe header {name!r} value contains control characters"
        if len(value) > MAX_VALUE_LEN:
            return f"probe header {name!r} value exceeds {MAX_VALUE_LEN} characters"
        total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
    if total > MAX_HEADER_BYTES:
        return "probe headers exceed the 8KB total-size limit"
    return None


def argv_for(binary: str, action: str, payload: dict) -> list[str] | None:
    """Build fixed curl argv; the validated URL is strictly after ``--``.

    Redirects surface as data, never followed: no ``-L`` is passed.
    """
    if action not in DISPATCH_ACTIONS or target_refusal(payload) is not None:
        return None
    argv = [
        binary,
        "-sS",
        "-o",
        "-",
        "-D",
        "-",
        "--max-time",
        str(int(TIMEOUT_SECONDS)),
    ]
    for name, value in payload.get("headers", {}).items():
        argv.extend(["-H", f"{name}: {value}"])
    argv.extend(["--", payload["url"].strip()])
    return argv
