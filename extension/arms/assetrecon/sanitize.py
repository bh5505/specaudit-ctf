"""Bounded observation text: constant redaction, then control filtering/caps."""
from __future__ import annotations

import os
import re
import urllib.parse


def safe_text(raw, maximum=512):
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    for env in ("SHODAN_API_KEY", "CERTSPOTTER_TOKEN"):
        secret = os.environ.get(env)
        if secret and len(secret) <= 4096:
            for form in (secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret)):
                text = re.sub(re.escape(form), "[REDACTED]", text, flags=re.IGNORECASE)
    text = re.sub(r"(?i)\b(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|api[-_]?key|access[-_]?key)\b[^\r\n]*", "[REDACTED]", text)
    text = re.sub(r"(?i)\b(?:bearer|basic)\s+\S+", "[REDACTED]", text)
    text = re.sub(r"(?i)\[redacted\][^\r\n]*", "[REDACTED]", text)
    text = re.sub(r"(?i)(?:https?://)[^\s/@]+:[^\s/@]+@", "[REDACTED]@", text)
    text = "".join(c if 32 <= ord(c) <= 126 else " " for c in text)
    return dict(preview=text[:maximum], preview_truncated=len(text) > maximum)
