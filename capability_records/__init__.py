"""Bounded value predicates for structural records, with no I/O or authority.

References and digests are declarations here: these predicates do not resolve
artifacts, authenticate authors, check bytes, or read a clock.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def is_sha256_digest(value: Any) -> bool:
    """Require the complete ``sha256:<64 lowercase hex>`` string."""
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def is_bounded_text(value: Any, *, max_length: int = 8192) -> bool:
    """Accept bounded nonblank Unicode prose, permitting tabs and line breaks."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= max_length
        and bool(value.strip())
        and all(ord(char) >= 32 or char in "\t\r\n" for char in value)
        and not any(127 <= ord(char) <= 159 for char in value)
        and not any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    )


def is_reference(value: Any) -> bool:
    """Require trimmed, nonblank text of at most 1024 chars without controls."""
    return (
        is_bounded_text(value, max_length=1024)
        and value == value.strip()
        and all(ord(char) >= 32 for char in value)
    )


def is_stable_id(value: Any) -> bool:
    """Require an ASCII identifier, starting alphanumeric, of 1..128 chars."""
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def is_source_timestamp(value: Any) -> bool:
    """Require a real RFC3339 date/time with explicit zone, without aging it.

    Seconds are required; fractions have 1..6 digits. Leap seconds are outside
    this structural contract. No implicit timezone or clock is consulted.
    """
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def is_reference_list(value: Any, *, allow_empty: bool = False) -> bool:
    """Accept a bounded flat list/tuple of references; no nested placeholders."""
    return (
        isinstance(value, (list, tuple))
        and (bool(value) or allow_empty)
        and len(value) <= 256
        and all(is_reference(item) for item in value)
    )


def is_concrete_content(value: Any) -> bool:
    """Accept nonempty prose/list/tuple/mapping content; reject placeholders.

    All leaves are nonblank text of at most 8192 chars. Mapping keys are
    references. Containers have at most 256 entries, nesting is at most eight
    levels, and the entire value has at most 4096 nodes. Cycles are invalid.
    Boolean, numeric and null leaves are outside this prose/reference contract.
    """
    ancestors: set[int] = set()
    remaining = 4096

    def visit(item: Any, depth: int) -> bool:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 8:
            return False
        if isinstance(item, str):
            return is_bounded_text(item)
        if not isinstance(item, (Mapping, list, tuple)):
            return False
        if not item or len(item) > 256 or id(item) in ancestors:
            return False
        ancestors.add(id(item))
        try:
            if isinstance(item, Mapping):
                return all(
                    is_reference(key) and visit(child, depth + 1)
                    for key, child in item.items()
                )
            return all(visit(child, depth + 1) for child in item)
        finally:
            ancestors.remove(id(item))

    return visit(value, 0)


__all__ = [
    "is_bounded_text", "is_concrete_content", "is_reference",
    "is_reference_list", "is_sha256_digest", "is_source_timestamp", "is_stable_id",
]
