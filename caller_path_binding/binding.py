"""Dynamic caller-path binding and custody (EVID-01)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

BINDING_VERSION = "specaudit.ctf.caller-path-binding.v1"

_MAX_BYTES = 16 * 1024 * 1024
_MAX_PATH = 1024


class CallerPathBindingError(ValueError):
    """Raised when a binding cannot be created."""


@dataclass(frozen=True)
class CallerPathBinding:
    version: str
    attempt_id: str
    arm_id: str
    action: str
    path: str
    byte_count: int
    digest: str
    collected_at: str
    custody: str


def _digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def bind_caller_path(
    *,
    attempt_id: str,
    arm_id: str,
    action: str,
    path: str,
    content: bytes,
    collected_at: str,
    custody: str = "validator-held-before-attempt",
) -> CallerPathBinding:
    """Bind caller-selected bytes to an attempt.

    The path is recorded as a locator only; identity is the digest of the
    bytes actually read.  Size, digest and collection time are bound.
    """
    if not isinstance(attempt_id, str) or not attempt_id:
        raise CallerPathBindingError("attempt_id must be nonempty string")
    if not isinstance(arm_id, str) or not arm_id:
        raise CallerPathBindingError("arm_id must be nonempty string")
    if not isinstance(action, str) or not action:
        raise CallerPathBindingError("action must be nonempty string")
    if not isinstance(path, str) or not path or len(path) > _MAX_PATH:
        raise CallerPathBindingError("path must be nonempty bounded string")
    if not isinstance(content, (bytes, bytearray)):
        raise CallerPathBindingError("content must be bytes")
    if len(content) > _MAX_BYTES:
        raise CallerPathBindingError("content exceeds byte cap")
    if len(content) == 0:
        raise CallerPathBindingError("content must be nonempty")
    if not isinstance(collected_at, str) or not collected_at:
        raise CallerPathBindingError("collected_at must be nonempty string")
    if not isinstance(custody, str) or not custody:
        raise CallerPathBindingError("custody must be nonempty string")
    # Reject control characters in path.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        raise CallerPathBindingError("path contains control characters")
    return CallerPathBinding(
        version=BINDING_VERSION,
        attempt_id=attempt_id,
        arm_id=arm_id,
        action=action,
        path=path,
        byte_count=len(content),
        digest=_digest_bytes(bytes(content)),
        collected_at=collected_at,
        custody=custody,
    )


__all__ = [
    "BINDING_VERSION",
    "CallerPathBinding",
    "CallerPathBindingError",
    "bind_caller_path",
]
