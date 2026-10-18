"""Describe caller-supplied bytes without claiming acquisition or custody.

This pure helper never opens the locator. Approved-root acquisition, proof of
reader consumption, source authentication and durable replay checks belong to
the existing trusted-reader mechanisms and are not established by this record.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from capability_records import is_reference, is_source_timestamp, is_stable_id

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
    evidence_class: str = "declared"
    limitations: tuple[str, ...] = (
        "bytes-supplied-by-caller-not-acquired-from-locator",
        "source-and-reader-consumption-not-authenticated",
        "custody-label-is-a-caller-assertion",
        "no-durable-replay-or-grading-decision",
    )


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
    custody: str = "caller-declared-bytes",
) -> CallerPathBinding:
    """Bind caller-selected bytes to an attempt.

    The path is a locator only; identity is the digest of the supplied bytes.
    Collection time and custody are caller declarations. Even an explicitly
    supplied validator custody label does not prove the validator held bytes
    before dispatch or that a reader consumed them.
    """
    if not is_stable_id(attempt_id):
        raise CallerPathBindingError("attempt_id must be a bounded stable identifier")
    if not is_stable_id(arm_id):
        raise CallerPathBindingError("arm_id must be a bounded stable identifier")
    if not is_stable_id(action):
        raise CallerPathBindingError("action must be a bounded stable identifier")
    if not is_reference(path) or len(path) > _MAX_PATH:
        raise CallerPathBindingError("path must be a nonblank bounded locator without controls")
    if not isinstance(content, (bytes, bytearray)):
        raise CallerPathBindingError("content must be bytes")
    bound_content = bytes(content)
    if len(bound_content) > _MAX_BYTES:
        raise CallerPathBindingError("content exceeds byte cap")
    if len(bound_content) == 0:
        raise CallerPathBindingError("content must be nonempty")
    if not is_source_timestamp(collected_at):
        raise CallerPathBindingError("collected_at must be an RFC3339 timestamp with a zone")
    if not is_reference(custody):
        raise CallerPathBindingError("custody must be a nonblank bounded caller assertion")
    return CallerPathBinding(
        version=BINDING_VERSION,
        attempt_id=attempt_id,
        arm_id=arm_id,
        action=action,
        path=path,
        byte_count=len(bound_content),
        digest=_digest_bytes(bound_content),
        collected_at=collected_at,
        custody=custody,
    )


__all__ = [
    "BINDING_VERSION",
    "CallerPathBinding",
    "CallerPathBindingError",
    "bind_caller_path",
]
