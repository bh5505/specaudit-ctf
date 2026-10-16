"""Five-layer adjudication evidence chain for CTF evaluation runs.

Raw custody, observations, inference, adjudication and workpaper are
bound by digest with sibling machine/human verdicts; evidence classes
are carried through unchanged and no override verdict field exists.
See chain.py for the honest limits: digests bind bytes only when the
operator retains them, and the chain authenticates nothing
cryptographically.
"""
from __future__ import annotations

from evidence_chain.chain import (
    ANALYST_ROLE, EVIDENCE_CLASSES, GRADING_LIMITATION, GRADING_SOURCE,
    RUBRIC_SOURCE, SCHEMA, SCHEMA_VERSION, ChainError, VerificationResult,
    build_chain, verify_chain,
)

__all__ = [
    "ANALYST_ROLE", "EVIDENCE_CLASSES", "GRADING_LIMITATION", "GRADING_SOURCE",
    "RUBRIC_SOURCE", "SCHEMA", "SCHEMA_VERSION", "ChainError",
    "VerificationResult", "build_chain", "verify_chain",
]
