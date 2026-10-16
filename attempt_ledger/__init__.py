"""Append-only attempt ledger for CTF evaluation runs.

Rows chain through SHA-256 digests over canonical JSON; optional keyed
mode adds HMAC-SHA256 tags under an operator-held key. See ledger.py
for the honest integrity limits: neither mode makes the stored file
immutable, and unkeyed truncation is detectable only against a
retained head. No network, no subprocess, no clock reads.
"""
from __future__ import annotations

from attempt_ledger.ledger import (
    ASSISTANCE, ATTEMPT_CLASSES, COMPLETION, LANES, SCHEMA, SCHEMA_VERSION,
    LedgerError, VerificationResult, append_row, row_digest, summarize,
    verify_ledger,
)

__all__ = [
    "ASSISTANCE", "ATTEMPT_CLASSES", "COMPLETION", "LANES", "SCHEMA",
    "SCHEMA_VERSION", "LedgerError", "VerificationResult", "append_row",
    "row_digest", "summarize", "verify_ledger",
]
