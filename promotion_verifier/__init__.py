"""Promotion verifier (GOV-01).

Validates a promotion-event record against the required evidence fields
(subject/contract digests, implementation revision, reviewer, exercised
path, regression result, supported versions, source revisions, accepted
limitations).  Pure and fail-closed.  No network, no subprocess, no clock
reads, no stored module state.

This module verifies record *shape and completeness* only; it does not
authenticate a reviewer or prove that a named artifact/regression/path
exists (that requires a future verifier with real evidence).
"""

from .verifier import (
    PromotionVerifierError,
    PromotionResult,
    verify_promotion,
    PROMOTION_VERSION,
    REQUIRED_PROMOTION_FIELDS,
)

__all__ = [
    "PromotionVerifierError",
    "PromotionResult",
    "verify_promotion",
    "PROMOTION_VERSION",
    "REQUIRED_PROMOTION_FIELDS",
]
