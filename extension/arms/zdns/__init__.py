"""Curated zdns dispatch-only arm."""

from .arm import ZdnsArm
from .policy import ALLOWED_ACTIONS, ARM_ID, DISPATCH_ACTIONS

__all__ = [
    "ALLOWED_ACTIONS",
    "ARM_ID",
    "DISPATCH_ACTIONS",
    "ZdnsArm",
]
