"""Curated deepsec CLI arm."""

from .arm import DeepsecArm
from .policy import ALLOWED_ACTIONS, ARM_ID, DISPATCH_ACTIONS

__all__ = [
    "ALLOWED_ACTIONS",
    "ARM_ID",
    "DISPATCH_ACTIONS",
    "DeepsecArm",
]
