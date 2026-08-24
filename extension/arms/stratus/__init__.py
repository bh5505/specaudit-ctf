"""Curated stratus-red-team CLI arm."""

from .arm import StratusArm
from .policy import ALLOWED_ACTIONS, ARM_ID, DISPATCH_ACTIONS

__all__ = [
    "ALLOWED_ACTIONS",
    "ARM_ID",
    "DISPATCH_ACTIONS",
    "StratusArm",
]
