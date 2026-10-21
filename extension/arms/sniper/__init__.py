"""Curated sniper arm."""

from .arm import SniperArm
from .policy import ALLOWED_ACTIONS, ARM_ID

__all__ = [
    "ALLOWED_ACTIONS",
    "ARM_ID",
    "SniperArm",
]
