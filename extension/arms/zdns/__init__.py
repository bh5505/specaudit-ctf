"""Curated zdns arm."""

from .arm import ZdnsArm
from .policy import ALLOWED_ACTIONS, ARM_ID

__all__ = [
    "ALLOWED_ACTIONS",
    "ARM_ID",
    "ZdnsArm",
]
