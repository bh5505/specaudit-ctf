"""Curated m365pwned arm: synthetic M365 consent case reads."""
from .arm import M365PwnedArm
from .policy import ALLOWED_ACTIONS, ARM_ID
__all__ = ["ALLOWED_ACTIONS", "ARM_ID", "M365PwnedArm"]
