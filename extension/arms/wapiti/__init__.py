"""Curated wapiti dispatch-only arm."""

from .arm import WapitiArm
from .policy import ARM_ID, DISPATCH_ACTIONS

__all__ = [
    "ARM_ID",
    "DISPATCH_ACTIONS",
    "WapitiArm",
]
