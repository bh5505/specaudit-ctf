"""Curated Prowler CSPM MCP arm."""

from .arm import ProwlerArm
from .policy import ALLOWED_PREFIXES, ARM_ID, BLOCKED_PREFIXES

__all__ = [
    "ALLOWED_PREFIXES",
    "ARM_ID",
    "BLOCKED_PREFIXES",
    "ProwlerArm",
]
