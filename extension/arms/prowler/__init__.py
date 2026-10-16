"""Curated Prowler CSPM MCP arm."""

from .arm import ProwlerArm
from .policy import ALLOWED_TOOLS, ARM_ID, BLOCKED_PREFIXES, BLOCKED_TOOLS

__all__ = [
    "ALLOWED_TOOLS",
    "ARM_ID",
    "BLOCKED_PREFIXES",
    "BLOCKED_TOOLS",
    "ProwlerArm",
]
