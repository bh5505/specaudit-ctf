"""Curated metasploit MCP arm."""

from .arm import MetasploitArm
from .policy import ALLOWED_TOOLS, ARM_ID, DISPATCH_TOOLS

__all__ = [
    "ALLOWED_TOOLS",
    "ARM_ID",
    "DISPATCH_TOOLS",
    "MetasploitArm",
]
