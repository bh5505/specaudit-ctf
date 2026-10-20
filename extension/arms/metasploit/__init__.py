"""Curated metasploit MCP arm."""

from .arm import MetasploitArm
from .policy import ARM_ID

__all__ = [
    "ARM_ID",
    "MetasploitArm",
]
