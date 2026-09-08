"""Curated security-detections-mcp arm: local rule reads over pinned indexes."""

from .arm import SecurityDetectionsMcpArm
from .policy import ALLOWED_ACTIONS, ARM_ID

__all__ = [
    "ALLOWED_ACTIONS",
    "ARM_ID",
    "SecurityDetectionsMcpArm",
]
