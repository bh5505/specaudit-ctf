"""Curated security-detections-mcp arm: local rule reads over frozen indexes."""

from .arm import SecurityDetectionsMcpArm
from .policy import ALLOWED_ACTIONS, ARM_ID

__all__ = [
    "ALLOWED_ACTIONS",
    "ARM_ID",
    "SecurityDetectionsMcpArm",
]
