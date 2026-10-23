"""OSV advisory arm: offline snapshot reads and bounded live queries."""

from .arm import OsvArm
from .policy import ALLOWED_ACTIONS, ARM_ID

__all__ = [
    "ALLOWED_ACTIONS",
    "ARM_ID",
    "OsvArm",
]
