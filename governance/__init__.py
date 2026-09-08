"""Repository-local governance register validation.

This package is intentionally outside the shipped ``extension`` package.  It
describes and checks governance state; it grants no runtime authority.
"""

from .check import (
    Inventory,
    RegisterLoadError,
    Registry,
    ValidationIssue,
    ValidationReport,
    load_register,
    snapshot_invoke_profiles,
    validate_register,
)

__all__ = [
    "Inventory",
    "RegisterLoadError",
    "Registry",
    "ValidationIssue",
    "ValidationReport",
    "load_register",
    "snapshot_invoke_profiles",
    "validate_register",
]
