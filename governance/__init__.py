"""Repository-local governance register validation.

This package is intentionally outside the shipped ``extension`` package.  It
describes and checks governance state; it grants no runtime authority.
"""

from .check import (
    CoverageInventory,
    Inventory,
    RegisterLoadError,
    Registry,
    ValidationIssue,
    ValidationReport,
    load_coverage_inventory,
    load_register,
    snapshot_coverage_catalog,
    snapshot_invoke_profiles,
    validate_register,
)

__all__ = [
    "CoverageInventory",
    "Inventory",
    "RegisterLoadError",
    "Registry",
    "ValidationIssue",
    "ValidationReport",
    "load_coverage_inventory",
    "load_register",
    "snapshot_coverage_catalog",
    "snapshot_invoke_profiles",
    "validate_register",
]
