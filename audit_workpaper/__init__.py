"""Workpaper structural rubric and separate caller-declared human verdict.

Structure alone leaves human quality pending. An overall pass additionally
requires attributed adjudication bound to the exact workpaper digest; that
assertion remains unauthenticated and does not establish calibration or custody.
See :mod:`audit_workpaper.rubric` for the evidence and reference contracts.
"""

from .rubric import (
    WorkpaperRubricResult,
    grade_workpaper,
    RUBRIC_VERSION,
)

__all__ = ["WorkpaperRubricResult", "grade_workpaper", "RUBRIC_VERSION"]
