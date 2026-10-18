"""Audit workpaper rubric (AUDIT-01).

Pure, deterministic grading of a human workpaper document against the
audit-quality criteria in PROGRAM.md / CURRICULUM.md.  No network, no
subprocess, no clock reads, no stored module state.  The rubric grades
structure and traceability; it does not replace professional standards
and does not authenticate any underlying evidence.
"""

from .rubric import (
    WorkpaperRubricResult,
    grade_workpaper,
    RUBRIC_VERSION,
)

__all__ = ["WorkpaperRubricResult", "grade_workpaper", "RUBRIC_VERSION"]
