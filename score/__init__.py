"""Public scoring over ``specaudit.ctf.execution-result.v1`` envelopes.

The scorer grades one or more execution-result envelope files and
answers ``passed`` with per-gate detail. Two rules are structural:

- **Transport success is never a verdict.** ``transport_ok`` is echoed
  per envelope, labelled informational, and participates in no pass
  decision anywhere in this package.
- **A skipped or failed required arm is never success.** The
  ``required_arms_complete`` gate fails closed on it, and the parser
  the scorer projects already forces ``failed`` for that case.

The scorer is a thin grading projection over the repository's own
envelope parser (``extension.envelopes.parse_execution_result``); it
never reimplements envelope semantics, never reads inner range
lifecycle documents, and never follows artifact digests to bytes on
disk. It reports verdicts; it does not mint them.

Exit codes (``python -m score``): ``0`` the run passed, ``1`` the
scorer ran and the verdict is negative (this includes unreadable or
invalid envelope files, which are scored as failed entries), ``2``
scorer-level usage errors (no inputs, unusable rubric). stdout carries
a valid JSON score document for both ``0`` and ``1``.

This package is a checkout teaching-path deliverable: it runs from
this repository with Python 3.11+ and the repo's own dependencies, and
is outside the sealed ``extension`` surface (the wheel build does not
include it).
"""

from __future__ import annotations

from .rubric import Rubric, load_rubric
from .scorer import score_envelope, score_run

__all__ = ["Rubric", "load_rubric", "score_envelope", "score_run"]
