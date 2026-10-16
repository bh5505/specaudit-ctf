"""CLI: ``python -m containment`` -- run the containment matrix.

Requires an explicit roster JSON (the package never imports
``safety.check``): ``[{"arm_id": ..., "action": ..., "path_argument": ...},
...]`` where ``path_argument`` is null for discovery-only rows. Prints the
run_matrix summary JSON and exits 0 only when the run has zero failures.
On win32 the label is ``partial`` (POSIX-only hostile classes are skipped
with reasons, not silently dropped).
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
from typing import Sequence

from containment.harness import RosterEntry, run_matrix
from containment.profile import OperatorProfile


def _roster_from_json(text: str) -> tuple[RosterEntry, ...]:
    rows = json.loads(text)
    if not isinstance(rows, list) or not rows:
        raise ValueError("roster must be a non-empty JSON array")
    entries = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("arm_id"), str) \
                or not isinstance(row.get("action"), str):
            raise ValueError("roster rows need string arm_id and action")
        path_argument = row.get("path_argument")
        if path_argument is not None and not isinstance(path_argument, str):
            raise ValueError("roster path_argument must be a string or null")
        entries.append(RosterEntry(row["arm_id"], row["action"], path_argument))
    return tuple(entries)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m containment",
        description="Run the containment rehearsal matrix (SAFE-01, empirical).",
    )
    parser.add_argument("--approved-root", required=True,
                        help="operator-approved input root (created if missing)")
    parser.add_argument("--scratch-root", required=True,
                        help="the only root where mutation verbs are arguable")
    parser.add_argument("--fixtures-root", required=True,
                        help="where per-arm input fixtures materialize (inside the approved root)")
    parser.add_argument("--roster-json", required=True,
                        help="path to the frozen roster JSON array")
    parser.add_argument("--ledger", default=None,
                        help="containment-LOCAL attempt ledger file (operator-rehearsal lane)")
    parser.add_argument("--no-canaries", action="store_true",
                        help="skip the enforced and control canary children")
    parser.add_argument("--recorded-at", default=None,
                        help="ISO datetime for ledger rows (defaults to now: the CLI owns the clock)")
    args = parser.parse_args(list(argv) if argv is not None else None)

    roster_text = Path(args.roster_json).read_text(encoding="utf-8")
    roster = _roster_from_json(roster_text)
    profile = OperatorProfile(
        approved_root=str(Path(args.approved_root).resolve()),
        scratch_root=str(Path(args.scratch_root).resolve()),
    )
    recorded_at = (
        datetime.fromisoformat(args.recorded_at) if args.recorded_at
        else datetime.now().replace(microsecond=0)
    )
    summary = run_matrix(
        profile, roster, Path(args.fixtures_root).resolve(),
        recorded_at=recorded_at,
        ledger_path=Path(args.ledger) if args.ledger else None,
        include_canaries=not args.no_canaries,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if not summary["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
