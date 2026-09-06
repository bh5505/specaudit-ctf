"""Per-cell stability stats from a variance sweep's report files.

Reads ``<root>/<cell>/report-*.json`` (the layout
``lab/matrix-variance.sh`` produces) and emits, per cell: attempts,
passes, pass rate, tool-call distribution, verified spread, severity
flags, duration spread, and every failure reason verbatim. Honest
flakiness is the deliverable: a head that varies is a finding, never
something to smooth over. Output is JSON (``--json``) or a markdown
table (default); nothing here grades, smooths, or retries.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

FAIL_STATES = ("failed",)


def _head(report: dict[str, Any]) -> dict[str, Any]:
    head = report.get("head")
    return head if isinstance(head, dict) else {}


def _cell_stats(cell: str, reports: list[dict[str, Any]]) -> dict[str, Any]:
    attempts = len(reports)
    tool_calls: list[int] = []
    verified_counts: list[int] = []
    durations: list[float] = []
    severity_flags = 0
    passes = 0
    failures: list[str] = []
    for index, report in enumerate(reports, start=1):
        head = _head(report)
        status = str(head.get("status") or report.get("status") or "unknown")
        trace = head.get("trace") if isinstance(head.get("trace"), dict) else {}
        calls = trace.get("tool_calls")
        # bool is an int in Python; a bare True/False must never count
        # as a tool-call count.
        if isinstance(calls, int) and not isinstance(calls, bool) and calls >= 0:
            tool_calls.append(calls)
        verified = head.get("verified")
        if isinstance(verified, list):
            verified_counts.append(len(verified))
        grade = head.get("grade") if isinstance(head.get("grade"), dict) else {}
        mismatches = grade.get("severity_mismatches")
        if isinstance(mismatches, list):
            severity_flags += len(mismatches)
        spawn = head.get("spawn") if isinstance(head.get("spawn"), dict) else {}
        duration = spawn.get("duration_s")
        if isinstance(duration, (int, float)) and duration >= 0:
            durations.append(float(duration))
        if status in FAIL_STATES or head.get("passed") is not True:
            reason = str(head.get("reason") or "").strip() or status
            failures.append(f"attempt-{index}: {reason}")
        else:
            passes += 1

    def spread(values: list[float]) -> str:
        if not values:
            return "n/a"
        if len(values) == 1:
            return f"{values[0]:g}"
        return f"{min(values):g}-{max(values):g} (median {statistics.median(values):g})"

    return {
        "cell": cell,
        "attempts": attempts,
        "passes": passes,
        "pass_rate": round(passes / attempts, 3) if attempts else 0.0,
        "tool_calls": spread([float(v) for v in tool_calls]),
        "verified": spread([float(v) for v in verified_counts]),
        "severity_flags": severity_flags,
        "duration_s": spread(durations),
        "failures": failures,
    }


def collect(root: Path) -> list[dict[str, Any]]:
    """Gather per-cell stats from every report-*.json under root.

    Cells are the directories holding report files, named relative to
    root, so a root that stacks head-host subdirectories still yields
    one row per cell.
    """
    grouped: dict[Path, list[Path]] = {}
    for path in sorted(root.rglob("report-*.json")):
        grouped.setdefault(path.parent, []).append(path)
    rows: list[dict[str, Any]] = []
    for cell_dir in sorted(grouped):
        reports: list[dict[str, Any]] = []
        for path in grouped[cell_dir]:
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeError) as exc:
                reports.append(
                    {"head": {"status": "failed", "passed": False, "reason": f"unreadable report: {exc}"}}
                )
                continue
            if isinstance(document, dict):
                reports.append(document)
            else:
                # Valid JSON that is not an object (null, a list, a
                # string) is still an unreadable REPORT: it must count
                # as an attempt and produce a failure row, never
                # silently vanish from the stats.
                reports.append(
                    {
                        "head": {
                            "status": "failed",
                            "passed": False,
                            "reason": "unreadable report: expected a JSON object",
                        }
                    }
                )
        rows.append(_cell_stats(cell_dir.relative_to(root).as_posix(), reports))
    return rows


def markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| cell | attempts | passes (rate) | tool calls | verified | severity flags | duration s | failures |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        # Reasons are free text; escape pipes so a reason containing
        # one cannot break the markdown table.
        failures = (
            "; ".join(failure.replace("|", "\\|") for failure in row["failures"])
            if row["failures"]
            else "none"
        )
        lines.append(
            f"| {row['cell']} | {row['attempts']} | {row['passes']} ({row['pass_rate']:.0%}) "
            f"| {row['tool_calls']} | {row['verified']} | {row['severity_flags']} "
            f"| {row['duration_s']} | {failures} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="matrix-stats",
        description="Per-cell stability stats from a variance sweep's report files.",
    )
    parser.add_argument("root", help="directory holding <cell>/report-*.json files")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of markdown")
    args = parser.parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print(f"matrix-stats: not a directory: {root}", file=sys.stderr)
        return 2
    rows = collect(root)
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(markdown(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
