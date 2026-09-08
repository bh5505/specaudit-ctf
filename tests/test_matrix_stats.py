"""The variance summarizer: honest per-cell stability stats, no smoothing."""

from __future__ import annotations

import json
from pathlib import Path

from lab.matrix_stats import collect, main, markdown

ROOT = Path(__file__).resolve().parents[1]


def _report(
    *,
    passed: bool,
    calls: int,
    verified: int,
    duration: float = 1.0,
    severity_flags: int = 0,
    reason: str | None = None,
) -> dict:
    grade: dict = {}
    if severity_flags:
        grade = {"severity_mismatches": [{"finding_key": "k"} for _ in range(severity_flags)]}
    head: dict = {
        "status": "passed" if passed else "failed",
        "passed": passed,
        "verified": list(range(verified)),
        "trace": {"tool_calls": calls},
        "spawn": {"duration_s": duration},
    }
    if grade:
        head["grade"] = grade
    if reason:
        head["reason"] = reason
    return {"head": head}


def test_collect_computes_stability_stats(tmp_path: Path) -> None:
    cell = tmp_path / "claude-kali" / "telecom-aws-06-chain-rehearsal"
    cell.mkdir(parents=True)
    (cell / "report-1.json").write_text(
        json.dumps(_report(passed=True, calls=2, verified=5, duration=10.0)),
        encoding="utf-8",
    )
    (cell / "report-2.json").write_text(
        json.dumps(
            _report(passed=True, calls=14, verified=5, duration=20.0, severity_flags=1)
        ),
        encoding="utf-8",
    )
    (cell / "report-3.json").write_text(
        json.dumps(_report(passed=False, calls=9, verified=0, duration=33.5, reason="no found.json")),
        encoding="utf-8",
    )
    rows = collect(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["attempts"] == 3
    assert row["passes"] == 2
    assert row["pass_rate"] == 0.667
    assert row["tool_calls"] == "2-14 (median 9)"
    assert row["verified"] == "0-5 (median 5)"
    assert row["severity_flags"] == 1
    assert row["duration_s"] == "10-33.5 (median 20)"
    assert row["failures"] == ["attempt-3: no found.json"]


def test_collect_survives_an_unreadable_report(tmp_path: Path) -> None:
    cell = tmp_path / "codex-ubuntu" / "lab-knowledge-01-attack-mapping"
    cell.mkdir(parents=True)
    (cell / "report-1.json").write_text("{not json", encoding="utf-8")
    (cell / "report-2.json").write_text(
        json.dumps(_report(passed=True, calls=6, verified=3, duration=40.0)),
        encoding="utf-8",
    )
    rows = collect(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["attempts"] == 2
    assert row["passes"] == 1
    assert "unreadable report" in row["failures"][0]


def test_markdown_renders_failures_verbatim(tmp_path: Path) -> None:
    cell = tmp_path / "cell-x"
    cell.mkdir()
    (cell / "report-1.json").write_text(
        json.dumps(_report(passed=False, calls=0, verified=0, reason="attempt has no found.json")),
        encoding="utf-8",
    )
    text = markdown(collect(tmp_path))
    assert "| cell-x | 1 | 0 (0%)" in text
    assert "attempt has no found.json" in text


def test_main_rejects_a_missing_root(tmp_path: Path, capsys) -> None:
    assert main([str(tmp_path / "absent")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_collect_counts_non_object_json_as_failure(tmp_path: Path) -> None:
    """Valid JSON that is not an object must count as an attempt with a
    failure row - it may never silently vanish from the stats."""
    cell = tmp_path / "head-host" / "some-cell"
    cell.mkdir(parents=True)
    (cell / "report-1.json").write_text("null", encoding="utf-8")
    (cell / "report-2.json").write_text(
        json.dumps(_report(passed=True, calls=4, verified=3, duration=12.0)),
        encoding="utf-8",
    )
    rows = collect(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    # The nested cell name is root-relative: head-host dir + cell dir.
    assert row["cell"] == "head-host/some-cell"
    assert row["attempts"] == 2
    assert row["passes"] == 1
    assert any("expected a JSON object" in failure for failure in row["failures"])


def test_markdown_escapes_pipes_in_failure_reasons(tmp_path: Path) -> None:
    cell = tmp_path / "cell-y"
    cell.mkdir()
    (cell / "report-1.json").write_text(
        json.dumps(_report(passed=False, calls=0, verified=0, reason="a | b")),
        encoding="utf-8",
    )
    text = markdown(collect(tmp_path))
    assert r"a \| b" in text
