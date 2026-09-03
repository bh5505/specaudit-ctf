"""Verdict-vocabulary drift guard — hermetic tests.

The live repository must pass the guard (schemas and code agree
today); synthetic drift must fail closed, naming both sides.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from score.drift import _check, drift_check, main

ROOT = Path(__file__).resolve().parent.parent
EXECUTION_SCHEMA = ROOT / "extension" / "schema" / "execution-result.v1.schema.json"


def test_live_repository_has_no_drift() -> None:
    report = drift_check()
    assert report["ok"] is True, report
    for name, check in report["checks"].items():
        assert check["ok"] is True, (name, check["detail"])


def test_drift_fails_closed_naming_both_sides() -> None:
    check = _check(
        "status_domain",
        EXECUTION_SCHEMA,
        "/properties/status",
        ["complete", "degraded"],  # code side "lost" failed
    )
    assert check["ok"] is False
    assert check["schema_only"] == ["failed"]
    assert check["code_only"] == []


def test_unreadable_schema_side_fails_closed(tmp_path: Path) -> None:
    empty = tmp_path / "nope.json"
    check = _check("x", empty, "/properties/status/enum", ["complete"])
    assert check["ok"] is False
    assert "unreadable" in check["detail"]


def test_cli_exit_codes() -> None:
    ok = subprocess.run(
        [sys.executable, "-m", "score.drift"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert ok.returncode == 0
    assert '"ok": true' in ok.stdout
