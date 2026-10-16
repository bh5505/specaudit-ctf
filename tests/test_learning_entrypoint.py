"""The public offline dispatcher keeps all six importable workflows reachable."""

import json
import subprocess
import sys


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "learning", *args],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_public_workflow_help_and_detection_case():
    assert _run("--help").returncode == 0
    for command in ("graph", "k8s", "review", "agent", "detection", "triage"):
        result = _run(command, "--help")
        assert result.returncode == 0, (command, result.stderr)
        assert "usage:" in result.stdout.lower()
    verdict = _run("detection", "--case", "missing-telemetry")
    assert verdict.returncode == 0
    stages = json.loads(verdict.stdout)["stages"]
    assert stages["events_collected"]["state"] == "not_met"
    assert stages["rule_fired"]["state"] == "unknown"


def test_unknown_workflow_is_refused():
    result = _run("unrecognized")
    assert result.returncode == 2
    assert "unknown learning workflow" in result.stderr
