"""Semgrep CLI integration tests (first-party binary; hermetic fake)."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from extension.arms.semgrep import SemgrepArm
from extension.arms.semgrep.policy import (
    ENV_BIN,
    ENV_ENDPOINT,
    ENV_SCAN_ROOT,
)
from tests.test_arm_semgrep import _spec

RULES = (
    "rules:\n"
    "  - id: demo\n"
    "    pattern: print(...)\n"
    "    message: demo\n"
    "    languages: [python]\n"
    "    severity: WARNING\n"
)


def _fake_semgrep(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "semgrep-payload.py"
    script.write_text(body, encoding="utf-8")
    if os.name == "nt":
        wrapper = tmp_path / "semgrep.bat"
        wrapper.write_text(
            '@"%s" "%s" %%*\n' % (sys.executable, script), encoding="utf-8"
        )
        return wrapper
    wrapper = tmp_path / "semgrep"
    wrapper.write_text(
        "#!%s\nexec(open(r'%s').read())\n" % (sys.executable, script),
        encoding="utf-8",
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return wrapper


ECHO_SCAN = (
    "import json, sys\n"
    "argv = sys.argv[1:]\n"
    "assert argv[0] == 'scan' and argv[1] == '--config', argv\n"
    "cfg = open(argv[2], encoding='utf-8').read()\n"
    "evidence = {'argv_tail': argv[3:], 'config': cfg}\n"
    "print(json.dumps({'results': [{'check_id': 'demo', 'path': 'a.py',"
    " 'evidence': evidence}], 'errors': []}))\n"
)


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    binary = _fake_semgrep(tmp_path, ECHO_SCAN)
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.py").write_text("print('x')\n", encoding="utf-8")
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_SCAN_ROOT, str(root))
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    return root


def test_cli_list_tools_static(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    monkeypatch.setenv(ENV_BIN, str(tmp_path / "missing"))
    result = SemgrepArm().invoke(_spec(), "list_tools", {})
    assert result.ok is True
    assert result.output["surface"] == "cli"
    assert result.output["dispatch_actions"] == ["semgrep_scan"]
    assert result.output["dispatch_armed"] is False
    assert result.output["mcp_endpoint_actions"]


def test_cli_scan_runs_inline_config_hermetic(cli_env: Path) -> None:
    result = SemgrepArm().invoke(_spec(), "semgrep_scan", {"config": RULES})
    assert result.ok is True, result.error
    assert result.output["total"] == 1
    first = result.output["results"][0]
    assert first["check_id"] == "demo"
    # The inline rule pack reached the binary as a file; metrics off;
    # JSON mode; the target is the scan root.
    evidence = first["evidence"]
    assert evidence["config"] == RULES
    assert "--metrics=off" in evidence["argv_tail"]
    assert "--json" in evidence["argv_tail"]
    assert Path(result.output["target"]).name == "root"


def test_cli_scan_refusals(cli_env: Path) -> None:
    arm = SemgrepArm()
    # Registry config refused (egress gate).
    refused = arm.invoke(_spec(), "semgrep_scan", {"config": "p/python"})
    assert refused.ok is False
    assert "registry" in refused.error
    # Target must stay inside the scan root.
    escape = arm.invoke(
        _spec(), "semgrep_scan", {"config": RULES, "target": "../outside"}
    )
    assert escape.ok is False
    assert "inside the scan root" in escape.error


def test_cli_scan_requires_scan_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_semgrep(tmp_path, ECHO_SCAN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.delenv(ENV_SCAN_ROOT, raising=False)
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    result = SemgrepArm().invoke(_spec(), "semgrep_scan", {"config": RULES})
    assert result.ok is False
    assert ENV_SCAN_ROOT in result.error


def test_cli_scan_binary_failure_is_honest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_semgrep(
        tmp_path, "import sys\nsys.stderr.write('boom')\nsys.exit(2)\n"
    )
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_SCAN_ROOT, str(root))
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    result = SemgrepArm().invoke(_spec(), "semgrep_scan", {"config": RULES})
    assert result.ok is False
    assert "boom" in result.error


def test_cli_invoke_end_to_end_envelope(
    cli_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from extension.__main__ import main as invoke_main

    args_json = json.dumps({"config": RULES})
    code = invoke_main(["invoke", "semgrep-mcp", "semgrep_scan", args_json])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["capability_id"] == "semgrep-mcp.semgrep_scan"
    assert payload["status"] == "complete"
    assert payload["transport_ok"] is True
