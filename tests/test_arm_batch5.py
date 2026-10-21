"""Tests for the dark-moon and pyrit arms. All hermetic."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from extension.arms.darkmoon import ARM_ID as DARK_MOON_ID
from extension.arms.darkmoon import DarkMoonArm
from extension.arms.darkmoon.policy import (
    CAVEATS as DARK_MOON_CAVEATS,
)
from extension.arms.darkmoon.policy import (
    ENV_BIN as DARK_MOON_BIN,
)
from extension.arms.darkmoon.policy import argv_for as darkmoon_argv_for
from extension.arms.pyrit import ARM_ID as PYRIT_ID
from extension.arms.pyrit import PyritArm
from extension.arms.pyrit.policy import CAVEATS as PYRIT_CAVEATS
from extension.arms.pyrit.policy import ENV_BIN as PYRIT_BIN
from extension.arms.pyrit.policy import argv_for as pyrit_argv_for
from extension.contract import ArmSpec, NotInstalledError


def _spec(arm_id: str) -> ArmSpec:
    return ArmSpec(
        id=arm_id,
        protocols=("cli",),
        notes="Fixture arm.",
    )


def _fake_binary(tmp_path: Path, name: str, body: str) -> Path:
    script = tmp_path / f"{name}-payload.py"
    script.write_text(body, encoding="utf-8")
    if os.name == "nt":
        wrapper = tmp_path / f"{name}.bat"
        wrapper.write_text(
            f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8"
        )
        return wrapper
    wrapper = tmp_path / name
    wrapper.write_text(
        f"#!{sys.executable}\nexec(open(r'{script}').read())\n",
        encoding="utf-8",
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return wrapper


ECHO_ARGV = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
SLEEP_BODY = "import time\ntime.sleep(30)\n"


# --- shared install gate ------------------------------------------------


def test_darkmoon_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DARK_MOON_BIN, raising=False)
    monkeypatch.setattr(
        "extension.arms.darkmoon.arm.resolve_binary", lambda: None
    )
    arm = DarkMoonArm()
    assert arm.installed(_spec(DARK_MOON_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(DARK_MOON_ID), "list_tools", {})


def test_pyrit_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PYRIT_BIN, raising=False)
    monkeypatch.setattr("extension.arms.pyrit.arm.resolve_binary", lambda: None)
    arm = PyritArm()
    assert arm.installed(_spec(PYRIT_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(PYRIT_ID), "list_tools", {})


# --- dark-moon ----------------------------------------------------------


def test_darkmoon_list_tools_static(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(_spec(DARK_MOON_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["caveats"] == DARK_MOON_CAVEATS
    assert "composite egress" in result.output["caveats"]
    assert "MCP" in result.output["caveats"]
    assert "log" in result.output["actions"]
    assert "list_tools" in result.output["actions"]


def test_darkmoon_list_tools_reports_caveats(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(_spec(DARK_MOON_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["caveats"] == DARK_MOON_CAVEATS


def test_darkmoon_list_tools_extra_args_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "list_tools", {"session_id": "x"}
    )
    assert result.ok is False
    assert "fixed argv" in result.error


def test_darkmoon_tools_call_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(_spec(DARK_MOON_ID), "tools/call", {})
    assert result.ok is False
    assert "not supported" in result.error


def test_darkmoon_log_without_session_id_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(_spec(DARK_MOON_ID), "log", {})
    assert result.ok is False
    assert "session_id" in result.error


def test_darkmoon_log_runs_local(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "log", {"session_id": "sess-1"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["--log", "sess-1"]


def test_darkmoon_campaign_argv_is_one_token() -> None:
    cmd = darkmoon_argv_for(
        "/bin/darkmoon.sh", "campaign", {"target": "example.com"}
    )
    assert cmd == ["/bin/darkmoon.sh", "TARGET: example.com"]
    cmd = darkmoon_argv_for(
        "/bin/darkmoon.sh", "run", {"target": "http://10.10.0.1:3000"}
    )
    assert cmd == ["/bin/darkmoon.sh", "TARGET: http://10.10.0.1:3000"]
    assert len(cmd) == 2


def test_darkmoon_campaign_uses_operator_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": "10.10.0.1"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["TARGET: 10.10.0.1"]


@pytest.mark.parametrize("action", ["campaign", "run"])
def test_darkmoon_campaign_and_run_argv(
    action: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), action, {"target": "10.10.0.1"}
    )
    assert result.ok is True
    argv = result.output["argv"]
    assert argv == ["TARGET: 10.10.0.1"]


def test_darkmoon_url_target_one_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID),
        "campaign",
        {"target": "http://10.10.0.1:3000"},
    )
    assert result.ok is True
    assert result.output["argv"] == ["TARGET: http://10.10.0.1:3000"]


def test_darkmoon_url_userinfo_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID),
        "campaign",
        {"target": "http://user:secret@10.10.0.1/"},
    )
    assert result.ok is True
    assert darkmoon_argv_for(str(binary), "campaign", {"target": "http://user:secret@10.10.0.1/"})[-1] == "TARGET: http://user:secret@10.10.0.1/"
    assert result.output["argv"] == ["TARGET: http://[redacted]@10.10.0.1/"]


def test_darkmoon_run_accepts_operator_selected_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "run", {"target": "8.8.8.8"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["TARGET: 8.8.8.8"]


def test_darkmoon_flag_shaped_target_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": "--help"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["TARGET: --help"]


def test_darkmoon_unbracketed_ipv6_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": "2001:db8::1"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["TARGET: 2001:db8::1"]



@pytest.mark.parametrize(
    "target,argv_token",
    [
        ("[2001:db8::1]", "TARGET: [2001:db8::1]"),
        ("http://[2001:db8::1]/", "TARGET: http://[2001:db8::1]/"),
    ],
)
def test_darkmoon_bracketed_ipv6_runs(
    target: str,
    argv_token: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": target}
    )
    assert result.ok is True
    assert result.output["argv"] == [argv_token]


@pytest.mark.parametrize("target", ["[]", "http://[]", "[gggg::1]", "[2001:db8::1"])
def test_darkmoon_unrestricted_targets_pass_through(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": target}
    )
    assert result.ok is True
    assert result.output["argv"] == [f"TARGET: {target}"]


@pytest.mark.parametrize(
    "target",
    ["", "   ", "a\x00b", "a\rb", "a\nb", "a\r\nb"],
)
def test_darkmoon_malformed_target_controls_refused(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": target}
    )
    assert result.ok is False
    assert result.error is not None
    assert (
        "requires a target" in result.error
        or "control characters" in result.error
    )


@pytest.mark.parametrize("target", [None, 123, ["x"], {"t": "x"}])
def test_darkmoon_nonstring_target_refused(
    target: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": target}
    )
    assert result.ok is False
    assert "requires a target" in result.error


def test_darkmoon_extra_args_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID),
        "campaign",
        {"target": "10.10.0.1", "FOCUS": "sqli"},
    )
    assert result.ok is False
    assert "only args.target" in result.error
    assert "fixed argv" in result.error


def test_darkmoon_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", SLEEP_BODY)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    result = DarkMoonArm(timeout=1.0).invoke(
        _spec(DARK_MOON_ID), "log", {"session_id": "sess-1"}
    )
    assert result.ok is False
    assert "timed out" in result.error


# --- pyrit --------------------------------------------------------------


def test_pyrit_list_tools_static(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(_spec(PYRIT_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["caveats"] == PYRIT_CAVEATS
    assert "pyrit_scan" in result.output["caveats"]
    assert "list_scenarios" in result.output["actions"]


def test_pyrit_list_tools_reports_caveats(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(_spec(PYRIT_ID), "tools/list", {})
    assert result.ok is True
    assert result.output["caveats"] == PYRIT_CAVEATS


def test_pyrit_list_scenarios_argv_frozen(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(_spec(PYRIT_ID), "list_scenarios", {})
    assert result.ok is True
    assert result.output["argv"] == ["--list-scenarios"]
    assert pyrit_argv_for(str(binary), "list_scenarios", {}) == [
        str(binary),
        "--list-scenarios",
    ]


def test_pyrit_list_scenarios_extra_args_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID), "list_scenarios", {"scenario": "airt.cyber"}
    )
    assert result.ok is False
    assert "fixed argv" in result.error


def test_pyrit_scan_uses_operator_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "10.10.0.1"},
    )
    assert result.ok is True
    assert result.output["argv"] == ["airt.cyber", "--target", "10.10.0.1"]


def test_pyrit_scan_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "10.10.0.1"},
    )
    assert result.ok is True
    assert result.output["argv"] == [
        "airt.cyber",
        "--target",
        "10.10.0.1",
    ]


def test_pyrit_url_target_passed_through(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {
            "scenario": "foundry.red_team_agent",
            "target": "https://lab.internal/app",
        },
    )
    assert result.ok is True
    assert result.output["argv"] == [
        "foundry.red_team_agent",
        "--target",
        "https://lab.internal/app",
    ]


def test_pyrit_url_userinfo_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {
            "scenario": "foundry.red_team_agent",
            "target": "http://user:secret@10.10.0.1/",
        },
    )
    assert result.ok is True
    assert pyrit_argv_for(str(binary), "scan", {"scenario": "foundry.red_team_agent", "target": "http://user:secret@10.10.0.1/"})[-1] == "http://user:secret@10.10.0.1/"
    assert result.output["argv"] == [
        "foundry.red_team_agent",
        "--target",
        "http://[redacted]@10.10.0.1/",
    ]


def test_pyrit_scan_accepts_operator_selected_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "8.8.8.8"},
    )
    assert result.ok is True
    assert result.output["argv"] == ["airt.cyber", "--target", "8.8.8.8"]


def test_pyrit_flag_shaped_target_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "--target"},
    )
    assert result.ok is True
    assert result.output["argv"] == ["airt.cyber", "--target", "--target"]


def test_pyrit_scenario_flag_shaped_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "-e", "target": "10.10.0.1"},
    )
    assert result.ok is False
    assert "flag-shaped" in result.error


def test_pyrit_scenario_without_fixed_pattern_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt/cyber", "target": "10.10.0.1"},
    )
    assert result.ok is True
    assert result.output["argv"] == ["airt/cyber", "--target", "10.10.0.1"]


def test_pyrit_non_http_scheme_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "file:///etc/passwd"},
    )
    assert result.ok is True
    assert result.output["argv"] == [
        "airt.cyber",
        "--target",
        "file:///etc/passwd",
    ]


def test_pyrit_unbracketed_ipv6_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "2001:db8::1"},
    )
    assert result.ok is True
    assert result.output["argv"] == ["airt.cyber", "--target", "2001:db8::1"]



@pytest.mark.parametrize(
    "target,passed",
    [
        ("[2001:db8::1]", "[2001:db8::1]"),
        ("http://[2001:db8::1]/", "http://[2001:db8::1]/"),
    ],
)
def test_pyrit_bracketed_ipv6_runs(
    target: str,
    passed: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": target},
    )
    assert result.ok is True
    assert result.output["argv"] == [
        "airt.cyber",
        "--target",
        passed,
    ]


@pytest.mark.parametrize("target", ["[]", "http://[]", "[gggg::1]", "[2001:db8::1"])
def test_pyrit_unrestricted_targets_pass_through(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": target},
    )
    assert result.ok is True
    assert result.output["argv"] == ["airt.cyber", "--target", target]


@pytest.mark.parametrize(
    "target",
    ["", "   ", "a\x00b", "a\rb", "a\nb", "a\r\nb"],
)
def test_pyrit_malformed_target_controls_refused(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": target},
    )
    assert result.ok is False
    assert result.error is not None
    assert (
        "requires a target" in result.error
        or "control characters" in result.error
    )


@pytest.mark.parametrize(
    "scenario",
    ["", "   ", "a\x00b", "a\rb", "a\nb"],
)
def test_pyrit_malformed_scenario_controls_refused(
    scenario: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": scenario, "target": "10.10.0.1"},
    )
    assert result.ok is False
    assert result.error is not None
    assert (
        "requires a scenario" in result.error
        or "control characters" in result.error
    )


def test_pyrit_extra_args_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {
            "scenario": "airt.cyber",
            "target": "10.10.0.1",
            "--techniques": "base64",
        },
    )
    assert result.ok is False
    assert "only args.scenario and args.target" in result.error
    assert "fixed argv" in result.error


def test_pyrit_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", SLEEP_BODY)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm(timeout=1.0).invoke(_spec(PYRIT_ID), "list_scenarios", {})
    assert result.ok is False
    assert "timed out" in result.error
