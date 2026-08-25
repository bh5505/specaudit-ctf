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
from extension.arms.darkmoon.policy import (
    ENV_DISPATCH_SCOPE as DARK_MOON_SCOPE,
)
from extension.arms.darkmoon.policy import argv_for as darkmoon_argv_for
from extension.arms.darkmoon.policy import canonical_host as darkmoon_canonical_host
from extension.arms.pyrit import ARM_ID as PYRIT_ID
from extension.arms.pyrit import PyritArm
from extension.arms.pyrit.policy import CAVEATS as PYRIT_CAVEATS
from extension.arms.pyrit.policy import ENV_BIN as PYRIT_BIN
from extension.arms.pyrit.policy import ENV_DISPATCH_SCOPE as PYRIT_SCOPE
from extension.arms.pyrit.policy import argv_for as pyrit_argv_for
from extension.arms.pyrit.policy import canonical_host as pyrit_canonical_host
from extension.contract import ArmSpec, NotInstalledError


def _spec(arm_id: str) -> ArmSpec:
    return ArmSpec(
        id=arm_id,
        protocols=("cli",),
        curated=True,
        notes="Fixture arm.",
        tier="research",
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


def test_darkmoon_list_tools_static_and_unarmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.delenv(DARK_MOON_SCOPE, raising=False)
    result = DarkMoonArm().invoke(_spec(DARK_MOON_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
    assert result.output["caveats"] == DARK_MOON_CAVEATS
    assert "composite egress" in result.output["caveats"]
    assert "MCP" in result.output["caveats"]
    assert "log" in result.output["read_actions"]
    assert "list_tools" in result.output["read_actions"]
    assert result.output["dispatch_actions"] == ["campaign", "run"]


def test_darkmoon_list_tools_blanket_scope_is_unarmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "*")
    result = DarkMoonArm().invoke(_spec(DARK_MOON_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
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
    assert "not on the allowlist" in result.error


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


def test_darkmoon_unarmed_refusal_names_env_and_caveat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.delenv(DARK_MOON_SCOPE, raising=False)
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": "10.10.0.1"}
    )
    assert result.ok is False
    assert DARK_MOON_SCOPE in result.error
    assert "Caveat:" in result.error
    assert DARK_MOON_CAVEATS in result.error
    assert "[redacted]" not in result.error


@pytest.mark.parametrize("action", ["campaign", "run"])
def test_darkmoon_armed_in_scope_runs_and_logs(
    action: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "10.10.0.0/16")
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), action, {"target": "10.10.0.1"}
    )
    assert result.ok is True
    argv = result.output["output"]["argv"]
    assert argv == ["TARGET: 10.10.0.1"]
    assert result.output["dispatch"]["scope"] == "10.10.0.0/16"
    assert result.output["dispatch"]["target"] == "10.10.0.1"
    err = capsys.readouterr().err
    assert "[dispatch]" in err
    assert "arm=dark-moon" in err
    assert f"action={action}" in err
    assert "target=10.10.0.1" in err


def test_darkmoon_url_target_one_token_and_host_authorize(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "10.10.0.0/16")
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID),
        "campaign",
        {"target": "http://10.10.0.1:3000"},
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == ["TARGET: http://10.10.0.1:3000"]
    assert result.output["dispatch"]["target"] == "10.10.0.1"
    err = capsys.readouterr().err
    assert "arm=dark-moon" in err
    assert "target=10.10.0.1" in err


def test_darkmoon_url_userinfo_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "10.10.0.0/16")
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID),
        "campaign",
        {"target": "http://user:secret@10.10.0.1/"},
    )
    assert result.ok is False
    assert "userinfo" in result.error
    assert "secret" not in result.error
    assert "[redacted]" not in result.error


def test_darkmoon_out_of_scope_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "10.10.0.0/16")
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "run", {"target": "8.8.8.8"}
    )
    assert result.ok is False
    assert "outside the armed dispatch scope" in result.error


def test_darkmoon_flag_shaped_target_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "10.10.0.0/16")
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": "--help"}
    )
    assert result.ok is False
    assert "flag-shaped" in result.error


def test_darkmoon_unbracketed_ipv6_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "2001:db8::1")
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": "2001:db8::1"}
    )
    assert result.ok is False
    assert "IPv6" in result.error


def test_darkmoon_canonical_host_rebrackets_ipv6() -> None:
    assert darkmoon_canonical_host("[2001:db8::1]") == "[2001:db8::1]"
    assert darkmoon_canonical_host("http://[2001:db8::1]/") == "[2001:db8::1]"
    assert darkmoon_canonical_host("10.10.0.1") == "10.10.0.1"
    assert darkmoon_canonical_host("lab.internal") == "lab.internal"


@pytest.mark.parametrize(
    "target,argv_token",
    [
        ("[2001:db8::1]", "TARGET: [2001:db8::1]"),
        ("http://[2001:db8::1]/", "TARGET: http://[2001:db8::1]/"),
    ],
)
def test_darkmoon_bracketed_ipv6_armed_in_scope(
    target: str,
    argv_token: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "2001:db8::1")
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": target}
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == [argv_token]
    assert result.output["dispatch"]["target"] == "[2001:db8::1]"
    err = capsys.readouterr().err
    assert "arm=dark-moon" in err
    assert "target=[2001:db8::1]" in err


@pytest.mark.parametrize("target", ["[]", "http://[]", "[gggg::1]", "[2001:db8::1"])
def test_darkmoon_malformed_ipv6_is_result_not_traceback(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "2001:db8::1")
    result = DarkMoonArm().invoke(
        _spec(DARK_MOON_ID), "campaign", {"target": target}
    )
    assert result.ok is False
    assert result.error is not None
    assert "hostname" in result.error or "http(s)" in result.error


def test_darkmoon_extra_args_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV)
    monkeypatch.setenv(DARK_MOON_BIN, str(binary))
    monkeypatch.setenv(DARK_MOON_SCOPE, "10.10.0.0/16")
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


def test_pyrit_list_tools_static_and_unarmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.delenv(PYRIT_SCOPE, raising=False)
    result = PyritArm().invoke(_spec(PYRIT_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
    assert result.output["caveats"] == PYRIT_CAVEATS
    assert "pyrit_scan" in result.output["caveats"]
    assert "list_scenarios" in result.output["read_actions"]
    assert result.output["dispatch_actions"] == ["scan"]


def test_pyrit_list_tools_blanket_scope_is_unarmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "*")
    result = PyritArm().invoke(_spec(PYRIT_ID), "tools/list", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
    assert result.output["caveats"] == PYRIT_CAVEATS


def test_pyrit_list_scenarios_argv_frozen_no_dispatch_log(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    result = PyritArm().invoke(_spec(PYRIT_ID), "list_scenarios", {})
    assert result.ok is True
    assert result.output["argv"] == ["--list-scenarios"]
    err = capsys.readouterr().err
    assert "[dispatch]" not in err
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


def test_pyrit_unarmed_refusal_names_env_and_caveat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.delenv(PYRIT_SCOPE, raising=False)
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "10.10.0.1"},
    )
    assert result.ok is False
    assert PYRIT_SCOPE in result.error
    assert "Caveat:" in result.error
    assert PYRIT_CAVEATS in result.error
    assert "[redacted]" not in result.error


def test_pyrit_armed_in_scope_runs_and_logs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "10.10.0.0/16")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "10.10.0.1"},
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == [
        "airt.cyber",
        "--target",
        "10.10.0.1",
    ]
    assert result.output["dispatch"]["scope"] == "10.10.0.0/16"
    assert result.output["dispatch"]["target"] == "10.10.0.1"
    err = capsys.readouterr().err
    assert "[dispatch]" in err
    assert "arm=pyrit" in err
    assert "target=10.10.0.1" in err


def test_pyrit_url_target_passed_through_host_authorized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "lab.internal")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {
            "scenario": "foundry.red_team_agent",
            "target": "https://lab.internal/app",
        },
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == [
        "foundry.red_team_agent",
        "--target",
        "https://lab.internal/app",
    ]
    assert result.output["dispatch"]["target"] == "lab.internal"
    err = capsys.readouterr().err
    assert "target=lab.internal" in err


def test_pyrit_url_userinfo_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "10.10.0.0/16")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {
            "scenario": "foundry.red_team_agent",
            "target": "http://user:secret@10.10.0.1/",
        },
    )
    assert result.ok is False
    assert "userinfo" in result.error
    assert "secret" not in result.error
    assert "[redacted]" not in result.error


def test_pyrit_out_of_scope_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "10.10.0.0/16")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "8.8.8.8"},
    )
    assert result.ok is False
    assert "outside the armed dispatch scope" in result.error


def test_pyrit_flag_shaped_target_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "10.10.0.0/16")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "--target"},
    )
    assert result.ok is False
    assert "flag-shaped" in result.error


def test_pyrit_scenario_flag_shaped_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "10.10.0.0/16")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "-e", "target": "10.10.0.1"},
    )
    assert result.ok is False
    assert "flag-shaped" in result.error


def test_pyrit_scenario_regex_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "10.10.0.0/16")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt/cyber", "target": "10.10.0.1"},
    )
    assert result.ok is False
    assert "scenario" in result.error


def test_pyrit_non_http_scheme_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "10.10.0.0/16")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "file:///etc/passwd"},
    )
    assert result.ok is False
    assert "http(s)" in result.error


def test_pyrit_unbracketed_ipv6_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "2001:db8::1")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": "2001:db8::1"},
    )
    assert result.ok is False
    assert "IPv6" in result.error


def test_pyrit_canonical_host_rebrackets_ipv6() -> None:
    assert pyrit_canonical_host("[2001:db8::1]") == "[2001:db8::1]"
    assert pyrit_canonical_host("http://[2001:db8::1]/") == "[2001:db8::1]"
    assert pyrit_canonical_host("10.10.0.1") == "10.10.0.1"
    assert pyrit_canonical_host("lab.internal") == "lab.internal"


@pytest.mark.parametrize(
    "target,passed",
    [
        ("[2001:db8::1]", "[2001:db8::1]"),
        ("http://[2001:db8::1]/", "http://[2001:db8::1]/"),
    ],
)
def test_pyrit_bracketed_ipv6_armed_in_scope(
    target: str,
    passed: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "2001:db8::1")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": target},
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == [
        "airt.cyber",
        "--target",
        passed,
    ]
    assert result.output["dispatch"]["target"] == "[2001:db8::1]"
    err = capsys.readouterr().err
    assert "arm=pyrit" in err
    assert "target=[2001:db8::1]" in err


@pytest.mark.parametrize("target", ["[]", "http://[]", "[gggg::1]", "[2001:db8::1"])
def test_pyrit_malformed_ipv6_is_result_not_traceback(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "2001:db8::1")
    result = PyritArm().invoke(
        _spec(PYRIT_ID),
        "scan",
        {"scenario": "airt.cyber", "target": target},
    )
    assert result.ok is False
    assert result.error is not None
    assert "hostname" in result.error or "http(s)" in result.error


def test_pyrit_extra_args_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV)
    monkeypatch.setenv(PYRIT_BIN, str(binary))
    monkeypatch.setenv(PYRIT_SCOPE, "10.10.0.0/16")
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
