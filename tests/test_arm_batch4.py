"""Tests for routersploit, sniper, and zgrab2 arms. All hermetic."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from extension.arms.routersploit import ARM_ID as ROUTERSPLOIT_ID
from extension.arms.routersploit import RoutersploitArm
from extension.arms.routersploit.policy import CAVEATS as ROUTERSPLOIT_CAVEATS
from extension.arms.routersploit.policy import MODULE_RE, OPTION_KEYS
from extension.arms.routersploit.policy import resolve_binary as routersploit_resolve_binary
from extension.arms.sniper import ARM_ID as SNIPER_ID
from extension.arms.sniper import SniperArm
from extension.arms.sniper.policy import CAVEATS as SNIPER_CAVEATS
from extension.arms.sniper.policy import MODES
from extension.arms.zgrab2 import ARM_ID as ZGRAB2_ID
from extension.arms.zgrab2 import Zgrab2Arm
from extension.arms.zgrab2.policy import CAVEATS as ZGRAB2_CAVEATS
from extension.arms.zgrab2.policy import MODULES
from extension.contract import ArmSpec, NotInstalledError


def _spec(arm_id: str) -> ArmSpec:
    return ArmSpec(
        id=arm_id, protocols=("cli",), curated=True, notes="Fixture arm."
    )


def _fake_binary(tmp_path: Path, name: str, body: str) -> Path:
    script = tmp_path / f"{name}-payload.py"
    script.write_text(body, encoding="utf-8")
    if os.name == "nt":
        wrapper = tmp_path / f"{name}.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return wrapper
    wrapper = tmp_path / name
    wrapper.write_text(
        f"#!{sys.executable}\nexec(open(r'{script}').read())\n", encoding="utf-8"
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return wrapper


ECHO_ARGV = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
ECHO_ARGV_AND_STDIN = (
    "import json, sys\n"
    "print(json.dumps({'argv': sys.argv[1:], 'stdin': sys.stdin.read()}))\n"
)
ECHO_ARGV_AND_CWD = (
    "import json, os, sys\n"
    "print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd()}))\n"
)
SLEEP_BODY = "import time\ntime.sleep(2)\n"


# --- routersploit -------------------------------------------------------


def test_routersploit_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ROUTERSPLOIT_BIN", raising=False)
    monkeypatch.setattr(
        "extension.arms.routersploit.arm.resolve_binary", lambda: None
    )
    arm = RoutersploitArm()
    spec = _spec(ROUTERSPLOIT_ID)
    assert arm.installed(spec) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(spec, "list_tools", {})


def test_routersploit_list_tools_static_and_unarmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", SLEEP_BODY)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.delenv("ROUTERSPLOIT_DISPATCH_SCOPE", raising=False)
    result = RoutersploitArm(timeout=1.0).invoke(
        _spec(ROUTERSPLOIT_ID), "list_tools", {}
    )
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
    assert result.output["caveats"] == ROUTERSPLOIT_CAVEATS
    assert "executes the module" in result.output["caveats"]
    assert "check" in result.output["caveats"]
    assert result.output["dispatch_actions"] == ["run"]
    assert "list_tools" in result.output["read_actions"]
    assert result.output["module_pattern"] == MODULE_RE.pattern
    assert result.output["option_keys"] == list(OPTION_KEYS)
    aliased = RoutersploitArm().invoke(_spec(ROUTERSPLOIT_ID), "tools/list", {})
    assert aliased.ok is True
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.1")
    armed = RoutersploitArm().invoke(_spec(ROUTERSPLOIT_ID), "list_tools", {})
    assert armed.output["dispatch_armed"] is True


def test_routersploit_list_tools_blanket_unarmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "*")
    result = RoutersploitArm().invoke(_spec(ROUTERSPLOIT_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
    assert result.output["caveats"] == ROUTERSPLOIT_CAVEATS


def test_routersploit_list_tools_extra_args_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID), "list_tools", {"module": "scanners/autopwn"}
    )
    assert result.ok is False
    assert "fixed argv" in result.error


def test_routersploit_unarmed_refusal_names_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_CWD)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.delenv("ROUTERSPLOIT_DISPATCH_SCOPE", raising=False)
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": "10.10.0.1"},
    )
    assert result.ok is False
    assert "ROUTERSPLOIT_DISPATCH_SCOPE" in result.error
    assert "Caveat:" in result.error
    assert ROUTERSPLOIT_CAVEATS in result.error


def test_routersploit_armed_in_scope_runs_logs_and_temp_cwd(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_CWD)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {
            "module": "scanners/autopwn",
            "target": "10.10.0.1",
            "port": 80,
            "username": "admin",
        },
    )
    assert result.ok is True
    argv = result.output["output"]["argv"]
    assert argv[:3] == ["-m", "scanners/autopwn", "-s"]
    assert "target 10.10.0.1" in argv
    assert "port 80" in argv
    assert "username admin" in argv
    assert "password" not in " ".join(argv)
    assert result.output["dispatch"]["scope"] == "10.10.0.0/16"
    assert result.output["dispatch"]["target"] == "10.10.0.1"
    err = capsys.readouterr().err
    assert "[dispatch]" in err and "arm=routersploit" in err
    assert "action=run" in err and "target=10.10.0.1" in err
    cwd = Path(result.output["output"]["cwd"]).resolve()
    assert cwd != Path.cwd().resolve()
    assert Path(tempfile.gettempdir()).resolve() in cwd.parents


def test_routersploit_relative_bin_resolves_absolute_and_temp_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "rsf", ECHO_ARGV_AND_CWD)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", f"./{binary.name}")
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    resolved = routersploit_resolve_binary()
    assert resolved is not None
    assert Path(resolved).is_absolute()
    assert Path(resolved).resolve() == binary.resolve()
    captured: dict[str, list[str]] = {}
    real_run = subprocess.run

    def _run(*args, **kwargs):
        captured["cmd"] = list(args[0])
        return real_run(*args, **kwargs)

    monkeypatch.setattr("extension.arms.routersploit.arm.subprocess.run", _run)
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": "10.10.0.1"},
    )
    assert result.ok is True
    assert Path(captured["cmd"][0]).is_absolute()
    assert Path(captured["cmd"][0]).resolve() == binary.resolve()
    cwd = Path(result.output["output"]["cwd"]).resolve()
    assert Path(tempfile.gettempdir()).resolve() in cwd.parents


def test_routersploit_url_target_authorizes_hostname(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_CWD)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": "http://10.10.0.1/"},
    )
    assert result.ok is True
    assert result.output["dispatch"]["target"] == "10.10.0.1"
    assert "target http://10.10.0.1/" in result.output["output"]["argv"]


def test_routersploit_out_of_scope_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": "8.8.8.8"},
    )
    assert result.ok is False
    assert "outside the armed dispatch scope" in result.error
    assert "Caveat:" in result.error


def test_routersploit_flag_shaped_and_unbracketed_ipv6(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    spec = _spec(ROUTERSPLOIT_ID)
    result = RoutersploitArm().invoke(
        spec, "run", {"module": "scanners/autopwn", "target": "--help"}
    )
    assert result.ok is False
    assert "flag-shaped" in result.error
    result = RoutersploitArm().invoke(
        spec, "run", {"module": "scanners/autopwn", "target": "2001:db8::1"}
    )
    assert result.ok is False
    assert "IPv6" in result.error


@pytest.mark.parametrize(
    "target",
    [
        "[]",
        "http://[]",
        "https://[gggg::1]/",
        "[:]",
        "[:::]",
        "[gggg::1]",
        "[2001:db8::1",
        "[10.10.0.1]",
    ],
)
def test_routersploit_malformed_ipv6_is_refusal_not_crash(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "2001:db8::1")
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": target},
    )
    assert result.ok is False
    assert result.error is not None


def test_routersploit_url_userinfo_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {
            "module": "scanners/autopwn",
            "target": "http://user:secret@10.10.0.1/",
        },
    )
    assert result.ok is False
    assert "userinfo" in result.error
    assert "secret" not in result.error
    assert "[redacted]" not in result.error


def test_routersploit_bracketed_ipv6_armed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_CWD)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "2001:db8::1")
    spec = _spec(ROUTERSPLOIT_ID)
    result = RoutersploitArm().invoke(
        spec,
        "run",
        {"module": "scanners/autopwn", "target": "[2001:db8::1]"},
    )
    assert result.ok is True
    assert result.output["dispatch"]["target"] == "[2001:db8::1]"
    assert "target [2001:db8::1]" in result.output["output"]["argv"]
    err = capsys.readouterr().err
    assert "target=[2001:db8::1]" in err
    result = RoutersploitArm().invoke(
        spec,
        "run",
        {"module": "scanners/autopwn", "target": "http://[2001:db8::1]/"},
    )
    assert result.ok is True
    assert result.output["dispatch"]["target"] == "[2001:db8::1]"
    assert "target http://[2001:db8::1]/" in result.output["output"]["argv"]
    err = capsys.readouterr().err
    assert "target=[2001:db8::1]" in err


def test_routersploit_bad_module_and_password_extra(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    spec = _spec(ROUTERSPLOIT_ID)
    for module in ("../etc/passwd", "exploits/x; rm", "-e"):
        result = RoutersploitArm().invoke(
            spec, "run", {"module": module, "target": "10.10.0.1"}
        )
        assert result.ok is False, module
    result = RoutersploitArm().invoke(
        spec,
        "run",
        {
            "module": "scanners/autopwn",
            "target": "10.10.0.1",
            "password": "secret",
        },
    )
    assert result.ok is False
    assert "fixed argv" in result.error


def test_routersploit_username_charset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_CWD)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    spec = _spec(ROUTERSPLOIT_ID)
    result = RoutersploitArm().invoke(
        spec,
        "run",
        {
            "module": "scanners/autopwn",
            "target": "10.10.0.1",
            "username": "admin;rm",
        },
    )
    assert result.ok is False
    assert "username" in result.error
    result = RoutersploitArm().invoke(
        spec,
        "run",
        {
            "module": "scanners/autopwn",
            "target": "10.10.0.1",
            "username": "user_name.1-ok",
        },
    )
    assert result.ok is True
    assert "username user_name.1-ok" in result.output["output"]["argv"]


def test_routersploit_check_action_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    spec = _spec(ROUTERSPLOIT_ID)
    for action in ("check", "command_check"):
        result = RoutersploitArm().invoke(spec, action, {})
        assert result.ok is False
        assert "allowlist" in result.error


def test_routersploit_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", SLEEP_BODY)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    result = RoutersploitArm(timeout=1.0).invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": "10.10.0.1"},
    )
    assert result.ok is False
    assert "timed out" in result.error


# --- sniper -------------------------------------------------------------


def test_sniper_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SNIPER_BIN", raising=False)
    monkeypatch.setattr("extension.arms.sniper.arm.resolve_binary", lambda: None)
    arm = SniperArm()
    spec = _spec(SNIPER_ID)
    assert arm.installed(spec) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(spec, "list_tools", {})


def test_sniper_list_tools_caveats_and_blanket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.delenv("SNIPER_DISPATCH_SCOPE", raising=False)
    result = SniperArm().invoke(_spec(SNIPER_ID), "list_tools", {})
    assert result.ok is True
    caveats = result.output["caveats"]
    assert caveats == SNIPER_CAVEATS
    lowered = caveats.lower()
    assert "sub-tool" in lowered
    assert "root" in lowered
    assert "telemetry" in lowered
    assert "composite" in lowered
    assert result.output["dispatch_armed"] is False
    assert result.output["dispatch_actions"] == ["scan"]
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "*")
    result = SniperArm().invoke(_spec(SNIPER_ID), "list_tools", {})
    assert result.output["dispatch_armed"] is False
    assert result.output["caveats"] == SNIPER_CAVEATS
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "10.10.0.1")
    result = SniperArm().invoke(_spec(SNIPER_ID), "list_tools", {})
    assert result.output["dispatch_armed"] is True


def test_sniper_unarmed_refusal_names_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.delenv("SNIPER_DISPATCH_SCOPE", raising=False)
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "10.10.0.1", "mode": "normal"},
    )
    assert result.ok is False
    assert "SNIPER_DISPATCH_SCOPE" in result.error
    assert "Caveat:" in result.error
    assert SNIPER_CAVEATS in result.error


def test_sniper_armed_in_scope_fixed_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "10.10.0.0/16")
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "10.10.0.1", "mode": "fullportonly"},
    )
    assert result.ok is True
    argv = result.output["output"]["argv"]
    assert argv == ["-t", "10.10.0.1", "-m", "fullportonly"]
    assert "-p" not in argv and "-fp" not in argv
    assert result.output["dispatch"]["target"] == "10.10.0.1"
    err = capsys.readouterr().err
    assert "[dispatch]" in err and "arm=sniper" in err
    assert "target=10.10.0.1" in err


@pytest.mark.parametrize("mode", sorted(MODES))
def test_sniper_closed_modes(
    mode: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "lab.internal")
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "lab.internal", "mode": mode},
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == ["-t", "lab.internal", "-m", mode]


def test_sniper_discover_and_port_modes_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "10.10.0.0/16")
    spec = _spec(SNIPER_ID)
    for mode in ("discover", "port"):
        result = SniperArm().invoke(
            spec, "scan", {"target": "10.10.0.1", "mode": mode}
        )
        assert result.ok is False
        assert "mode" in result.error
    result = SniperArm().invoke(
        spec,
        "scan",
        {"target": "10.10.0.1", "mode": "normal", "port": 80},
    )
    assert result.ok is False
    assert "fixed argv" in result.error


def test_sniper_out_of_scope_flag_shaped_ipv6(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "10.10.0.0/16")
    spec = _spec(SNIPER_ID)
    result = SniperArm().invoke(
        spec, "scan", {"target": "8.8.8.8", "mode": "normal"}
    )
    assert result.ok is False
    assert "outside the armed dispatch scope" in result.error
    result = SniperArm().invoke(
        spec, "scan", {"target": "--target", "mode": "normal"}
    )
    assert result.ok is False
    assert "flag-shaped" in result.error
    result = SniperArm().invoke(
        spec, "scan", {"target": "2001:db8::1", "mode": "web"}
    )
    assert result.ok is False
    assert "IPv6" in result.error


@pytest.mark.parametrize("target", ["[]", "http://[]"])
def test_sniper_malformed_ipv6_is_refusal_not_crash(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "2001:db8::1")
    result = SniperArm().invoke(
        _spec(SNIPER_ID), "scan", {"target": target, "mode": "normal"}
    )
    assert result.ok is False
    assert result.error is not None


def test_sniper_url_userinfo_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "10.10.0.0/16")
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "http://user:secret@10.10.0.1/", "mode": "web"},
    )
    assert result.ok is False
    assert "userinfo" in result.error
    assert "secret" not in result.error
    assert "[redacted]" not in result.error


def test_sniper_bracketed_ipv6_armed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "2001:db8::1")
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "[2001:db8::1]", "mode": "normal"},
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == [
        "-t",
        "[2001:db8::1]",
        "-m",
        "normal",
    ]
    assert result.output["dispatch"]["target"] == "[2001:db8::1]"
    err = capsys.readouterr().err
    assert "target=[2001:db8::1]" in err


def test_sniper_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = _fake_binary(tmp_path, "sniper", SLEEP_BODY)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    monkeypatch.setenv("SNIPER_DISPATCH_SCOPE", "10.10.0.0/16")
    result = SniperArm(timeout=1.0).invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "10.10.0.1", "mode": "stealth"},
    )
    assert result.ok is False
    assert "timed out" in result.error


# --- zgrab2 -------------------------------------------------------------


def test_zgrab2_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZGRAB2_BIN", raising=False)
    monkeypatch.setattr("extension.arms.zgrab2.arm.resolve_binary", lambda: None)
    arm = Zgrab2Arm()
    spec = _spec(ZGRAB2_ID)
    assert arm.installed(spec) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(spec, "list_modules", {})


def test_zgrab2_list_modules_and_list_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", SLEEP_BODY)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    monkeypatch.delenv("ZGRAB2_DISPATCH_SCOPE", raising=False)
    arm = Zgrab2Arm(timeout=1.0)
    spec = _spec(ZGRAB2_ID)
    listed = arm.invoke(spec, "list_modules", {})
    assert listed.ok is True
    assert listed.output["modules"] == sorted(MODULES)
    tools = arm.invoke(spec, "list_tools", {})
    assert tools.ok is True
    assert tools.output["modules"] == sorted(MODULES)
    assert tools.output["dispatch_armed"] is False
    assert tools.output["caveats"] == ZGRAB2_CAVEATS
    assert "list_modules" in tools.output["read_actions"]
    monkeypatch.setenv("ZGRAB2_DISPATCH_SCOPE", "*")
    tools = arm.invoke(spec, "list_tools", {})
    assert tools.output["dispatch_armed"] is False
    assert tools.output["caveats"] == ZGRAB2_CAVEATS
    monkeypatch.setenv("ZGRAB2_DISPATCH_SCOPE", "10.10.0.1")
    tools = arm.invoke(spec, "list_tools", {})
    assert tools.output["dispatch_armed"] is True


def test_zgrab2_unarmed_refusal_names_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    monkeypatch.delenv("ZGRAB2_DISPATCH_SCOPE", raising=False)
    result = Zgrab2Arm().invoke(
        _spec(ZGRAB2_ID),
        "scan",
        {"target": "10.10.0.1", "module": "http"},
    )
    assert result.ok is False
    assert "ZGRAB2_DISPATCH_SCOPE" in result.error
    assert "Caveat:" in result.error


def test_zgrab2_armed_host_on_stdin_not_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    monkeypatch.setenv("ZGRAB2_DISPATCH_SCOPE", "10.10.0.0/16")
    result = Zgrab2Arm().invoke(
        _spec(ZGRAB2_ID),
        "scan",
        {"target": "10.10.0.1", "module": "http"},
    )
    assert result.ok is True
    echoed = result.output["output"]
    assert echoed["argv"] == ["http"]
    assert echoed["stdin"] == "10.10.0.1\n"
    assert "10.10.0.1" not in echoed["argv"]
    assert result.output["dispatch"]["target"] == "10.10.0.1"
    err = capsys.readouterr().err
    assert "[dispatch]" in err and "arm=zgrab2" in err
    assert "target=10.10.0.1" in err


def test_zgrab2_optional_port(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    monkeypatch.setenv("ZGRAB2_DISPATCH_SCOPE", "10.10.0.0/16")
    result = Zgrab2Arm().invoke(
        _spec(ZGRAB2_ID),
        "scan",
        {"target": "10.10.0.1", "module": "http", "port": 8443},
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == ["http", "--port", "8443"]
    assert result.output["output"]["stdin"] == "10.10.0.1\n"


def test_zgrab2_ipv6_stdin_unbracketed_auth_bracketed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    monkeypatch.setenv("ZGRAB2_DISPATCH_SCOPE", "2001:db8::1")
    result = Zgrab2Arm().invoke(
        _spec(ZGRAB2_ID),
        "scan",
        {"target": "2001:db8::1", "module": "tls"},
    )
    assert result.ok is True
    echoed = result.output["output"]
    assert echoed["stdin"] == "2001:db8::1\n"
    assert "2001:db8::1" not in echoed["argv"]
    assert echoed["argv"] == ["tls"]
    assert result.output["dispatch"]["target"] == "[2001:db8::1]"
    err = capsys.readouterr().err
    assert "target=[2001:db8::1]" in err


def test_zgrab2_unknown_module_cipher_comma(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    monkeypatch.setenv("ZGRAB2_DISPATCH_SCOPE", "10.10.0.0/16")
    spec = _spec(ZGRAB2_ID)
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "10.10.0.1", "module": "cipher"}
    )
    assert result.ok is False
    assert "module" in result.error
    result = Zgrab2Arm().invoke(
        spec,
        "scan",
        {"target": "10.10.0.1", "module": "http", "--cipher": "AES"},
    )
    assert result.ok is False
    assert "fixed argv" in result.error
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "10.10.0.1,8.8.8.8", "module": "http"}
    )
    assert result.ok is False
    assert "comma" in result.error


def test_zgrab2_flag_shaped_and_out_of_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    monkeypatch.setenv("ZGRAB2_DISPATCH_SCOPE", "10.10.0.0/16")
    spec = _spec(ZGRAB2_ID)
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "--port", "module": "http"}
    )
    assert result.ok is False
    assert "flag-shaped" in result.error
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "[--help]", "module": "http"}
    )
    assert result.ok is False
    assert "flag-shaped" in result.error
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "8.8.8.8", "module": "ssh"}
    )
    assert result.ok is False
    assert "outside the armed dispatch scope" in result.error


def test_zgrab2_json_stdout_and_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    monkeypatch.setenv("ZGRAB2_DISPATCH_SCOPE", "example.com")
    result = Zgrab2Arm().invoke(
        _spec(ZGRAB2_ID),
        "scan",
        {"target": "example.com", "module": "dns"},
    )
    assert result.ok is True
    assert isinstance(result.output["output"], dict)
    assert result.output["output"]["argv"] == ["dns"]
    sleeper = _fake_binary(tmp_path, "zgrab2-sleep", SLEEP_BODY)
    monkeypatch.setenv("ZGRAB2_BIN", str(sleeper))
    result = Zgrab2Arm(timeout=1.0).invoke(
        _spec(ZGRAB2_ID),
        "scan",
        {"target": "example.com", "module": "dns"},
    )
    assert result.ok is False
    assert "timed out" in result.error
