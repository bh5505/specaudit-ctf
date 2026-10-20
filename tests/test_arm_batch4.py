"""Tests for routersploit, sniper, and zgrab2 arms. All hermetic."""

from __future__ import annotations

import json
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
from extension.arms.routersploit.policy import RUN_KEYS as ROUTERSPLOIT_RUN_KEYS
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
        id=arm_id,
        protocols=("cli",),
        notes="Fixture arm.",
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
FAIL_WITH_ARGV_ON_STDERR = (
    "import json, sys\n"
    "sys.stderr.write(json.dumps(sys.argv[1:]))\n"
    "sys.exit(1)\n"
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


def test_routersploit_list_tools_static(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", SLEEP_BODY)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm(timeout=1.0).invoke(
        _spec(ROUTERSPLOIT_ID), "list_tools", {}
    )
    assert result.ok is True
    assert result.output["caveats"] == ROUTERSPLOIT_CAVEATS
    assert "executes the module" in result.output["caveats"]
    assert "check" in result.output["caveats"]
    assert "list_tools" in result.output["actions"]
    assert result.output["option_keys"] == sorted(ROUTERSPLOIT_RUN_KEYS)
    assert "password" in result.output["options"]
    assert "-s" in result.output["options"]
    aliased = RoutersploitArm().invoke(_spec(ROUTERSPLOIT_ID), "tools/list", {})
    assert aliased.ok is True
    assert RoutersploitArm().invoke(_spec(ROUTERSPLOIT_ID), "list_tools", {}).ok


def test_routersploit_list_tools_reports_caveats(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(_spec(ROUTERSPLOIT_ID), "list_tools", {})
    assert result.ok is True
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
    assert "no arguments" in result.error


def test_routersploit_run_uses_operator_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_CWD)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": "10.10.0.1"},
    )
    assert result.ok is True
    assert "target 10.10.0.1" in result.output["argv"]


def test_routersploit_run_argv_and_temp_cwd(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_CWD)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {
            "module": "scanners/autopwn",
            "target": "10.10.0.1",
            "port": 80,
            "username": "admin",
            "options": {"threads": 4, "ssl": "true"},
        },
    )
    assert result.ok is True
    argv = result.output["argv"]
    assert argv == [
        "-m", "scanners/autopwn",
        "-s", "target 10.10.0.1",
        "-s", "port 80",
        "-s", "username admin",
        "-s", "threads 4",
        "-s", "ssl true",
    ]

    cwd = Path(result.output["cwd"]).resolve()
    assert cwd != Path.cwd().resolve()
    assert Path(tempfile.gettempdir()).resolve() in cwd.parents


def test_routersploit_relative_bin_resolves_absolute_and_temp_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "rsf", ECHO_ARGV_AND_CWD)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", f"./{binary.name}")
    resolved = routersploit_resolve_binary()
    assert resolved is not None
    assert Path(resolved).is_absolute()
    assert Path(resolved).resolve() == binary.resolve()
    captured: dict[str, list[str]] = {}
    from extension.arms.bounded_capture import run_bounded as real_run

    def _run(*args, **kwargs):
        captured["cmd"] = list(args[0])
        return real_run(*args, **kwargs)

    monkeypatch.setattr("extension.arms.routersploit.arm.run_bounded", _run)
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": "10.10.0.1"},
    )
    assert result.ok is True
    assert Path(captured["cmd"][0]).is_absolute()
    assert Path(captured["cmd"][0]).resolve() == binary.resolve()
    cwd = Path(result.output["cwd"]).resolve()
    assert Path(tempfile.gettempdir()).resolve() in cwd.parents


@pytest.mark.parametrize(
    "target",
    [
        "10.10.0.1",
        "8.8.8.8",
        "router.lab",
        "http://10.10.0.1/",
        "https://router.lab:8443/path",
        "2001:db8::1",
        "[2001:db8::1]",
        "http://[2001:db8::1]/",
        "[]",
        "http://[]",
        "[:::]",
    ],
)
def test_routersploit_operator_target_expressions_pass_through(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": target},
    )
    assert result.ok is True
    assert f"target {target}" in result.output["argv"]


def test_routersploit_run_accepts_operator_selected_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {"module": "scanners/autopwn", "target": "8.8.8.8"},
    )
    assert result.ok is True
    assert "target 8.8.8.8" in result.output["argv"]


def test_routersploit_flag_shaped_module_and_target_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    spec = _spec(ROUTERSPLOIT_ID)
    result = RoutersploitArm().invoke(
        spec, "run", {"module": "scanners/autopwn", "target": "--help"}
    )
    assert result.ok is False
    assert "flag-shaped" in result.error
    result = RoutersploitArm().invoke(
        spec, "run", {"module": "--module", "target": "10.10.0.1"}
    )
    assert result.ok is False
    assert "flag-shaped" in result.error


def test_routersploit_url_userinfo_passes_through_secret_scrubbed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {
            "module": "scanners/autopwn",
            "target": "http://user:s3cret-pw@10.10.0.1/",
        },
    )
    assert result.ok is True
    assert "target http://user:[redacted]@10.10.0.1/" in result.output["argv"]
    assert "s3cret-pw" not in json.dumps(result.output)


def test_routersploit_bracketed_ipv6_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_CWD)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    spec = _spec(ROUTERSPLOIT_ID)
    result = RoutersploitArm().invoke(
        spec,
        "run",
        {"module": "scanners/autopwn", "target": "[2001:db8::1]"},
    )
    assert result.ok is True
    assert "target [2001:db8::1]" in result.output["argv"]

    result = RoutersploitArm().invoke(
        spec,
        "run",
        {"module": "scanners/autopwn", "target": "http://[2001:db8::1]/"},
    )
    assert result.ok is True
    assert "target http://[2001:db8::1]/" in result.output["argv"]



def test_routersploit_modules_pass_through_without_taxonomy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    spec = _spec(ROUTERSPLOIT_ID)
    # No shell interprets argv, so metacharacters are inert data. A module
    # is still one upstream -m token, so whitespace stays refused.
    for module in (
        "scanners/autopwn",
        "exploits/custom/router_rce",
        "../etc/passwd",
        "exploits/x;rm",
    ):
        result = RoutersploitArm().invoke(
            spec, "run", {"module": module, "target": "10.10.0.1"}
        )
        assert result.ok is True, module
        assert result.output["argv"][:2] == ["-m", module]


def test_routersploit_password_and_custom_options_pass_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {
            "module": "creds/router_brute",
            "target": "10.10.0.1",
            "options": {
                "username": "admin",
                "password": "s3cret-hunter2",
                "threads": 4,
            },
        },
    )
    assert result.ok is True
    argv = result.output["argv"]
    assert "-s" in argv
    assert "username admin" in argv
    assert "threads 4" in argv
    assert "password [redacted]" in argv
    assert "s3cret-hunter2" not in json.dumps(result.output)


def test_routersploit_secret_scrubbed_on_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", FAIL_WITH_ARGV_ON_STDERR)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(
        _spec(ROUTERSPLOIT_ID),
        "run",
        {
            "module": "creds/router_brute",
            "target": "10.10.0.1",
            "options": {"password": "s3cret-hunter2"},
        },
    )
    assert result.ok is False
    assert "s3cret-hunter2" not in result.error
    assert "s3cret-hunter2" not in json.dumps(result.output)
    assert "[redacted]" in result.error


@pytest.mark.parametrize(
    "payload",
    [
        {"target": "10.10.0.1"},
        {"module": "scanners/autopwn"},
        {"module": "", "target": "10.10.0.1"},
        {"module": "scanners/autopwn", "target": ""},
        {"module": "scanners/autopwn", "target": "10.10.0.1\nevil"},
        {"module": "scanners/autopwn", "target": "10.10.0.1 evil"},
        {"module": "scanners/autopwn", "target": "10.10.0.1",
         "password": "s3cret"},
        {"module": "scanners/autopwn", "target": "10.10.0.1", "port": "80"},
        {"module": "scanners/autopwn", "target": "10.10.0.1", "port": 0},
        {"module": "scanners/autopwn", "target": "10.10.0.1", "port": 70000},
        {"module": "scanners/autopwn", "target": "10.10.0.1", "port": True},
        {"module": "scanners/autopwn", "target": "10.10.0.1", "username": 7},
        {"module": "scanners/autopwn", "target": "10.10.0.1",
         "username": "ad\nmin"},
        {"module": "scanners/autopwn", "target": "10.10.0.1",
         "options": ["password", "s3cret"]},
        {"module": "scanners/autopwn", "target": "10.10.0.1",
         "options": {"": "s3cret"}},
        {"module": "scanners/autopwn", "target": "10.10.0.1",
         "options": {"pass word": "s3cret"}},
        {"module": "scanners/autopwn", "target": "10.10.0.1",
         "options": {"password": "a\x00b"}},
        {"module": "scanners/autopwn", "target": "10.10.0.1",
         "options": {"password": True}},
        {"module": "scanners/autopwn", "target": "10.10.0.1",
         "options": {"nested": {"a": 1}}},
    ],
)
def test_routersploit_invalid_technical_args_refused(
    payload: dict, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    result = RoutersploitArm().invoke(_spec(ROUTERSPLOIT_ID), "run", payload)
    assert result.ok is False
    assert result.error is not None


def test_routersploit_username_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_CWD)
    monkeypatch.setenv("ROUTERSPLOIT_BIN", str(binary))
    spec = _spec(ROUTERSPLOIT_ID)
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
    assert "username user_name.1-ok" in result.output["argv"]
    # Shell metacharacters are inert without a shell: one argv element.
    result = RoutersploitArm().invoke(
        spec,
        "run",
        {
            "module": "scanners/autopwn",
            "target": "10.10.0.1",
            "username": "admin;rm",
        },
    )
    assert result.ok is True
    assert "username admin;rm" in result.output["argv"]


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


def test_sniper_list_tools_caveats(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    result = SniperArm().invoke(_spec(SNIPER_ID), "list_tools", {})
    assert result.ok is True
    caveats = result.output["caveats"]
    assert caveats == SNIPER_CAVEATS
    lowered = caveats.lower()
    assert "sub-tool" in lowered
    assert "root" in lowered
    assert "telemetry" in lowered
    assert "composite" in lowered
    assert "list_tools" in result.output["actions"]


def test_sniper_scan_uses_operator_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "10.10.0.1", "mode": "normal"},
    )
    assert result.ok is True
    assert result.output["argv"] == ["-t", "10.10.0.1", "-m", "normal"]


def test_sniper_scan_default_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "10.10.0.1", "mode": "fullportonly"},
    )
    assert result.ok is True
    argv = result.output["argv"]
    assert argv == ["-t", "10.10.0.1", "-m", "fullportonly"]



@pytest.mark.parametrize("mode", sorted(MODES))
def test_sniper_modes_pass_through(
    mode: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "lab.internal", "mode": mode},
    )
    assert result.ok is True
    assert result.output["argv"] == ["-t", "lab.internal", "-m", mode]


def test_sniper_discover_and_port_modes_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    spec = _spec(SNIPER_ID)
    for mode in ("discover", "port"):
        result = SniperArm().invoke(
            spec, "scan", {"target": "10.10.0.1", "mode": mode}
        )
        assert result.ok is True
        assert result.output["argv"][-1] == mode
    result = SniperArm().invoke(
        spec,
        "scan",
        {"target": "10.10.0.1", "mode": "port", "options": ["-p", "80"]},
    )
    assert result.ok is True
    assert result.output["argv"] == ["-t", "10.10.0.1", "-m", "port", "-p", "80"]


def test_sniper_target_validation_and_operator_selected_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    spec = _spec(SNIPER_ID)
    result = SniperArm().invoke(
        spec, "scan", {"target": "8.8.8.8", "mode": "normal"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["-t", "8.8.8.8", "-m", "normal"]
    result = SniperArm().invoke(
        spec, "scan", {"target": "--target", "mode": "normal"}
    )
    assert result.ok is False
    assert "flag-shaped" in result.error
    result = SniperArm().invoke(spec, "scan", {"target": "2001:db8::1", "mode": "web"})
    assert result.ok is True
    assert result.output["argv"][1] == "2001:db8::1"


@pytest.mark.parametrize("target", ["[]", "http://[]", "10.10.0.0/24"])
def test_sniper_passes_target_expression_to_upstream(
    target: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    result = SniperArm().invoke(
        _spec(SNIPER_ID), "scan", {"target": target, "mode": "normal"}
    )
    assert result.ok is True
    assert result.output["argv"][1] == target


def test_sniper_url_userinfo_is_operator_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "http://user:secret@10.10.0.1/", "mode": "web"},
    )
    assert result.ok is True
    assert result.output["argv"][1] == "http://user:secret@10.10.0.1/"


def test_sniper_bracketed_ipv6_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
    result = SniperArm().invoke(
        _spec(SNIPER_ID),
        "scan",
        {"target": "[2001:db8::1]", "mode": "normal"},
    )
    assert result.ok is True
    assert result.output["argv"] == [
        "-t",
        "[2001:db8::1]",
        "-m",
        "normal",
    ]



def test_sniper_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = _fake_binary(tmp_path, "sniper", SLEEP_BODY)
    monkeypatch.setenv("SNIPER_BIN", str(binary))
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
    arm = Zgrab2Arm(timeout=1.0)
    spec = _spec(ZGRAB2_ID)
    listed = arm.invoke(spec, "list_modules", {})
    assert listed.ok is True
    assert listed.output["modules"] == sorted(MODULES)
    tools = arm.invoke(spec, "list_tools", {})
    assert tools.ok is True
    assert tools.output["modules"] == sorted(MODULES)
    assert tools.output["caveats"] == ZGRAB2_CAVEATS
    assert "list_modules" in tools.output["actions"]
    tools = arm.invoke(spec, "list_tools", {})
    assert tools.output["caveats"] == ZGRAB2_CAVEATS
    tools = arm.invoke(spec, "list_tools", {})


def test_zgrab2_scan_uses_operator_target_on_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    result = Zgrab2Arm().invoke(
        _spec(ZGRAB2_ID),
        "scan",
        {"target": "10.10.0.1", "module": "http"},
    )
    assert result.ok is True
    assert result.output["output"]["stdin"] == "10.10.0.1\n"


def test_zgrab2_host_is_sent_on_stdin_not_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
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



def test_zgrab2_optional_port(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    result = Zgrab2Arm().invoke(
        _spec(ZGRAB2_ID),
        "scan",
        {"target": "10.10.0.1", "module": "http", "port": 8443},
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == ["http", "--port", "8443"]
    assert result.output["output"]["stdin"] == "10.10.0.1\n"


def test_zgrab2_ipv6_is_sent_on_stdin_unbracketed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
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



def test_zgrab2_operator_module_options_and_stdin_shape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    spec = _spec(ZGRAB2_ID)
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "10.10.0.1", "module": "cipher"}
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == ["cipher"]
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "10.10.0.1", "module": "http", "options": ["--method", "HEAD"]}
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == ["http", "--method", "HEAD"]
    result = Zgrab2Arm().invoke(
        spec,
        "scan",
        {"target": "10.10.0.1", "module": "http", "--cipher": "AES"},
    )
    assert result.ok is False
    assert "args.options" in result.error
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "10.10.0.1,8.8.8.8", "module": "http"}
    )
    assert result.ok is False
    assert "comma" in result.error


def test_zgrab2_target_is_stdin_data_even_when_flag_shaped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
    spec = _spec(ZGRAB2_ID)
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "--port", "module": "http"}
    )
    assert result.ok is True
    assert result.output["output"]["stdin"] == "--port\n"
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "[--help]", "module": "http"}
    )
    assert result.ok is True
    assert result.output["output"]["stdin"] == "[--help]\n"
    result = Zgrab2Arm().invoke(
        spec, "scan", {"target": "8.8.8.8", "module": "ssh"}
    )
    assert result.ok is True
    assert result.output["output"]["stdin"] == "8.8.8.8\n"
    assert result.output["output"]["argv"] == ["ssh"]


def test_zgrab2_json_stdout_and_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zgrab2", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv("ZGRAB2_BIN", str(binary))
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
