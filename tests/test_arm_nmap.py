"""Tests for the curated nmap arm. All hermetic: a fake binary, no network."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

from extension.arms.nmap import ARM_ID as NMAP_ID
from extension.arms.nmap import NmapArm
from extension.arms.nmap.policy import (
    CAVEATS,
    MODES,
    argv_for,
    resolve_binary,
)
from extension.contract import ArmSpec, NotInstalledError


def _spec() -> ArmSpec:
    return ArmSpec(
        id=NMAP_ID,
        protocols=("cli",),
        curated=True,
        notes="Fixture arm.",
        tier="research",
    )


def _fake_binary(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "nmap-payload.py"
    script.write_text(body, encoding="utf-8")
    if os.name == "nt":
        wrapper = tmp_path / "nmap.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return wrapper
    wrapper = tmp_path / "nmap"
    wrapper.write_text(
        f"#!{sys.executable}\nexec(open(r'{script}').read())\n", encoding="utf-8"
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return wrapper


ECHO_ARGV = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
XML_BODY = 'import sys\nprint("<?xml version=\\"1.0\\"?><nmaprun></nmaprun>")\n'
FAIL_BODY = "import sys\nsys.stderr.write('Failed to resolve')\nsys.exit(2)\n"


@pytest.fixture
def armed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    binary = _fake_binary(tmp_path, ECHO_ARGV)
    monkeypatch.setenv("NMAP_BIN", str(binary))
    monkeypatch.setenv("NMAP_DISPATCH_SCOPE", "10.10.0.0/16,lab.internal")
    return binary


# --- install gate -------------------------------------------------------


def test_not_installed_without_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NMAP_BIN", raising=False)
    arm = NmapArm()
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "list_tools", {})


def test_installed_follows_env_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "extension.arms.nmap.arm.resolve_binary", lambda: "X:/nmap"
    )
    assert NmapArm().installed(_spec())


# --- read tier ----------------------------------------------------------


def test_list_tools_shape(armed: Path) -> None:
    result = NmapArm().invoke(_spec(), "list_tools", {})
    assert result.ok
    assert result.output["read_actions"] == ["list_tools", "tools/list"]
    assert result.output["dispatch_actions"] == ["scan"]
    assert result.output["dispatch_armed"] is True
    assert result.output["modes"] == sorted(MODES)
    assert "NPSL" in result.output["caveats"]


def test_list_tools_rejects_arguments(armed: Path) -> None:
    result = NmapArm().invoke(_spec(), "list_tools", {"x": 1})
    assert not result.ok and "no arguments" in result.error


# --- dispatch gate ------------------------------------------------------


def test_scan_refused_unarmed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NMAP_BIN", str(_fake_binary(tmp_path, ECHO_ARGV)))
    monkeypatch.delenv("NMAP_DISPATCH_SCOPE", raising=False)
    result = NmapArm().invoke(_spec(), "scan", {"target": "10.10.0.5"})
    assert not result.ok
    assert "NMAP_DISPATCH_SCOPE" in result.error and "Caveat" in result.error


def test_scan_refused_out_of_scope(armed: Path) -> None:
    result = NmapArm().invoke(_spec(), "scan", {"target": "192.0.2.9"})
    assert not result.ok and "outside the armed dispatch scope" in result.error


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.0/24",          # CIDR
        "10.10.0.1-20",         # octet range
        "-Pn",                  # flag-shaped
        "a b",                  # whitespace
        "http://10.10.0.5",     # URL
        "scanme.nmap.org,10.10.0.5",  # host list
        "lab@10.10.0.5",        # userinfo
        "10.10.0.5;id",         # control chars
        "[10.10.0.5]",          # bracketed IPv4 crashes urlparse upstream
        "[lab.internal]",       # bracketed hostname
        "[10.10.0.5",           # unmatched bracket
    ],
)
def test_scan_refuses_non_single_host_targets(armed: Path, target: str) -> None:
    result = NmapArm().invoke(_spec(), "scan", {"target": target})
    assert not result.ok
    assert "target" in result.error


def test_scan_refuses_bad_mode_and_ports(armed: Path) -> None:
    bad_mode = NmapArm().invoke(
        _spec(), "scan", {"target": "10.10.0.5", "mode": "aggressive"}
    )
    assert not bad_mode.ok and "mode" in bad_mode.error
    bad_ports = NmapArm().invoke(
        _spec(), "scan", {"target": "10.10.0.5", "ports": [22, 0]}
    )
    assert not bad_ports.ok and "outside 1..65535" in bad_ports.error
    str_ports = NmapArm().invoke(
        _spec(), "scan", {"target": "10.10.0.5", "ports": ["22"]}
    )
    assert not str_ports.ok and "list of integers" in str_ports.error


def test_scan_rejects_extra_keys(armed: Path) -> None:
    result = NmapArm().invoke(
        _spec(), "scan", {"target": "10.10.0.5", "script": "safe"}
    )
    assert not result.ok and "fixed argv" in result.error


# --- happy path ---------------------------------------------------------


def test_scan_happy_path_argv_and_stamp(
    armed: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = NmapArm().invoke(
        _spec(),
        "scan",
        {"target": "10.10.0.5", "mode": "version", "ports": [22, 80]},
    )
    assert result.ok
    # Output is redacted text; the fake binary's JSON echo survives
    # redaction, so parse it back out for the exact-argv assertion.
    argv = json.loads(result.output["output"])["argv"]
    assert argv == ["-sT", "-sV", "-T4", "-oX", "-", "-p", "22,80", "10.10.0.5"]
    stamp = result.output["dispatch"]
    assert stamp == {
        "dispatch": "true",
        "scope": "10.10.0.0/16,lab.internal",
        "target": "10.10.0.5",
    }
    audit = capsys.readouterr().err
    assert "[dispatch]" in audit and "arm=nmap action=scan" in audit


def test_scan_default_top_ports_argv(armed: Path) -> None:
    result = NmapArm().invoke(_spec(), "scan", {"target": "lab.internal"})
    assert result.ok
    argv = json.loads(result.output["output"])["argv"]
    assert argv == ["-sT", "-T4", "-oX", "-", "--top-ports", "100", "lab.internal"]


def test_scan_nonzero_exit_is_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = _fake_binary(tmp_path, FAIL_BODY)
    monkeypatch.setenv("NMAP_BIN", str(binary))
    monkeypatch.setenv("NMAP_DISPATCH_SCOPE", "10.10.0.0/16")
    result = NmapArm().invoke(_spec(), "scan", {"target": "10.10.0.5"})
    assert not result.ok and "Failed to resolve" in result.error
    assert result.output["dispatch"]["target"] == "10.10.0.5"


def test_scan_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = _fake_binary(tmp_path, "import time\ntime.sleep(30)\n")
    monkeypatch.setenv("NMAP_BIN", str(binary))
    monkeypatch.setenv("NMAP_DISPATCH_SCOPE", "10.10.0.0/16")
    result = NmapArm(timeout=0.2).invoke(_spec(), "scan", {"target": "10.10.0.5"})
    assert not result.ok and "timed out" in result.error


def test_scan_xml_output_stays_redacted_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, XML_BODY)
    monkeypatch.setenv("NMAP_BIN", str(binary))
    monkeypatch.setenv("NMAP_DISPATCH_SCOPE", "10.10.0.0/16")
    result = NmapArm().invoke(_spec(), "scan", {"target": "10.10.0.5"})
    assert result.ok
    assert isinstance(result.output["output"], str)
    assert "<nmaprun>" in result.output["output"]


# --- argv assembly unit ---------------------------------------------------


def test_argv_for_is_closed() -> None:
    assert argv_for("nmap", "10.0.0.1", "connect", None) == [
        "nmap", "-sT", "-T4", "-oX", "-", "--top-ports", "100", "10.0.0.1",
    ]
    assert argv_for("nmap", "10.0.0.1", None, [443]) == [
        "nmap", "-sT", "-T4", "-oX", "-", "-p", "443", "10.0.0.1",
    ]


def test_bracketed_ipv6_literal_is_allowed() -> None:
    from extension.arms.nmap.policy import host_refusal

    assert host_refusal({"target": "[::1]"}) is None


def test_shared_scope_check_fails_closed_on_malformed_targets() -> None:
    """target_in_scope returns False (never raises) for urlparse-hostile
    forms — the security seam refuses by construction."""
    from extension.arms.dispatch import Scope, parse_scope, target_in_scope

    scope, _ = parse_scope("10.10.0.0/16")
    assert scope is not None
    for target in ("[10.10.0.5]", "[lab.internal]", "[10.10.0.5", "10.10.0.5]"):
        assert target_in_scope(target, scope) is False
