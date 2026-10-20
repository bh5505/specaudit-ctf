"""Hermetic tests for Nmap command assembly and subprocess results."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from extension.arms.nmap import ARM_ID, NmapArm
from extension.arms.nmap.policy import MODES, argv_for, host_refusal
from extension.contract import ArmSpec, NotInstalledError


def _spec() -> ArmSpec:
    return ArmSpec(id=ARM_ID, protocols=("cli",), notes="Fixture arm")


def _fake_binary(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "nmap-payload.py"
    script.write_text(body, encoding="utf-8")
    if os.name == "nt":
        wrapper = tmp_path / "nmap.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return wrapper
    wrapper = tmp_path / "nmap"
    wrapper.write_text(f"#!{sys.executable}\nexec(open(r'{script}').read())\n", encoding="utf-8")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return wrapper


ECHO_ARGV = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
FAIL_BODY = "import sys\nsys.stderr.write('Failed to resolve')\nsys.exit(2)\n"


@pytest.fixture
def binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = _fake_binary(tmp_path, ECHO_ARGV)
    monkeypatch.setenv("NMAP_BIN", str(path))
    return path


def _argv(result) -> list[str]:
    assert result.ok, result.error
    return json.loads(result.output["output"])["argv"]


def test_not_installed_without_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NMAP_BIN", raising=False)
    monkeypatch.setattr("extension.arms.nmap.arm.resolve_binary", lambda: None)
    arm = NmapArm()
    assert not arm.installed(_spec())
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "scan", {"target": "example.com"})


def test_installed_follows_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("extension.arms.nmap.arm.resolve_binary", lambda: "X:/nmap")
    assert NmapArm().installed(_spec())


def test_list_tools_shape_and_arguments(binary: Path) -> None:
    result = NmapArm().invoke(_spec(), "list_tools", {})
    assert result.ok
    assert result.output["actions"] == ["list_tools", "scan", "tools/list"]
    assert result.output["modes"] == sorted(MODES)
    assert "NPSL" in result.output["caveats"]
    assert "no arguments" in NmapArm().invoke(_spec(), "list_tools", {"x": 1}).error


@pytest.mark.parametrize("target", ["192.0.2.9", "10.0.0.0/24", "10.10.0.1-20", "scanme.nmap.org", "lab.internal"])
def test_operator_target_expression_is_passed_to_nmap(binary: Path, target: str) -> None:
    result = NmapArm().invoke(_spec(), "scan", {"target": target})
    assert result.ok
    assert _argv(result)[-1] == target


@pytest.mark.parametrize("target", ["-Pn", "a b", "a\x00b", "a\nb"])
def test_target_must_be_one_nonflag_argument(binary: Path, target: str) -> None:
    result = NmapArm().invoke(_spec(), "scan", {"target": target})
    assert not result.ok
    assert "target" in result.error


def test_scan_mode_ports_and_extra_keys(binary: Path) -> None:
    arm = NmapArm()
    assert "mode" in arm.invoke(_spec(), "scan", {"target": "example.com", "mode": "bad"}).error
    assert "outside 1..65535" in arm.invoke(_spec(), "scan", {"target": "example.com", "ports": [0]}).error
    assert "list of integers" in arm.invoke(_spec(), "scan", {"target": "example.com", "ports": ["22"]}).error
    assert "args.options" in arm.invoke(_spec(), "scan", {"target": "example.com", "unknown": True}).error


def test_operator_options_reach_nmap_as_argv(binary: Path) -> None:
    result = NmapArm().invoke(_spec(), "scan", {
        "target": "198.51.100.10", "options": ["-sS", "-O", "--script", "default", "-T5"],
    })
    assert _argv(result) == ["-sS", "-O", "--script", "default", "-T5", "-oX", "-", "198.51.100.10"]


def test_options_require_separate_argv_tokens(binary: Path) -> None:
    arm = NmapArm()
    assert "list of argv strings" in arm.invoke(_spec(), "scan", {"target": "example.com", "options": "-sS"}).error
    assert "NUL" in arm.invoke(_spec(), "scan", {"target": "example.com", "options": ["-sS\x00x"]}).error


def test_scan_version_argv(binary: Path) -> None:
    result = NmapArm().invoke(_spec(), "scan", {"target": "10.10.0.5", "mode": "version", "ports": [22, 80]})
    assert _argv(result) == ["-sT", "-sV", "-T4", "-oX", "-", "-p", "22,80", "10.10.0.5"]


def test_scan_default_top_ports_argv(binary: Path) -> None:
    result = NmapArm().invoke(_spec(), "scan", {"target": "lab.internal"})
    assert _argv(result) == ["-sT", "-T4", "-oX", "-", "--top-ports", "100", "lab.internal"]


def test_version_light_argv(binary: Path) -> None:
    result = NmapArm().invoke(_spec(), "scan", {"target": "10.10.0.5", "mode": "version-light", "ports": [443]})
    assert _argv(result) == ["-sT", "-sV", "--version-light", "-Pn", "-n", "--unprivileged", "-T4", "-oX", "-", "-p", "443", "10.10.0.5"]


@pytest.mark.parametrize("target", ["2001:db8::10", "[2001:db8::10]"])
def test_ipv6_target_argv(binary: Path, target: str) -> None:
    result = NmapArm().invoke(_spec(), "scan", {"target": target, "ports": [443]})
    assert _argv(result) == ["-6", "-sT", "-T4", "-oX", "-", "-p", "443", "2001:db8::10"]


def test_nonzero_exit_is_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NMAP_BIN", str(_fake_binary(tmp_path, FAIL_BODY)))
    result = NmapArm().invoke(_spec(), "scan", {"target": "example.com"})
    assert not result.ok and "Failed to resolve" in result.error


def test_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NMAP_BIN", str(_fake_binary(tmp_path, "import time\ntime.sleep(30)\n")))
    result = NmapArm(timeout=0.2).invoke(_spec(), "scan", {"target": "example.com"})
    assert not result.ok and "timed out" in result.error


def test_xml_output_stays_text(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    body = 'print("<?xml version=\\"1.0\\"?><nmaprun></nmaprun>")\n'
    monkeypatch.setenv("NMAP_BIN", str(_fake_binary(tmp_path, body)))
    result = NmapArm().invoke(_spec(), "scan", {"target": "example.com"})
    assert result.ok and "<nmaprun>" in result.output["output"]


def test_argv_for_keeps_target_separate() -> None:
    assert argv_for("nmap", "10.0.0.1", "connect", None) == ["nmap", "-sT", "-T4", "-oX", "-", "--top-ports", "100", "10.0.0.1"]
    assert argv_for("nmap", "10.0.0.1", None, [443])[-3:] == ["-p", "443", "10.0.0.1"]
    assert host_refusal({"target": "[::1]"}) is None
