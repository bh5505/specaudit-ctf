"""Tests for the mitreattack, vuls, wapiti, and commix arms. All hermetic."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from extension.arms.commix import ARM_ID as COMMIX_ID
from extension.arms.commix import CommixArm
from extension.arms.mitreattack import ARM_ID as MITRE_ID
from extension.arms.mitreattack import MitreattackArm
from extension.arms.vuls import ARM_ID as VULS_ID
from extension.arms.vuls import VulsArm
from extension.arms.wapiti import ARM_ID as WAPITI_ID
from extension.arms.wapiti import WapitiArm
from extension.contract import ArmSpec, Extension, NotInstalledError


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


# --- mitreattack --------------------------------------------------------


def test_mitreattack_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MITREATTACK_BIN", raising=False)
    monkeypatch.setattr(
        "extension.arms.mitreattack.arm.resolve_binary", lambda: None
    )
    with pytest.raises(NotInstalledError):
        MitreattackArm().invoke(_spec(MITRE_ID), "to_excel", {"input": "x.json"})


def test_mitreattack_local_conversion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle = tmp_path / "enterprise.bundle.json"
    bundle.write_text('{"type": "bundle", "id": "x"}', encoding="utf-8")
    binary = _fake_binary(tmp_path, "attack-to-excel", ECHO_ARGV)
    monkeypatch.setenv("MITREATTACK_BIN", str(binary))
    result = MitreattackArm().invoke(
        _spec(MITRE_ID), "to_excel", {"input": str(bundle)}
    )
    assert result.ok is True
    argv = result.output["argv"]
    # Upstream v6.2.0 attack-to-excel (Typer): file input is the
    # from-stix --stix-file option; a bare positional is an
    # unrecognized command (verified 2026-09-05 stdin class-sweep).
    assert argv == ["from-stix", "--stix-file", str(bundle)]


def test_mitreattack_url_input_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "attack-to-excel", ECHO_ARGV)
    monkeypatch.setenv("MITREATTACK_BIN", str(binary))
    result = MitreattackArm().invoke(
        _spec(MITRE_ID),
        "to_excel",
        {"input": "https://attack.mitre.org/stix/bundle.json"},
    )
    assert result.ok is False
    assert "not a URL" in result.error


def test_mitreattack_missing_file_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "attack-to-excel", ECHO_ARGV)
    monkeypatch.setenv("MITREATTACK_BIN", str(binary))
    result = MitreattackArm().invoke(
        _spec(MITRE_ID), "to_excel", {"input": str(tmp_path / "nope.json")}
    )
    assert result.ok is False
    assert "not an existing file" in result.error


def test_mitreattack_download_action_not_exposed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "attack-to-excel", ECHO_ARGV)
    monkeypatch.setenv("MITREATTACK_BIN", str(binary))
    result = MitreattackArm().invoke(_spec(MITRE_ID), "download_attack_stix", {})
    assert result.ok is False
    assert result.error is not None


# --- vuls ---------------------------------------------------------------


def test_vuls_report_summary_fixed_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "vuls", ECHO_ARGV)
    monkeypatch.setenv("VULS_BIN", str(binary))
    result = VulsArm().invoke(_spec(VULS_ID), "report", {})
    assert result.ok is True
    assert result.output["argv"] == ["report"]
    result = VulsArm().invoke(_spec(VULS_ID), "summary", {})
    assert result.ok is True
    assert result.output["argv"] == ["summary"]


def test_vuls_read_args_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "vuls", ECHO_ARGV)
    monkeypatch.setenv("VULS_BIN", str(binary))
    result = VulsArm().invoke(
        _spec(VULS_ID), "report", {"--refresh-cve": True}
    )
    assert result.ok is False
    assert "no caller arguments" in result.error


def test_vuls_fetch_runs_selected_upstream_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "vuls", ECHO_ARGV)
    monkeypatch.setenv("VULS_BIN", str(binary))
    result = VulsArm().invoke(_spec(VULS_ID), "fetch", {})
    assert result.ok is True
    assert result.output["argv"] == ["fetch"]


def test_vuls_scan_uses_fixed_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "vuls", ECHO_ARGV)
    monkeypatch.setenv("VULS_BIN", str(binary))
    result = VulsArm().invoke(_spec(VULS_ID), "scan", {})
    assert result.ok is True
    assert result.output["argv"] == ["scan"]


# --- wapiti / commix -----------------------------------------------------


@pytest.mark.parametrize(
    "arm_cls,arm_id,bin_name,bin_env",
    [
        (WapitiArm, WAPITI_ID, "wapiti", "WAPITI_BIN"),
        (CommixArm, COMMIX_ID, "commix", "COMMIX_BIN"),
    ],
)
class TestScanArms:
    def test_scan_runs_with_valid_url(
        self,
        arm_cls: type,
        arm_id: str,
        bin_name: str,
        bin_env: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        binary = _fake_binary(tmp_path, bin_name, ECHO_ARGV)
        monkeypatch.setenv(bin_env, str(binary))
        result = arm_cls().invoke(
            _spec(arm_id), "scan", {"url": "http://10.10.0.1/"}
        )
        assert result.ok is True
        assert "http://10.10.0.1/" in result.output["output"]["argv"]

    def test_scan_passes_target_in_fixed_argv(
        self,
        arm_cls: type,
        arm_id: str,
        bin_name: str,
        bin_env: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        binary = _fake_binary(tmp_path, bin_name, ECHO_ARGV)
        monkeypatch.setenv(bin_env, str(binary))
        result = arm_cls().invoke(
            _spec(arm_id), "scan", {"url": "http://10.10.0.1/app.php?id=1"}
        )
        assert result.ok is True
        argv = result.output["output"]["argv"]
        assert "http://10.10.0.1/app.php?id=1" in argv

    def test_invalid_target_refused(
        self,
        arm_cls: type,
        arm_id: str,
        bin_name: str,
        bin_env: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        binary = _fake_binary(tmp_path, bin_name, ECHO_ARGV)
        monkeypatch.setenv(bin_env, str(binary))
        result = arm_cls().invoke(
            _spec(arm_id), "scan", {"url": "file:///etc/passwd"}
        )
        assert result.ok is False
        assert "http(s) URL" in result.error

    def test_non_scan_action_refused(
        self,
        arm_cls: type,
        arm_id: str,
        bin_name: str,
        bin_env: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        binary = _fake_binary(tmp_path, bin_name, ECHO_ARGV)
        monkeypatch.setenv(bin_env, str(binary))
        result = arm_cls().invoke(_spec(arm_id), "list_modules", {})
        assert result.ok is False
        assert "not on the allowlist" in result.error

    def test_extra_args_refused(
        self,
        arm_cls: type,
        arm_id: str,
        bin_name: str,
        bin_env: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        binary = _fake_binary(tmp_path, bin_name, ECHO_ARGV)
        monkeypatch.setenv(bin_env, str(binary))
        result = arm_cls().invoke(
            _spec(arm_id),
            "scan",
            {"url": "http://10.10.0.1/", "--proxy": "x"},
        )
        assert result.ok is False
        assert "only args.url" in result.error


# --- wiring -------------------------------------------------------------


def test_commix_argv_disables_stdin_target_parsing() -> None:
    # commix >= 4 parses TARGETS from stdin when stdin is not a tty and
    # then ignores -u; a subprocess-captured scan would exit 0 having
    # scanned nothing. --ignore-stdin (hidden upstream option, verified
    # against commix 4.1-0kali1 source 2026-09-04) restores argv-only
    # targeting. Pinned after the lab measurement caught the silent
    # no-scan exit.
    from extension.arms.commix.policy import argv_for

    assert argv_for("/usr/bin/commix", "http://10.10.0.1/f") == [
        "/usr/bin/commix",
        "--batch",
        "--ignore-stdin",
        "-u",
        "http://10.10.0.1/f",
    ]


def test_default_extension_wires_new_arms(monkeypatch: pytest.MonkeyPatch) -> None:
    for env in (
        "MITREATTACK_BIN",
        "VULS_BIN",
        "WAPITI_BIN",
        "COMMIX_BIN",
        "ZAP_API_ENDPOINT",
    ):
        monkeypatch.delenv(env, raising=False)
    for mod in ("mitreattack", "vuls", "wapiti", "commix"):
        monkeypatch.setattr(
            f"extension.arms.{mod}.arm.resolve_binary", lambda: None
        )
    ext = Extension()
    for arm_id in (MITRE_ID, VULS_ID, WAPITI_ID, COMMIX_ID, "zaproxy"):
        assert arm_id in ext.arms
        with pytest.raises(NotInstalledError):
            ext.invoke(arm_id, "anything", {})
