"""Host + arm availability report: read-only, Kali-aware, hermetic."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from extension.availability import armed_scopes, build_report, host_profile
from extension.contract import Extension
from extension.__main__ import main as cli_main


def test_kali_detection_uses_the_canonical_os_release(tmp_path: Path) -> None:
    release = tmp_path / "os-release"
    release.write_text(
        'PRETTY_NAME="Kali GNU/Linux Rolling"\n'
        'NAME="Kali GNU/Linux"\n'
        "ID=kali\n"
        'ID_LIKE=debian\n'
        "VERSION_ID=2026.3\n"
        "# comment\n",
        encoding="utf-8",
    )
    profile = host_profile(str(release))
    assert profile["is_kali"] is True
    assert profile["os_id"] == "kali"
    assert profile["os_version_id"] == "2026.3"
    assert profile["os_pretty_name"] == "Kali GNU/Linux Rolling"


def test_non_kali_linux_and_fallback_profiles(tmp_path: Path) -> None:
    debian = tmp_path / "os-release"
    debian.write_text("ID=debian\nVERSION_ID=12\n", encoding="utf-8")
    assert host_profile(str(debian))["is_kali"] is False
    missing = tmp_path / "absent"
    profile = host_profile(str(missing))
    assert profile["is_kali"] is False
    assert "os_id" not in profile


def test_armed_scopes_lists_only_set_scope_envs() -> None:
    env = {
        "NMAP_DISPATCH_SCOPE": "10.10.0.0/16",
        "ZAP_DISPATCH_SCOPE": "   ",
        "NMAP_BIN": "x",
    }
    assert armed_scopes(env) == ["NMAP_DISPATCH_SCOPE"]
    assert armed_scopes({}) == []


def test_build_report_shape_and_install_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "nmap-tool"
    fake.write_text("x", encoding="utf-8")
    monkeypatch.setenv("NMAP_BIN", str(fake))
    monkeypatch.delenv("NMAP_DISPATCH_SCOPE", raising=False)
    release = tmp_path / "os-release"
    release.write_text("ID=kali\n", encoding="utf-8")
    report = build_report(
        Extension(), environ=dict(os.environ), os_release_paths=(str(release),)
    )
    assert report["host"]["is_kali"] is True
    assert report["armed_scopes"] == []
    by_id = {row["id"]: row for row in report["arms"]}
    assert len(by_id) == 27
    assert by_id["nmap"] == {
        "id": "nmap",
        "tier": "research",
        "held": False,
        "installed": True,
    }
    assert by_id["burp-mcp"]["held"] is True
    assert by_id["agent-wiz"]["tier"] == "maintained"


def test_availability_is_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """The report never invokes arms: a poisoned handler proves it."""
    ext = Extension()
    for handler in ext.arms.values():
        monkeypatch.setattr(
            handler, "invoke", lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("availability invoked an arm")
            )
        )
    rows = ext.availability()
    assert len(rows) == 27  # the report completed without dispatching


def test_cli_availability_subcommand(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = cli_main(["availability"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {"host", "armed_scopes", "arms"}
    assert any(row["id"] == "nmap" for row in payload["arms"])
