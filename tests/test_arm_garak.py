"""Unit + fake-binary tests for the curated garak arm. No live garak."""

from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path

import pytest

from extension.arms.garak import ARM_ID, GarakArm
from extension.arms.garak.policy import (
    ENV_BIN,
    ENV_REPORT_DIR,
    ENV_TARGET,
    argv_for,
    report_dir,
)
from extension.contract import ArmSpec, Extension, NotInstalledError


def _spec() -> ArmSpec:
    return ArmSpec(
        id=ARM_ID,
        protocols=("cli",),
        curated=True,
        notes="Fixture curated CLI arm.",
        tier="research",
    )


def _fake_binary(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "payload.py"
    script.write_text(body, encoding="utf-8")
    if os.name == "nt":
        wrapper = tmp_path / "garak.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return wrapper
    wrapper = tmp_path / "garak"
    wrapper.write_text(
        f"#!{sys.executable}\nexec(open(r'{script}').read())\n", encoding="utf-8"
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return wrapper


@pytest.fixture
def fake_bin(tmp_path: Path) -> Path:
    return _fake_binary(
        tmp_path,
        "import sys\nprint('argv:', sys.argv[1:])\n",
    )


@pytest.fixture(autouse=True)
def _target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_TARGET, "local:stub")


def _arm() -> GarakArm:
    return GarakArm()


# --- install gate (binary AND target binding) ----------------------------


def test_not_installed_without_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_BIN, raising=False)
    monkeypatch.setattr("extension.arms.garak.arm.resolve_binary", lambda: None)
    arm = _arm()
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "list_probes", {})


def test_binary_without_target_not_installed(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    monkeypatch.delenv(ENV_TARGET, raising=False)
    arm = _arm()
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "list_probes", {})


def test_binary_and_target_install(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    assert _arm().installed(_spec()) is True


# --- policy --------------------------------------------------------------


def test_probe_dispatch_blocked(monkeypatch: pytest.MonkeyPatch, fake_bin: Path) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    for action in ("run", "scan", "probe", "duck"):
        result = _arm().invoke(_spec(), action, {})
        assert result.ok is False, action
        assert "probe dispatch is blocked" in result.error


def test_caller_args_refused(monkeypatch: pytest.MonkeyPatch, fake_bin: Path) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    result = _arm().invoke(_spec(), "list_probes", {"--probes": "x"})
    assert result.ok is False
    assert "fixed argv" in result.error


def test_listing_argv_fixed(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    monkeypatch.delenv(ENV_REPORT_DIR, raising=False)
    result = _arm().invoke(_spec(), "list_probes", {})
    assert result.ok is True
    assert "argv: ['--list_probes']" in result.output

    result = _arm().invoke(_spec(), "list_detectors", {})
    assert result.ok is True
    assert "argv: ['--list_detectors']" in result.output


def test_argv_for_rejects_report() -> None:
    with pytest.raises(KeyError):
        argv_for("garak", "report")


# --- report reading ------------------------------------------------------


def test_report_requires_dir_env(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    monkeypatch.delenv(ENV_REPORT_DIR, raising=False)
    result = _arm().invoke(_spec(), "report", {})
    assert result.ok is False
    assert "GARAK_REPORT_DIR is required" in result.error


def test_report_reads_newest_jsonl(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path, tmp_path: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    old = tmp_path / "garak.report.1.jsonl"
    old.write_text('{"old": true}\n', encoding="utf-8")
    time.sleep(0.05)
    new = tmp_path / "garak.report.2.jsonl"
    new.write_text('{"new": true}\n', encoding="utf-8")
    monkeypatch.setenv(ENV_REPORT_DIR, str(tmp_path))
    result = _arm().invoke(_spec(), "report", {})
    assert result.ok is True
    assert result.output["path"] == "garak.report.2.jsonl"
    assert '"new": true' in result.output["text"]


def test_report_empty_dir(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path, tmp_path: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    monkeypatch.setenv(ENV_REPORT_DIR, str(tmp_path))
    result = _arm().invoke(_spec(), "report", {})
    assert result.ok is False
    assert "no report files" in result.error


def test_report_dir_not_a_directory(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path, tmp_path: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    monkeypatch.setenv(ENV_REPORT_DIR, str(tmp_path / "missing"))
    result = _arm().invoke(_spec(), "report", {})
    assert result.ok is False
    assert "not a directory" in result.error


# --- failure paths -------------------------------------------------------


def test_listing_failure_redacts_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(
        tmp_path,
        "import sys\nsys.stderr.write('token abc secret boom\\n')\nsys.exit(3)\n",
    )
    monkeypatch.setenv(ENV_BIN, str(binary))
    result = _arm().invoke(_spec(), "list_probes", {})
    assert result.ok is False
    assert "[redacted]" in result.error
    assert "token" not in result.error.lower()


def test_listing_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = _fake_binary(tmp_path, "import time\ntime.sleep(30)\n")
    monkeypatch.setenv(ENV_BIN, str(binary))
    result = GarakArm(timeout=1.0).invoke(_spec(), "list_probes", {})
    assert result.ok is False
    assert "timed out" in result.error


# --- extension wiring ----------------------------------------------------


def test_default_extension_wires_garak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_BIN, raising=False)
    monkeypatch.setattr("extension.arms.garak.arm.resolve_binary", lambda: None)
    ext = Extension()
    assert "garak" in ext.arms
    with pytest.raises(NotInstalledError):
        ext.invoke("garak", "list_probes", {})


def test_report_dir_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_REPORT_DIR, str(tmp_path))
    path, refusal = report_dir()
    assert path == tmp_path.resolve() or path == tmp_path
    assert refusal is None
    monkeypatch.delenv(ENV_REPORT_DIR, raising=False)
    path, refusal = report_dir()
    assert path is None and refusal is not None


def test_report_dir_root_refused(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    root = Path(fake_bin.anchor)  # "/" on POSIX, "C:\" on Windows
    monkeypatch.setenv(ENV_REPORT_DIR, str(root))
    result = _arm().invoke(_spec(), "report", {})
    assert result.ok is False
    assert "filesystem root" in result.error


def test_success_listing_redacted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # chr(10) avoids newline-escape confusion between this file and the
    # generated payload script.
    binary = _fake_binary(
        tmp_path,
        "import sys\n"
        "sys.stdout.write('probe list: token abc here' + chr(10))\n",
    )
    monkeypatch.setenv(ENV_BIN, str(binary))
    result = _arm().invoke(_spec(), "list_probes", {})
    assert result.ok is True
    assert "[redacted]" in result.output
    assert "token" not in result.output.lower()
