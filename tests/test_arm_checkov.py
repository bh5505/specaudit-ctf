"""Unit + fake-binary tests for the curated checkov arm. No live checkov."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from extension.arms.checkov import ARM_ID, CheckovArm
from extension.arms.checkov.policy import (
    ENV_BIN,
    ENV_SCAN_ROOT,
    argv_for,
    resolve_scan_root,
)
from extension.contract import ArmSpec, Extension, ExtensionError, NotInstalledError


def _spec() -> ArmSpec:
    return ArmSpec(
        id=ARM_ID,
        protocols=("cli",),
        curated=True,
        notes="Fixture curated CLI arm.",
    )


def _write_exec(tmp_path: Path, name: str, body: str) -> Path:
    """Write a runnable fake binary; .bat on Windows, shebang elsewhere."""
    if os.name == "nt":
        wrapper = tmp_path / f"{name}.bat"
        wrapper.write_text(body, encoding="utf-8")
        return wrapper
    wrapper = tmp_path / name
    wrapper.write_text(body, encoding="utf-8")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return wrapper


@pytest.fixture
def fake_bin(tmp_path: Path) -> Path:
    """A fake checkov that echoes its argv back as JSON."""
    script = tmp_path / "fake-checkov.py"
    script.write_text(
        "import json, sys\n"
        "print(json.dumps({'argv': sys.argv[1:], 'env_marker': 'offline'}))\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        return _write_exec(
            tmp_path, "checkov", f'@"{sys.executable}" "{script}" %*\n'
        )
    return _write_exec(
        tmp_path,
        "checkov",
        f"#!{sys.executable}\n"
        f"import sys; sys.argv[0] = 'checkov'; "
        f"exec(open(r'{script}').read())\n",
    )


def _arm() -> CheckovArm:
    return CheckovArm()


# --- install gate -------------------------------------------------------


def test_not_installed_without_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_BIN, raising=False)
    monkeypatch.setattr("extension.arms.checkov.arm.resolve_binary", lambda: None)
    arm = _arm()
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "scan", {})


def test_bin_env_installs(monkeypatch: pytest.MonkeyPatch, fake_bin: Path) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    assert _arm().installed(_spec()) is True


# --- policy -------------------------------------------------------------


def test_only_scan_action_allowed(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path
) -> None:
    # Install gate fires before policy; a fake binary keeps this hermetic.
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    result = _arm().invoke(_spec(), "version", {})
    assert result.ok is False
    assert "not on the allowlist" in result.error


def test_caller_args_refused(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    result = _arm().invoke(_spec(), "scan", {"--flag": "x"})
    assert result.ok is False
    assert "fixed argv" in result.error


def test_scan_root_containment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, refusal = resolve_scan_root()
    assert root is not None and refusal is None
    assert root.name == "range"

    monkeypatch.setenv(ENV_SCAN_ROOT, str(tmp_path))
    root, refusal = resolve_scan_root()
    assert root is None
    assert "packaged synthetic range" in refusal

    monkeypatch.setenv(ENV_SCAN_ROOT, "tf_s3_public_access")
    root2, refusal2 = resolve_scan_root()
    assert root2 is None
    assert refusal2 is not None


def test_argv_is_fixed(monkeypatch: pytest.MonkeyPatch, fake_bin: Path) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    monkeypatch.delenv(ENV_SCAN_ROOT, raising=False)
    root = Path("some") / "root"
    argv = argv_for(str(fake_bin), root)
    assert argv[:4] == [str(fake_bin), "scan", "-d", str(root)]
    assert argv[4:] == ["--framework", "terraform", "-o", "json", "--skip-download"]


# --- invoke -------------------------------------------------------------


def test_scan_runs_fixed_argv(
    monkeypatch: pytest.MonkeyPatch, fake_bin: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    monkeypatch.delenv(ENV_SCAN_ROOT, raising=False)
    result = _arm().invoke(_spec(), "scan", {})
    assert result.ok is True
    argv = result.output["argv"]
    assert argv[0] == "scan"
    assert argv[1] == "-d"
    assert argv[3:] == ["--framework", "terraform", "-o", "json", "--skip-download"]


def _fail_binary(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "payload.py"
    script.write_text(body, encoding="utf-8")
    if os.name == "nt":
        return _write_exec(
            tmp_path, "checkov", f'@"{sys.executable}" "{script}" %*\n'
        )
    return _write_exec(
        tmp_path, "checkov", f"#!{sys.executable}\nexec(open(r'{script}').read())\n"
    )


def test_scan_failure_redacts_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fail_binary(
        tmp_path,
        "import sys\nsys.stderr.write('token abc secret failed hard\\n')\nsys.exit(2)\n",
    )
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.delenv(ENV_SCAN_ROOT, raising=False)
    result = _arm().invoke(_spec(), "scan", {})
    assert result.ok is False
    assert "[redacted]" in result.error
    assert "token" not in result.error.lower()


def test_scan_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = _fail_binary(tmp_path, "import time\ntime.sleep(30)\n")
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.delenv(ENV_SCAN_ROOT, raising=False)
    result = CheckovArm(timeout=1.0).invoke(_spec(), "scan", {})
    assert result.ok is False
    assert "timed out" in result.error


def test_scan_outside_root_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake_bin: Path
) -> None:
    monkeypatch.setenv(ENV_BIN, str(fake_bin))
    monkeypatch.setenv(ENV_SCAN_ROOT, str(tmp_path))
    result = _arm().invoke(_spec(), "scan", {})
    assert result.ok is False
    assert "packaged synthetic range" in result.error


# --- extension wiring ---------------------------------------------------


def test_default_extension_wires_checkov(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_BIN, raising=False)
    monkeypatch.setattr("extension.arms.checkov.arm.resolve_binary", lambda: None)
    ext = Extension()
    assert "checkov" in ext.arms
    with pytest.raises(NotInstalledError):
        ext.invoke("checkov", "scan", {})


def test_curated_never_rides_generic_cli_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even a checkov binary on PATH must not reach the generic transport."""
    monkeypatch.delenv(ENV_BIN, raising=False)
    monkeypatch.setattr("extension.arms.checkov.arm.resolve_binary", lambda: None)
    ext = Extension(arms={})
    with pytest.raises(ExtensionError) as err:
        ext.invoke("checkov", "scan", {})
    assert "specialized handler" in str(err.value)
