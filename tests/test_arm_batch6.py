"""Tests for deepsec, vvah, ai-deep-sast, and agent-wiz arms. All hermetic."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from extension.arms.aideepsast import ARM_ID as AI_DEEP_SAST_ID
from extension.arms.aideepsast import AiDeepSastArm
from extension.arms.agentwiz import ARM_ID as AGENT_WIZ_ID
from extension.arms.agentwiz import AgentWizArm
from extension.arms.deepsec import ARM_ID as DEEPSEC_ID
from extension.arms.deepsec import DeepsecArm
from extension.arms.deepsec.policy import WORKSPACE_CONFIG_FAMILY
from extension.arms.vvah import ARM_ID as VVAH_ID
from extension.arms.vvah import VvahArm
from extension.contract import ArmSpec, NotInstalledError

REPO_ROOT = Path(__file__).resolve().parents[1]

ECHO_ARGV_AND_CWD = (
    "import json, os, sys\n"
    "print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd()}))\n"
)
SLEEP_BODY = "import time\ntime.sleep(30)\n"


def _spec(arm_id: str) -> ArmSpec:
    return ArmSpec(
        id=arm_id, protocols=("cli",), curated=True, notes="Fixture arm."
    )


def _fake_binary(tmp_path: Path, name: str, body: str = ECHO_ARGV_AND_CWD) -> Path:
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


def _cwd_echoed(result) -> Path:
    payload = result.output["output"] if isinstance(result.output, dict) and "dispatch" in result.output else result.output
    return Path(payload["cwd"]).resolve()


def _argv(result) -> list:
    payload = result.output["output"] if isinstance(result.output, dict) and "dispatch" in result.output else result.output
    return payload["argv"]


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    workspace = repo / ".deepsec"
    workspace.mkdir(parents=True)
    (workspace / "deepsec.config.ts").write_text(
        "export default {}\n", encoding="utf-8"
    )
    return repo, workspace


def _scan_tree(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "scanroot"
    repo = root / "target"
    repo.mkdir(parents=True)
    return root, repo


def _local_semgrep(root: Path) -> Path:
    rules = root / "local-rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    return rules


# --- deepsec -------------------------------------------------------------


def test_deepsec_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEC_BIN", raising=False)
    monkeypatch.setattr("extension.arms.deepsec.arm.resolve_binary", lambda: None)
    arm = DeepsecArm()
    assert arm.installed(_spec(DEEPSEC_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(DEEPSEC_ID), "scan", {})


@pytest.mark.parametrize(
    "name",
    ["npx", "pnpm", "npm", "yarn", "npx.cmd", "pnpm.exe", "npx.bat", "npx.ps1"],
)
def test_deepsec_package_manager_bin_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    launcher = tmp_path / name
    launcher.write_text("echo\n", encoding="utf-8")
    monkeypatch.setenv("DEEPSEC_BIN", str(launcher))
    arm = DeepsecArm()
    assert arm.installed(_spec(DEEPSEC_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(DEEPSEC_ID), "list_tools", {})


def test_deepsec_unset_scan_root_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.delenv("DEEPSEC_SCAN_ROOT", raising=False)
    result = DeepsecArm().invoke(_spec(DEEPSEC_ID), "scan", {})
    assert result.ok is False
    assert "DEEPSEC_SCAN_ROOT" in result.error


def test_deepsec_missing_config_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    empty = tmp_path / "emptyws"
    empty.mkdir()
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_SCAN_ROOT", str(empty))
    result = DeepsecArm().invoke(_spec(DEEPSEC_ID), "scan", {})
    assert result.ok is False
    assert "deepsec.config.ts" in result.error


def test_deepsec_mjs_workspace_accepted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    workspace = tmp_path / "repo" / ".deepsec"
    workspace.mkdir(parents=True)
    (workspace / "deepsec.config.mjs").write_text(
        "export default {}\n", encoding="utf-8"
    )
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_SCAN_ROOT", str(workspace))
    result = DeepsecArm().invoke(_spec(DEEPSEC_ID), "scan", {})
    assert result.ok is True
    assert _argv(result) == ["scan"]


def test_deepsec_filesystem_root_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_SCAN_ROOT", str(Path(tmp_path.anchor)))
    result = DeepsecArm().invoke(_spec(DEEPSEC_ID), "scan", {})
    assert result.ok is False
    assert "filesystem root" in result.error


@pytest.mark.parametrize("action", ["init", "sandbox", "revalidate"])
def test_deepsec_blocked_actions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, action: str
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    result = DeepsecArm().invoke(_spec(DEEPSEC_ID), action, {})
    assert result.ok is False
    assert "blocked" in result.error


def test_deepsec_extra_args_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    _, workspace = _workspace(tmp_path)
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_SCAN_ROOT", str(workspace))
    result = DeepsecArm().invoke(
        _spec(DEEPSEC_ID), "scan", {"matchers": "xss", "--agent": "codex"}
    )
    assert result.ok is False
    assert "fixed argv" in result.error


def test_deepsec_list_tools_caveats_and_blanket_unarmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_DISPATCH_SCOPE", "*")
    result = DeepsecArm().invoke(_spec(DEEPSEC_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
    caveats = result.output["caveats"]
    assert "init out of band" in caveats
    assert "workspace" in caveats
    assert "thousands of dollars" in caveats
    assert "matcher state" in caveats
    assert result.output["workspace_config"] == WORKSPACE_CONFIG_FAMILY
    assert ".mjs" in result.output["workspace_config"]
    listed = DeepsecArm().invoke(_spec(DEEPSEC_ID), "tools/list", {"extra": 1})
    assert listed.ok is False


def test_deepsec_scan_argv_cwd_no_positional(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    _, workspace = _workspace(tmp_path)
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_SCAN_ROOT", str(workspace))
    result = DeepsecArm().invoke(_spec(DEEPSEC_ID), "scan", {})
    assert result.ok is True
    assert _argv(result) == ["scan"]
    assert _cwd_echoed(result) == workspace.resolve()
    assert not (REPO_ROOT / "run_manifest.json").exists()


def test_deepsec_root_parent_accepted_outside_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    repo, workspace = _workspace(tmp_path)
    outside = tmp_path / "other"
    outside.mkdir()
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_SCAN_ROOT", str(workspace))
    ok = DeepsecArm().invoke(_spec(DEEPSEC_ID), "scan", {"root": str(repo)})
    assert ok.ok is True
    argv = _argv(ok)
    assert argv[0] == "scan"
    assert "--root" in argv
    assert str(repo.resolve()) in argv
    bad = DeepsecArm().invoke(_spec(DEEPSEC_ID), "scan", {"root": str(outside)})
    assert bad.ok is False
    assert "workspace parent" in bad.error
    flag = DeepsecArm().invoke(_spec(DEEPSEC_ID), "scan", {"root": "-evil"})
    assert flag.ok is False
    assert "non-flag path" in flag.error
    nul = DeepsecArm().invoke(
        _spec(DEEPSEC_ID), "scan", {"root": str(repo) + "\x00evil"}
    )
    assert nul.ok is False
    assert "control characters" in nul.error
    monkeypatch.setenv("DEEPSEC_DISPATCH_SCOPE", "localhost")
    stamped = DeepsecArm().invoke(
        _spec(DEEPSEC_ID), "process", {"root": str(repo)}
    )
    assert stamped.ok is True
    assert stamped.output["dispatch"]["target"] == f"repo:{repo.resolve()}"


def test_deepsec_process_unarmed_names_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    _, workspace = _workspace(tmp_path)
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_SCAN_ROOT", str(workspace))
    monkeypatch.delenv("DEEPSEC_DISPATCH_SCOPE", raising=False)
    result = DeepsecArm().invoke(_spec(DEEPSEC_ID), "process", {})
    assert result.ok is False
    assert "DEEPSEC_DISPATCH_SCOPE" in result.error
    assert "Caveat:" in result.error


def test_deepsec_process_armed_logs_repo(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    _, workspace = _workspace(tmp_path)
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_SCAN_ROOT", str(workspace))
    monkeypatch.setenv("DEEPSEC_DISPATCH_SCOPE", "localhost")
    result = DeepsecArm().invoke(
        _spec(DEEPSEC_ID), "process", {"project_id": "my-app"}
    )
    assert result.ok is True
    assert _argv(result) == ["process", "--project-id", "my-app"]
    assert result.output["dispatch"]["target"] == f"repo:{workspace}"
    err = capsys.readouterr().err
    assert "[dispatch]" in err
    assert "arm=deepsec" in err
    assert "target=repo:" in err
    assert _cwd_echoed(result) == workspace.resolve()


def test_deepsec_scan_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec", SLEEP_BODY)
    _, workspace = _workspace(tmp_path)
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_SCAN_ROOT", str(workspace))
    arm = DeepsecArm(timeout=1.0)
    assert arm._timeout_for("scan") == 1.0
    assert arm._timeout_for("process") == 600.0
    result = arm.invoke(_spec(DEEPSEC_ID), "scan", {})
    assert result.ok is False
    assert "timed out" in result.error


def test_deepsec_list_tools_armed_localhost(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "deepsec")
    monkeypatch.setenv("DEEPSEC_BIN", str(binary))
    monkeypatch.setenv("DEEPSEC_DISPATCH_SCOPE", "localhost")
    result = DeepsecArm().invoke(_spec(DEEPSEC_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is True


# --- vvah ----------------------------------------------------------------


def test_vvah_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VVAH_BIN", raising=False)
    monkeypatch.setattr("extension.arms.vvah.arm.resolve_binary", lambda: None)
    arm = VvahArm()
    assert arm.installed(_spec(VVAH_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(VVAH_ID), "doctor", {})


def test_vvah_doctor_and_estimate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "vvaharness")
    root, repo = _scan_tree(tmp_path)
    monkeypatch.setenv("VVAH_BIN", str(binary))
    monkeypatch.setenv("VVAH_SCAN_ROOT", str(root))
    doctor = VvahArm().invoke(_spec(VVAH_ID), "doctor", {})
    assert doctor.ok is True
    assert _argv(doctor) == ["doctor"]
    assert _cwd_echoed(doctor) == root.resolve()
    estimate = VvahArm().invoke(_spec(VVAH_ID), "estimate", {"repo": str(repo)})
    assert estimate.ok is True
    argv = _argv(estimate)
    assert argv[0] == "estimate"
    assert "--repo" in argv
    assert str(repo.resolve()) in argv
    assert _cwd_echoed(estimate) == root.resolve()
    assert not (REPO_ROOT / "run_manifest.json").exists()


def test_vvah_scan_unarmed_and_stop_after(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "vvaharness")
    root, repo = _scan_tree(tmp_path)
    monkeypatch.setenv("VVAH_BIN", str(binary))
    monkeypatch.setenv("VVAH_SCAN_ROOT", str(root))
    monkeypatch.delenv("VVAH_DISPATCH_SCOPE", raising=False)
    unarmed = VvahArm().invoke(_spec(VVAH_ID), "scan", {"repo": str(repo)})
    assert unarmed.ok is False
    assert "VVAH_DISPATCH_SCOPE" in unarmed.error
    assert "Caveat:" in unarmed.error
    monkeypatch.setenv("VVAH_DISPATCH_SCOPE", "localhost")
    armed = VvahArm().invoke(_spec(VVAH_ID), "scan", {"repo": str(repo)})
    assert armed.ok is True
    argv = _argv(armed)
    assert "scan" in argv
    assert "--stop-after" in argv
    assert "s9" in argv
    assert "--repo" in argv
    assert _cwd_echoed(armed) == root.resolve()
    err = capsys.readouterr().err
    assert "[dispatch]" in err and "arm=vvah" in err and "target=repo:" in err
    assert armed.output["dispatch"]["target"].startswith("repo:")
    assert not (REPO_ROOT / "run_manifest.json").exists()


def test_vvah_remediate_dual_gate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "vvaharness")
    root, repo = _scan_tree(tmp_path)
    monkeypatch.setenv("VVAH_BIN", str(binary))
    monkeypatch.setenv("VVAH_SCAN_ROOT", str(root))
    monkeypatch.setenv("VVAH_DISPATCH_SCOPE", "localhost")
    monkeypatch.delenv("VVAH_ALLOW_REMEDIATE", raising=False)
    denied = VvahArm().invoke(_spec(VVAH_ID), "remediate", {"repo": str(repo)})
    assert denied.ok is False
    assert "VVAH_ALLOW_REMEDIATE" in denied.error
    monkeypatch.setenv("VVAH_ALLOW_REMEDIATE", "true")
    still = VvahArm().invoke(_spec(VVAH_ID), "remediate", {"repo": str(repo)})
    assert still.ok is False
    monkeypatch.setenv("VVAH_ALLOW_REMEDIATE", "1")
    ok = VvahArm().invoke(_spec(VVAH_ID), "remediate", {"repo": str(repo)})
    assert ok.ok is True
    argv = _argv(ok)
    assert argv[0] == "remediate"
    assert "scan" not in argv
    assert "s9" not in argv
    assert "--repo" in argv
    err = capsys.readouterr().err
    assert "arm=vvah" in err and "target=repo:" in err


def test_vvah_validate_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "vvaharness")
    monkeypatch.setenv("VVAH_BIN", str(binary))
    result = VvahArm().invoke(_spec(VVAH_ID), "validate", {})
    assert result.ok is False
    assert "not on any tier" in result.error


def test_vvah_stop_after_extra_arg_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "vvaharness")
    root, repo = _scan_tree(tmp_path)
    monkeypatch.setenv("VVAH_BIN", str(binary))
    monkeypatch.setenv("VVAH_SCAN_ROOT", str(root))
    monkeypatch.setenv("VVAH_DISPATCH_SCOPE", "localhost")
    result = VvahArm().invoke(
        _spec(VVAH_ID), "scan", {"repo": str(repo), "stop_after": "s11"}
    )
    assert result.ok is False
    assert "fixed argv" in result.error
    flag = VvahArm().invoke(_spec(VVAH_ID), "scan", {"repo": "-evil"})
    assert flag.ok is False
    assert "flag-shaped" in flag.error
    nul = VvahArm().invoke(
        _spec(VVAH_ID), "scan", {"repo": str(repo) + "\x00evil"}
    )
    assert nul.ok is False
    assert "control characters" in nul.error


def test_vvah_list_tools_blanket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "vvaharness")
    monkeypatch.setenv("VVAH_BIN", str(binary))
    monkeypatch.setenv("VVAH_DISPATCH_SCOPE", "*")
    result = VvahArm().invoke(_spec(VVAH_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
    assert "s9" in result.output["caveats"]
    assert "remediate" in result.output["caveats"]
    assert "live-probes" in result.output["caveats"]
    assert "estimate spends nothing" in result.output["caveats"]


def test_vvah_path_outside_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "vvaharness")
    root, _ = _scan_tree(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    monkeypatch.setenv("VVAH_BIN", str(binary))
    monkeypatch.setenv("VVAH_SCAN_ROOT", str(root))
    result = VvahArm().invoke(_spec(VVAH_ID), "estimate", {"repo": str(outside)})
    assert result.ok is False
    assert "must stay inside" in result.error


# --- ai-deep-sast --------------------------------------------------------


def test_aideepsast_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AI_DEEP_SAST_BIN", raising=False)
    monkeypatch.setattr(
        "extension.arms.aideepsast.arm.resolve_binary", lambda: None
    )
    arm = AiDeepSastArm()
    assert arm.installed(_spec(AI_DEEP_SAST_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(AI_DEEP_SAST_ID), "scan", {"target": "."})


def test_aideepsast_scan_skip_llm_ai_scan_does_not(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "aideepsast")
    root, repo = _scan_tree(tmp_path)
    rules = _local_semgrep(root)
    monkeypatch.setenv("AI_DEEP_SAST_BIN", str(binary))
    monkeypatch.setenv("AI_DEEP_SAST_SCAN_ROOT", str(root))
    monkeypatch.setenv("AI_DEEP_SAST_SEMGREP_CONFIG", str(rules))
    scan = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID), "scan", {"target": str(repo)}
    )
    assert scan.ok is True
    assert "--skip-llm" in _argv(scan)
    assert "--target" in _argv(scan)
    assert "--semgrep-config" in _argv(scan)
    assert str(rules.resolve()) in _argv(scan)
    assert _cwd_echoed(scan) == root.resolve()
    monkeypatch.delenv("AI_DEEP_SAST_DISPATCH_SCOPE", raising=False)
    unarmed = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID), "ai_scan", {"target": str(repo)}
    )
    assert unarmed.ok is False
    assert "AI_DEEP_SAST_DISPATCH_SCOPE" in unarmed.error
    assert "Caveat:" in unarmed.error
    monkeypatch.setenv("AI_DEEP_SAST_DISPATCH_SCOPE", "localhost")
    ai = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID), "ai_scan", {"target": str(repo)}
    )
    assert ai.ok is True
    assert "--skip-llm" not in _argv(ai)
    assert "--target" in _argv(ai)
    assert "--semgrep-config" in _argv(ai)
    err = capsys.readouterr().err
    assert "arm=ai-deep-sast" in err and "target=repo:" in err


def test_aideepsast_dry_run_missing_bin_is_result_not_install_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "aideepsast")
    root, repo = _scan_tree(tmp_path)
    monkeypatch.setenv("AI_DEEP_SAST_BIN", str(binary))
    monkeypatch.setenv("AI_DEEP_SAST_SCAN_ROOT", str(root))
    monkeypatch.delenv("AI_DEEP_SAST_DEEPSCAN_BIN", raising=False)
    monkeypatch.setattr(
        "extension.arms.aideepsast.arm.resolve_deepscan_binary", lambda: None
    )
    result = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID), "dry_run", {"target": str(repo)}
    )
    assert result.ok is False
    assert "deepscan binary not configured" in result.error
    deepscan = _fake_binary(tmp_path, "deepscan")
    monkeypatch.setattr(
        "extension.arms.aideepsast.arm.resolve_deepscan_binary",
        lambda: str(deepscan),
    )
    ok = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID), "dry_run", {"target": str(repo)}
    )
    assert ok.ok is True
    assert "--dry-run" in _argv(ok)
    assert "--target" in _argv(ok)
    assert _cwd_echoed(ok) == root.resolve()


def test_aideepsast_skip_llm_on_ai_scan_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "aideepsast")
    root, repo = _scan_tree(tmp_path)
    monkeypatch.setenv("AI_DEEP_SAST_BIN", str(binary))
    monkeypatch.setenv("AI_DEEP_SAST_SCAN_ROOT", str(root))
    monkeypatch.setenv("AI_DEEP_SAST_DISPATCH_SCOPE", "localhost")
    monkeypatch.setenv("AI_DEEP_SAST_SEMGREP_CONFIG", str(_local_semgrep(root)))
    result = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID),
        "ai_scan",
        {"target": str(repo), "skip_llm": True},
    )
    assert result.ok is False
    assert "fixed argv" in result.error
    flag = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID), "scan", {"target": "-evil"}
    )
    assert flag.ok is False
    assert "flag-shaped" in flag.error


def test_aideepsast_list_tools_blanket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "aideepsast")
    monkeypatch.setenv("AI_DEEP_SAST_BIN", str(binary))
    monkeypatch.setenv("AI_DEEP_SAST_DISPATCH_SCOPE", "*")
    result = AiDeepSastArm().invoke(_spec(AI_DEEP_SAST_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
    assert "--skip-llm" in result.output["caveats"]
    assert "Foundation-Sec" in result.output["caveats"]
    assert result.output["semgrep_config"] == "AI_DEEP_SAST_SEMGREP_CONFIG"


def test_aideepsast_scan_requires_local_semgrep_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "aideepsast")
    root, repo = _scan_tree(tmp_path)
    monkeypatch.setenv("AI_DEEP_SAST_BIN", str(binary))
    monkeypatch.setenv("AI_DEEP_SAST_SCAN_ROOT", str(root))
    monkeypatch.delenv("AI_DEEP_SAST_SEMGREP_CONFIG", raising=False)
    missing = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID), "scan", {"target": str(repo)}
    )
    assert missing.ok is False
    assert "AI_DEEP_SAST_SEMGREP_CONFIG" in missing.error
    monkeypatch.setenv("AI_DEEP_SAST_SEMGREP_CONFIG", "p/owasp-top-ten")
    registry = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID), "scan", {"target": str(repo)}
    )
    assert registry.ok is False
    assert "registry" in registry.error
    nul = AiDeepSastArm().invoke(
        _spec(AI_DEEP_SAST_ID),
        "scan",
        {"target": str(repo) + "\x00evil"},
    )
    assert nul.ok is False
    assert "control characters" in nul.error


# --- agent-wiz -----------------------------------------------------------


def test_agentwiz_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_WIZ_BIN", raising=False)
    monkeypatch.setattr(
        "extension.arms.agentwiz.arm.resolve_binary", lambda: None
    )
    arm = AgentWizArm()
    assert arm.installed(_spec(AGENT_WIZ_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(AGENT_WIZ_ID), "extract", {})


def test_agentwiz_frameworks_argparse_verbatim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "agent-wiz")
    root = tmp_path / "scanroot"
    src = root / "src"
    src.mkdir(parents=True)
    out = root / "graph.json"
    monkeypatch.setenv("AGENT_WIZ_BIN", str(binary))
    monkeypatch.setenv("AGENT_WIZ_SCAN_ROOT", str(root))
    for bad in ("llamaindex", "pydantic_ai"):
        result = AgentWizArm().invoke(
            _spec(AGENT_WIZ_ID),
            "extract",
            {"framework": bad, "directory": str(src), "output": str(out)},
        )
        assert result.ok is False
        assert "argparse choices" in result.error
    for good in ("llama_index", "pydantic"):
        result = AgentWizArm().invoke(
            _spec(AGENT_WIZ_ID),
            "extract",
            {"framework": good, "directory": str(src), "output": str(out)},
        )
        assert result.ok is True
        argv = _argv(result)
        assert argv[0] == "extract"
        assert good in argv
        assert "--framework" in argv
        assert "--directory" in argv
        assert "--output" in argv
        assert _cwd_echoed(result) == root.resolve()
    assert not any(REPO_ROOT.glob("*_vis"))
    assert not any(REPO_ROOT.glob("*_report.md"))


def test_agentwiz_visualize_and_analyze(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "agent-wiz")
    root = tmp_path / "scanroot"
    root.mkdir()
    graph = root / "graph.json"
    graph.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("AGENT_WIZ_BIN", str(binary))
    monkeypatch.setenv("AGENT_WIZ_SCAN_ROOT", str(root))
    vis = AgentWizArm().invoke(
        _spec(AGENT_WIZ_ID), "visualize", {"input": str(graph)}
    )
    assert vis.ok is True
    assert _argv(vis)[0] == "visualize"
    assert "--input" in _argv(vis)
    assert "--open" not in _argv(vis)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AGENT_WIZ_DISPATCH_SCOPE", "localhost")
    missing = AgentWizArm().invoke(
        _spec(AGENT_WIZ_ID), "analyze", {"input": str(graph)}
    )
    assert missing.ok is False
    assert missing.error == "OpenAI credential env is unset"
    assert "[redacted]" not in missing.error
    assert "OPENAI_API_KEY" not in missing.error
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-used")
    monkeypatch.delenv("AGENT_WIZ_DISPATCH_SCOPE", raising=False)
    unarmed = AgentWizArm().invoke(
        _spec(AGENT_WIZ_ID), "analyze", {"input": str(graph)}
    )
    assert unarmed.ok is False
    assert "AGENT_WIZ_DISPATCH_SCOPE" in unarmed.error
    assert "Caveat:" in unarmed.error
    monkeypatch.setenv("AGENT_WIZ_DISPATCH_SCOPE", "localhost")
    ok = AgentWizArm().invoke(
        _spec(AGENT_WIZ_ID), "analyze", {"input": str(graph)}
    )
    assert ok.ok is True
    argv = _argv(ok)
    assert argv[0] == "analyze"
    assert "--input" in argv
    assert _cwd_echoed(ok) == root.resolve()
    err = capsys.readouterr().err
    assert "arm=agent-wiz" in err and "graph:" in err
    assert ok.output["dispatch"]["target"].startswith("graph:")
    assert not any(REPO_ROOT.glob("*_vis"))
    assert not any(REPO_ROOT.glob("*_report.md"))


def test_agentwiz_extract_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "agent-wiz", SLEEP_BODY)
    root = tmp_path / "scanroot"
    src = root / "src"
    src.mkdir(parents=True)
    out = root / "graph.json"
    monkeypatch.setenv("AGENT_WIZ_BIN", str(binary))
    monkeypatch.setenv("AGENT_WIZ_SCAN_ROOT", str(root))
    arm = AgentWizArm(timeout=1.0)
    assert arm._timeout_for("extract") == 1.0
    assert arm._timeout_for("visualize") == 1.0
    assert arm._timeout_for("analyze") == 300.0
    result = arm.invoke(
        _spec(AGENT_WIZ_ID),
        "extract",
        {"framework": "langgraph", "directory": str(src), "output": str(out)},
    )
    assert result.ok is False
    assert "timed out" in result.error


def test_agentwiz_list_tools_blanket_and_frameworks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "agent-wiz")
    monkeypatch.setenv("AGENT_WIZ_BIN", str(binary))
    monkeypatch.setenv("AGENT_WIZ_DISPATCH_SCOPE", "*")
    result = AgentWizArm().invoke(_spec(AGENT_WIZ_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_armed"] is False
    assert "llama_index" in result.output["frameworks"]
    assert "pydantic" in result.output["frameworks"]
    assert "llamaindex" not in result.output["frameworks"]
    assert "pydantic_ai" not in result.output["frameworks"]
    assert "OpenAI" in result.output["caveats"]


def test_agentwiz_extra_args_and_flag_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "agent-wiz")
    root = tmp_path / "scanroot"
    root.mkdir()
    graph = root / "graph.json"
    graph.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("AGENT_WIZ_BIN", str(binary))
    monkeypatch.setenv("AGENT_WIZ_SCAN_ROOT", str(root))
    result = AgentWizArm().invoke(
        _spec(AGENT_WIZ_ID), "visualize", {"input": str(graph), "open": True}
    )
    assert result.ok is False
    assert "fixed argv" in result.error
    flag = AgentWizArm().invoke(
        _spec(AGENT_WIZ_ID), "visualize", {"input": "-x"}
    )
    assert flag.ok is False
    assert "flag-shaped" in flag.error
    nul = AgentWizArm().invoke(
        _spec(AGENT_WIZ_ID), "visualize", {"input": str(graph) + "\x00"}
    )
    assert nul.ok is False
    assert "control characters" in nul.error
