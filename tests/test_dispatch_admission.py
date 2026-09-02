"""Dispatch-class invoke admission: the 2026-09-01 scope-gated profiles.

Admission is the manifest/metadata event; the arms' own scope gates
remain the enforcement point. All hermetic (fake binary, fake endpoint).
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.invoke_profiles import INVOKE_PROFILES, invoke_profile


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


def test_dispatch_profiles_are_admitted_with_honest_truth() -> None:
    expected = {
        "nmap.scan",
        "zaproxy.ascan_scan",
        "zaproxy.spider_scan",
    }
    admitted = {
        capability_id
        for capability_id, profile in INVOKE_PROFILES.items()
        if profile.action != "list_tools"
    }
    assert admitted == expected
    profile = invoke_profile("nmap", "scan")
    assert profile.safety_class == "R1"
    assert profile.side_effects == ("subprocess", "network-egress")
    assert profile.default_off is True and profile.synthetic_only is False
    assert profile.approval_ref == "operator://dispatch-scope/NMAP_DISPATCH_SCOPE"
    assert profile.roe_ref == "doc://README#dispatch-doctrine"


def test_nmap_scan_unarmed_is_an_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NMAP_BIN", str(_fake_binary(tmp_path, "print('x')\n")))
    monkeypatch.delenv("NMAP_DISPATCH_SCOPE", raising=False)
    outcome = dispatch_invoke(
        Extension(), arm_id="nmap", action="scan", args={"target": "10.10.0.5"}
    )
    assert outcome.contract_error is None  # admitted; not a -32602 case
    assert outcome.exit_code == 1
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["capability_id"] == "nmap.scan"
    assert outcome.envelope["safety_class"] == "R1"
    assert "NMAP_DISPATCH_SCOPE" in (outcome.stderr_line or "")
    assert "nmap.scan" in (outcome.stderr_line or "")


def test_nmap_scan_armed_completes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    monkeypatch.setenv("NMAP_BIN", str(_fake_binary(tmp_path, body)))
    monkeypatch.setenv("NMAP_DISPATCH_SCOPE", "10.10.0.0/16")
    outcome = dispatch_invoke(
        Extension(),
        arm_id="nmap",
        action="scan",
        args={"target": "10.10.0.5", "ports": [22]},
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert outcome.envelope["capability_id"] == "nmap.scan"


def test_zap_scan_admitted_but_requires_endpoint_and_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ZAP_API_ENDPOINT", raising=False)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="zaproxy",
        action="ascan_scan",
        args={"url": "http://10.10.0.5/"},
    )
    # Admitted profile: the refusal is the arm's own gate (not installed),
    # carried as a typed failure — never the pre-admission refusal.
    assert outcome.exit_code == 2
    assert outcome.envelope is not None
    assert outcome.envelope["limitations"] == ["arm is not installed"]


def test_unadmitted_dispatch_actions_still_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ZGRAB2_BIN", str(_fake_binary(tmp_path, "print('x')\n")))
    outcome = dispatch_invoke(
        Extension(), arm_id="zgrab2", action="scan", args={"target": "10.10.0.5"}
    )
    assert outcome.exit_code == 2
    assert outcome.envelope is not None
    assert "unknown capability" in " ".join(outcome.envelope["limitations"]).lower()
