"""Dispatch-class invoke admission: scope-gated profiles (2026-09-01 wave
plus the 2026-09-02/03 continuations).

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


def _fake_binary(tmp_path: Path, body: str, stem: str = "nmap") -> Path:
    script = tmp_path / f"{stem}-payload.py"
    script.write_text(body, encoding="utf-8")
    if os.name == "nt":
        wrapper = tmp_path / f"{stem}.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return wrapper
    wrapper = tmp_path / stem
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
        "zgrab2.scan",
        "wapiti.scan",
        "zdns.lookup",
        "pyrit.scan",
        "routersploit.run",
        "osmedeus.scan",
        "page-fetch.fetch",
        "commix.scan",
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
    # 2026-09-02 continuation waves: same honest truth, timeouts mirroring
    # each arm's policy TIMEOUT_SECONDS.
    for capability_id, scope_env, timeout_ms in (
        ("zgrab2.scan", "ZGRAB2_DISPATCH_SCOPE", 60_000),
        ("wapiti.scan", "WAPITI_DISPATCH_SCOPE", 600_000),
        ("zdns.lookup", "ZDNS_DISPATCH_SCOPE", 60_000),
        ("pyrit.scan", "PYRIT_DISPATCH_SCOPE", 600_000),
        ("routersploit.run", "ROUTERSPLOIT_DISPATCH_SCOPE", 120_000),
        ("osmedeus.scan", "OSMEDEUS_DISPATCH_SCOPE", 600_000),
        ("page-fetch.fetch", "PAGE_FETCH_DISPATCH_SCOPE", 60_000),
        ("commix.scan", "COMMIX_DISPATCH_SCOPE", 600_000),
    ):
        wave = INVOKE_PROFILES[capability_id]
        assert wave.safety_class == "R1"
        assert wave.side_effects == ("subprocess", "network-egress")
        assert wave.default_off is True and wave.synthetic_only is False
        assert wave.tier == "research"
        assert wave.timeout_ms == timeout_ms
        assert wave.approval_ref == f"operator://dispatch-scope/{scope_env}"
        assert wave.roe_ref == "doc://README#dispatch-doctrine"


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


def test_zgrab2_scan_unarmed_is_an_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        "ZGRAB2_BIN", str(_fake_binary(tmp_path, "print('x')\n", stem="zgrab2"))
    )
    monkeypatch.delenv("ZGRAB2_DISPATCH_SCOPE", raising=False)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="zgrab2",
        action="scan",
        args={"target": "10.10.0.5", "module": "http"},
    )
    assert outcome.contract_error is None
    assert outcome.exit_code == 1
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["capability_id"] == "zgrab2.scan"
    assert "ZGRAB2_DISPATCH_SCOPE" in (outcome.stderr_line or "")
    assert "zgrab2.scan" in (outcome.stderr_line or "")


def test_zgrab2_scan_armed_completes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    monkeypatch.setenv("ZGRAB2_BIN", str(_fake_binary(tmp_path, body, stem="zgrab2")))
    monkeypatch.setenv("ZGRAB2_DISPATCH_SCOPE", "10.10.0.0/16")
    outcome = dispatch_invoke(
        Extension(),
        arm_id="zgrab2",
        action="scan",
        args={"target": "10.10.0.5", "module": "http", "port": 8080},
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert outcome.envelope["capability_id"] == "zgrab2.scan"


def test_wapiti_scan_unarmed_is_an_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        "WAPITI_BIN", str(_fake_binary(tmp_path, "print('x')\n", stem="wapiti"))
    )
    monkeypatch.delenv("WAPITI_DISPATCH_SCOPE", raising=False)
    outcome = dispatch_invoke(
        Extension(), arm_id="wapiti", action="scan", args={"url": "http://10.10.0.5/"}
    )
    assert outcome.contract_error is None
    assert outcome.exit_code == 1
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["capability_id"] == "wapiti.scan"
    assert "WAPITI_DISPATCH_SCOPE" in (outcome.stderr_line or "")
    assert "wapiti.scan" in (outcome.stderr_line or "")


def test_wapiti_scan_armed_completes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    monkeypatch.setenv("WAPITI_BIN", str(_fake_binary(tmp_path, body, stem="wapiti")))
    monkeypatch.setenv("WAPITI_DISPATCH_SCOPE", "10.10.0.0/16")
    outcome = dispatch_invoke(
        Extension(), arm_id="wapiti", action="scan", args={"url": "http://10.10.0.5/"}
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert outcome.envelope["capability_id"] == "wapiti.scan"


def test_zdns_lookup_unarmed_is_an_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        "ZDNS_BIN", str(_fake_binary(tmp_path, "print('x')\n", stem="zdns"))
    )
    monkeypatch.delenv("ZDNS_DISPATCH_SCOPE", raising=False)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="zdns",
        action="lookup",
        args={"domain": "lab.example.com", "record_type": "A"},
    )
    assert outcome.contract_error is None
    assert outcome.exit_code == 1
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["capability_id"] == "zdns.lookup"
    assert "ZDNS_DISPATCH_SCOPE" in (outcome.stderr_line or "")
    assert "zdns.lookup" in (outcome.stderr_line or "")


def test_zdns_lookup_armed_completes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    monkeypatch.setenv("ZDNS_BIN", str(_fake_binary(tmp_path, body, stem="zdns")))
    monkeypatch.setenv("ZDNS_DISPATCH_SCOPE", "lab.example.com")
    outcome = dispatch_invoke(
        Extension(),
        arm_id="zdns",
        action="lookup",
        args={"domain": "lab.example.com", "record_type": "A"},
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert outcome.envelope["capability_id"] == "zdns.lookup"


def test_pyrit_scan_unarmed_is_an_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        "PYRIT_BIN", str(_fake_binary(tmp_path, "print('x')\n", stem="pyrit"))
    )
    monkeypatch.delenv("PYRIT_DISPATCH_SCOPE", raising=False)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="pyrit",
        action="scan",
        args={"scenario": "airt.cyber", "target": "lab.example.com"},
    )
    assert outcome.contract_error is None
    assert outcome.exit_code == 1
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["capability_id"] == "pyrit.scan"
    assert "PYRIT_DISPATCH_SCOPE" in (outcome.stderr_line or "")
    assert "pyrit.scan" in (outcome.stderr_line or "")


def test_pyrit_scan_armed_completes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    monkeypatch.setenv("PYRIT_BIN", str(_fake_binary(tmp_path, body, stem="pyrit")))
    monkeypatch.setenv("PYRIT_DISPATCH_SCOPE", "lab.example.com")
    outcome = dispatch_invoke(
        Extension(),
        arm_id="pyrit",
        action="scan",
        args={"scenario": "airt.cyber", "target": "lab.example.com"},
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert outcome.envelope["capability_id"] == "pyrit.scan"


def test_routersploit_run_unarmed_is_an_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        "ROUTERSPLOIT_BIN",
        str(_fake_binary(tmp_path, "print('x')\n", stem="routersploit")),
    )
    monkeypatch.delenv("ROUTERSPLOIT_DISPATCH_SCOPE", raising=False)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="routersploit",
        action="run",
        args={
            "module": "scanners/routers/http_basic_brute",
            "target": "10.10.0.5",
        },
    )
    assert outcome.contract_error is None
    assert outcome.exit_code == 1
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["capability_id"] == "routersploit.run"
    assert "ROUTERSPLOIT_DISPATCH_SCOPE" in (outcome.stderr_line or "")
    assert "routersploit.run" in (outcome.stderr_line or "")


def test_routersploit_run_armed_completes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    monkeypatch.setenv(
        "ROUTERSPLOIT_BIN", str(_fake_binary(tmp_path, body, stem="routersploit"))
    )
    monkeypatch.setenv("ROUTERSPLOIT_DISPATCH_SCOPE", "10.10.0.0/16")
    outcome = dispatch_invoke(
        Extension(),
        arm_id="routersploit",
        action="run",
        args={
            "module": "scanners/routers/http_basic_brute",
            "target": "10.10.0.5",
        },
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert outcome.envelope["capability_id"] == "routersploit.run"


def test_osmedeus_scan_unarmed_is_an_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        "OSMEDEUS_BIN", str(_fake_binary(tmp_path, "print('x')\n", stem="osmedeus"))
    )
    monkeypatch.delenv("OSMEDEUS_DISPATCH_SCOPE", raising=False)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="osmedeus",
        action="scan",
        args={"target": "lab.example.com"},
    )
    assert outcome.contract_error is None
    assert outcome.exit_code == 1
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["capability_id"] == "osmedeus.scan"
    assert "OSMEDEUS_DISPATCH_SCOPE" in (outcome.stderr_line or "")
    assert "osmedeus.scan" in (outcome.stderr_line or "")


def test_osmedeus_scan_armed_completes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    monkeypatch.setenv(
        "OSMEDEUS_BIN", str(_fake_binary(tmp_path, body, stem="osmedeus"))
    )
    monkeypatch.setenv("OSMEDEUS_DISPATCH_SCOPE", "lab.example.com")
    outcome = dispatch_invoke(
        Extension(),
        arm_id="osmedeus",
        action="scan",
        args={"target": "lab.example.com"},
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert outcome.envelope["capability_id"] == "osmedeus.scan"


def test_page_fetch_unarmed_is_an_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        "PAGE_FETCH_BIN",
        str(_fake_binary(tmp_path, "print('x')\n", stem="page-fetch")),
    )
    monkeypatch.delenv("PAGE_FETCH_DISPATCH_SCOPE", raising=False)
    outcome = dispatch_invoke(
        Extension(),
        arm_id="page-fetch",
        action="fetch",
        args={"url": "http://10.10.0.5/"},
    )
    assert outcome.contract_error is None
    assert outcome.exit_code == 1
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["capability_id"] == "page-fetch.fetch"
    assert "PAGE_FETCH_DISPATCH_SCOPE" in (outcome.stderr_line or "")
    assert "page-fetch.fetch" in (outcome.stderr_line or "")


def test_page_fetch_armed_completes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    monkeypatch.setenv(
        "PAGE_FETCH_BIN", str(_fake_binary(tmp_path, body, stem="page-fetch"))
    )
    monkeypatch.setenv("PAGE_FETCH_DISPATCH_SCOPE", "10.10.0.0/16")
    outcome = dispatch_invoke(
        Extension(),
        arm_id="page-fetch",
        action="fetch",
        args={"url": "http://10.10.0.5/"},
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert outcome.envelope["capability_id"] == "page-fetch.fetch"


def test_commix_scan_unarmed_is_an_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        "COMMIX_BIN", str(_fake_binary(tmp_path, "print('x')\n", stem="commix"))
    )
    monkeypatch.delenv("COMMIX_DISPATCH_SCOPE", raising=False)
    outcome = dispatch_invoke(
        Extension(), arm_id="commix", action="scan", args={"url": "http://10.10.0.5/"}
    )
    assert outcome.contract_error is None
    assert outcome.exit_code == 1
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["capability_id"] == "commix.scan"
    assert "COMMIX_DISPATCH_SCOPE" in (outcome.stderr_line or "")
    assert "commix.scan" in (outcome.stderr_line or "")


def test_commix_scan_armed_completes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
    monkeypatch.setenv(
        "COMMIX_BIN", str(_fake_binary(tmp_path, body, stem="commix"))
    )
    monkeypatch.setenv("COMMIX_DISPATCH_SCOPE", "10.10.0.0/16")
    outcome = dispatch_invoke(
        Extension(), arm_id="commix", action="scan", args={"url": "http://10.10.0.5/"}
    )
    assert outcome.exit_code == 0
    assert outcome.envelope is not None
    assert outcome.envelope["status"] == "complete"
    assert outcome.envelope["capability_id"] == "commix.scan"


def test_dispatch_timeouts_mirror_arm_policy() -> None:
    # Admission metadata must not drift from arm reality: each dispatch
    # profile's timeout mirrors its arm's policy timeout (zaproxy uses
    # SCAN_TIMEOUT for its scan-class API calls).
    from extension.arms.nmap.policy import TIMEOUT_SECONDS as NMAP_T
    from extension.arms.wapiti.policy import TIMEOUT_SECONDS as WAPITI_T
    from extension.arms.zap.policy import SCAN_TIMEOUT as ZAP_SCAN_T
    from extension.arms.zdns.policy import TIMEOUT_SECONDS as ZDNS_T
    from extension.arms.zgrab2.policy import TIMEOUT_SECONDS as ZGRAB2_T
    from extension.arms.pyrit.policy import TIMEOUT_SECONDS as PYRIT_T
    from extension.arms.routersploit.policy import TIMEOUT_SECONDS as RSF_T
    from extension.arms.osmedeus.policy import TIMEOUT_SECONDS as OSM_T
    from extension.arms.pagefetch.policy import TIMEOUT_SECONDS as PF_T
    from extension.arms.commix.policy import TIMEOUT_SECONDS as COMMIX_T

    expected_ms = {
        "nmap.scan": NMAP_T,
        "zaproxy.ascan_scan": ZAP_SCAN_T,
        "zaproxy.spider_scan": ZAP_SCAN_T,
        "zgrab2.scan": ZGRAB2_T,
        "wapiti.scan": WAPITI_T,
        "zdns.lookup": ZDNS_T,
        "pyrit.scan": PYRIT_T,
        "routersploit.run": RSF_T,
        "osmedeus.scan": OSM_T,
        "page-fetch.fetch": PF_T,
        "commix.scan": COMMIX_T,
    }
    for capability_id, seconds in expected_ms.items():
        profile = INVOKE_PROFILES[capability_id]
        assert profile.timeout_ms == int(seconds * 1000), capability_id


def test_unadmitted_dispatch_actions_still_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # sniper.scan is the standing DELIBERATELY-unadmitted example (the
    # doc-20 deferral: composite unbounded sub-tool egress, root-only
    # binary, phones home when armed).
    monkeypatch.setenv(
        "SNIPER_BIN", str(_fake_binary(tmp_path, "print('x')\n", stem="sniper"))
    )
    outcome = dispatch_invoke(
        Extension(), arm_id="sniper", action="scan", args={"target": "10.10.0.5"}
    )
    assert outcome.exit_code == 2
    assert outcome.envelope is not None
    assert "unknown capability" in " ".join(outcome.envelope["limitations"]).lower()
