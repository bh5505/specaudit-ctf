"""Tests for stratus, osmedeus, zdns, page-fetch, caldera, and gti arms."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from extension.arms.caldera import ARM_ID as CALDERA_ID
from extension.arms.caldera import CalderaArm
from extension.arms.gti import ALLOWED_TOOLS as GTI_TOOLS
from extension.arms.gti import ARM_ID as GTI_ID
from extension.arms.gti import GtiArm
from extension.arms.osmedeus import ARM_ID as OSMEDEUS_ID
from extension.arms.osmedeus import OsmedeusArm
from extension.arms.pagefetch import ARM_ID as PAGE_FETCH_ID
from extension.arms.pagefetch import PageFetchArm
from extension.arms.stratus import ARM_ID as STRATUS_ID
from extension.arms.stratus import StratusArm
from extension.arms.zdns import ARM_ID as ZDNS_ID
from extension.arms.zdns import ZdnsArm
from extension.contract import ArmSpec, NotInstalledError


def _spec(arm_id: str) -> ArmSpec:
    return ArmSpec(
        id=arm_id, protocols=("cli",), curated=True, notes="Fixture arm."
    )


def _fake_binary(tmp_path: Path, name: str) -> Path:
    script = tmp_path / f"{name}-payload.py"
    script.write_text(
        "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n",
        encoding="utf-8",
    )
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


# --- stratus -------------------------------------------------------------


def test_stratus_list_is_local_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "stratus")
    monkeypatch.setenv("STRATUS_BIN", str(binary))
    result = StratusArm().invoke(_spec(STRATUS_ID), "list", {})
    assert result.ok is True
    assert result.output["argv"] == ["list"]


def test_stratus_dispatch_default_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "stratus")
    monkeypatch.setenv("STRATUS_BIN", str(binary))
    monkeypatch.delenv("STRATUS_DISPATCH_SCOPE", raising=False)
    result = StratusArm().invoke(
        _spec(STRATUS_ID), "detonate", {"technique": "aws.exfiltration.s3"}
    )
    assert result.ok is False
    assert "STRATUS_DISPATCH_SCOPE" in result.error


def test_stratus_dispatch_armed_runs_and_logs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = _fake_binary(tmp_path, "stratus")
    monkeypatch.setenv("STRATUS_BIN", str(binary))
    monkeypatch.setenv("STRATUS_DISPATCH_SCOPE", "aws-account-lab")
    result = StratusArm().invoke(
        _spec(STRATUS_ID), "detonate", {"technique": "aws.exfiltration.s3"}
    )
    assert result.ok is True
    assert "aws.exfiltration.s3" in result.output["output"]["argv"]
    err = capsys.readouterr().err
    assert "arm=stratus-red-team" in err
    assert "target=aws.exfiltration.s3" in err


def test_stratus_bad_technique_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "stratus")
    monkeypatch.setenv("STRATUS_BIN", str(binary))
    monkeypatch.setenv("STRATUS_DISPATCH_SCOPE", "lab")
    result = StratusArm().invoke(
        _spec(STRATUS_ID), "detonate", {"technique": "x; rm -rf /"}
    )
    assert result.ok is False
    assert "technique id must match" in result.error


# --- osmedeus ------------------------------------------------------------


def test_osmedeus_assets_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "osmedeus")
    monkeypatch.setenv("OSMEDEUS_BIN", str(binary))
    result = OsmedeusArm().invoke(_spec(OSMEDEUS_ID), "assets", {})
    assert result.ok is True
    assert result.output["argv"] == ["assets"]


def test_osmedeus_scan_dispatch_gated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "osmedeus")
    monkeypatch.setenv("OSMEDEUS_BIN", str(binary))
    monkeypatch.delenv("OSMEDEUS_DISPATCH_SCOPE", raising=False)
    result = OsmedeusArm().invoke(
        _spec(OSMEDEUS_ID), "scan", {"target": "http://lab.internal/"}
    )
    assert result.ok is False
    assert "OSMEDEUS_DISPATCH_SCOPE" in result.error
    monkeypatch.setenv("OSMEDEUS_DISPATCH_SCOPE", "lab.internal")
    result = OsmedeusArm().invoke(
        _spec(OSMEDEUS_ID), "scan", {"target": "http://lab.internal/"}
    )
    assert result.ok is True
    assert "http://lab.internal/" in result.output["output"]["argv"]
    # Out-of-scope target refused.
    result = OsmedeusArm().invoke(
        _spec(OSMEDEUS_ID), "scan", {"target": "http://other.example/"}
    )
    assert result.ok is False
    assert "outside the armed dispatch scope" in result.error


# --- zdns ----------------------------------------------------------------


def test_zdns_lookup_dispatch_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zdns")
    monkeypatch.setenv("ZDNS_BIN", str(binary))
    monkeypatch.delenv("ZDNS_DISPATCH_SCOPE", raising=False)
    result = ZdnsArm().invoke(
        _spec(ZDNS_ID), "lookup", {"domain": "example.com"}
    )
    assert result.ok is False
    assert "ZDNS_DISPATCH_SCOPE" in result.error
    monkeypatch.setenv("ZDNS_DISPATCH_SCOPE", "example.com")
    result = ZdnsArm().invoke(
        _spec(ZDNS_ID), "lookup", {"domain": "example.com", "record_type": "MX"}
    )
    assert result.ok is True
    assert result.output["output"]["argv"] == ["MX", "example.com"]


def test_zdns_record_type_validated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zdns")
    monkeypatch.setenv("ZDNS_BIN", str(binary))
    monkeypatch.setenv("ZDNS_DISPATCH_SCOPE", "example.com")
    result = ZdnsArm().invoke(
        _spec(ZDNS_ID), "lookup", {"domain": "example.com", "record_type": "X"}
    )
    assert result.ok is False
    assert "record_type" in result.error
    result = ZdnsArm().invoke(
        _spec(ZDNS_ID), "lookup", {"domain": "example.com/junk"}
    )
    assert result.ok is False
    assert "invalid characters" in result.error


# --- page-fetch ----------------------------------------------------------


def test_page_fetch_dispatch_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "page-fetch")
    monkeypatch.setenv("PAGE_FETCH_BIN", str(binary))
    monkeypatch.delenv("PAGE_FETCH_DISPATCH_SCOPE", raising=False)
    result = PageFetchArm().invoke(
        _spec(PAGE_FETCH_ID), "fetch", {"url": "http://10.10.0.1/"}
    )
    assert result.ok is False
    assert "PAGE_FETCH_DISPATCH_SCOPE" in result.error
    monkeypatch.setenv("PAGE_FETCH_DISPATCH_SCOPE", "10.10.0.0/16")
    result = PageFetchArm().invoke(
        _spec(PAGE_FETCH_ID), "fetch", {"url": "http://10.10.0.1/"}
    )
    assert result.ok is True
    assert "http://10.10.0.1/" in result.output["output"]["argv"]


def test_page_fetch_non_http_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "page-fetch")
    monkeypatch.setenv("PAGE_FETCH_BIN", str(binary))
    monkeypatch.setenv("PAGE_FETCH_DISPATCH_SCOPE", "*")  # blanket refused later
    result = PageFetchArm().invoke(
        _spec(PAGE_FETCH_ID), "fetch", {"url": "file:///etc/passwd"}
    )
    assert result.ok is False
    assert "http(s)" in result.error


# --- caldera -------------------------------------------------------------


@pytest.fixture(autouse=True)
def _caldera_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CALDERA_API_KEY", "caldera-fixture-key")


class _Resp:
    def __init__(self, payload: bytes = b'{"ok": true}') -> None:
        self._payload = payload

    def read(self, _n: int = -1) -> bytes:
        return self._payload

    def __enter__(self) -> "_Resp":
        return self

    def __exit__(self, *args: Any) -> None:
        return None


class _Urlopen:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, req: Any, timeout: float | None = None) -> _Resp:
        self.calls.append(
            {
                "url": req.full_url,
                "method": req.get_method(),
                "headers": dict(req.headers),
            }
        )
        return _Resp()


def _caldera(urlopen: _Urlopen | None = None) -> CalderaArm:
    return CalderaArm(
        endpoint="http://127.0.0.1:8765", urlopen=urlopen or _Urlopen()
    )


def test_caldera_needs_endpoint_and_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CALDERA_ENDPOINT", raising=False)
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    arm = CalderaArm()
    assert arm.installed(_spec(CALDERA_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(CALDERA_ID), "abilities", {})
    monkeypatch.setenv("CALDERA_ENDPOINT", "http://127.0.0.1:8765")
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    assert CalderaArm().installed(_spec(CALDERA_ID)) is False


def test_caldera_read_views(monkeypatch: pytest.MonkeyPatch) -> None:
    urlopen = _Urlopen()
    result = _caldera(urlopen).invoke(_spec(CALDERA_ID), "abilities", {})
    assert result.ok is True
    call = urlopen.calls[0]
    assert call["method"] == "GET"
    assert call["url"].endswith("/api/abilities")
    assert call["headers"].get("Api-key")


def test_caldera_read_args_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _caldera().invoke(
        _spec(CALDERA_ID), "abilities", {"x": 1}
    )
    assert result.ok is False
    assert "no arguments" in result.error


def test_caldera_schedule_dispatch(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("CALDERA_DISPATCH_SCOPE", raising=False)
    urlopen = _Urlopen()
    result = _caldera(urlopen).invoke(
        _spec(CALDERA_ID), "schedule_operation", {"operation": "op-1"}
    )
    assert result.ok is False
    assert "CALDERA_DISPATCH_SCOPE" in result.error
    assert urlopen.calls == []

    monkeypatch.setenv("CALDERA_DISPATCH_SCOPE", "lab-agents")
    result = _caldera(urlopen).invoke(
        _spec(CALDERA_ID), "schedule_operation", {"operation": "op 1"}
    )
    assert result.ok is True
    call = urlopen.calls[0]
    assert call["method"] == "POST"
    assert "/api/operations/op%201/schedule" in call["url"]
    err = capsys.readouterr().err
    assert "arm=caldera" in err and "target=unknown" in err


def test_caldera_bad_operation_name_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CALDERA_DISPATCH_SCOPE", "lab")
    result = _caldera().invoke(
        _spec(CALDERA_ID), "schedule_operation", {"operation": "op/../../x"}
    )
    assert result.ok is False
    assert "operation id must match" in result.error


# --- gti -----------------------------------------------------------------


class FakeGtiSession:
    def __init__(self, tools: list[dict[str, Any]] | None = None) -> None:
        self.tools = tools or [{"name": name} for name in GTI_TOOLS]
        self.calls: list[tuple[str, dict]] = []

    def connect(self) -> None:
        return None

    def list_tools(self) -> list[dict[str, Any]]:
        return list(self.tools)

    def call_tool(
        self, name: str, arguments: dict | None = None
    ) -> dict[str, Any]:
        self.calls.append((name, dict(arguments or {})))
        return {"content": [{"type": "text", "text": json.dumps({"ok": name})}]}

    def close(self) -> None:
        return None


def _gti(session: FakeGtiSession) -> GtiArm:
    return GtiArm(
        endpoint="http://127.0.0.1:9",
        session_factory=lambda url, timeout=10.0: session,
    )


def test_gti_allowlisted_lookup() -> None:
    session = FakeGtiSession()
    result = _gti(session).invoke(
        _spec(GTI_ID), "get_domain_report", {"domain": "example.com"}
    )
    assert result.ok is True
    assert session.calls == [("get_domain_report", {"domain": "example.com"})]


def test_gti_unknown_tool_refused() -> None:
    session = FakeGtiSession()
    result = _gti(session).invoke(_spec(GTI_ID), "launch_attack", {})
    assert result.ok is False
    assert "not on the allowlist" in result.error


def test_gti_list_tools_reports_no_dispatch_tier() -> None:
    result = _gti(FakeGtiSession()).invoke(_spec(GTI_ID), "list_tools", {})
    assert result.ok is True
    assert result.output["dispatch_tier"] == "none"
    assert {t["name"] for t in result.output["tools"]} == set(GTI_TOOLS)


def test_gti_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GTI_MCP_ENDPOINT", raising=False)
    arm = GtiArm()
    assert arm.installed(_spec(GTI_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(GTI_ID), "get_domain_report", {})


def test_osmedeus_flag_shaped_target_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "osmedeus")
    monkeypatch.setenv("OSMEDEUS_BIN", str(binary))
    monkeypatch.setenv("OSMEDEUS_DISPATCH_SCOPE", "lab")
    result = OsmedeusArm().invoke(_spec(OSMEDEUS_ID), "scan", {"target": "-h"})
    assert result.ok is False
    assert "flag-shaped" in result.error


def test_zdns_flag_shaped_domain_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zdns")
    monkeypatch.setenv("ZDNS_BIN", str(binary))
    monkeypatch.setenv("ZDNS_DISPATCH_SCOPE", "example.com")
    result = ZdnsArm().invoke(_spec(ZDNS_ID), "lookup", {"domain": "-h"})
    assert result.ok is False
    assert "flag-shaped" in result.error
