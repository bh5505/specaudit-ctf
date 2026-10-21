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
        id=arm_id,
        protocols=("cli",),
        notes="Fixture arm.",
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


def test_stratus_detonate_uses_fixed_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "stratus")
    monkeypatch.setenv("STRATUS_BIN", str(binary))
    result = StratusArm().invoke(
        _spec(STRATUS_ID), "detonate", {"technique": "aws.exfiltration.s3"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["detonate", "aws.exfiltration.s3"]


def test_stratus_bad_technique_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "stratus")
    monkeypatch.setenv("STRATUS_BIN", str(binary))
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


def test_osmedeus_scan_uses_fixed_flow_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "osmedeus")
    monkeypatch.setenv("OSMEDEUS_BIN", str(binary))
    result = OsmedeusArm().invoke(
        _spec(OSMEDEUS_ID), "scan", {"target": "http://lab.internal/"}
    )
    assert result.ok is True
    assert result.output["argv"] == [
        "scan", "-f", "url", "-t", "http://lab.internal/"
    ]
    # v5.1.0 flag pin: a URL target selects the url flow (-f url ahead
    # of -t); the default flow requires a domain target upstream.
    # A hostname target rides the default flow (no -f).
    result = OsmedeusArm().invoke(
        _spec(OSMEDEUS_ID), "scan", {"target": "lab.internal"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["scan", "-t", "lab.internal"]
    # A second operator-supplied URL is passed to the selected flow too.
    result = OsmedeusArm().invoke(
        _spec(OSMEDEUS_ID), "scan", {"target": "http://other.example/"}
    )
    assert result.ok is True
    assert result.output["argv"] == [
        "scan", "-f", "url", "-t", "http://other.example/"
    ]


# --- zdns ----------------------------------------------------------------


def test_zdns_lookup_uses_fixed_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zdns")
    monkeypatch.setenv("ZDNS_BIN", str(binary))
    result = ZdnsArm().invoke(
        _spec(ZDNS_ID), "lookup", {"domain": "example.com"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["A", "example.com"]
    result = ZdnsArm().invoke(
        _spec(ZDNS_ID), "lookup", {"domain": "example.com", "record_type": "MX"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["MX", "example.com"]


def test_zdns_operator_record_type_and_domain_pass_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zdns")
    monkeypatch.setenv("ZDNS_BIN", str(binary))
    result = ZdnsArm().invoke(
        _spec(ZDNS_ID), "lookup", {"domain": "example.com", "record_type": "CAA"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["CAA", "example.com"]
    result = ZdnsArm().invoke(
        _spec(ZDNS_ID), "lookup", {"domain": "_sip._tcp.example.com"}
    )
    assert result.ok is True
    assert result.output["argv"] == ["A", "_sip._tcp.example.com"]
    invalid = ZdnsArm().invoke(
        _spec(ZDNS_ID), "lookup", {"domain": "example.com\nother"}
    )
    assert invalid.ok is False and "argv token" in invalid.error


# --- page-fetch ----------------------------------------------------------


def test_page_fetch_uses_stdin_delivery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "page-fetch")
    monkeypatch.setenv("PAGE_FETCH_BIN", str(binary))
    result = PageFetchArm().invoke(
        _spec(PAGE_FETCH_ID), "fetch", {"url": "http://10.10.0.1/"}
    )
    assert result.ok is True
    # Upstream reads URLs from stdin only (verified in detectify/
    # page-fetch main.go 2026-09-05): argv carries no target at all —
    # the stdin-fed delivery itself is pinned in test_stdin_hygiene.
    assert result.output["argv"] == []


def test_page_fetch_non_http_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "page-fetch")
    monkeypatch.setenv("PAGE_FETCH_BIN", str(binary))
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
                "body": req.data,
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
        arm.invoke(_spec(CALDERA_ID), "request", {"path": "/api/v2/abilities"})
    monkeypatch.setenv("CALDERA_ENDPOINT", "http://127.0.0.1:8765")
    assert CalderaArm().installed(_spec(CALDERA_ID)) is False


def test_caldera_direct_get_and_post_requests() -> None:
    urlopen = _Urlopen()
    arm = _caldera(urlopen)
    read = arm.invoke(_spec(CALDERA_ID), "request", {"path": "/api/v2/abilities"})
    created = arm.invoke(_spec(CALDERA_ID), "request", {
        "path": "/api/v2/operations", "method": "POST", "json": {"name": "op-1"},
    })
    assert read.ok and created.ok
    assert urlopen.calls[0]["method"] == "GET"
    assert urlopen.calls[0]["url"].endswith("/api/v2/abilities")
    assert urlopen.calls[0]["headers"].get("Key") == "caldera-fixture-key"
    assert urlopen.calls[1]["method"] == "POST"
    assert json.loads(urlopen.calls[1]["body"]) == {"name": "op-1"}


def test_caldera_selected_api_path_is_not_blocked() -> None:
    urlopen = _Urlopen()
    result = _caldera(urlopen).invoke(_spec(CALDERA_ID), "request", {
        "path": "/api/v2/operations/report", "method": "POST",
        "json": {"operation_id": "operator-chosen"},
    })
    assert result.ok
    assert urlopen.calls[0]["url"].endswith("/api/v2/operations/report")


def test_caldera_request_shape_keeps_api_key_on_endpoint() -> None:
    urlopen = _Urlopen()
    for path in ("https://elsewhere.invalid/", "//elsewhere.invalid/x", "/x\r\nHeader: value"):
        result = _caldera(urlopen).invoke(_spec(CALDERA_ID), "request", {"path": path})
        assert not result.ok
    assert urlopen.calls == []


def test_caldera_list_tools_describes_request() -> None:
    result = _caldera().invoke(_spec(CALDERA_ID), "list_tools", {})
    assert result.ok
    assert "request" in result.output["actions"]


# --- gti -----------------------------------------------------------------


SERVER_GTI_TOOLS = ("get_domain_report", "analyse_file", "create_collection")


def test_gti_advertised_upload_tool_runs() -> None:
    session = FakeGtiSession()
    result = _gti(session).invoke(_spec(GTI_ID), "analyse_file", {"file": "sample.bin"})
    assert result.ok is True
    assert session.calls == [("analyse_file", {"file": "sample.bin"})]


class FakeGtiSession:
    def __init__(self, tools: list[dict[str, Any]] | None = None) -> None:
        self.tools = tools or [{"name": name} for name in SERVER_GTI_TOOLS]
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
    # The factory replaces the endpoint with a fake session.
    return GtiArm(
        endpoint="https://gti-front.example.invalid:9",
        session_factory=lambda url, timeout=10.0: session,
    )


def test_gti_advertised_lookup() -> None:
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
    assert "not available on the server" in result.error


def test_gti_list_tools_reports_supported_tools() -> None:
    result = _gti(FakeGtiSession()).invoke(_spec(GTI_ID), "list_tools", {})
    assert result.ok is True
    assert {t["name"] for t in result.output["tools"]} == set(SERVER_GTI_TOOLS)


def test_gti_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GTI_MCP_ENDPOINT", raising=False)
    arm = GtiArm()
    assert arm.installed(_spec(GTI_ID)) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(GTI_ID), "get_domain_report", {})


def test_osmedeus_target_is_operator_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "osmedeus")
    monkeypatch.setenv("OSMEDEUS_BIN", str(binary))
    result = OsmedeusArm().invoke(_spec(OSMEDEUS_ID), "scan", {"target": "-h"})
    assert result.ok is True
    assert result.output["argv"] == ["scan", "-t", "-h"]


def test_zdns_domain_is_operator_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = _fake_binary(tmp_path, "zdns")
    monkeypatch.setenv("ZDNS_BIN", str(binary))
    result = ZdnsArm().invoke(_spec(ZDNS_ID), "lookup", {"domain": "-h"})
    assert result.ok is True
    assert result.output["argv"] == ["A", "-h"]
