"""Hermetic ZAP native-API request tests; no live ZAP instance."""

from __future__ import annotations

import json
from typing import Any

import pytest

from extension.arms.zap import ARM_ID, ZapArm
from extension.arms.zap.policy import ENV_API_KEY, ENV_ENDPOINT
from extension.contract import ArmSpec, NotInstalledError


def _spec() -> ArmSpec:
    return ArmSpec(id=ARM_ID, protocols=("mcp",), notes="Fixture arm")


class _Resp:
    def __init__(self, payload: bytes) -> None:
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
        self.calls.append({
            "url": req.full_url, "method": req.get_method(),
            "headers": dict(req.headers), "data": req.data,
        })
        return _Resp(json.dumps({"ok": True}).encode())


def _arm(urlopen: _Urlopen | None = None) -> ZapArm:
    return ZapArm(endpoint="http://127.0.0.1:9", urlopen=urlopen or _Urlopen())


def test_endpoint_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    arm = ZapArm()
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "request", {"path": "/JSON/core/view/version/"})


def test_view_and_scan_request_paths_reach_zap() -> None:
    urlopen = _Urlopen()
    arm = _arm(urlopen)
    view = arm.invoke(_spec(), "request", {
        "path": "/JSON/alert/view/alerts/", "params": {"start": 0, "count": 10},
    })
    scan = arm.invoke(_spec(), "request", {
        "path": "/JSON/ascan/action/scan/", "method": "POST",
        "params": {"url": "http://198.51.100.8/"},
    })
    assert view.ok and scan.ok
    assert urlopen.calls[0]["method"] == "GET"
    assert urlopen.calls[0]["url"].endswith("/JSON/alert/view/alerts/?start=0&count=10")
    assert urlopen.calls[1]["method"] == "POST"
    assert urlopen.calls[1]["data"] == b"url=http%3A%2F%2F198.51.100.8%2F"


def test_other_native_api_action_is_not_blocked() -> None:
    urlopen = _Urlopen()
    result = _arm(urlopen).invoke(_spec(), "request", {
        "path": "/JSON/core/action/shutdown/", "method": "POST", "params": {},
    })
    assert result.ok
    assert urlopen.calls[0]["url"].endswith("/JSON/core/action/shutdown/")


def test_request_path_stays_on_configured_endpoint() -> None:
    urlopen = _Urlopen()
    for path in ("https://elsewhere.invalid/", "//elsewhere.invalid/x", "/x\r\nHeader: value"):
        result = _arm(urlopen).invoke(_spec(), "request", {"path": path})
        assert not result.ok
    assert urlopen.calls == []


def test_api_key_header_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, "test-secret")
    urlopen = _Urlopen()
    result = _arm(urlopen).invoke(_spec(), "request", {"path": "/JSON/core/view/version/"})
    assert result.ok
    assert urlopen.calls[0]["headers"].get("X-zap-api-key") == "test-secret"


def test_list_tools_describes_request() -> None:
    result = _arm().invoke(_spec(), "list_tools", {})
    assert result.ok
    assert "request" in result.output["actions"]
