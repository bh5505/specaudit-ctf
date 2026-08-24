"""Unit + stub tests for the curated zaproxy arm. No live ZAP."""

from __future__ import annotations

import json
from typing import Any

import pytest

from extension.arms.zap import ALLOWED_VIEWS, ARM_ID, DISPATCH_ACTIONS, ZapArm
from extension.arms.zap.policy import ENV_API_KEY, ENV_DISPATCH_SCOPE, ENV_ENDPOINT
from extension.contract import ArmSpec, NotInstalledError


def _spec() -> ArmSpec:
    return ArmSpec(
        id=ARM_ID,
        protocols=("cli", "mcp", "http"),
        curated=True,
        notes="Fixture curated arm.",
    )


class _Resp:
    def __init__(self, payload: bytes, status: int = 200) -> None:
        self._payload = payload
        self.status = status

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
                "data": req.data,
            }
        )
        return _Resp(json.dumps({"ok": True}).encode("utf-8"))


def _arm(urlopen: _Urlopen | None = None) -> ZapArm:
    return ZapArm(endpoint="http://127.0.0.1:9", urlopen=urlopen or _Urlopen())


# --- install gate -------------------------------------------------------


def test_not_installed_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_ENDPOINT, raising=False)
    arm = ZapArm()
    assert arm.installed(_spec()) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec(), "alerts", {})


def test_bad_endpoint_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_ENDPOINT, "http://127.0.0.1:9/\r\nX: y")
    assert ZapArm().installed(_spec()) is False


# --- read tier ----------------------------------------------------------


def test_allowlisted_view_gets_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    urlopen = _Urlopen()
    result = _arm(urlopen).invoke(_spec(), "alerts", {"start": 0, "count": 10})
    assert result.ok is True
    call = urlopen.calls[0]
    assert call["method"] == "GET"
    assert call["url"].startswith("http://127.0.0.1:9/JSON/alert/view/alerts/")
    assert "start=0" in call["url"] and "count=10" in call["url"]


def test_view_params_whitelisted(monkeypatch: pytest.MonkeyPatch) -> None:
    urlopen = _Urlopen()
    result = _arm(urlopen).invoke(
        _spec(), "alerts", {"apikey": "x", "start": 0}
    )
    assert result.ok is False
    assert "not allowed" in result.error
    assert urlopen.calls == []


def test_view_digits_enforced() -> None:
    result = _arm().invoke(_spec(), "alerts", {"count": "20;rm -rf"})
    assert result.ok is False
    assert "non-negative integer" in result.error


def test_baseurl_must_be_http(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _arm().invoke(_spec(), "alerts_summary", {"baseurl": "file:///etc"})
    assert result.ok is False
    assert "http(s)" in result.error


def test_unknown_view_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    urlopen = _Urlopen()
    result = _arm(urlopen).invoke(_spec(), "coreAction_shutdown", {})
    assert result.ok is False
    assert "not on the allowlist" in result.error
    assert urlopen.calls == []


def test_list_tools_shows_tiers_and_armed_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _arm().invoke(_spec(), "list_tools", {})
    assert result.ok is True
    assert result.output["read_views"] == sorted(ALLOWED_VIEWS)
    assert result.output["dispatch_actions"] == sorted(DISPATCH_ACTIONS)
    assert result.output["dispatch_armed"] is False
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    result = _arm().invoke(_spec(), "list_tools", {})
    assert result.output["dispatch_armed"] is True


# --- dispatch tier ------------------------------------------------------


def test_scan_unarmed_refused_names_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ENV_DISPATCH_SCOPE, raising=False)
    urlopen = _Urlopen()
    result = _arm(urlopen).invoke(_spec(), "ascan_scan", {"url": "http://10.10.0.1/"})
    assert result.ok is False
    assert ENV_DISPATCH_SCOPE in result.error
    assert "dispatch action" in result.error
    assert urlopen.calls == []


def test_scan_armed_in_scope_runs_posts_and_logs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    urlopen = _Urlopen()
    result = _arm(urlopen).invoke(_spec(), "ascan_scan", {"url": "http://10.10.0.1/"})
    assert result.ok is True
    call = urlopen.calls[0]
    assert call["method"] == "POST"
    assert call["url"].endswith("/JSON/ascan/action/scan/")
    assert b"url=http%3A%2F%2F10.10.0.1%2F" in call["data"]
    assert result.output["dispatch"]["scope"] == "10.10.0.0/16"
    err = capsys.readouterr().err
    assert "[dispatch]" in err and "arm=zaproxy" in err and "action=ascan_scan" in err


def test_scan_out_of_scope_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    urlopen = _Urlopen()
    result = _arm(urlopen).invoke(_spec(), "spider_scan", {"url": "http://8.8.8.8/"})
    assert result.ok is False
    assert "outside the armed dispatch scope" in result.error
    assert urlopen.calls == []


def test_scan_requires_url() -> None:
    result = _arm().invoke(_spec(), "ascan_scan", {})
    assert result.ok is False
    assert "args.url" in result.error


def test_api_key_header_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, "secret-key-1")
    urlopen = _Urlopen()
    result = _arm(urlopen).invoke(_spec(), "version", {})
    assert result.ok is True
    assert urlopen.calls[0]["headers"].get("X-zap-api-key") == "secret-key-1"
