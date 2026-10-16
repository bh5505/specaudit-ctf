"""Synthetic HTTP redirects cannot carry arm credentials off the API endpoint."""

from __future__ import annotations

from email.message import Message
from io import BytesIO
from urllib import request, response

import pytest

from extension.arms.caldera import CalderaArm
from extension.arms.zap import ZapArm
from extension.contract import ArmSpec


class _Redirect(request.BaseHandler):
    handler_order = 100

    def __init__(self) -> None:
        self.calls: list[request.Request] = []

    def http_open(self, req: request.Request):
        self.calls.append(req)
        headers = Message()
        headers["Location"] = "http://off-scope.invalid/collect"
        result = response.addinfourl(BytesIO(b"redirect refused"), headers, req.full_url, 302)
        result.msg = "Found"
        return result


@pytest.mark.parametrize("arm_name, action, args, header", [
    ("caldera", "abilities", {}, "Key"),
    ("caldera", "schedule_operation", {"operation": "op-1"}, "Key"),
    ("zap", "version", {}, "X-zap-api-key"),
    ("zap", "ascan_scan", {"url": "http://10.10.0.1/"}, "X-zap-api-key"),
])
def test_api_redirect_refused_without_followup_request(
    monkeypatch: pytest.MonkeyPatch,
    arm_name: str,
    action: str,
    args: dict,
    header: str,
) -> None:
    redirect = _Redirect()
    build_opener = request.build_opener
    monkeypatch.setattr(request, "build_opener", lambda *handlers: build_opener(*handlers, redirect))
    monkeypatch.setenv("CALDERA_API_KEY", "test-secret")
    monkeypatch.setenv("ZAP_API_KEY", "test-secret")
    monkeypatch.setenv("CALDERA_DISPATCH_SCOPE", "lab-agents")
    monkeypatch.setenv("ZAP_DISPATCH_SCOPE", "10.10.0.0/16")
    arm = (
        CalderaArm(endpoint="http://127.0.0.1:8765")
        if arm_name == "caldera"
        else ZapArm(endpoint="http://127.0.0.1:8080")
    )
    spec = ArmSpec(
        id=arm.ARM_ID,
        protocols=("mcp",),
        curated=True,
        notes="Synthetic redirect test.",
        tier="research",
    )

    result = arm.invoke(spec, action, args)

    assert not result.ok
    assert "HTTP 302" in result.error
    assert len(redirect.calls) == 1
    assert redirect.calls[0].get_header(header) == "test-secret"
    assert redirect.calls[0].full_url.startswith("http://127.0.0.1:")
