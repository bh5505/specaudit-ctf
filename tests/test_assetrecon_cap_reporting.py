"""Provider caps must distinguish completed work from suppressed expansion."""
import pytest

from extension.arms.assetrecon import AssetReconArm
from extension.arms.assetrecon import arm
from extension.contract import ArmSpec


@pytest.mark.parametrize("providers", [("google",), ("google", "cloudflare")])
@pytest.mark.parametrize("discover_address", [False, True])
def test_exact_cap_reports_only_unfinished_expansion(monkeypatch, providers, discover_address):
    calls = []
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", ",".join(providers))

    def collect(request, timeout):
        calls.append(request)
        data = []
        if discover_address and request.get("variant") == "A":
            data = [{"name": "public.com", "type": "A", "value": "8.8.8.8"}]
        return {"ok": True, "digest": "0" * 64, "data": data, "dns_status": 0}

    monkeypatch.setattr(arm, "run_worker", collect)
    result = AssetReconArm().invoke(
        ArmSpec("asset-recon", ("cli",), True, "Hermetic fixture", "research"),
        "discover",
        {"live": True, "providers": list(providers), "seeds": {"domains": ["public.com"]},
         "limits": {"max_requests": 2 * len(providers), "min_interval_ms": 50}},
    )
    assert len(calls) == 2 * len(providers)
    assert all(request["kind"] == "domain" for request in calls)
    assert result.ok is not discover_address
    assert result.output["status"] == ("partial" if discover_address else "complete")
    if discover_address:
        assert any(node["id"] == "ip:8.8.8.8" for node in result.output["nodes"])
        assert "provider request cap reached with unqueried nodes" in result.output["limitations"]
    else:
        assert not result.output["limitations"]
