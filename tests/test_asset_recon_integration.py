"""Public recon registration, authorization metadata and artifact custody."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from extension.__main__ import main as cli_main
from extension.availability import armed_scopes
from extension.contract import Extension, Result
from extension.dispatch import dispatch_invoke
from extension.invoke_profiles import INVOKE_PROFILES
from extension.mcp_server import McpServer


ACTIONS = ("list_tools", "plan", "parse", "ct", "ptr", "discover", "probe")
FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "extension/arms/assetrecon/fixtures"


def _offline_packet() -> dict:
    return {
        "seeds": {"domains": ["example.test"]},
        "limits": {"max_depth": 5},
        "fixtures": [{"source": source, "path": str(FIXTURE_ROOT / name)}
                     for source, name in (("crtsh", "ct.json"), ("dns", "dns.json"),
                                          ("registry", "registry.json"), ("shodan", "shodan.json"))],
    }


def test_one_recon_registration_and_exact_profiles() -> None:
    ext = Extension()
    assert "asset-recon" in ext.arms
    assert "ct-recon" not in ext.arms and "ptr-recon" not in ext.arms
    row = next(row for row in ext.availability() if row["id"] == "asset-recon")
    assert row == {"id": "asset-recon", "tier": "research", "held": False, "installed": True}
    profiles = {p.action: p for p in INVOKE_PROFILES.values() if p.arm_id == "asset-recon"}
    assert set(profiles) == set(ACTIONS)
    assert ext.invoke("asset-recon", "list_tools", {}).output["actions"] == list(ACTIONS)
    for action, profile in profiles.items():
        assert profile.tier == "research" and profile.default_off
        if action != "list_tools":
            assert profile.timeout_ms == 60_000
        if action in ("list_tools", "plan", "parse"):
            assert profile.safety_class == "R0"
            assert profile.side_effects == ("local-read",)
            assert profile.approval_ref is None
        else:
            assert profile.safety_class == "R1" and not profile.synthetic_only
            if action == "probe":
                assert profile.side_effects == ("subprocess", "network-egress")
                assert profile.approval_ref == "operator://dispatch-scope/ASSET_RECON_PROBE_SCOPE"
            else:
                assert profile.side_effects == ("local-read", "subprocess", "network-egress")
                assert profile.approval_ref == "operator://provider-grant/ASSET_RECON_PROVIDERS"


def test_availability_names_both_independent_grants() -> None:
    assert armed_scopes({
        "ASSET_RECON_PROVIDERS": "crtsh",
        "ASSET_RECON_PROBE_SCOPE": "192.0.2.1",
        "SHODAN_API_KEY": "never expose",
    }) == ["ASSET_RECON_PROBE_SCOPE", "ASSET_RECON_PROVIDERS"]


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("status", ("complete", "partial", "failed"))
def test_every_action_admitted_with_noncomplete_custody(
    action: str, status: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the real shared dispatch; no target/provider calls occur."""
    ext = Extension()
    output = {
        "schema": "specaudit.ctf.asset-recon.v1", "status": status,
        "nodes": [{"id": "domain:example.test"}],
        "limitations": [] if status == "complete" else ["provider request failed"],
    }
    monkeypatch.setattr(ext.arms["asset-recon"], "invoke", lambda spec, called, args:
        Result(status == "complete", "asset-recon", called, output,
               None if status == "complete" else "provider request failed"))
    custody = tmp_path / "custody"
    custody.mkdir()
    outcome = dispatch_invoke(
        ext, arm_id="asset-recon", action=action, args={},
        attempt_id="attempt-" + "a" * 64, artifact_dir=str(custody),
    )
    assert outcome.contract_error is None
    assert outcome.exit_code == (0 if status == "complete" else 1)
    assert outcome.envelope["status"] == ("complete" if status == "complete" else "failed")
    files = list(custody.iterdir())
    assert len(files) == 1
    blob = files[0].read_bytes()
    assert json.loads(blob) == output
    assert outcome.envelope["artifacts"][0]["digest"] == "sha256:" + hashlib.sha256(blob).hexdigest()


@pytest.mark.parametrize("action", ACTIONS)
def test_cli_and_mcp_reach_each_registered_action_unarmed(
    action: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ASSET_RECON_PROVIDERS", raising=False)
    monkeypatch.delenv("ASSET_RECON_PROBE_SCOPE", raising=False)
    args = {} if action == "list_tools" else {"seeds": {"domains": ["example.test"]}}
    code = cli_main(["invoke", "asset-recon", action, json.dumps(args)])
    cli = json.loads(capsys.readouterr().out)
    response = McpServer().handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "invoke", "arguments": {
            "id": "asset-recon", "action": action, "args": args,
        }},
    })
    assert "error" not in response
    mcp = response["result"]["structuredContent"]
    assert cli["capability_id"] == mcp["capability_id"] == f"asset-recon.{action}"
    assert "unknown capability" not in cli["limitations"]
    assert cli["status"] == mcp["status"]
    assert response["result"]["isError"] == (code != 0)
    if action in ("ct", "ptr", "probe"):
        assert code != 0 and cli["status"] == "failed"


def test_unknown_recon_action_refused_before_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    ext = Extension()
    monkeypatch.setattr(ext.arms["asset-recon"], "invoke", lambda *a: pytest.fail("dispatched"))
    outcome = dispatch_invoke(ext, arm_id="asset-recon", action="observe")
    assert outcome.exit_code == 2
    assert outcome.envelope["status"] == "failed"
    assert outcome.envelope["limitations"] == ["unknown capability"]


@pytest.mark.parametrize("method,inner_env", (("nmap", "NMAP_DISPATCH_SCOPE"), ("zgrab2", "ZGRAB2_DISPATCH_SCOPE")))
@pytest.mark.parametrize("outer,inner", ((False, False), (False, True), (True, False), (True, True)))
def test_probe_requires_both_independent_grants_before_worker(
    method: str, inner_env: str, outer: bool, inner: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from extension.arms.assetrecon import arm

    # A global literal exercises authorization rather than the reserved-IP
    # refusal. The worker is replaced; this test cannot contact the address.
    target = "93.184.216.34"
    for env, enabled in (("ASSET_RECON_PROBE_SCOPE", outer), (inner_env, inner)):
        monkeypatch.setenv(env, target if enabled else "")
    calls = []

    def worker(payload, timeout):
        calls.append(payload)
        return {"ok": True, "service": "fixture"}

    monkeypatch.setattr(arm, "run_worker", worker)
    ext = Extension()
    result = ext.invoke("asset-recon", "probe", {
        "live": True, "targets": [{"ip": target, "port": 443, "method": method}],
    })
    assert result.ok is (outer and inner)
    assert len(calls) == (1 if outer and inner else 0)
    assert result.output["status"] == ("complete" if outer and inner else "failed")


def test_probe_grants_do_not_replace_explicit_live_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    from extension.arms.assetrecon import arm

    monkeypatch.setenv("ASSET_RECON_PROBE_SCOPE", "93.184.216.34")
    monkeypatch.setenv("NMAP_DISPATCH_SCOPE", "93.184.216.34")
    monkeypatch.setattr(arm, "run_worker", lambda *a: pytest.fail("unrequested live probe"))
    result = Extension().invoke("asset-recon", "probe", {
        "live": False, "targets": [{"ip": "93.184.216.34", "port": 443, "method": "nmap"}],
    })
    assert result.ok is False and result.output["status"] == "failed"


def test_committed_offline_packet_produces_evidence_backed_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    from extension.arms.assetrecon import arm

    monkeypatch.setattr(arm, "run_worker", lambda *a: pytest.fail("offline packet started worker"))
    result = Extension().invoke("asset-recon", "discover", _offline_packet())
    assert result.ok and result.output["status"] == "complete"
    output = result.output
    assert output["requests"] == 0
    edges = {(e["source"], e["relation"], e["target"]) for e in output["edges"]}
    assert {
        ("domain:example.test", "discovered_under", "domain:api.example.test"),
        ("certificate:" + "a" * 64, "san", "domain:api.example.test"),
        ("domain:api.example.test", "resolves_to", "ip:192.0.2.10"),
        ("ip:192.0.2.10", "announced_by", "asn:64496"),
        ("asn:64496", "registered_to", "organization:Example Research"),
    } <= edges
    evidence = {e["id"]: e for e in output["evidence"]}
    expected_hashes = {f["source"]: hashlib.sha256(Path(f["path"]).read_bytes()).hexdigest()
                       for f in _offline_packet()["fixtures"]}
    assert {e["source"] for e in evidence.values()} == set(expected_hashes)
    for edge in output["edges"]:
        assert edge["evidence"]
        for ref in edge["evidence"]:
            record = evidence[ref]
            assert record["artifact_sha256"] == expected_hashes[record["source"]]
            assert record["observation"]["source"] == record["source"]
    by_id = {n["id"]: n for n in output["nodes"]}
    for key in ("ip:192.0.2.10", "asn:64496", "organization:Example Research"):
        association = by_id[key]["association"]
        assert association["score"] > 0
        assert association["reasons"]
        assert association["reasons"] != ["infrastructure evidence alone does not establish ownership"]
        assert any(signal["evidence"] for signal in association["signals"])
    for node in output["nodes"]:
        for signal in node["association"]["signals"]:
            assert set(signal["evidence"]) <= set(evidence)


def test_excluded_seed_and_downstream_evidence_do_not_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    from extension.arms.assetrecon import arm

    monkeypatch.setattr(arm, "run_worker", lambda *a: pytest.fail("offline packet started worker"))
    payload = _offline_packet()
    payload["seeds"]["ips"] = ["192.0.2.10"]
    payload["exclusions"] = {"networks": ["192.0.2.0/24"]}
    result = Extension().invoke("asset-recon", "discover", payload)
    assert result.ok
    # ASN and organization are reachable only through the excluded seed IP.
    # Check the whole serialized output, including evidence and explanations.
    output = json.dumps(result.output)
    for forbidden in ("192.0.2.10", "192.0.2.0/24", "64496", "Example Research"):
        assert forbidden not in output
    assert "198.51.100.25" in output  # sibling path remains useful


def test_real_partial_packet_retains_mode_a_graph_and_fails_public_envelope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from extension.arms.assetrecon import arm

    monkeypatch.setattr(arm, "run_worker", lambda *a: pytest.fail("offline packet started worker"))
    payload = _offline_packet()
    payload["limits"]["max_depth"] = 1
    inner = Extension().invoke("asset-recon", "discover", payload)
    assert inner.ok is False and inner.output["status"] == "partial"
    assert inner.output["nodes"] and inner.output["limitations"]
    custody = tmp_path / "custody"
    custody.mkdir()
    code = cli_main(["invoke", "asset-recon", "discover", json.dumps(payload),
                     "--attempt-id", "attempt-" + "b" * 64, "--artifact-dir", str(custody)])
    envelope = json.loads(capsys.readouterr().out)
    assert code == 1 and envelope["status"] == "failed"
    assert "nodes" not in envelope  # Mode A graph bytes belong to custody.
    files = list(custody.iterdir())
    assert len(files) == 1
    report = json.loads(files[0].read_bytes())
    assert report == inner.output
    assert envelope["artifacts"][0]["digest"] == "sha256:" + hashlib.sha256(files[0].read_bytes()).hexdigest()


@pytest.mark.skipif(os.name != "posix", reason="live worker requires POSIX")
def test_worker_startup_refusal_is_independent_of_callers_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from extension.arms.assetrecon.model import Refusal
    from extension.arms.assetrecon.runner import run_worker

    monkeypatch.chdir(tmp_path)
    # An invalid operation cannot contact providers/targets. This exact
    # refusal means the worker started and returned its typed JSON result;
    # a missing module/nonzero child exit instead reports "worker failed".
    with pytest.raises(Refusal, match="^provider or probe failed$"):
        run_worker({"operation": "runtime-refusal-check"}, 5)
