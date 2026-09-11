"""Hermetic fresh implementation gates: no provider or target contacts."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from extension.arms.assetrecon import AssetReconArm
from extension.arms.assetrecon import arm, worker
from extension.arms.assetrecon.graph import Graph
from extension.arms.assetrecon.model import Budget, Exclusions, Observation, Refusal, live_value, normalize, pattern_covers, seeds
from extension.arms.assetrecon.probe_policy import validate_target
from extension.arms.assetrecon.runner import WorkerRefusal, _accept_result, run_worker
from extension.arms.assetrecon.sanitize import safe_text
from extension.arms.assetrecon.sources import ADAPTERS, decode, read_fixture, shodan
from extension.contract import ArmSpec

SPEC = ArmSpec("asset-recon", ("cli",), True, "Hermetic fixture", "research")
FIXTURES = Path(arm.__file__).parent / "fixtures"
FP = "a" * 64
HASH = "0" * 64


def invoke(action, payload):
    return AssetReconArm().invoke(SPEC, action, payload)


def packet():
    return dict(seeds={"domains": ["example.test"]}, organization_hints=["Example Research"], limits={"max_depth": 5},
                fixtures=[{"source": source, "path": str(FIXTURES / filename)} for source, filename in
                          (("crtsh", "ct.json"), ("dns", "dns.json"), ("registry", "registry.json"), ("shodan", "shodan.json"))])


def assert_closed(output):
    ids = {n["id"] for n in output["nodes"]}
    evidence = {e["id"] for e in output["evidence"]}
    used = set()
    for edge in output["edges"]:
        assert edge["source"] in ids and edge["target"] in ids
        assert set(edge["evidence"]) <= evidence
        used.update(edge["evidence"])
    assert evidence == used
    for node in output["nodes"]:
        for signal in node["association"]["signals"]:
            assert set(signal["evidence"]) <= evidence


def test_offline_packet_is_useful_and_closed(monkeypatch):
    monkeypatch.setattr(arm, "run_worker", lambda *_: pytest.fail("offline attempted live worker"))
    result = invoke("discover", packet())
    assert result.ok, result.output
    nodes = {n["id"]: n for n in result.output["nodes"]}
    assert "ip:192.0.2.10" in nodes
    assert "organization:Example Research" in nodes
    assert nodes["ip:192.0.2.10"]["association"]["score"] > 0
    assert nodes["asn:64496"]["association"]["signals"]
    assert_closed(result.output)
    attributes = [e["observation"]["attributes"] for e in result.output["evidence"]]
    assert any(a.get("observed_at") == "2020-02-03T04:05:06Z" for a in attributes)
    assert any(a.get("ttl") == 300 for a in attributes)
    assert all(e["origin"] == "local-fixture" and e["locator"].startswith("fixture:sha256:") for e in result.output["evidence"])
    assert result.output["context"] == {
        "action": "discover",
        "seeds": {
            "count": 1,
            "sha256": result.output["context"]["seeds"]["sha256"],
        },
        "exclusions": {
            "domain_count": 0,
            "network_count": 0,
            "policy_sha256": result.output["context"]["exclusions"]["policy_sha256"],
        },
        "limits": result.output["context"]["limits"],
        "organization_hints": {
            "count": 1,
            "sha256": result.output["context"]["organization_hints"]["sha256"],
        },
        "domains_file_sha256": None,
        "targets_file_sha256": None,
        "live": False,
        "providers": [],
        "fixture_sources": ["crtsh", "dns", "registry", "shodan"],
    }


def test_plan_normalizes_exclusions_and_does_not_collect(monkeypatch):
    monkeypatch.setattr(arm, "run_worker", lambda *_: pytest.fail("plan ran worker"))
    result = invoke("plan", dict(seeds={"domains": ["Example.TEST.", "blocked.example.test"], "ips": ["192.0.2.1"]}, exclusions={"domains": ["blocked.example.test"], "networks": ["192.0.2.0/24"]}))
    assert result.ok
    plan = result.output["plan"]
    assert plan["seeds"] == [{"type": "domain", "value": "example.test"}]
    assert plan["excluded_seed_count"] == 2
    assert not plan["collection_performed"]
    assert not result.output["nodes"] and not result.output["evidence"]


@pytest.mark.parametrize("action", ["ct", "ptr", "discover"])
def test_live_is_default_off(action, monkeypatch):
    monkeypatch.delenv("ASSET_RECON_PROVIDERS", raising=False)
    monkeypatch.setattr(arm, "run_worker", lambda *_: pytest.fail("unarmed request"))
    result = invoke(action, dict(seeds={"domains": ["public.com"]}, live=True, providers=["crtsh"]))
    assert not result.ok


@pytest.mark.parametrize("action,provider", [("ct", "google"), ("ptr", "crtsh"), ("ct", "shodan"), ("ptr", "registry")])
def test_provider_family_mismatch_never_runs(action, provider, monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", provider)
    monkeypatch.setattr(arm, "run_worker", lambda *_: pytest.fail("wrong family ran"))
    assert not invoke(action, dict(seeds={"domains": ["public.com"], "ips": ["8.8.8.8"]}, live=True, providers=[provider])).ok


@pytest.mark.parametrize(
    "action,seeds_value,provider",
    [
        ("ct", {"ips": ["8.8.8.8"]}, "crtsh"),
        ("ptr", {"domains": ["public.com"]}, "google"),
    ],
)
def test_bulk_collection_actions_refuse_wrong_seed_family_before_worker(
    action, seeds_value, provider, monkeypatch,
):
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", provider)
    monkeypatch.setattr(arm, "run_worker", lambda *_: pytest.fail("wrong seed family ran"))
    result = invoke(action, {"live": True, "providers": [provider], "seeds": seeds_value})
    assert not result.ok and result.output["status"] == "failed"


def test_list_tools_separates_fixture_only_sources():
    result = invoke("list_tools", {})
    assert "dns" in result.output["fixture_sources"]
    assert "dns" not in result.output["live_providers"]
    assert result.output["maximum_limits"]["max_requests"] == 32
    assert {"networks", "domains_file", "targets_file"} <= set(result.output["seed_fields"])
    assert {"http", "tcp-hello", "nmap", "zgrab2"} <= set(result.output["probe_methods"])


def test_list_tools_does_not_expose_mutable_limit_defaults():
    result = invoke("list_tools", {})
    result.output["default_limits"]["max_requests"] = 999
    result.output["maximum_limits"]["max_requests"] = 999
    second = invoke("list_tools", {})
    assert second.output["default_limits"]["max_requests"] == 16
    assert second.output["maximum_limits"]["max_requests"] == 32


def test_exclusions_override_seeds_and_edges():
    payload = packet()
    payload["seeds"]["ips"] = ["192.0.2.10"]
    payload["exclusions"] = {"networks": ["192.0.2.0/24"], "domains": ["mail.example.test"]}
    output = invoke("discover", payload).output
    values = {n["value"] for n in output["nodes"]}
    assert "192.0.2.10" not in values and "mail.example.test" not in values
    assert_closed(output)


def test_one_label_domain_suffix_exclusion_is_allowed_and_label_bounded():
    exclusions = Exclusions({"domains": [".net"]})
    assert exclusions.denies("domain", "customer.public.net")
    assert exclusions.denies("domain", "public.net")
    assert not exclusions.denies("domain", "public.network")


def test_printable_provider_organization_and_opaque_record_id_are_preserved(tmp_path):
    fixture = tmp_path / "registry.json"
    fixture.write_text('[{"prefix":"8.8.8.0/24","asn":15169,"organization":"O\'Reilly: Network + Cloud"}]')
    result = invoke("parse", {
        "seeds": {"asns": [15169]},
        "fixtures": [{"source": "registry", "path": str(fixture)}],
    })
    assert result.ok
    assert "organization:O'Reilly: Network + Cloud" in {node["id"] for node in result.output["nodes"]}

    issuance = {"id": "page:2/next?", "dns_names": ["public.com"], "cert_sha256": FP}
    observations = list(ADAPTERS["certspotter"].parse([issuance]))
    assert observations[0].attributes["record_id"] == issuance["id"]


def test_all_seeds_excluded_refuses():
    result = invoke("discover", dict(seeds={"domains": ["example.test"]}, exclusions={"domains": ["example.test"]}))
    assert not result.ok and not result.output["nodes"]


def test_cidr_expansion_is_bounded():
    result = seeds({"networks": ["192.0.2.0/30"]}, Exclusions({"networks": ["192.0.2.1/32"]}))
    assert result == [("ip", "192.0.2.0"), ("ip", "192.0.2.2"), ("ip", "192.0.2.3")]
    with pytest.raises(Refusal):
        seeds({"networks": ["2001:db8::/64"]}, Exclusions())


@pytest.mark.parametrize("value", ["192.0.2.1", "127.0.0.1", "10.0.0.1", "224.0.0.1", "ff02::1", "fec0::1", "2001:db8::1", "169.254.1.1", "::1"])
def test_non_global_probe_values_refused(value, monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROBE_SCOPE", value)
    monkeypatch.setattr(arm, "run_worker", lambda *_: pytest.fail("reserved probe attempted"))
    assert not invoke("probe", dict(live=True, targets=[{"ip": value, "port": 80, "method": "tcp"}])).ok


@pytest.mark.parametrize("number,allowed", [(23456, False), (64495, True), (64496, False), (64511, False), (64512, False), (65534, False), (65535, False), (65536, False), (65551, False), (65552, True), (131071, True), (4199999999, True), (4200000000, False), (4294967295, False)])
def test_asn_boundaries(number, allowed):
    assert live_value("asn", str(number)) is allowed


@pytest.mark.parametrize("limits", [[], {"max_nodes": True}, {"max_depth": 6}, {"max_output_bytes": 10}, {"unknown": 1}])
def test_bad_limits_refuse(limits):
    assert not invoke("plan", dict(seeds={"domains": ["example.test"]}, limits=limits)).ok


def test_fixture_reader_refuses_symlink_fifo_directory_and_deep_json(tmp_path):
    file = tmp_path / "fixture.json"
    file.write_text("[]")
    link = tmp_path / "link.json"
    link.symlink_to(file)
    fifo = tmp_path / "fifo"
    paths = [link, tmp_path]
    if hasattr(os, "mkfifo"):
        os.mkfifo(fifo)
        paths.append(fifo)
    for path in paths:
        with pytest.raises(Refusal):
            read_fixture(str(path))
    with pytest.raises(Refusal):
        decode(b"[" * 25 + b"]" * 25)
    assert read_fixture(str(file))[1] == hashlib.sha256(b"[]").hexdigest()


def test_bounded_json_domain_seed_file_is_hashed_not_echoed(tmp_path):
    domains = tmp_path / "domains.json"
    domains.write_text('["bulk.public.com", "blocked.public.com"]')
    fixture = tmp_path / "empty-dns.json"
    fixture.write_text("[]")
    result = invoke("discover", {
        "seeds": {"domains_file": str(domains)},
        "exclusions": {"domains": ["blocked.public.com"]},
        "fixtures": [{"source": "dns", "path": str(fixture)}],
    })
    assert result.output["context"]["seeds"]["count"] == 1
    assert result.output["context"]["domains_file_sha256"] == hashlib.sha256(domains.read_bytes()).hexdigest()
    assert "blocked.public.com" not in json.dumps(result.output)


def test_output_budget_prunes_closed_units():
    payload = packet()
    payload["limits"]["max_output_bytes"] = 4096
    result = invoke("discover", payload)
    assert not result.ok and result.output["status"] == "partial"
    assert len(json.dumps(result.output).encode()) <= 4096
    assert_closed(result.output)


def test_output_budget_bounds_large_seed_manifest(tmp_path):
    fixture = tmp_path / "empty-dns.json"
    fixture.write_text("[]")
    domains = [f"n{number}.example.test" for number in range(64)]
    result = invoke("discover", {
        "seeds": {"domains": domains},
        "fixtures": [{"source": "dns", "path": str(fixture)}],
        "limits": {"max_output_bytes": 4096},
    })
    assert len(json.dumps(result.output).encode()) <= 4096
    assert result.output["context"]["seeds"]["count"] == 64
    assert not result.ok and result.output["status"] == "partial"


def test_invalid_later_fixture_preserves_completed_portion(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json")
    payload = packet()
    payload["fixtures"].append({"source": "dns", "path": str(path)})
    result = invoke("discover", payload)
    assert not result.ok and result.output["edges"]
    assert_closed(result.output)


def test_failed_fixture_still_records_selected_source(tmp_path):
    missing = tmp_path / "missing.json"
    result = invoke("parse", {
        "seeds": {"domains": ["example.test"]},
        "fixtures": [{"source": "dns", "path": str(missing)}],
    })
    assert not result.ok and result.output["status"] == "partial"
    assert result.output["context"]["fixture_sources"] == ["dns"]


def test_invalid_worker_digest_cannot_enter_provenance(monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", "google")
    monkeypatch.setattr(arm, "run_worker", lambda *a, **k: {
        "ok": True, "digest": "not-a-digest", "data": [], "dns_status": 0,
    })
    result = invoke("discover", {
        "live": True,
        "providers": ["google"],
        "seeds": {"domains": ["public.com"]},
        "limits": {"min_interval_ms": 50},
    })
    assert not result.ok
    assert "not-a-digest" not in json.dumps(result.output)


def test_fingerprint_seed_reaches_names():
    result = invoke("discover", dict(seeds={"fingerprints": [FP]}, fixtures=[{"source": "crtsh", "path": str(FIXTURES / "ct.json")}]))
    assert result.ok
    assert any(n["value"] == "api.example.test" for n in result.output["nodes"])


def test_ct_root_need_not_be_literal_san():
    result = invoke("parse", dict(seeds={"domains": ["example.test"]}, fixtures=[{"source": "crtsh", "path": str(FIXTURES / "ct.json")}]))
    assert result.output["edges"]
    assert any(e["relation"] == "discovered_under" for e in result.output["edges"])


def test_crtsh_single_name_retains_query_evidence_without_fake_co_name():
    observations = list(ADAPTERS["crtsh"].parse([{"name_value": "public.com", "id": 1}]))
    assert len(observations) == 1
    assert observations[0].relation == "query_match"
    assert observations[0].left == observations[0].right == "public.com"


def test_wildcard_is_one_label_only():
    assert pattern_covers("*.example.test", "api.example.test")
    assert not pattern_covers("*.example.test", "deep.api.example.test")
    assert not pattern_covers("*.example.test", "example.test")


def test_graph_adjacency_visits_linear_in_records():
    budget = Budget({"max_nodes": 1000, "max_edges": 2000, "max_depth": 5})
    graph = Graph([("domain", "example.test")], Exclusions(), budget)
    records = [(Observation("dns", "domain", "example.test", "cname", "domain", f"n{i}.example.test"), HASH) for i in range(800)]
    graph.expand(records)
    assert len(graph.edges) == 800
    assert graph.record_visits <= 2 * len(records)


def test_graph_revisits_a_node_when_a_later_edge_finds_a_shorter_path():
    budget = Budget({"max_depth": 3})
    graph = Graph([("domain", "root.example.test")], Exclusions(), budget)
    long_path = [
        (Observation("dns", "domain", "root.example.test", "cname", "domain", "long.example.test"), HASH),
        (Observation("dns", "domain", "long.example.test", "cname", "domain", "pivot.example.test"), HASH),
        (Observation("dns", "domain", "pivot.example.test", "cname", "domain", "leaf.example.test"), HASH),
    ]
    graph.expand(long_path)
    assert graph.nodes["domain:leaf.example.test"]["depth"] == 3
    records = long_path + [
        # This shorter edge is encountered after pivot was already queued on
        # the longer path; leaf must still be reachable within max_depth.
        (Observation("dns", "domain", "root.example.test", "cname", "domain", "pivot.example.test"), "1" * 64),
    ]
    graph.expand(records)
    assert graph.nodes["domain:pivot.example.test"]["depth"] == 1
    assert graph.nodes["domain:leaf.example.test"]["depth"] == 2


def test_shodan_host_services_and_search_banner_parse():
    service = {"port": 443, "transport": "tcp", "timestamp": "2020-02-03T04:05:06Z", "ssl": {"cert": {"fingerprint": {"sha256": FP}}}}
    records = list(shodan({"ip_str": "192.0.2.1", "org": "Example Research", "data": [service]}))
    served = next(record for record in records if record.relation == "served_certificate")
    assert served.attributes["port"] == 443
    assert any(record.relation == "observed_organization" for record in records)
    records = list(shodan({"matches": [{"ip_str": "192.0.2.1", "data": "HTTP/1.1 200", "hostnames": ["example.test"]}]}))
    assert records[0].relation == "observed_hostname"
    assert list(shodan({"ip_str": "192.0.2.1", "ssl": None, "asn": None})) == []


def dns_reply(value="8.8.8.8", *, question="public.com.", rr=1, status=0):
    return {"Status": status, "TC": False, "Question": [{"name": question, "type": rr}],
            "Answer": [{"name": question, "type": rr, "data": value, "TTL": 300}] if status == 0 else []}


@pytest.mark.parametrize("source", ["google", "cloudflare"])
def test_doh_binding_and_ttl(source, monkeypatch):
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: (dns_reply(), HASH))
    result = worker.collect(source, "domain", "public.com", "A")
    assert result["data"][0]["ttl"] == 300
    bad = dns_reply(question="unrelated.com.")
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: (bad, HASH))
    with pytest.raises(Refusal):
        worker.collect(source, "domain", "public.com", "A")


def test_ptr_rfc2317_alias_binding(monkeypatch):
    name = ipaddress.ip_address("8.8.8.8").reverse_pointer
    alias = "8.0/25.8.8.8.in-addr.arpa."
    data = {"Status": 0, "TC": False, "Question": [{"name": name, "type": 12}], "Answer": [
        {"name": name, "type": 5, "data": alias}, {"name": alias, "type": 12, "data": "dns.public.com."}]}
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: (data, HASH))
    assert worker.collect("google", "ip", "8.8.8.8")["data"] == [{"name": "8.8.8.8", "type": "PTR", "value": "dns.public.com."}]


def test_certspotter_cursor_cycle_preserves_partial(monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", "certspotter")
    cursors = iter(["one", "two", "one"])
    calls = []
    def fake(request, timeout):
        calls.append(request)
        cursor = next(cursors)
        return {"ok": True, "digest": HASH, "data": [{"id": cursor, "dns_names": ["api.public.com"], "cert_sha256": FP}], "cursor": cursor}
    monkeypatch.setattr(arm, "run_worker", fake)
    result = invoke("ct", {"live": True, "providers": ["certspotter"], "seeds": {"domains": ["public.com"]}, "limits": {"min_interval_ms": 50}})
    assert not result.ok and result.output["edges"] and len(calls) == 3


def test_certspotter_pagination_empty_page_closes(monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", "certspotter")
    calls = []
    def fake(request, timeout):
        calls.append(request)
        return {"ok": True, "digest": HASH, "data": [{"id": "opaque", "dns_names": ["api.public.com"], "cert_sha256": FP}], "cursor": "opaque"} if len(calls) == 1 else {"ok": True, "digest": HASH, "data": [], "cursor": None}
    monkeypatch.setattr(arm, "run_worker", fake)
    result = invoke("ct", {"live": True, "providers": ["certspotter"], "seeds": {"domains": ["public.com"]}, "limits": {"min_interval_ms": 50}})
    assert result.ok and len(calls) == 2
    assert calls[1]["variant"] == "opaque"


def test_dns_negative_disagreement_and_provenance(monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", "google,cloudflare")
    monkeypatch.setattr(arm, "run_worker", lambda request, timeout: {"ok": True, "digest": HASH, "data": [], "dns_status": 3 if request["source"] == "google" else 0})
    result = invoke("ptr", {"live": True, "providers": ["google", "cloudflare"], "seeds": {"ips": ["8.8.8.8"]}, "limits": {"min_interval_ms": 50}})
    assert not result.ok
    assert {e["source"] for e in result.output["evidence"]} == {"google", "cloudflare"}
    assert {e["relation"] for e in result.output["edges"]} == {"dns_nxdomain", "dns_nodata"}


@pytest.mark.parametrize("changes", [{"method": "exploit"}, {"port": True}, {"method": "tcp-hello", "hello": "DELETE /"}, {"extra": 1}, {"method": "http", "url": "http://8.8.8.8/?key=secret"}, {"method": "http", "url": "http://8.8.8.8/admin"}])
def test_direct_worker_rejects_bad_probe_before_network(changes, monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROBE_SCOPE", "8.8.8.8")
    monkeypatch.setattr(worker, "probe", lambda *_: pytest.fail("invalid worker request touched network"))
    with pytest.raises(Refusal):
        worker.execute({"operation": "probe", "live": True, "target": {"ip": "8.8.8.8", "port": 80, "method": "tcp", **changes}})


@pytest.mark.parametrize("source,kind,variant", [("dns", "ip", None), ("google", "certificate", None), ("crtsh", "certificate", None), ("google", "domain", "TXT"), ("registry", "asn", "any-url")])
def test_direct_worker_rejects_bad_collect_before_network(source, kind, variant, monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", source)
    monkeypatch.setattr(worker, "collect", lambda *_: pytest.fail("invalid worker collected"))
    with pytest.raises(Refusal):
        worker.execute({"operation": "collect", "live": True, "source": source, "kind": kind, "value": "8.8.8.8", "variant": variant})


def test_probe_dual_scope_and_host_binding(monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROBE_SCOPE", "8.8.8.8,public.com")
    monkeypatch.delenv("NMAP_DISPATCH_SCOPE", raising=False)
    with pytest.raises(Refusal):
        validate_target({"ip": "8.8.8.8", "port": 443, "method": "nmap"})
    target, _, _ = validate_target({"ip": "8.8.8.8", "port": 443, "method": "http", "host": "public.com", "url": "https://public.com/"})
    assert target["ip"] == "8.8.8.8" and target["host"] == "public.com"
    with pytest.raises(Refusal):
        validate_target(dict(target, url="https://other.com/"))


def test_constant_redaction_precedes_preview_cap(monkeypatch):
    secret = "canary/key+secret"
    monkeypatch.setenv("SHODAN_API_KEY", secret)
    value = safe_text("SMTP welcome\r\npassword=" + "a" * 1000 + "\r\n" + secret + " canary%2Fkey%2Bsecret")
    assert "SMTP welcome" in value["preview"]
    assert "[REDACTED]" in value["preview"]
    assert secret not in value["preview"] and "canary%2F" not in value["preview"]


def test_worker_refusal_is_hermetic_subprocess():
    with pytest.raises(Refusal):
        run_worker({"operation": "runtime-refusal-check"}, 2)


@pytest.mark.skipif(os.name != "posix", reason="live worker is POSIX-only")
def test_worker_deadline_reaps_blocking_child(monkeypatch):
    from extension.arms.assetrecon import runner
    original = subprocess.Popen
    children = []
    def fake(*args, **kwargs):
        child = original([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(runner.subprocess, "Popen", fake)
    start = time.monotonic()
    with pytest.raises(Refusal):
        run_worker({}, .2)
    assert time.monotonic() - start < 2
    assert children[0].poll() is not None


@pytest.mark.parametrize("pattern,accepted", [("*.public.com", True), ("*.sub.public.com", True), ("*.com", True), ("*.unrelated.com", False)])
def test_certspotter_binding_wildcards(pattern, accepted, monkeypatch):
    row = {"id": "opaque1", "dns_names": [pattern], "cert_sha256": FP}
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: ([row], HASH))
    if accepted:
        assert worker.collect("certspotter", "domain", "public.com")["data"] == [row]
    else:
        with pytest.raises(Refusal):
            worker.collect("certspotter", "domain", "public.com")


def test_certspotter_requests_parent_wildcards_and_reports_coverage(monkeypatch):
    captured = []
    def fake(url, *args, **kwargs):
        captured.append(url)
        return [], HASH
    monkeypatch.setattr(worker, "fetch", fake)
    response = worker.collect("certspotter", "domain", "public.com")
    assert "match_wildcards=true" in captured[0]
    assert response["limitations"]


def test_certspotter_cursor_is_bounded_opaque_and_url_encoded(monkeypatch):
    captured = []
    row = {"id": "page:2/next?", "dns_names": ["public.com"], "cert_sha256": FP}

    def fake(url, *args, **kwargs):
        captured.append(url)
        return [row], HASH

    monkeypatch.setattr(worker, "fetch", fake)
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", "certspotter")
    request = worker.validate_request({
        "operation": "collect", "live": True, "source": "certspotter",
        "kind": "domain", "value": "public.com", "variant": row["id"],
    })
    response = worker.collect(request["source"], request["kind"], request["value"], request["variant"])
    assert response["cursor"] == row["id"]
    assert "after=page%3A2%2Fnext%3F" in captured[0]


@pytest.mark.skipif(os.name != "posix", reason="live worker is POSIX-only")
def test_real_worker_success_contract_with_hermetic_boundary(monkeypatch):
    from extension.arms.assetrecon import runner
    original = subprocess.Popen
    script = "from extension.arms.assetrecon import worker; worker.collect=lambda *a: {'ok': True, 'data': [], 'digest': '0'*64, 'dns_status': 0}; worker.main()"
    def fake(*args, **kwargs):
        return original([sys.executable, "-c", script], **kwargs)
    monkeypatch.setattr(runner.subprocess, "Popen", fake)
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", "google")
    result = run_worker({"operation": "collect", "live": True, "source": "google", "kind": "domain", "value": "public.com", "variant": "A"}, 2)
    assert result == {"ok": True, "data": [], "digest": HASH, "dns_status": 0}


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.timeouts = []
        self.connected = None
    def settimeout(self, value):
        self.timeouts.append(value)
    def sendall(self, value):
        self.sent.append(value)
    def connect(self, value):
        self.connected = value
    def recv(self, amount):
        if not self.chunks:
            return b""
        item = self.chunks.pop(0)
        if isinstance(item, Exception):
            raise item
        piece = item[:amount]
        if len(item) > amount:
            self.chunks.insert(0, item[amount:])
        return piece
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


def test_http_body_headers_fragmentation_and_redaction(monkeypatch):
    monkeypatch.setenv("CERTSPOTTER_TOKEN", "canarySecret")
    sock = FakeSocket([b"HTTP/1.1 200 OK\r\nServ", b"er: Demo/1\r\nSet-Cookie: sensitive\r\n\r\n<h1>Hello</h1>\npassword=abc\ncanarySecret"])
    result = worker.http_get(sock, {"url": "http://public.com/"})
    assert result["complete"] is True
    assert result["headers"] == {"server": "Demo/1"}
    assert "Hello" in result["body_preview"]
    assert "abc" not in result["body_preview"] and "canarySecret" not in result["body_preview"]
    assert "[REDACTED]" in result["body_preview"]
    assert sock.sent == [b"GET / HTTP/1.0\r\nHost: public.com\r\nConnection: close\r\n\r\n"]


def test_http_truncated_body_degrades_but_preserves_headers():
    sock = FakeSocket([b"HTTP/1.1 200 OK\r\nServer: Demo\r\n\r\npartial", TimeoutError()])
    result = worker.http_get(sock, {"url": "http://public.com/"})
    assert not result["complete"] and result["capture_truncated"]
    assert result["body_preview"] == "partial"
    assert result["headers"]["server"] == "Demo"


def test_http_capture_limit_is_hard():
    sock = FakeSocket([b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 20000])
    result = worker.http_get(sock, {"url": "http://public.com/"})
    assert result["bytes"] == 16384 and not result["complete"]
    assert result["body_preview_truncated"] and len(result["body_preview"]) == 512


@pytest.mark.parametrize("method", ["tcp-hello", "udp-hello"])
def test_hello_sends_only_fixed_greeting_and_reads_once(method, monkeypatch):
    sock = FakeSocket([b"Demo Server 1.2\r\n"])
    monkeypatch.setattr(worker.socket, "socket", lambda *a: sock)
    result = worker.probe({"ip": "8.8.8.8", "port": 1234, "method": method})
    assert sock.connected == ("8.8.8.8", 1234)
    assert sock.sent == [b"hello\r\n"]
    assert "Demo Server 1.2" in result["preview"]


def test_native_http_host_does_not_resolve(monkeypatch):
    sock = FakeSocket([b"HTTP/1.1 200 OK\r\n\r\nHello"])
    monkeypatch.setattr(worker.socket, "socket", lambda *a: sock)
    monkeypatch.setattr(worker.socket, "getaddrinfo", lambda *a: pytest.fail("probe resolved hostname"))
    result = worker.probe({"ip": "8.8.8.8", "port": 80, "method": "http", "host": "public.com", "url": "http://public.com/"})
    assert sock.connected == ("8.8.8.8", 80)
    assert result["body_preview"] == "Hello"


def test_scanner_composes_public_arm_contract(monkeypatch):
    from extension.arms.nmap import NmapArm
    from extension.contract import Result
    calls = []
    def fake(self, spec, action, payload):
        calls.append((action, payload))
        return Result(True, "nmap", "scan", {"output": '<nmaprun><host><ports><port portid="443"><state state="open"/><service name="https" product="Demo" version="1.2" extrainfo="password=secret"/></port></ports></host></nmaprun>'})
    monkeypatch.setattr(NmapArm, "invoke", fake)
    result = worker.probe({"ip": "8.8.8.8", "port": 443, "method": "nmap"})
    assert calls == [("scan", {"target": "8.8.8.8", "mode": "version-light", "ports": [443]})]
    observation = result["observations"][0]
    assert observation["version"] == "1.2" and observation["product"] == "Demo"
    assert observation["extrainfo"] == "[REDACTED]"


def test_registry_overview_projects_bound_holder(monkeypatch):
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: ({"status": "ok", "data": {"resource": "AS65552", "holder": "Example Holder"}}, HASH))
    response = worker.collect("registry", "asn", "65552", "overview")
    assert response["data"] == [{"asn": 65552, "organization": "Example Holder"}]


def test_registry_normalizes_real_ripestat_string_asn_fixture(monkeypatch):
    captured = json.loads(
        (FIXTURES / "ripe-stat-network-info-8.8.8.8.json").read_text(encoding="utf-8")
    )
    assert captured["data"]["asns"] == ["15169"]  # Provider's actual wire shape.
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: (captured, HASH))
    response = worker.collect("registry", "ip", "8.8.8.8")
    assert response["data"] == [
        {"ip": "8.8.8.8", "prefix": "8.8.8.0/24", "asn": 15169}
    ]


@pytest.mark.parametrize("asn", ["", "AS15169", "15.169", "-1", "4294967296"])
def test_registry_rejects_non_wire_asn_strings(monkeypatch, asn):
    captured = {
        "status": "ok",
        "data": {"asns": [asn], "prefix": "8.8.8.0/24"},
    }
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: (captured, HASH))
    with pytest.raises(Refusal, match="ASN"):
        worker.collect("registry", "ip", "8.8.8.8")


def test_registry_network_info_must_bind_queried_ip(monkeypatch):
    response = {"status": "ok", "data": {"prefix": "1.1.1.0/24", "asns": [13335]}}
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: (response, HASH))
    with pytest.raises(Refusal):
        worker.collect("registry", "ip", "8.8.8.8")


def test_shodan_live_results_must_bind_query(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fixture-key")
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: ({"ip_str": "1.1.1.1"}, HASH))
    with pytest.raises(Refusal):
        worker.collect("shodan", "ip", "8.8.8.8")
    mismatch = {"total": 1, "matches": [{
        "ip_str": "8.8.8.8",
        "ssl": {"cert": {"fingerprint": {"sha256": "b" * 64}}},
    }]}
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: (mismatch, HASH))
    with pytest.raises(Refusal):
        worker.collect("shodan", "certificate", FP)


def test_provider_credentials_are_bounded_before_transport(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "line\nbreak")
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: pytest.fail("invalid credential reached transport"))
    with pytest.raises(Refusal):
        worker.collect("shodan", "ip", "8.8.8.8")
    with pytest.raises(Refusal):
        worker.credential("x" * 4097)


def test_zgrab_composition_retains_only_bounded_redacted_summary(monkeypatch):
    from extension.arms.zgrab2 import Zgrab2Arm
    from extension.contract import Result
    payload = {"data": {"banner": {"status": "success", "result": {
        "banner": "Demo password=secret", "padding": "x" * 1000,
    }}}}
    monkeypatch.setattr(
        Zgrab2Arm, "invoke",
        lambda *a, **k: Result(True, "zgrab2", "scan", {"output": payload}),
    )
    response = worker.probe({"ip": "8.8.8.8", "port": 443, "method": "zgrab2", "module": "banner"})
    observation = response["observations"][0]
    assert observation["status"] == "responded"
    assert "secret" not in observation["result_preview"]
    assert len(observation["result_preview"]) <= 512


def test_probe_refusal_category_survives_worker_redaction(monkeypatch):
    failure = {
        "ok": False,
        "reason": "connection_refused",
        "error": "operation failed [REDACTED]",
    }
    with pytest.raises(WorkerRefusal) as exc:
        _accept_result(failure, "probe")
    assert exc.value.reason == "connection_refused"
    with pytest.raises(Refusal) as untrusted:
        _accept_result({**failure, "reason": "secret-target"}, "probe")
    assert type(untrusted.value) is Refusal

    monkeypatch.setenv("ASSET_RECON_PROBE_SCOPE", "8.8.8.8")
    monkeypatch.setattr(
        arm, "run_worker", lambda *_args: (_ for _ in ()).throw(exc.value)
    )
    result = invoke(
        "probe",
        {"live": True, "targets": [{"ip": "8.8.8.8", "port": 80, "method": "tcp"}]},
    )
    assert result.ok is False
    assert result.error == "reason:probe_connection_refused"
    assert result.output["limitations"] == [
        "explicit probe refused: connection_refused"
    ]
    assert "[REDACTED]" not in result.error


def test_worker_failure_categories_never_include_exception_text():
    hostile = ConnectionRefusedError("secret target /operator/private")
    assert worker._failure_reason("probe", hostile) == "connection_refused"
    assert worker._failure_reason("collect", hostile) is None


def test_probe_partial_capture_stays_partial(monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROBE_SCOPE", "8.8.8.8")
    monkeypatch.setattr(arm, "run_worker", lambda *a: {"ok": True, "complete": False, "http_status": 200, "body_preview": "partial"})
    result = invoke("probe", {"live": True, "targets": [{"ip": "8.8.8.8", "port": 80, "method": "http", "url": "http://8.8.8.8/"}]})
    assert not result.ok and result.output["status"] == "partial" and result.output["probes"]


def test_probe_output_trimming_preserves_earlier_limitations(monkeypatch):
    monkeypatch.setenv("ASSET_RECON_PROBE_SCOPE", "8.8.8.8")
    monkeypatch.setattr(
        arm,
        "run_worker",
        lambda *a: {"ok": True, "complete": False, "body_preview": "x" * 5000},
    )
    result = invoke(
        "probe",
        {
            "live": True,
            "targets": [{"ip": "8.8.8.8", "port": 80, "method": "tcp"}],
            "limits": {"max_output_bytes": 4096},
        },
    )
    assert not result.ok and not result.output["probes"]
    assert result.output["limitations"] == [
        "explicit probe capture incomplete",
        "probe output budget reached",
    ]


def test_empty_discover_does_not_report_collection_success():
    assert not invoke("discover", {"seeds": {"domains": ["example.test"]}}).ok
