"""Hermetic tests for tools/demo_rollup_hosts.py (durable rollup builder)."""
from tools.demo_rollup_hosts import T3, build_rollup

A = "ext_telecom_asmvm_t1_critical_vuln_on_exposed"
C = "ext_telecom_asmvm_t1_asmvm_critical_service_corroborated"
B = "ext_telecom_asmvm_t1_asmvm_critical_internal_record_only"


def _t3(ip, port, prov="alert_asserted_direct", tactics="TA0001 - Initial Access, TA0002 - Execution"):
    return {"check_id": T3, "record_locator": f"{ip}:{port} / service:x",
            "title": f"Technique context is not consumed for service {ip}:{port}",
            "details": f"technique=T1190 - X; tactic={tactics}; provenance_class={prov}; gap_count=1; consumer_predicate=absent",
            "risk_score": 40}


def _tier(check, ip, risk=60):
    return {"check_id": check, "record_locator": f"vm:asset:{ip} + asm:ip:{ip}",
            "title": f"finding {ip}", "risk_score": risk}


def test_tiers_derived_by_check_id():
    finds = [_tier(A, "1.1.1.1"), _tier(C, "2.2.2.2"), _tier(B, "3.3.3.3"),
             _t3("1.1.1.1", 80)]
    r = build_rollup(finds)
    assert "1.1.1.1" in r["tiers"]["A_flagship_ip_only"]
    assert "2.2.2.2" in r["tiers"]["C_port_corroborated"]
    assert "3.3.3.3" in r["tiers"]["B_inverse_internal_only"]
    assert "1.1.1.1" in r["tiers"]["T3_technique_context"]


def test_rollup_schema_feeds_ranking():
    finds = [_t3("1.1.1.1", 80, tactics="TA0001 - Initial Access")]
    r = build_rollup(finds)
    hr = r["hosts_ranked"]
    assert len(hr) == 1
    assert hr[0]["ip"] == "1.1.1.1"
    assert hr[0]["t3_rows"] == 1
    assert hr[0]["stages_observed"] == ["TA0001"]
    assert hr[0]["prov_mix"] == {"alert_asserted_direct": 1}
    assert r["rollup_top_risk"] == [{"ip": "1.1.1.1", "risk_max": 40.0}]
    # schema keys match what demo_rank_hosts.rank_hosts() reads
    assert {"tiers", "rollup_top_risk", "hosts_ranked"} == set(r.keys())


def test_mixed_provenance_rolls_up():
    finds = [_t3("1.1.1.1", 80, prov="alert_asserted_direct"),
             _t3("1.1.1.1", 443, prov="alert_endpoint_bridged")]
    r = build_rollup(finds)
    hr = [h for h in r["hosts_ranked"] if h["ip"] == "1.1.1.1"][0]
    assert hr["t3_rows"] == 2
    assert hr["prov_mix"] == {"alert_asserted_direct": 1, "alert_endpoint_bridged": 1}


def test_host_without_technique_context_excluded():
    finds = [_tier(A, "9.9.9.9")]
    r = build_rollup(finds)
    assert all(h["ip"] != "9.9.9.9" for h in r["hosts_ranked"])
    assert "9.9.9.9" in r["tiers"]["A_flagship_ip_only"]
