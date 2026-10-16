"""Hermetic tests for tools/demo_rollup_hosts.py (durable rollup builder)."""
from tools.demo_rollup_hosts import build_rollup

TECH = "demo_pack_t3_technique_context"
CRIT = "demo_pack_t1_exposed"


def _tech(ip, port, prov="alert_asserted_direct",
          tactics="TA0001 - Initial Access, TA0002 - Execution"):
    return {"check_id": TECH, "record_locator": f"{ip}:{port} / service:x",
            "title": f"Technique context is not consumed for service {ip}:{port}",
            "details": f"technique=T1190 - X; tactic={tactics}; provenance_class={prov}; gap_count=1; consumer_predicate=absent",
            "severity": "high", "risk_score": 40}


def _crit(ip, risk=60, locator=None, severity="critical"):
    return {"check_id": CRIT, "record_locator": locator or f"host:{ip} / asset:{ip}",
            "title": f"finding {ip}", "severity": severity, "risk_score": risk}


def test_tiers_derived_from_content():
    finds = [_crit("1.1.1.1"),
             _crit("2.2.2.2", locator="2.2.2.2:443 / service:x"),
             _tech("1.1.1.1", 80)]
    r = build_rollup(finds)
    # severity-critical findings land in critical_flagship...
    assert r["tiers"]["critical_flagship"] == ["1.1.1.1", "2.2.2.2"]
    # ...and gain port_corroborated only when the locator carries an ip:port token
    assert r["tiers"]["port_corroborated"] == ["2.2.2.2"]
    # technique-carrying findings (details markers) land in technique_context
    assert r["tiers"]["technique_context"] == ["1.1.1.1"]


def test_port_corroborated_requires_ip_port_token():
    finds = [_crit("1.1.1.1", locator="1.1.1.1:8443 / service:x"),
             _crit("2.2.2.2", locator="host:2.2.2.2")]
    r = build_rollup(finds)
    assert r["tiers"]["port_corroborated"] == ["1.1.1.1"]
    assert set(r["tiers"]["critical_flagship"]) == {"1.1.1.1", "2.2.2.2"}


def test_non_critical_finding_contributes_risk_only():
    finds = [{"check_id": "demo_pack_t2_other", "record_locator": "host:9.9.9.9",
              "title": "note on 9.9.9.9", "severity": "high", "risk_score": 55}]
    r = build_rollup(finds)
    assert all(not ips for ips in r["tiers"].values())
    assert r["rollup_top_risk"] == [{"ip": "9.9.9.9", "risk_max": 55.0}]


def test_operator_tier_map_overrides_derivation():
    finds = [_crit("1.1.1.1", locator="1.1.1.1:443 / service:x"),
             _tech("2.2.2.2", 80)]
    r = build_rollup(finds, tier_for_check={CRIT: "flagship_ip_only",
                                            TECH: "bridge_context"})
    # mapped check ids use the operator's tier values verbatim...
    assert r["tiers"]["flagship_ip_only"] == ["1.1.1.1"]
    assert r["tiers"]["bridge_context"] == ["2.2.2.2"]
    # ...instead of the content-derived tiers
    assert "1.1.1.1" not in r["tiers"]["critical_flagship"]
    assert "1.1.1.1" not in r["tiers"]["port_corroborated"]
    assert "2.2.2.2" not in r["tiers"]["technique_context"]
    # technique context is still parsed from the details markers
    assert [h["ip"] for h in r["hosts_ranked"]] == ["2.2.2.2"]


def test_rollup_schema_feeds_ranking():
    finds = [_tech("1.1.1.1", 80, tactics="TA0001 - Initial Access")]
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
    finds = [_tech("1.1.1.1", 80, prov="alert_asserted_direct"),
             _tech("1.1.1.1", 443, prov="alert_endpoint_bridged")]
    r = build_rollup(finds)
    hr = [h for h in r["hosts_ranked"] if h["ip"] == "1.1.1.1"][0]
    assert hr["t3_rows"] == 2
    assert hr["prov_mix"] == {"alert_asserted_direct": 1, "alert_endpoint_bridged": 1}


def test_host_without_technique_context_excluded():
    finds = [_crit("9.9.9.9")]
    r = build_rollup(finds)
    assert all(h["ip"] != "9.9.9.9" for h in r["hosts_ranked"])
    assert "9.9.9.9" in r["tiers"]["critical_flagship"]
