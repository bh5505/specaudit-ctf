"""Hermetic tests for tools/demo_rank_hosts.py (G4 asset)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import demo_rank_hosts  # noqa: E402


def _rollup():
    tiers = {
        "C_port_corroborated": ["198.51.100.7"],
        "B_inverse_internal_only": ["203.0.113.9"],
        "A_flagship_ip_only": ["198.51.100.7", "203.0.113.9"],
    }
    hosts = [
        # C-tier host, direct provenance, many rows/stages -> must rank first
        {"ip": "198.51.100.7", "t3_rows": 10,
         "stages_observed": ["TA0001", "TA0002", "TA0004"], "prov_mix":
            {"alert_asserted_direct": 8, "alert_endpoint_bridged": 2}},
        # same non-C tier A only; bridged dominant -> lower
        {"ip": "203.0.113.9", "t3_rows": 4,
         "stages_observed": ["TA0006"], "prov_mix": {"alert_endpoint_bridged": 4}},
        # no context at all -> zero-factor baseline
        {"ip": "192.0.2.1", "t3_rows": 0,
         "stages_observed": [], "prov_mix": {}},
    ]
    risk = [{"ip": "198.51.100.7", "risk_max": 40}, {"ip": "203.0.113.9", "risk_max": 20},
            {"ip": "192.0.2.1", "risk_max": 0}]
    return {"tiers": tiers, "rollup_top_risk": risk, "hosts_ranked": hosts}


def test_rule_weights_and_tier_boost_order():
    ranked = demo_rank_hosts.rank_hosts(_rollup())
    assert [r["ip"] for r in ranked] == ["198.51.100.7", "203.0.113.9", "192.0.2.1"]
    top, mid, base = ranked
    # manual rule arithmetic for cross-checks
    assert top["score"] == round(100 + 30 + min(10, 50) * 0.5 + 3 * 1.0 + 40, 1)
    assert mid["score"] == round(15 + min(4, 50) * 0.5 + 1.0 + 20, 1)
    assert base["score"] == round(15 + 0 + 0 + 0, 1)


def test_badges_and_dominant_provenance_choice():
    ranked = demo_rank_hosts.rank_hosts(_rollup())
    top = ranked[0]
    assert top["tier_badges"] == "[C][A]" and top["provenance_dominant"] == \
        "alert_asserted_direct"
    # tie on count -> lexicographic dominance falls to the larger-count key anyway;
    # verify bridged-only host reports bridged
    mid = next(r for r in ranked if r["ip"] == "203.0.113.9")
    assert mid["provenance_dominant"] == "alert_endpoint_bridged"


def test_rule_text_documented():
    assert "100*C-tier" in demo_rank_hosts.RULE_TEXT and "0.5*min(rows,50)" in \
        demo_rank_hosts.RULE_TEXT
