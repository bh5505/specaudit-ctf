"""Hermetic tests for tools/demo_alert_pairings.py (G3 durable)."""
from pathlib import Path

import pytest

from tools.demo_alert_pairings import extract_pairings

pytest.importorskip("duckdb")

ALERT = "demo_alert.csv"
ENDPOINT = "demo_alert_endpoint.csv"
SERVICE = "demo_service_endpoint.csv"

TABLES = ("demo_alert", "demo_alert_endpoint", "demo_service_endpoint")

PREDICATE = """
SELECT a.vendor_alert_id, a.alert_id, s.ip, s.port,
       a.mitre_tactic, a.mitre_technique, MAX(a.asr_rule) AS asr_rule,
       CASE WHEN a.ipv4_list = ae.ip THEN 'alert_asserted_direct'
            ELSE 'alert_endpoint_bridged' END AS provenance_class
FROM demo_alert a
JOIN demo_alert_endpoint ae
  ON ae.run_id = a.run_id AND ae.engagement_id = a.engagement_id
 AND ae.alert_id = a.alert_id
JOIN demo_service_endpoint s
  ON s.run_id = ae.run_id AND s.engagement_id = ae.engagement_id AND s.ip = ae.ip
WHERE a.mitre_technique IS NOT NULL AND TRIM(a.mitre_technique) <> ''
  AND a.is_active_state AND ae.is_active_state AND s.is_active
  AND s.ip IN ({placeholders})
GROUP BY 1,2,3,4,5,6,8
ORDER BY s.ip, s.port, a.alert_id
"""


def _silver(tmp_path: Path) -> Path:
    d = tmp_path / "ev"
    d.mkdir()
    (d / ALERT).write_text(
        "vendor_alert_id,alert_id,mitre_tactic,mitre_technique,asr_rule,"
        "ipv4_list,is_active_state,run_id,engagement_id\n"
        "VA-1,al-1,Initial Access,T1190,Rule-A,203.0.113.10,true,r1,e1\n"
        "VA-2,al-2,Execution,T1059,Rule-B,203.0.113.11,true,r1,e1\n",
        encoding="utf-8")
    (d / ENDPOINT).write_text(
        "alert_id,ip,is_active_state,run_id,engagement_id\n"
        "al-1,203.0.113.10,true,r1,e1\n"
        "al-2,203.0.113.11,true,r1,e1\n",
        encoding="utf-8")
    (d / SERVICE).write_text(
        "service_endpoint_id,ip,port,is_active,run_id,engagement_id\n"
        "svc-1,203.0.113.10,443,true,r1,e1\n"
        "svc-2,203.0.113.11,8443,true,r1,e1\n",
        encoding="utf-8")
    return d


def test_no_configuration_returns_empty(tmp_path):
    ev = _silver(tmp_path)
    # pairing tables and predicate are operator-supplied; without them the
    # result is an explicit empty, not an approximation
    assert extract_pairings(ev, ["203.0.113.10"]) == []
    assert extract_pairings(ev, ["203.0.113.10"], tables=TABLES) == []


def test_predicate_must_be_a_single_select(tmp_path):
    ev = _silver(tmp_path)
    with pytest.raises(ValueError, match="single SELECT"):
        extract_pairings(ev, ["203.0.113.10"], tables=TABLES,
                         join_predicate="SELECT 1; DROP TABLE demo_alert")


def test_extract_pairings_preserves_per_alert_identity(tmp_path):
    pairs = extract_pairings(_silver(tmp_path),
                             ["203.0.113.10", "203.0.113.11"],
                             tables=TABLES, join_predicate=PREDICATE)
    assert len(pairs) == 2
    p1 = next(p for p in pairs if p["vendor_alert_id"] == "VA-1")
    assert p1["mitre_technique"] == "T1190"
    assert p1["asr_rule"] == "Rule-A"
    assert p1["ip"] == "203.0.113.10" and p1["port"] == 443
    assert p1["provenance_class"] == "alert_asserted_direct"


def test_extract_pairings_focus_filters(tmp_path):
    pairs = extract_pairings(_silver(tmp_path), ["203.0.113.10"],
                             tables=TABLES, join_predicate=PREDICATE)
    # only the focused host survives
    assert pairs and all(p["ip"] == "203.0.113.10" for p in pairs)
