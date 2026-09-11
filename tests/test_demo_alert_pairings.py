"""Hermetic tests for tools/demo_alert_pairings.py (G3 durable)."""
import json
from pathlib import Path

import pytest

from tools.demo_alert_pairings import extract_pairings

pytest.importorskip("duckdb")

ALERT = "ext_telecom_asmvm_alert.csv"
ENDPOINT = "ext_telecom_asmvm_alert_endpoint.csv"
SERVICE = "ext_telecom_asmvm_service_endpoint.csv"


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


def test_extract_pairings_preserves_per_alert_identity(tmp_path):
    pairs = extract_pairings(_silver(tmp_path),
                             ["203.0.113.10", "203.0.113.11"])
    assert len(pairs) == 2
    p1 = next(p for p in pairs if p["vendor_alert_id"] == "VA-1")
    assert p1["mitre_technique"] == "T1190"
    assert p1["asr_rule"] == "Rule-A"
    assert p1["ip"] == "203.0.113.10" and p1["port"] == 443
    assert p1["provenance_class"] == "alert_asserted_direct"


def test_extract_pairings_focus_filters(tmp_path):
    pairs = extract_pairings(_silver(tmp_path), ["203.0.113.10"])
    # only the focused host survives
    assert pairs and all(p["ip"] == "203.0.113.10" for p in pairs)
