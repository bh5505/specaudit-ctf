"""Curated arms Tier 4: R02, R08, R25, R17, R36, R38.

All six arms are in-process read arms (no binary, no endpoint).
Tests use synthetic fixture files to verify fail-closed behavior,
argument validation, output capping, and list_tools shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extension.contract import (
    ArmSpec,
    Catalog,
    CatalogEntry,
    Extension,
    NotInstalledError,
)

from extension.arms.ad_pathfinder import ARM_ID as R02_ID, AdPathfinderArm
from extension.arms.gpohound import ARM_ID as R08_ID, GpohoundArm
from extension.arms.claude_ad import ARM_ID as R25_ID, ClaudeAdArm
from extension.arms.numasec import ARM_ID as R17_ID, NumasecArm
from extension.arms.rubeus import ARM_ID as R36_ID, RubeusArm
from extension.arms.m365pwned import ARM_ID as R38_ID, M365PwnedArm


def _spec(arm_id: str) -> ArmSpec:
    return ArmSpec(id=arm_id, protocols=("cli",), curated=True, notes="test", tier="research")


def _ext(arm_id: str, handler) -> Extension:
    entry = CatalogEntry(id=arm_id, kind="arm", protocols=("cli",), curated=True, notes="test", tier="research")
    return Extension(catalog=Catalog([entry]), arms={arm_id: handler})


# --- Fixtures ---

@pytest.fixture
def ad_export(tmp_path: Path) -> Path:
    data = [
        {"path_id": "P1", "source": "DC01", "target": "SQL01", "length": 3, "risk_score": 8.5,
         "nodes": ["DC01", "FILE01", "SQL01"], "edges": [{"from": "DC01", "to": "FILE01"}, {"from": "FILE01", "to": "SQL01"}],
         "datasource": "BloodHound"},
        {"path_id": "P2", "source": "DC01", "target": "WEB01", "length": 2, "risk_score": 6.0,
         "nodes": ["DC01", "WEB01"], "edges": [{"from": "DC01", "to": "WEB01"}],
         "datasource": None},
    ]
    path = tmp_path / "export.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def gpo_evidence(tmp_path: Path) -> Path:
    data = [
        {"policy_id": "GPO-001", "name": "Default Domain Policy", "status": "active",
         "links": [{"ou": "DC=corp,DC=local", "enforced": True}],
         "filters": {"security": ["S-1-5-21-123"], "wmi": []},
         "settings": {"password_policy": {"min_length": 12}}},
        {"policy_id": "GPO-002", "name": "Legacy Policy", "status": "disabled",
         "links": [], "filters": {}, "settings": {}},
    ]
    path = tmp_path / "gpo.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def ad_method(tmp_path: Path) -> Path:
    data = {
        "techniques": [
            {"technique_id": "AD-01", "name": "Kerberoasting", "category": "credential",
             "prerequisites": ["valid domain account", "SPN registered"],
             "observed_facts": ["TGS request for SPN"],
             "inference": "Service account password may be crackable",
             "mitre_mapping": "T1558.003"},
            {"technique_id": "AD-02", "name": "DCSync", "category": "credential",
             "prerequisites": ["Replication rights"],
             "observed_facts": ["DRSUAPI RPC calls"],
             "inference": "Full credential dump possible",
             "mitre_mapping": "T1003.006"},
        ]
    }
    path = tmp_path / "method.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def finding_ledger(tmp_path: Path) -> Path:
    data = [
        {"finding_id": "F001", "title": "Weak Password Policy", "status": "open",
         "severity": "high",
         "transitions": [
             {"from": "new", "to": "open", "actor": "analyst-1", "reason": "validated", "ts": "2026-09-01T10:00:00Z"},
         ]},
        {"finding_id": "F002", "title": "Missing Encryption", "status": "resolved",
         "severity": "medium",
         "transitions": [
             {"from": "new", "to": "open", "actor": "analyst-2", "reason": "confirmed", "ts": "2026-09-02T10:00:00Z"},
             {"from": "open", "to": "resolved", "actor": "dev-1", "reason": "fixed", "ts": "2026-09-03T10:00:00Z"},
         ]},
    ]
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def ad_telemetry(tmp_path: Path) -> Path:
    data = [
        {"event_id": "E001", "category": "kerberos", "description": "AS-REQ with unusual encryption",
         "severity": "medium", "indicators": [{"type": "encryption_type", "value": "[REDACTED]"}]},
        {"event_id": "E002", "category": "ldap", "description": "Large LDAP query",
         "severity": "low", "indicators": [{"type": "query_size", "value": "[REDACTED]"}]},
    ]
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def m365_cases(tmp_path: Path) -> Path:
    data = [
        {"case_id": "C001", "name": "Consent Phish", "description": "OAuth consent phishing",
         "risk_level": "high",
         "consent_flow": {"user_action": "clicked approve", "app_permissions": ["Mail.Read"]},
         "data_access": {"mailbox_count": 1, "files_accessed": 0},
         "permissions": ["Mail.Read", "User.Read"],
         "risk_assessment": "High risk: full mailbox read access granted to external app"},
        {"case_id": "C002", "name": "Legacy Auth", "description": "Basic auth enabled",
         "risk_level": "medium",
         "consent_flow": {}, "data_access": {}, "permissions": [],
         "risk_assessment": "Medium risk: no MFA enforcement"},
    ]
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ======================================================================
# R02: AD-PathFinder
# ======================================================================

class TestR02AdPathfinder:
    def test_installed(self) -> None:
        assert AdPathfinderArm().installed(_spec(R02_ID)) is True
        assert AdPathfinderArm().installed(_spec("other")) is False

    def test_list_tools(self) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(R02_ID, "list_tools", {})
        assert result.ok is True and "path" in result.output["read_actions"]

    def test_path_by_id(self, ad_export: Path) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(R02_ID, "path", {"export": str(ad_export), "path_id": "P1"})
        assert result.ok is True and result.output["source"] == "DC01"

    def test_path_not_found(self, ad_export: Path) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(R02_ID, "path", {"export": str(ad_export), "path_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_paths(self, ad_export: Path) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(R02_ID, "list_paths", {"export": str(ad_export)})
        assert result.ok is True and result.output["total"] == 2

    def test_list_datasources(self, ad_export: Path) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(R02_ID, "list_datasources", {"export": str(ad_export)})
        assert result.ok is True

    def test_url_refused(self) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(R02_ID, "path", {"export": "https://x/e.json", "path_id": "P1"})
        assert result.ok is False and "local file, not a URL" in result.error


# ======================================================================
# R08: GPOHound
# ======================================================================

class TestR08Gpohound:
    def test_installed(self) -> None:
        assert GpohoundArm().installed(_spec(R08_ID)) is True

    def test_list_tools(self) -> None:
        result = _ext(R08_ID, GpohoundArm()).invoke(R08_ID, "list_tools", {})
        assert result.ok is True and "policy" in result.output["read_actions"]

    def test_policy_by_id(self, gpo_evidence: Path) -> None:
        result = _ext(R08_ID, GpohoundArm()).invoke(R08_ID, "policy", {"evidence": str(gpo_evidence), "policy_id": "GPO-001"})
        assert result.ok is True and result.output["name"] == "Default Domain Policy"

    def test_policy_not_found(self, gpo_evidence: Path) -> None:
        result = _ext(R08_ID, GpohoundArm()).invoke(R08_ID, "policy", {"evidence": str(gpo_evidence), "policy_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_policies(self, gpo_evidence: Path) -> None:
        result = _ext(R08_ID, GpohoundArm()).invoke(R08_ID, "list_policies", {"evidence": str(gpo_evidence)})
        assert result.ok is True and result.output["total"] == 2

    def test_list_links(self, gpo_evidence: Path) -> None:
        result = _ext(R08_ID, GpohoundArm()).invoke(R08_ID, "list_links", {"evidence": str(gpo_evidence), "gpo_id": "GPO-001"})
        assert result.ok is True


# ======================================================================
# R25: Claude-AD
# ======================================================================

class TestR25ClaudeAd:
    def test_installed(self) -> None:
        assert ClaudeAdArm().installed(_spec(R25_ID)) is True

    def test_list_tools(self) -> None:
        result = _ext(R25_ID, ClaudeAdArm()).invoke(R25_ID, "list_tools", {})
        assert result.ok is True and "technique" in result.output["read_actions"]

    def test_technique_by_id(self, ad_method: Path) -> None:
        result = _ext(R25_ID, ClaudeAdArm()).invoke(R25_ID, "technique", {"method_file": str(ad_method), "technique_id": "AD-01"})
        assert result.ok is True and result.output["name"] == "Kerberoasting"
        assert "prerequisites" in result.output and "inference" in result.output

    def test_technique_not_found(self, ad_method: Path) -> None:
        result = _ext(R25_ID, ClaudeAdArm()).invoke(R25_ID, "technique", {"method_file": str(ad_method), "technique_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_techniques(self, ad_method: Path) -> None:
        result = _ext(R25_ID, ClaudeAdArm()).invoke(R25_ID, "list_techniques", {"method_file": str(ad_method)})
        assert result.ok is True and result.output["count"] == 2

    def test_list_prerequisites(self, ad_method: Path) -> None:
        result = _ext(R25_ID, ClaudeAdArm()).invoke(R25_ID, "list_prerequisites", {"method_file": str(ad_method)})
        assert result.ok is True


# ======================================================================
# R17: numasec
# ======================================================================

class TestR17Numasec:
    def test_installed(self) -> None:
        assert NumasecArm().installed(_spec(R17_ID)) is True

    def test_list_tools(self) -> None:
        result = _ext(R17_ID, NumasecArm()).invoke(R17_ID, "list_tools", {})
        assert result.ok is True and "finding" in result.output["read_actions"]

    def test_finding_by_id(self, finding_ledger: Path) -> None:
        result = _ext(R17_ID, NumasecArm()).invoke(R17_ID, "finding", {"ledger": str(finding_ledger), "finding_id": "F001"})
        assert result.ok is True and result.output["title"] == "Weak Password Policy"

    def test_finding_not_found(self, finding_ledger: Path) -> None:
        result = _ext(R17_ID, NumasecArm()).invoke(R17_ID, "finding", {"ledger": str(finding_ledger), "finding_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_findings(self, finding_ledger: Path) -> None:
        result = _ext(R17_ID, NumasecArm()).invoke(R17_ID, "list_findings", {"ledger": str(finding_ledger)})
        assert result.ok is True and isinstance(result.output, list) and len(result.output) == 2

    def test_list_transitions(self, finding_ledger: Path) -> None:
        result = _ext(R17_ID, NumasecArm()).invoke(R17_ID, "list_transitions", {"ledger": str(finding_ledger), "finding_id": "F002"})
        assert result.ok is True and len(result.output["transitions"]) == 2


# ======================================================================
# R36: Rubeus
# ======================================================================

class TestR36Rubeus:
    def test_installed(self) -> None:
        assert RubeusArm().installed(_spec(R36_ID)) is True

    def test_list_tools(self) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(R36_ID, "list_tools", {})
        assert result.ok is True and "telemetry" in result.output["read_actions"]

    def test_telemetry_by_id(self, ad_telemetry: Path) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(R36_ID, "telemetry", {"telemetry_file": str(ad_telemetry), "event_id": "E001"})
        assert result.ok is True and result.output["category"] == "kerberos"

    def test_telemetry_not_found(self, ad_telemetry: Path) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(R36_ID, "telemetry", {"telemetry_file": str(ad_telemetry), "event_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_telemetry(self, ad_telemetry: Path) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(R36_ID, "list_telemetry", {"telemetry_file": str(ad_telemetry)})
        assert result.ok is True and result.output["total"] == 2

    def test_list_indicators(self, ad_telemetry: Path) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(R36_ID, "list_indicators", {"telemetry_file": str(ad_telemetry)})
        assert result.ok is True


# ======================================================================
# R38: M365Pwned
# ======================================================================

class TestR38M365Pwned:
    def test_installed(self) -> None:
        assert M365PwnedArm().installed(_spec(R38_ID)) is True

    def test_list_tools(self) -> None:
        result = _ext(R38_ID, M365PwnedArm()).invoke(R38_ID, "list_tools", {})
        assert result.ok is True and "case_study" in result.output["read_actions"]

    def test_case_study_by_id(self, m365_cases: Path) -> None:
        result = _ext(R38_ID, M365PwnedArm()).invoke(R38_ID, "case_study", {"cases_file": str(m365_cases), "case_id": "C001"})
        assert result.ok is True and result.output["name"] == "Consent Phish"

    def test_case_study_not_found(self, m365_cases: Path) -> None:
        result = _ext(R38_ID, M365PwnedArm()).invoke(R38_ID, "case_study", {"cases_file": str(m365_cases), "case_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_case_studies(self, m365_cases: Path) -> None:
        result = _ext(R38_ID, M365PwnedArm()).invoke(R38_ID, "list_case_studies", {"cases_file": str(m365_cases)})
        assert result.ok is True and result.output["total"] == 2

    def test_list_permissions(self, m365_cases: Path) -> None:
        result = _ext(R38_ID, M365PwnedArm()).invoke(R38_ID, "list_permissions", {"cases_file": str(m365_cases), "case_id": "C001"})
        assert result.ok is True


# ======================================================================
# Common: not-installed raises for wrong id
# ======================================================================

@pytest.mark.parametrize("arm_id,handler", [
    (R02_ID, AdPathfinderArm()),
    (R08_ID, GpohoundArm()),
    (R25_ID, ClaudeAdArm()),
    (R17_ID, NumasecArm()),
    (R36_ID, RubeusArm()),
    (R38_ID, M365PwnedArm()),
])
def test_wrong_id_raises(arm_id: str, handler) -> None:
    with pytest.raises(NotInstalledError):
        handler.invoke(_spec("wrong-id"), "list_tools", {})
