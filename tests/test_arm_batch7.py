"""Curated arms batch 7: R43, R35, R01, R33, R03, R34, R42, R15.

All eight arms are in-process read arms (no binary, no endpoint).
Tests use synthetic fixture files to verify fail-closed behavior,
argument validation, output capping, and list_tools shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from extension.contract import (
    ArmSpec,
    Catalog,
    CatalogEntry,
    Extension,
    NotInstalledError,
)

# --- Arm imports --------------------------------------------------------

from extension.arms.security_detections_mcp import ARM_ID as R43_ID, SecurityDetectionsMcpArm
from extension.arms.security_detections_mcp.policy import (
    ARG_KEYS as R43_KEYS,
    CAVEATS as R43_CAVEATS,
    ARMING as R43_ARMING,
)

from extension.arms.agentseal import ARM_ID as R35_ID, AgentSealArm
from extension.arms.agentseal.policy import (
    ARG_KEYS as R35_KEYS,
    CAVEATS as R35_CAVEATS,
    fixture_refusal,
)

from extension.arms.vulnify import ARM_ID as R01_ID, VulnifyArm
from extension.arms.vulnify.policy import (
    ARG_KEYS as R01_KEYS,
    feed_refusal,
)

from extension.arms.leonidas import ARM_ID as R33_ID, LeonidasArm
from extension.arms.leonidas.policy import (
    ARG_KEYS as R33_KEYS,
    corpus_refusal,
)

from extension.arms.specterops_skills import ARM_ID as R03_ID, SpecteropsSkillsArm
from extension.arms.specterops_skills.policy import (
    ARG_KEYS as R03_KEYS,
    catalog_refusal,
)

from extension.arms.detection_in_the_cloud import ARM_ID as R34_ID, DetectionInTheCloudArm
from extension.arms.detection_in_the_cloud.policy import (
    ARG_KEYS as R34_KEYS,
    playbook_dir_refusal,
)

from extension.arms.pentestkit import ARM_ID as R42_ID, PentestkitArm
from extension.arms.pentestkit.policy import (
    ARG_KEYS as R42_KEYS,
    ledger_refusal,
)

from extension.arms.collinear import ARM_ID as R15_ID, CollinearArm
from extension.arms.collinear.policy import (
    ARG_KEYS as R15_KEYS,
    scenarios_refusal,
)


# --- Helpers -----------------------------------------------------------

def _spec(arm_id: str) -> ArmSpec:
    return ArmSpec(
        id=arm_id,
        protocols=("cli",),
        curated=True,
        notes="test arm",
        tier="research",
    )


def _ext(arm_id: str, handler) -> Extension:
    entry = CatalogEntry(
        id=arm_id,
        kind="arm",
        protocols=("cli",),
        curated=True,
        notes="test arm row",
        tier="research",
    )
    return Extension(catalog=Catalog([entry]), arms={arm_id: handler})


# --- Fixtures -----------------------------------------------------------

@pytest.fixture
def detections_index(tmp_path: Path) -> Path:
    rules = [
        {"rule_id": "R001", "name": "Suspicious Login", "severity": "high", "category": "auth"},
        {"rule_id": "R002", "name": "Port Scan", "severity": "medium", "category": "network"},
        {"rule_id": "R003", "name": "Data Exfil", "severity": "critical", "category": "exfil"},
    ]
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules), encoding="utf-8")
    return path


@pytest.fixture
def detections_yaml_index(tmp_path: Path) -> Path:
    rules = [
        {"rule_id": "Y001", "name": "YAML Rule", "severity": "low"},
    ]
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.dump(rules), encoding="utf-8")
    return path


@pytest.fixture
def detections_wrapped_index(tmp_path: Path) -> Path:
    data = {"rules": [{"rule_id": "W001", "name": "Wrapped Rule", "severity": "high"}]}
    path = tmp_path / "wrapped.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def agentseal_fixture(tmp_path: Path) -> Path:
    data = {
        "scenarios": [
            {"id": "S1", "name": "SQL Injection", "findings": [{"type": "sqli", "path": "/api"}]},
            {"id": "S2", "name": "XSS Reflected", "findings": [{"type": "xss", "path": "/search"}]},
        ]
    }
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def vulnify_feed(tmp_path: Path) -> Path:
    feed = [
        {"cve_id": "CVE-2024-0001", "name": "Buffer Overflow", "severity": "critical", "description": "Heap overflow"},
        {"cve_id": "CVE-2024-0002", "name": "SQL Injection", "severity": "high", "description": "Auth bypass"},
    ]
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(feed), encoding="utf-8")
    return path


@pytest.fixture
def vulnify_jsonl_feed(tmp_path: Path) -> Path:
    lines = [
        json.dumps({"cve_id": "CVE-2024-0001", "name": "Vuln A", "severity": "high"}),
        json.dumps({"cve_id": "CVE-2024-0002", "name": "Vuln B", "severity": "low"}),
    ]
    path = tmp_path / "feed.jsonl"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


@pytest.fixture
def leonidas_corpus(tmp_path: Path) -> Path:
    data = {
        "techniques": [
            {"technique_id": "T-L01", "name": "S3 Public Bucket", "platform": "aws", "severity": "high",
             "executor": "aws s3api put-bucket-acl --bucket {{bucket}} --acl public-read"},
            {"technique_id": "T-L02", "name": "IAM Overprivileged", "platform": "aws", "severity": "medium",
             "executor": "aws iam attach-role-policy --role-name {{role}} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"},
        ]
    }
    path = tmp_path / "corpus.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


@pytest.fixture
def specterops_catalog(tmp_path: Path) -> Path:
    data = {
        "skills": [
            {"skill_id": "SK01", "name": "BloodHound Recon", "category": "ad", "description": "AD graph recon",
             "tool_mapping": "bloodhound", "steps": ["collect", "analyze"]},
            {"skill_id": "SK02", "name": "Kerberoasting", "category": "ad", "description": "SPN extraction",
             "tool_mapping": "rubeus", "steps": ["request", "crack"]},
        ]
    }
    path = tmp_path / "skills.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def detection_playbook_dir(tmp_path: Path) -> Path:
    pdir = tmp_path / "playbooks"
    pdir.mkdir()
    (pdir / "aws-s3.json").write_text(json.dumps({"name": "S3 Detection", "rules": [
        {"rule_id": "DR1", "name": "Public Bucket", "category": "s3", "severity": "high"}
    ]}), encoding="utf-8")
    (pdir / "aws-iam.yaml").write_text(yaml.dump({"name": "IAM Detection"}), encoding="utf-8")
    (pdir / "rules.json").write_text(json.dumps([
        {"rule_id": "R1", "name": "Root Login", "category": "iam", "severity": "critical"},
        {"rule_id": "R2", "name": "Unauth Access", "category": "auth", "severity": "high"},
    ]), encoding="utf-8")
    return pdir


@pytest.fixture
def pentestkit_ledger(tmp_path: Path) -> Path:
    data = [
        {"run_id": "run-001", "phase": "first_pass", "status": "pass", "score": 0.85},
        {"run_id": "run-002", "phase": "first_pass", "status": "fail", "score": 0.3},
        {"run_id": "run-003", "phase": "tuned", "status": "pass", "score": 0.92},
    ]
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def collinear_scenarios(tmp_path: Path) -> Path:
    data = {
        "scenarios": [
            {
                "scenario_id": "C1",
                "name": "Cloud Misconfig",
                "difficulty": "medium",
                "environment_type": "aws-sandbox",
                "description": "Find S3 misconfigurations",
                "environment_config": {"provider": "aws", "region": "us-east-1"},
                "task_brief": "Identify public S3 buckets",
                "expected_findings": [{"bucket": "data-lab", "issue": "public-read"}],
                "trace_keys": {"bucket": "data-lab"},
                "expected_evidence": ["s3:GetBucketAcl output"],
            }
        ]
    }
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ======================================================================
# R43: security-detections-mcp
# ======================================================================

class TestR43SecurityDetectionsMcp:
    def test_installed(self) -> None:
        arm = SecurityDetectionsMcpArm()
        assert arm.installed(_spec(R43_ID)) is True
        assert arm.installed(_spec("other")) is False

    def test_list_tools(self) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "list_tools", {})
        assert result.ok is True
        assert "list_rules" in result.output["read_actions"]
        assert result.output["dispatch_actions"] == []

    def test_list_rules(self, detections_index: Path) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "list_rules", {"index": str(detections_index)})
        assert result.ok is True
        assert result.output["total"] == 3
        assert len(result.output["rules"]) == 3
        assert result.output["rules"][0]["rule_id"] == "R001"

    def test_list_rules_yaml(self, detections_yaml_index: Path) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "list_rules", {"index": str(detections_yaml_index)})
        assert result.ok is True
        assert result.output["total"] == 1

    def test_list_rules_wrapped(self, detections_wrapped_index: Path) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "list_rules", {"index": str(detections_wrapped_index)})
        assert result.ok is True
        assert result.output["total"] == 1

    def test_search_rules(self, detections_index: Path) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "search_rules", {"index": str(detections_index), "query": "port"})
        assert result.ok is True
        assert result.output["total"] == 1
        assert result.output["rules"][0]["rule_id"] == "R002"

    def test_get_rule(self, detections_index: Path) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "get_rule", {"index": str(detections_index), "rule_id": "R003"})
        assert result.ok is True
        assert result.output["name"] == "Data Exfil"

    def test_get_rule_not_found(self, detections_index: Path) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "get_rule", {"index": str(detections_index), "rule_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_unknown_action(self, detections_index: Path) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "scan", {"index": str(detections_index)})
        assert result.ok is False and "not on the allowlist" in result.error

    def test_url_refused(self) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "list_rules", {"index": "https://example.com/rules.json"})
        assert result.ok is False and "local file, not a URL" in result.error

    def test_extra_args_refused(self, detections_index: Path) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "list_rules", {"index": str(detections_index), "extra": "x"})
        assert result.ok is False and "unexpected" in result.error


# ======================================================================
# R35: agentseal
# ======================================================================

class TestR35AgentSeal:
    def test_installed(self) -> None:
        arm = AgentSealArm()
        assert arm.installed(_spec(R35_ID)) is True

    def test_list_tools(self) -> None:
        ext = _ext(R35_ID, AgentSealArm())
        result = ext.invoke(R35_ID, "list_tools", {})
        assert result.ok is True
        assert "analyze" in result.output["read_actions"]

    def test_analyze(self, agentseal_fixture: Path) -> None:
        ext = _ext(R35_ID, AgentSealArm())
        result = ext.invoke(R35_ID, "analyze", {"fixture": str(agentseal_fixture)})
        assert result.ok is True
        scenarios = result.output.get("scenarios") or result.output.get("items")
        assert scenarios is not None
        assert len(scenarios) == 2

    def test_analyze_with_scenario_id(self, agentseal_fixture: Path) -> None:
        ext = _ext(R35_ID, AgentSealArm())
        result = ext.invoke(R35_ID, "analyze", {"fixture": str(agentseal_fixture), "scenario_id": "S1"})
        assert result.ok is True

    def test_list_scenarios(self, agentseal_fixture: Path) -> None:
        ext = _ext(R35_ID, AgentSealArm())
        result = ext.invoke(R35_ID, "list_scenarios", {"fixture": str(agentseal_fixture)})
        assert result.ok is True

    def test_url_refused(self) -> None:
        ext = _ext(R35_ID, AgentSealArm())
        result = ext.invoke(R35_ID, "analyze", {"fixture": "https://example.com/f.json"})
        assert result.ok is False and "local file, not a URL" in result.error

    def test_unknown_action(self, agentseal_fixture: Path) -> None:
        ext = _ext(R35_ID, AgentSealArm())
        result = ext.invoke(R35_ID, "scan", {"fixture": str(agentseal_fixture)})
        assert result.ok is False and "not on the allowlist" in result.error


# ======================================================================
# R01: vulnify
# ======================================================================

class TestR01Vulnify:
    def test_installed(self) -> None:
        arm = VulnifyArm()
        assert arm.installed(_spec(R01_ID)) is True

    def test_list_tools(self) -> None:
        ext = _ext(R01_ID, VulnifyArm())
        result = ext.invoke(R01_ID, "list_tools", {})
        assert result.ok is True
        assert "lookup" in result.output["read_actions"]

    def test_lookup_by_cve(self, vulnify_feed: Path) -> None:
        ext = _ext(R01_ID, VulnifyArm())
        result = ext.invoke(R01_ID, "lookup", {"feed": str(vulnify_feed), "cve_id": "CVE-2024-0001"})
        assert result.ok is True
        assert result.output["cve_id"] == "CVE-2024-0001"

    def test_lookup_not_found(self, vulnify_feed: Path) -> None:
        ext = _ext(R01_ID, VulnifyArm())
        result = ext.invoke(R01_ID, "lookup", {"feed": str(vulnify_feed), "cve_id": "CVE-9999-9999"})
        assert result.ok is False and "not found" in result.error

    def test_list_vulns(self, vulnify_feed: Path) -> None:
        ext = _ext(R01_ID, VulnifyArm())
        result = ext.invoke(R01_ID, "list_vulns", {"feed": str(vulnify_feed)})
        assert result.ok is True
        assert isinstance(result.output, list)
        assert len(result.output) == 2

    def test_jsonl_feed(self, vulnify_jsonl_feed: Path) -> None:
        ext = _ext(R01_ID, VulnifyArm())
        result = ext.invoke(R01_ID, "lookup", {"feed": str(vulnify_jsonl_feed), "cve_id": "CVE-2024-0002"})
        assert result.ok is True
        assert result.output["name"] == "Vuln B"

    def test_url_refused(self) -> None:
        ext = _ext(R01_ID, VulnifyArm())
        result = ext.invoke(R01_ID, "lookup", {"feed": "https://x/v.json", "cve_id": "CVE-2024-0001"})
        assert result.ok is False and "local file, not a URL" in result.error


# ======================================================================
# R33: leonidas
# ======================================================================

class TestR33Leonidas:
    def test_installed(self) -> None:
        arm = LeonidasArm()
        assert arm.installed(_spec(R33_ID)) is True

    def test_list_tools(self) -> None:
        ext = _ext(R33_ID, LeonidasArm())
        result = ext.invoke(R33_ID, "list_tools", {})
        assert result.ok is True
        assert "technique" in result.output["read_actions"]

    def test_technique_by_id(self, leonidas_corpus: Path) -> None:
        ext = _ext(R33_ID, LeonidasArm())
        result = ext.invoke(R33_ID, "technique", {"corpus": str(leonidas_corpus), "technique_id": "T-L01"})
        assert result.ok is True
        assert result.output["name"] == "S3 Public Bucket"
        assert "executor" in result.output

    def test_technique_not_found(self, leonidas_corpus: Path) -> None:
        ext = _ext(R33_ID, LeonidasArm())
        result = ext.invoke(R33_ID, "technique", {"corpus": str(leonidas_corpus), "technique_id": "T-NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_techniques(self, leonidas_corpus: Path) -> None:
        ext = _ext(R33_ID, LeonidasArm())
        result = ext.invoke(R33_ID, "list_techniques", {"corpus": str(leonidas_corpus)})
        assert result.ok is True
        assert result.output["total"] == 2

    def test_url_refused(self) -> None:
        ext = _ext(R33_ID, LeonidasArm())
        result = ext.invoke(R33_ID, "technique", {"corpus": "https://x/c.json", "technique_id": "T-L01"})
        assert result.ok is False and "local file, not a URL" in result.error


# ======================================================================
# R03: specterops-skills
# ======================================================================

class TestR03SpecteropsSkills:
    def test_installed(self) -> None:
        arm = SpecteropsSkillsArm()
        assert arm.installed(_spec(R03_ID)) is True

    def test_list_tools(self) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        result = ext.invoke(R03_ID, "list_tools", {})
        assert result.ok is True
        assert "skill" in result.output["read_actions"]

    def test_skill_by_id(self, specterops_catalog: Path) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        result = ext.invoke(R03_ID, "skill", {"catalog": str(specterops_catalog), "skill_id": "SK01"})
        assert result.ok is True
        assert result.output["name"] == "BloodHound Recon"

    def test_skill_not_found(self, specterops_catalog: Path) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        result = ext.invoke(R03_ID, "skill", {"catalog": str(specterops_catalog), "skill_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_skills(self, specterops_catalog: Path) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        result = ext.invoke(R03_ID, "list_skills", {"catalog": str(specterops_catalog)})
        assert result.ok is True
        assert result.output["count"] == 2

    def test_list_skills_by_category(self, specterops_catalog: Path) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        result = ext.invoke(R03_ID, "list_skills", {"catalog": str(specterops_catalog), "category": "ad"})
        assert result.ok is True
        assert result.output["count"] == 2

    def test_url_refused(self) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        result = ext.invoke(R03_ID, "skill", {"catalog": "https://x/s.json", "skill_id": "SK01"})
        assert result.ok is False and "local file, not a URL" in result.error


# ======================================================================
# R34: detection-in-the-cloud
# ======================================================================

class TestR34DetectionInTheCloud:
    def test_installed(self) -> None:
        arm = DetectionInTheCloudArm()
        assert arm.installed(_spec(R34_ID)) is True

    def test_list_tools(self) -> None:
        ext = _ext(R34_ID, DetectionInTheCloudArm())
        result = ext.invoke(R34_ID, "list_tools", {})
        assert result.ok is True
        assert "playbook" in result.output["read_actions"]

    def test_playbook(self, detection_playbook_dir: Path) -> None:
        ext = _ext(R34_ID, DetectionInTheCloudArm())
        result = ext.invoke(R34_ID, "playbook", {"playbook_dir": str(detection_playbook_dir), "name": "aws-s3"})
        assert result.ok is True
        assert result.output["name"] == "S3 Detection"

    def test_playbook_not_found(self, detection_playbook_dir: Path) -> None:
        ext = _ext(R34_ID, DetectionInTheCloudArm())
        result = ext.invoke(R34_ID, "playbook", {"playbook_dir": str(detection_playbook_dir), "name": "nope"})
        assert result.ok is False and "not found" in result.error

    def test_list_playbooks(self, detection_playbook_dir: Path) -> None:
        ext = _ext(R34_ID, DetectionInTheCloudArm())
        result = ext.invoke(R34_ID, "list_playbooks", {"playbook_dir": str(detection_playbook_dir)})
        assert result.ok is True
        assert result.output["total"] >= 2

    def test_list_rules(self, detection_playbook_dir: Path) -> None:
        ext = _ext(R34_ID, DetectionInTheCloudArm())
        result = ext.invoke(R34_ID, "list_rules", {"playbook_dir": str(detection_playbook_dir)})
        assert result.ok is True
        assert result.output["total"] == 2

    def test_dir_refusal_file(self, tmp_path: Path) -> None:
        f = tmp_path / "not-a-dir.json"
        f.write_text("{}", encoding="utf-8")
        ext = _ext(R34_ID, DetectionInTheCloudArm())
        result = ext.invoke(R34_ID, "playbook", {"playbook_dir": str(f), "name": "x"})
        assert result.ok is False and "not a directory" in result.error


# ======================================================================
# R42: pentestkit
# ======================================================================

class TestR42Pentestkit:
    def test_installed(self) -> None:
        arm = PentestkitArm()
        assert arm.installed(_spec(R42_ID)) is True

    def test_list_tools(self) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "list_tools", {})
        assert result.ok is True
        assert "result" in result.output["read_actions"]

    def test_result_by_run_id(self, pentestkit_ledger: Path) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "result", {"ledger": str(pentestkit_ledger), "run_id": "run-001"})
        assert result.ok is True
        assert result.output["status"] == "pass"
        assert result.output["score"] == 0.85

    def test_result_not_found(self, pentestkit_ledger: Path) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "result", {"ledger": str(pentestkit_ledger), "run_id": "nope"})
        assert result.ok is False and "not found" in result.error

    def test_list_results(self, pentestkit_ledger: Path) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "list_results", {"ledger": str(pentestkit_ledger)})
        assert result.ok is True
        assert result.output["total"] == 3

    def test_list_results_filtered(self, pentestkit_ledger: Path) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "list_results", {"ledger": str(pentestkit_ledger), "phase": "first_pass"})
        assert result.ok is True
        assert result.output["total"] == 2

    def test_summary(self, pentestkit_ledger: Path) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "summary", {"ledger": str(pentestkit_ledger)})
        assert result.ok is True
        assert result.output["total_runs"] == 3

    def test_url_refused(self) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "result", {"ledger": "https://x/l.json", "run_id": "run-001"})
        assert result.ok is False and "local file, not a URL" in result.error


# ======================================================================
# R15: collinear
# ======================================================================

class TestR15Collinear:
    def test_installed(self) -> None:
        arm = CollinearArm()
        assert arm.installed(_spec(R15_ID)) is True

    def test_list_tools(self) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "list_tools", {})
        assert result.ok is True
        assert "scenario" in result.output["read_actions"]

    def test_scenario_strips_answer_data(self, collinear_scenarios: Path) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "scenario", {"scenarios_file": str(collinear_scenarios), "scenario_id": "C1"})
        assert result.ok is True
        assert "expected_findings" not in result.output
        assert "trace_keys" not in result.output
        assert "expected_evidence" not in result.output
        assert result.output["description"] == "Find S3 misconfigurations"

    def test_scenario_not_found(self, collinear_scenarios: Path) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "scenario", {"scenarios_file": str(collinear_scenarios), "scenario_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_scenarios(self, collinear_scenarios: Path) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "list_scenarios", {"scenarios_file": str(collinear_scenarios)})
        assert result.ok is True
        assert result.output["total"] == 1
        # Verify answer data not in listing
        item = result.output["scenarios"][0]
        assert "expected_findings" not in item

    def test_verify_returns_scoring(self, collinear_scenarios: Path) -> None:
        ext = _ext(R15_ID, CollinearArm())
        submission = {"findings": [{"bucket": "data-lab", "issue": "public-read"}]}
        result = ext.invoke(R15_ID, "verify", {
            "scenarios_file": str(collinear_scenarios),
            "scenario_id": "C1",
            "submission": submission,
        })
        assert result.ok is True
        assert "score" in result.output or "verdict" in result.output
        # Must not expose expected answers
        assert "expected_findings" not in result.output

    def test_verify_not_found(self, collinear_scenarios: Path) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "verify", {
            "scenarios_file": str(collinear_scenarios),
            "scenario_id": "NOPE",
            "submission": {"findings": []},
        })
        assert result.ok is False and "not found" in result.error

    def test_url_refused(self) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "scenario", {"scenarios_file": "https://x/s.json", "scenario_id": "C1"})
        assert result.ok is False and "local file, not a URL" in result.error


# ======================================================================
# Common: not-installed raises for wrong id
# ======================================================================

@pytest.mark.parametrize("arm_id,handler", [
    (R43_ID, SecurityDetectionsMcpArm()),
    (R35_ID, AgentSealArm()),
    (R01_ID, VulnifyArm()),
    (R33_ID, LeonidasArm()),
    (R03_ID, SpecteropsSkillsArm()),
    (R34_ID, DetectionInTheCloudArm()),
    (R42_ID, PentestkitArm()),
    (R15_ID, CollinearArm()),
])
def test_wrong_id_raises(arm_id: str, handler) -> None:
    with pytest.raises(NotInstalledError):
        handler.invoke(_spec("wrong-id"), "list_tools", {})
