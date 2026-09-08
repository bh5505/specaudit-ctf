"""Curated arms batch 7: R43, R35, R01, R33, R03, R34, R42, R15.

All eight arms are in-process read arms (no binary, no endpoint).
Tests use synthetic fixture files to verify fail-closed behavior,
argument validation, output capping, and list_tools shape.
"""

from __future__ import annotations

import hashlib
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
from extension.arms.strict_data import StrictDataError, strict_json_loads
import extension.arms.strict_data as strict_data_module

# --- Arm imports --------------------------------------------------------

from extension.arms.security_detections_mcp import ARM_ID as R43_ID, SecurityDetectionsMcpArm
from extension.arms.security_detections_mcp import arm as r43_arm
from extension.arms.security_detections_mcp.policy import (
    ARG_KEYS as R43_KEYS,
    CAVEATS as R43_CAVEATS,
    ARMING as R43_ARMING,
)

from extension.arms.agentseal import ARM_ID as R35_ID, AgentSealArm
from extension.arms.agentseal import arm as r35_arm
from extension.arms.agentseal.policy import (
    ARG_KEYS as R35_KEYS,
    CAVEATS as R35_CAVEATS,
    fixture_refusal,
)

from extension.arms.vulnify import ARM_ID as R01_ID, VulnifyArm
from extension.arms.vulnify import arm as r01_arm
from extension.arms.vulnify.policy import (
    ARG_KEYS as R01_KEYS,
    feed_refusal,
)

from extension.arms.leonidas import ARM_ID as R33_ID, LeonidasArm
from extension.arms.leonidas import arm as r33_arm
from extension.arms.leonidas.policy import (
    ARG_KEYS as R33_KEYS,
    corpus_refusal,
)

from extension.arms.specterops_skills import ARM_ID as R03_ID, SpecteropsSkillsArm
from extension.arms.specterops_skills import arm as r03_arm
from extension.arms.specterops_skills.policy import (
    ARG_KEYS as R03_KEYS,
    catalog_refusal,
)

from extension.arms.detection_in_the_cloud import ARM_ID as R34_ID, DetectionInTheCloudArm
from extension.arms.detection_in_the_cloud import arm as r34_arm
from extension.arms.detection_in_the_cloud.policy import (
    ARG_KEYS as R34_KEYS,
    playbook_dir_refusal,
)

from extension.arms.pentestkit import ARM_ID as R42_ID, PentestkitArm
from extension.arms.pentestkit import arm as r42_arm
from extension.arms.pentestkit.policy import (
    ARG_KEYS as R42_KEYS,
    ledger_refusal,
)

from extension.arms.collinear import ARM_ID as R15_ID, CollinearArm
from extension.arms.collinear import arm as r15_arm
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


def _assert_file_source(
    output: dict, path: Path, original_bytes: bytes | None = None
) -> None:
    current_bytes = path.read_bytes()
    raw = current_bytes if original_bytes is None else original_bytes
    if original_bytes is not None:
        assert current_bytes == original_bytes
    assert output["source"] == {
        "kind": "operator-file",
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _rendered_output_bytes(output: object) -> int:
    return len(
        json.dumps(
            output, sort_keys=True, ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    )


@pytest.mark.parametrize("document", ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"])
def test_strict_json_decoder_refuses_every_nonfinite_spelling(document: str) -> None:
    with pytest.raises(StrictDataError, match="non-finite"):
        strict_json_loads(document)


@pytest.mark.parametrize("document", ["1e-9999", "-1e-9999"])
def test_strict_json_decoder_refuses_float_underflow(document: str) -> None:
    with pytest.raises(StrictDataError, match="underflows"):
        strict_json_loads(document)


def test_strict_json_decoder_bounds_structure_before_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def forbidden_decode(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        pytest.fail("over-budget JSON reached the materializing decoder")

    monkeypatch.setattr(strict_data_module.json, "loads", forbidden_decode)
    with pytest.raises(StrictDataError, match="node cap"):
        strict_json_loads("[0,0,0,0]", max_nodes=1)
    with pytest.raises(StrictDataError, match="nesting-depth cap"):
        strict_json_loads("[[0]]", max_depth=1)
    assert calls == 0


def test_strict_json_decoder_refuses_lone_surrogates() -> None:
    with pytest.raises(StrictDataError, match="Unicode scalar"):
        strict_json_loads('"\\ud800"')


# --- Fixtures -----------------------------------------------------------

@pytest.fixture
def detections_index(tmp_path: Path) -> Path:
    rules = [
        {"rule_id": "R001", "name": "Suspicious Login", "severity": "high", "category": "auth"},
        {"rule_id": "R002", "name": "Port Scan", "severity": "medium", "category": "network"},
        {"rule_id": "R003", "name": "Data Exfil", "severity": "critical", "category": "auth"},
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
            {"skill_id": "SK02", "name": "Kerberoasting", "category": "credential", "description": "SPN extraction",
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


def _fixture_data(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)


def _write_duplicate_mapping_key(
    path: Path, data: object, key: str, *, as_yaml: bool
) -> None:
    if not as_yaml:
        text = json.dumps(data)
        needle = f'"{key}":'
        assert needle in text
        path.write_text(
            text.replace(needle, f'"{key}": "shadowed", "{key}":', 1),
            encoding="utf-8",
        )
        return

    lines = yaml.safe_dump(data, sort_keys=False).splitlines()
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        indent = line[: len(line) - len(stripped)]
        if stripped.startswith(f"- {key}:"):
            lines[index] = f"{indent}- {key}: shadowed"
            lines.insert(index + 1, f"{indent}  {stripped[2:]}")
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return
        if stripped.startswith(f"{key}:"):
            lines.insert(index, f"{indent}{key}: shadowed")
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return
    raise AssertionError(f"fixture did not contain key {key!r}")


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
        assert result.output["returned"] == 3
        assert result.output["capped"] is False
        _assert_file_source(result.output, detections_index)

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
        result = ext.invoke(
            R43_ID,
            "search_rules",
            {"index": str(detections_index), "query": "auth", "limit": 1},
        )
        assert result.ok is True
        assert result.output["total"] == 2
        assert result.output["returned"] == 1
        assert result.output["capped"] is True
        assert result.output["rules"][0]["rule_id"] == "R001"
        _assert_file_source(result.output, detections_index)

    def test_get_rule(self, detections_index: Path) -> None:
        ext = _ext(R43_ID, SecurityDetectionsMcpArm())
        result = ext.invoke(R43_ID, "get_rule", {"index": str(detections_index), "rule_id": "R003"})
        assert result.ok is True
        assert result.output["rule"]["name"] == "Data Exfil"
        _assert_file_source(result.output, detections_index)

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
        _assert_file_source(result.output, agentseal_fixture)

    def test_analyze_with_scenario_id(self, agentseal_fixture: Path) -> None:
        ext = _ext(R35_ID, AgentSealArm())
        result = ext.invoke(R35_ID, "analyze", {"fixture": str(agentseal_fixture), "scenario_id": "S1"})
        assert result.ok is True
        assert result.output["total"] == 1
        assert [item["id"] for item in result.output["scenarios"]] == ["S1"]

    def test_scenario_selector_is_not_ignored_for_findings_only_fixture(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "findings.json"
        path.write_text(
            json.dumps({"findings": [{"type": "sqli", "path": "/api"}]}),
            encoding="utf-8",
        )
        result = _ext(R35_ID, AgentSealArm()).invoke(
            R35_ID,
            "analyze",
            {"fixture": str(path), "scenario_id": "S1"},
        )
        assert result.ok is False
        assert "findings-only" in result.error

    def test_list_scenarios(self, agentseal_fixture: Path) -> None:
        ext = _ext(R35_ID, AgentSealArm())
        result = ext.invoke(R35_ID, "list_scenarios", {"fixture": str(agentseal_fixture)})
        assert result.ok is True

    def test_analyze_preserves_both_top_level_evidence_containers(
        self, agentseal_fixture: Path
    ) -> None:
        data = json.loads(agentseal_fixture.read_text(encoding="utf-8"))
        data["findings"] = [{"type": "critical", "path": "/admin"}]
        agentseal_fixture.write_text(json.dumps(data), encoding="utf-8")
        result = _ext(R35_ID, AgentSealArm()).invoke(
            R35_ID, "analyze", {"fixture": str(agentseal_fixture)}
        )
        assert result.ok is True
        assert len(result.output["scenarios"]) == 2
        assert result.output["findings"] == data["findings"]
        assert result.output["scenario_total"] == 2
        assert result.output["finding_total"] == 1
        assert result.output["total"] == result.output["returned"] == 3
        _assert_file_source(result.output, agentseal_fixture)

        limited = _ext(R35_ID, AgentSealArm()).invoke(
            R35_ID,
            "analyze",
            {"fixture": str(agentseal_fixture), "limit": 1},
        )
        assert limited.ok is True
        assert limited.output["total"] == 3
        assert limited.output["returned"] == 1
        assert limited.output["scenario_returned"] == 1
        assert limited.output["finding_returned"] == 0
        assert limited.output["capped"] is True

        selected = _ext(R35_ID, AgentSealArm()).invoke(
            R35_ID,
            "analyze",
            {"fixture": str(agentseal_fixture), "scenario_id": "S1"},
        )
        assert selected.ok is False
        assert "unassociated top-level findings" in selected.error

    @pytest.mark.parametrize(
        "document",
        [
            {"findings": [{}]},
            {"scenarios": [{"id": "S1", "findings": [{}]}]},
        ],
    )
    def test_analyze_refuses_empty_finding_records(
        self, tmp_path: Path, document: dict
    ) -> None:
        path = tmp_path / "empty-finding.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        result = _ext(R35_ID, AgentSealArm()).invoke(
            R35_ID, "analyze", {"fixture": str(path)}
        )
        assert result.ok is False
        assert "non-empty mapping" in result.error

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
        assert result.output["vulnerability"]["cve_id"] == "CVE-2024-0001"
        _assert_file_source(result.output, vulnify_feed)

    def test_lookup_not_found(self, vulnify_feed: Path) -> None:
        ext = _ext(R01_ID, VulnifyArm())
        result = ext.invoke(R01_ID, "lookup", {"feed": str(vulnify_feed), "cve_id": "CVE-9999-9999"})
        assert result.ok is False and "not found" in result.error

    def test_list_vulns(self, vulnify_feed: Path) -> None:
        ext = _ext(R01_ID, VulnifyArm())
        result = ext.invoke(R01_ID, "list_vulns", {"feed": str(vulnify_feed)})
        assert result.ok is True
        assert len(result.output["vulnerabilities"]) == 2
        assert result.output["total"] == result.output["returned"] == 2
        assert result.output["capped"] is False
        _assert_file_source(result.output, vulnify_feed)

    def test_jsonl_feed(self, vulnify_jsonl_feed: Path) -> None:
        ext = _ext(R01_ID, VulnifyArm())
        result = ext.invoke(R01_ID, "lookup", {"feed": str(vulnify_jsonl_feed), "cve_id": "CVE-2024-0002"})
        assert result.ok is True
        assert result.output["vulnerability"]["name"] == "Vuln B"

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
        assert result.output["technique"]["name"] == "S3 Public Bucket"
        assert "executor" in result.output["technique"]
        _assert_file_source(result.output, leonidas_corpus)

    def test_technique_not_found(self, leonidas_corpus: Path) -> None:
        ext = _ext(R33_ID, LeonidasArm())
        result = ext.invoke(R33_ID, "technique", {"corpus": str(leonidas_corpus), "technique_id": "T-NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_techniques(self, leonidas_corpus: Path) -> None:
        ext = _ext(R33_ID, LeonidasArm())
        result = ext.invoke(R33_ID, "list_techniques", {"corpus": str(leonidas_corpus)})
        assert result.ok is True
        assert result.output["total"] == 2
        assert result.output["returned"] == 2
        assert result.output["capped"] is False
        _assert_file_source(result.output, leonidas_corpus)

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
        assert result.output["skill"]["name"] == "BloodHound Recon"
        _assert_file_source(result.output, specterops_catalog)

    def test_skill_not_found(self, specterops_catalog: Path) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        result = ext.invoke(R03_ID, "skill", {"catalog": str(specterops_catalog), "skill_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_skills(self, specterops_catalog: Path) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        result = ext.invoke(R03_ID, "list_skills", {"catalog": str(specterops_catalog)})
        assert result.ok is True
        assert result.output["count"] == 2
        assert result.output["total"] == result.output["returned"] == 2
        assert result.output["unfiltered_total"] == 2
        assert result.output["capped"] is False
        _assert_file_source(result.output, specterops_catalog)

    def test_list_skills_by_category(self, specterops_catalog: Path) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        result = ext.invoke(R03_ID, "list_skills", {"catalog": str(specterops_catalog), "category": "ad"})
        assert result.ok is True
        assert result.output["count"] == 1
        assert result.output["total"] == 1
        assert result.output["unfiltered_total"] == 2
        assert result.output["skills"][0]["skill_id"] == "SK01"

    def test_dual_selectors_must_identify_the_same_skill(
        self, specterops_catalog: Path
    ) -> None:
        ext = _ext(R03_ID, SpecteropsSkillsArm())
        consistent = ext.invoke(
            R03_ID,
            "skill",
            {
                "catalog": str(specterops_catalog),
                "skill_id": "SK01",
                "name": "BloodHound Recon",
            },
        )
        contradictory = ext.invoke(
            R03_ID,
            "skill",
            {
                "catalog": str(specterops_catalog),
                "skill_id": "SK01",
                "name": "Kerberoasting",
            },
        )
        assert consistent.ok is True
        assert contradictory.ok is False
        assert "do not identify the same skill" in contradictory.error

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
        assert result.output["playbook"]["name"] == "S3 Detection"
        _assert_file_source(result.output, detection_playbook_dir / "aws-s3.json")

    def test_playbook_not_found(self, detection_playbook_dir: Path) -> None:
        ext = _ext(R34_ID, DetectionInTheCloudArm())
        result = ext.invoke(R34_ID, "playbook", {"playbook_dir": str(detection_playbook_dir), "name": "nope"})
        assert result.ok is False and "not found" in result.error

    @pytest.mark.parametrize(
        "filename,content",
        [
            ("empty.md", "  \n"),
            ("empty.json", "{}"),
            ("unrelated.json", '{"unrelated": true}'),
            ("empty.yaml", "{}\n"),
        ],
    )
    def test_playbook_refuses_empty_or_unrelated_documents(
        self, detection_playbook_dir: Path, filename: str, content: str
    ) -> None:
        (detection_playbook_dir / filename).write_text(content, encoding="utf-8")
        result = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
            R34_ID,
            "playbook",
            {"playbook_dir": str(detection_playbook_dir), "name": filename},
        )
        assert result.ok is False

    def test_list_playbooks(self, detection_playbook_dir: Path) -> None:
        ext = _ext(R34_ID, DetectionInTheCloudArm())
        result = ext.invoke(
            R34_ID,
            "list_playbooks",
            {"playbook_dir": str(detection_playbook_dir), "limit": 1},
        )
        assert result.ok is True
        expected = [
            {"name": "aws-iam.yaml", "format": "yaml"},
            {"name": "aws-s3.json", "format": "json"},
            {"name": "rules.json", "format": "json"},
        ]
        listing_bytes = json.dumps(
            expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        assert result.output["total"] == 3
        assert result.output["returned"] == 1
        assert result.output["capped"] is True
        assert result.output["source"] == {
            "kind": "operator-directory-listing",
            "sha256": "sha256:" + hashlib.sha256(listing_bytes).hexdigest(),
            "bytes": len(listing_bytes),
        }

        (detection_playbook_dir / "z-new.md").write_text("# New\n", encoding="utf-8")
        changed = ext.invoke(
            R34_ID,
            "list_playbooks",
            {"playbook_dir": str(detection_playbook_dir), "limit": 1},
        )
        assert changed.ok is True
        assert changed.output["source"]["sha256"] != result.output["source"]["sha256"]

    def test_list_rules(self, detection_playbook_dir: Path) -> None:
        ext = _ext(R34_ID, DetectionInTheCloudArm())
        result = ext.invoke(R34_ID, "list_rules", {"playbook_dir": str(detection_playbook_dir)})
        assert result.ok is True
        assert result.output["total"] == 2
        assert result.output["returned"] == 2
        assert result.output["capped"] is False
        _assert_file_source(result.output, detection_playbook_dir / "rules.json")

    def test_list_rules_category_filter_reports_both_denominators(
        self, detection_playbook_dir: Path
    ) -> None:
        result = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
            R34_ID,
            "list_rules",
            {"playbook_dir": str(detection_playbook_dir), "category": "iam"},
        )
        assert result.ok is True
        assert result.output["total"] == result.output["returned"] == 1
        assert result.output["unfiltered_total"] == 2
        assert result.output["rules"][0]["rule_id"] == "R1"

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
        assert result.output["result"]["status"] == "pass"
        assert result.output["result"]["score"] == 0.85
        _assert_file_source(result.output, pentestkit_ledger)

    def test_result_not_found(self, pentestkit_ledger: Path) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "result", {"ledger": str(pentestkit_ledger), "run_id": "nope"})
        assert result.ok is False and "not found" in result.error

    def test_list_results(self, pentestkit_ledger: Path) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "list_results", {"ledger": str(pentestkit_ledger)})
        assert result.ok is True
        assert result.output["total"] == 3
        assert result.output["returned"] == 3
        assert result.output["capped"] is False
        _assert_file_source(result.output, pentestkit_ledger)

    def test_list_results_filtered(self, pentestkit_ledger: Path) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "list_results", {"ledger": str(pentestkit_ledger), "phase": "first_pass"})
        assert result.ok is True
        assert result.output["total"] == 2
        assert result.output["unfiltered_total"] == 3
        assert result.output["returned"] == 2
        assert result.output["capped"] is False
        assert result.output["runs"] == [
            {
                "run_id": "run-001",
                "phase": "first_pass",
                "status": "pass",
                "score": 0.85,
            },
            {
                "run_id": "run-002",
                "phase": "first_pass",
                "status": "fail",
                "score": 0.3,
            },
        ]

    def test_summary(self, pentestkit_ledger: Path) -> None:
        ext = _ext(R42_ID, PentestkitArm())
        result = ext.invoke(R42_ID, "summary", {"ledger": str(pentestkit_ledger)})
        assert result.ok is True
        assert result.output["total_runs"] == 3
        assert result.output["scored_runs"] == 3
        assert result.output["missing_score_runs"] == 0
        _assert_file_source(result.output, pentestkit_ledger)

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
        scenario = result.output["scenario"]
        assert "expected_findings" not in scenario
        assert "trace_keys" not in scenario
        assert "expected_evidence" not in scenario
        assert scenario["description"] == "Find S3 misconfigurations"
        _assert_file_source(result.output, collinear_scenarios)

    def test_scenario_not_found(self, collinear_scenarios: Path) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "scenario", {"scenarios_file": str(collinear_scenarios), "scenario_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_scenarios(self, collinear_scenarios: Path) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "list_scenarios", {"scenarios_file": str(collinear_scenarios)})
        assert result.ok is True
        assert result.output["total"] == 1
        assert result.output["returned"] == 1
        assert result.output["capped"] is False
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
        assert set(result.output) == {"scenario_id", "verdict", "source"}
        _assert_file_source(result.output, collinear_scenarios)

    def test_verify_not_found(self, collinear_scenarios: Path) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "verify", {
            "scenarios_file": str(collinear_scenarios),
            "scenario_id": "NOPE",
            "submission": {"findings": []},
        })
        assert result.ok is False and "not found" in result.error

    def test_dual_selectors_must_identify_the_same_scenario(
        self, collinear_scenarios: Path
    ) -> None:
        ext = _ext(R15_ID, CollinearArm())
        consistent = ext.invoke(
            R15_ID,
            "scenario",
            {
                "scenarios_file": str(collinear_scenarios),
                "scenario_id": "C1",
                "name": "Cloud Misconfig",
            },
        )
        contradictory = ext.invoke(
            R15_ID,
            "scenario",
            {
                "scenarios_file": str(collinear_scenarios),
                "scenario_id": "C1",
                "name": "Different Scenario",
            },
        )
        assert consistent.ok is True
        assert contradictory.ok is False
        assert "do not identify the same scenario" in contradictory.error

    def test_url_refused(self) -> None:
        ext = _ext(R15_ID, CollinearArm())
        result = ext.invoke(R15_ID, "scenario", {"scenarios_file": "https://x/s.json", "scenario_id": "C1"})
        assert result.ok is False and "local file, not a URL" in result.error


# ======================================================================
# Batch-wide hardening regressions
# ======================================================================


def test_all_list_limits_are_strict_and_report_capping(
    detections_index: Path,
    agentseal_fixture: Path,
    vulnify_feed: Path,
    leonidas_corpus: Path,
    specterops_catalog: Path,
    detection_playbook_dir: Path,
    pentestkit_ledger: Path,
    collinear_scenarios: Path,
) -> None:
    collinear_data = json.loads(collinear_scenarios.read_text(encoding="utf-8"))
    second = json.loads(json.dumps(collinear_data["scenarios"][0]))
    second["scenario_id"] = "C2"
    second["name"] = "Cloud Misconfig Two"
    collinear_data["scenarios"].append(second)
    collinear_scenarios.write_text(json.dumps(collinear_data), encoding="utf-8")

    cases = [
        (_ext(R43_ID, SecurityDetectionsMcpArm()), R43_ID, "list_rules", {"index": str(detections_index), "limit": 1}),
        (_ext(R35_ID, AgentSealArm()), R35_ID, "list_scenarios", {"fixture": str(agentseal_fixture), "limit": 1}),
        (_ext(R01_ID, VulnifyArm()), R01_ID, "list_vulns", {"feed": str(vulnify_feed), "limit": 1}),
        (_ext(R33_ID, LeonidasArm()), R33_ID, "list_techniques", {"corpus": str(leonidas_corpus), "limit": 1}),
        (_ext(R03_ID, SpecteropsSkillsArm()), R03_ID, "list_skills", {"catalog": str(specterops_catalog), "limit": 1}),
        (_ext(R34_ID, DetectionInTheCloudArm()), R34_ID, "list_playbooks", {"playbook_dir": str(detection_playbook_dir), "limit": 1}),
        (_ext(R42_ID, PentestkitArm()), R42_ID, "list_results", {"ledger": str(pentestkit_ledger), "limit": 1}),
        (_ext(R15_ID, CollinearArm()), R15_ID, "list_scenarios", {"scenarios_file": str(collinear_scenarios), "limit": 1}),
    ]
    for extension, arm_id, action, payload in cases:
        result = extension.invoke(arm_id, action, payload)
        assert result.ok is True, result.error
        assert result.output["total"] > 1
        assert result.output["returned"] == 1
        assert result.output["capped"] is True
        assert result.output["source"]["sha256"].startswith("sha256:")

    invalid_cases = [
        (_ext(R43_ID, SecurityDetectionsMcpArm()), R43_ID, "list_rules", {"index": str(detections_index)}),
        (_ext(R35_ID, AgentSealArm()), R35_ID, "list_scenarios", {"fixture": str(agentseal_fixture)}),
        (_ext(R01_ID, VulnifyArm()), R01_ID, "list_vulns", {"feed": str(vulnify_feed)}),
        (_ext(R33_ID, LeonidasArm()), R33_ID, "list_techniques", {"corpus": str(leonidas_corpus)}),
        (_ext(R03_ID, SpecteropsSkillsArm()), R03_ID, "list_skills", {"catalog": str(specterops_catalog)}),
        (_ext(R34_ID, DetectionInTheCloudArm()), R34_ID, "list_playbooks", {"playbook_dir": str(detection_playbook_dir)}),
        (_ext(R42_ID, PentestkitArm()), R42_ID, "list_results", {"ledger": str(pentestkit_ledger)}),
        (_ext(R15_ID, CollinearArm()), R15_ID, "list_scenarios", {"scenarios_file": str(collinear_scenarios)}),
    ]
    for invalid_limit in (True, "1", 0, 201):
        for extension, arm_id, action, base_payload in invalid_cases:
            result = extension.invoke(
                arm_id, action, {**base_payload, "limit": invalid_limit}
            )
            assert result.ok is False
            assert "limit" in result.error


def test_advertised_yaml_formats_are_real(
    tmp_path: Path, detection_playbook_dir: Path
) -> None:
    fixture = tmp_path / "agentseal.yaml"
    fixture.write_text(
        yaml.safe_dump({"scenarios": [{"id": "S1", "name": "One", "findings": []}]}),
        encoding="utf-8",
    )
    feed = tmp_path / "feed.yaml"
    feed.write_text(
        yaml.safe_dump([{"cve_id": "CVE-2024-1234", "name": "Example"}]),
        encoding="utf-8",
    )
    catalog = tmp_path / "skills.yaml"
    catalog.write_text(
        yaml.safe_dump({"skills": [{"skill_id": "S1", "name": "Method"}]}),
        encoding="utf-8",
    )
    ledger = tmp_path / "ledger.yaml"
    ledger.write_text(
        yaml.safe_dump([{"run_id": "run-y", "phase": "held_out", "status": "pass", "score": 1.0}]),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios.yaml"
    scenarios.write_text(
        yaml.safe_dump(
            {
                "scenarios": [
                    {
                        "scenario_id": "Y1",
                        "name": "YAML",
                        "expected_findings": [{"id": "expected"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    cases = [
        (_ext(R35_ID, AgentSealArm()), R35_ID, "analyze", {"fixture": str(fixture)}),
        (_ext(R01_ID, VulnifyArm()), R01_ID, "lookup", {"feed": str(feed), "cve_id": "CVE-2024-1234"}),
        (_ext(R03_ID, SpecteropsSkillsArm()), R03_ID, "skill", {"catalog": str(catalog), "skill_id": "S1"}),
        (_ext(R34_ID, DetectionInTheCloudArm()), R34_ID, "playbook", {"playbook_dir": str(detection_playbook_dir), "name": "aws-iam"}),
        (_ext(R42_ID, PentestkitArm()), R42_ID, "result", {"ledger": str(ledger), "run_id": "run-y"}),
        (_ext(R15_ID, CollinearArm()), R15_ID, "scenario", {"scenarios_file": str(scenarios), "scenario_id": "Y1"}),
    ]
    for extension, arm_id, action, payload in cases:
        result = extension.invoke(arm_id, action, payload)
        assert result.ok is True, result.error
        assert result.output["source"]["kind"] == "operator-file"


def test_yaml_aliases_are_refused_by_every_yaml_reader(tmp_path: Path) -> None:
    index = tmp_path / "rules.yaml"
    index.write_text("rule: &r {rule_id: R1, name: Rule}\nrules: [*r]\n", encoding="utf-8")
    fixture = tmp_path / "fixture.yaml"
    fixture.write_text("scenario: &s {id: S1, name: One}\nscenarios: [*s]\n", encoding="utf-8")
    feed = tmp_path / "feed.yaml"
    feed.write_text("vulnerabilities: [&v {cve_id: CVE-1, name: One}, *v]\n", encoding="utf-8")
    corpus = tmp_path / "corpus.yaml"
    corpus.write_text("techniques: [&t {technique_id: T1, name: One}, *t]\n", encoding="utf-8")
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text("skills: [&s {skill_id: S1, name: One}, *s]\n", encoding="utf-8")
    playbooks = tmp_path / "playbooks"
    playbooks.mkdir()
    (playbooks / "bad.yaml").write_text("name: &n Bad\ncopy: *n\n", encoding="utf-8")
    ledger = tmp_path / "ledger.yaml"
    ledger.write_text("runs: [&r {run_id: R1, phase: tuned, status: pass}, *r]\n", encoding="utf-8")
    scenarios = tmp_path / "scenarios.yaml"
    scenarios.write_text("scenarios: [&s {scenario_id: S1, name: One, expected_findings: []}, *s]\n", encoding="utf-8")

    cases = [
        (_ext(R43_ID, SecurityDetectionsMcpArm()), R43_ID, "list_rules", {"index": str(index)}),
        (_ext(R35_ID, AgentSealArm()), R35_ID, "analyze", {"fixture": str(fixture)}),
        (_ext(R01_ID, VulnifyArm()), R01_ID, "list_vulns", {"feed": str(feed)}),
        (_ext(R33_ID, LeonidasArm()), R33_ID, "list_techniques", {"corpus": str(corpus)}),
        (_ext(R03_ID, SpecteropsSkillsArm()), R03_ID, "list_skills", {"catalog": str(catalog)}),
        (_ext(R34_ID, DetectionInTheCloudArm()), R34_ID, "playbook", {"playbook_dir": str(playbooks), "name": "bad"}),
        (_ext(R42_ID, PentestkitArm()), R42_ID, "list_results", {"ledger": str(ledger)}),
        (_ext(R15_ID, CollinearArm()), R15_ID, "list_scenarios", {"scenarios_file": str(scenarios)}),
    ]
    for extension, arm_id, action, payload in cases:
        result = extension.invoke(arm_id, action, payload)
        assert result.ok is False
        assert "YAML" in result.error


@pytest.mark.parametrize(
    "module",
    [r43_arm, r35_arm, r01_arm, r33_arm, r03_arm, r34_arm, r42_arm, r15_arm],
    ids=lambda module: module.ARM_ID,
)
def test_every_yaml_loader_enforces_depth_and_node_caps(
    module, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = "leaf"
    for _ in range(70):
        nested = {"next": nested}
    with pytest.raises(yaml.YAMLError, match="nesting-depth cap"):
        yaml.load(yaml.safe_dump(nested), Loader=module._BoundedSafeLoader)

    with monkeypatch.context() as scoped:
        scoped.setattr(module, "MAX_DOCUMENT_NODES", 2)
        with pytest.raises(yaml.YAMLError, match="node cap"):
            yaml.load("root:\n  child: value\n", Loader=module._BoundedSafeLoader)


@pytest.mark.parametrize(
    "module",
    [r43_arm, r35_arm, r01_arm, r33_arm, r03_arm, r34_arm, r42_arm, r15_arm],
    ids=lambda module: module.ARM_ID,
)
def test_every_batch7_tree_refuses_unsafe_scalar_magnitudes(module) -> None:
    assert "integer" in module._tree_refusal(1 << 5_000)
    assert "string" in module._tree_refusal(
        "x" * (module.MAX_OUTPUT_CHARS + 1)
    )


@pytest.mark.parametrize(
    "module,fixture_name,arm_id,handler,action,path_key,extra",
    [
        (r43_arm, "detections_index", R43_ID, SecurityDetectionsMcpArm(), "list_rules", "index", {}),
        (r35_arm, "agentseal_fixture", R35_ID, AgentSealArm(), "analyze", "fixture", {}),
        (r01_arm, "vulnify_feed", R01_ID, VulnifyArm(), "list_vulns", "feed", {}),
        (r33_arm, "leonidas_corpus", R33_ID, LeonidasArm(), "list_techniques", "corpus", {}),
        (r03_arm, "specterops_catalog", R03_ID, SpecteropsSkillsArm(), "list_skills", "catalog", {}),
        (r34_arm, "detection_playbook_dir", R34_ID, DetectionInTheCloudArm(), "playbook", "playbook_dir", {"name": "aws-s3"}),
        (r42_arm, "pentestkit_ledger", R42_ID, PentestkitArm(), "list_results", "ledger", {}),
        (r15_arm, "collinear_scenarios", R15_ID, CollinearArm(), "list_scenarios", "scenarios_file", {}),
    ],
)
def test_every_batch7_loader_applies_the_tree_refusal_gate(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    module,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    extra: dict[str, object],
) -> None:
    source = request.getfixturevalue(fixture_name)
    monkeypatch.setattr(
        module,
        "_tree_refusal",
        lambda _data: "triggered the sentinel structure refusal",
    )
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: str(source), **extra},
    )
    assert result.ok is False
    assert "sentinel structure refusal" in result.error


def test_loaders_enforce_bounded_read_after_path_preflight(
    monkeypatch: pytest.MonkeyPatch,
    detections_index: Path,
    agentseal_fixture: Path,
    vulnify_feed: Path,
    leonidas_corpus: Path,
    specterops_catalog: Path,
    detection_playbook_dir: Path,
    pentestkit_ledger: Path,
    collinear_scenarios: Path,
) -> None:
    cases = [
        (r43_arm, "MAX_INDEX_BYTES", _ext(R43_ID, SecurityDetectionsMcpArm()), R43_ID, "list_rules", {"index": str(detections_index)}),
        (r35_arm, "MAX_FIXTURE_BYTES", _ext(R35_ID, AgentSealArm()), R35_ID, "analyze", {"fixture": str(agentseal_fixture)}),
        (r01_arm, "MAX_FEED_BYTES", _ext(R01_ID, VulnifyArm()), R01_ID, "list_vulns", {"feed": str(vulnify_feed)}),
        (r33_arm, "MAX_CORPUS_BYTES", _ext(R33_ID, LeonidasArm()), R33_ID, "list_techniques", {"corpus": str(leonidas_corpus)}),
        (r03_arm, "MAX_CATALOG_BYTES", _ext(R03_ID, SpecteropsSkillsArm()), R03_ID, "list_skills", {"catalog": str(specterops_catalog)}),
        (r34_arm, "MAX_PLAYBOOK_BYTES", _ext(R34_ID, DetectionInTheCloudArm()), R34_ID, "playbook", {"playbook_dir": str(detection_playbook_dir), "name": "aws-s3"}),
        (r42_arm, "MAX_LEDGER_BYTES", _ext(R42_ID, PentestkitArm()), R42_ID, "list_results", {"ledger": str(pentestkit_ledger)}),
        (r15_arm, "MAX_SCENARIOS_BYTES", _ext(R15_ID, CollinearArm()), R15_ID, "list_scenarios", {"scenarios_file": str(collinear_scenarios)}),
    ]
    for module, constant, extension, arm_id, action, payload in cases:
        with monkeypatch.context() as scoped:
            scoped.setattr(module, constant, 4)
            result = extension.invoke(arm_id, action, payload)
        assert result.ok is False
        assert "read cap" in result.error


def test_detection_directory_entry_cap_is_enforced(
    detection_playbook_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(r34_arm, "MAX_DIRECTORY_ENTRIES", 1)
    result = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
        R34_ID,
        "list_playbooks",
        {"playbook_dir": str(detection_playbook_dir)},
    )
    assert result.ok is False
    assert "entry cap" in result.error


@pytest.mark.parametrize(
    "module,fixture_name,arm_id,handler,action,path_key,extra",
    [
        (r43_arm, "detections_index", R43_ID, SecurityDetectionsMcpArm(), "list_rules", "index", {}),
        (r35_arm, "agentseal_fixture", R35_ID, AgentSealArm(), "analyze", "fixture", {}),
        (r01_arm, "vulnify_feed", R01_ID, VulnifyArm(), "list_vulns", "feed", {}),
        (r33_arm, "leonidas_corpus", R33_ID, LeonidasArm(), "list_techniques", "corpus", {}),
        (r03_arm, "specterops_catalog", R03_ID, SpecteropsSkillsArm(), "list_skills", "catalog", {}),
        (r34_arm, "detection_playbook_dir", R34_ID, DetectionInTheCloudArm(), "list_rules", "playbook_dir", {}),
        (r42_arm, "pentestkit_ledger", R42_ID, PentestkitArm(), "list_results", "ledger", {}),
    ],
)
def test_batch7_document_record_caps_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    module,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    extra: dict[str, object],
) -> None:
    source = request.getfixturevalue(fixture_name)
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(source), **extra}
    )
    assert result.ok is False
    assert "cap" in result.error


def test_collinear_document_record_cap_is_enforced(
    collinear_scenarios: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = json.loads(collinear_scenarios.read_text(encoding="utf-8"))
    second = dict(data["scenarios"][0])
    second["scenario_id"] = "C2"
    data["scenarios"].append(second)
    collinear_scenarios.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(r15_arm, "MAX_RECORDS", 1)
    result = _ext(R15_ID, CollinearArm()).invoke(
        R15_ID,
        "list_scenarios",
        {"scenarios_file": str(collinear_scenarios)},
    )
    assert result.ok is False
    assert "scenario cap" in result.error


def test_malformed_records_fail_closed_without_type_exceptions(tmp_path: Path) -> None:
    index = tmp_path / "rules.json"
    index.write_text("[1]", encoding="utf-8")
    fixture = tmp_path / "fixture.json"
    fixture.write_text('{"scenarios":[1]}', encoding="utf-8")
    feed = tmp_path / "feed.json"
    feed.write_text("[1]", encoding="utf-8")
    corpus = tmp_path / "corpus.json"
    corpus.write_text("[1]", encoding="utf-8")
    catalog = tmp_path / "catalog.json"
    catalog.write_text("[1]", encoding="utf-8")
    playbooks = tmp_path / "playbooks"
    playbooks.mkdir()
    (playbooks / "rules.json").write_text("[1]", encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    ledger.write_text("[1]", encoding="utf-8")
    scenarios = tmp_path / "scenarios.json"
    scenarios.write_text('{"scenarios":[1]}', encoding="utf-8")

    cases = [
        (_ext(R43_ID, SecurityDetectionsMcpArm()), R43_ID, "list_rules", {"index": str(index)}),
        (_ext(R35_ID, AgentSealArm()), R35_ID, "analyze", {"fixture": str(fixture)}),
        (_ext(R01_ID, VulnifyArm()), R01_ID, "list_vulns", {"feed": str(feed)}),
        (_ext(R33_ID, LeonidasArm()), R33_ID, "list_techniques", {"corpus": str(corpus)}),
        (_ext(R03_ID, SpecteropsSkillsArm()), R03_ID, "list_skills", {"catalog": str(catalog)}),
        (_ext(R34_ID, DetectionInTheCloudArm()), R34_ID, "list_rules", {"playbook_dir": str(playbooks)}),
        (_ext(R42_ID, PentestkitArm()), R42_ID, "list_results", {"ledger": str(ledger)}),
        (_ext(R15_ID, CollinearArm()), R15_ID, "list_scenarios", {"scenarios_file": str(scenarios)}),
    ]
    for extension, arm_id, action, payload in cases:
        result = extension.invoke(arm_id, action, payload)
        assert result.ok is False
        assert result.output is None


def test_unexpected_loader_failures_do_not_escape_or_echo(
    monkeypatch: pytest.MonkeyPatch,
    detections_index: Path,
    agentseal_fixture: Path,
    vulnify_feed: Path,
    leonidas_corpus: Path,
    specterops_catalog: Path,
    detection_playbook_dir: Path,
    pentestkit_ledger: Path,
    collinear_scenarios: Path,
) -> None:
    def explode(*_args, **_kwargs):
        raise AttributeError("private value /operator/secret")

    cases = [
        (r43_arm, "_load_index", _ext(R43_ID, SecurityDetectionsMcpArm()), R43_ID, "list_rules", {"index": str(detections_index)}),
        (r35_arm, "_load_fixture", _ext(R35_ID, AgentSealArm()), R35_ID, "analyze", {"fixture": str(agentseal_fixture)}),
        (r01_arm, "_load_feed", _ext(R01_ID, VulnifyArm()), R01_ID, "list_vulns", {"feed": str(vulnify_feed)}),
        (r33_arm, "_load_corpus", _ext(R33_ID, LeonidasArm()), R33_ID, "list_techniques", {"corpus": str(leonidas_corpus)}),
        (r03_arm, "_load_catalog", _ext(R03_ID, SpecteropsSkillsArm()), R03_ID, "list_skills", {"catalog": str(specterops_catalog)}),
        (r34_arm, "_read_bounded", _ext(R34_ID, DetectionInTheCloudArm()), R34_ID, "playbook", {"playbook_dir": str(detection_playbook_dir), "name": "aws-s3"}),
        (r42_arm, "_load_ledger", _ext(R42_ID, PentestkitArm()), R42_ID, "list_results", {"ledger": str(pentestkit_ledger)}),
        (r15_arm, "_load_scenarios", _ext(R15_ID, CollinearArm()), R15_ID, "list_scenarios", {"scenarios_file": str(collinear_scenarios)}),
    ]
    loader_pairs = [(arm_id, target) for _, target, _, arm_id, _, _ in cases]
    expected_loader_pairs = {
        (R43_ID, "_load_index"),
        (R35_ID, "_load_fixture"),
        (R01_ID, "_load_feed"),
        (R33_ID, "_load_corpus"),
        (R03_ID, "_load_catalog"),
        (R34_ID, "_read_bounded"),
        (R42_ID, "_load_ledger"),
        (R15_ID, "_load_scenarios"),
    }
    assert len(cases) == 8
    assert len(loader_pairs) == len(set(loader_pairs))
    assert set(loader_pairs) == expected_loader_pairs
    for module, target, extension, arm_id, action, payload in cases:
        with monkeypatch.context() as scoped:
            scoped.setattr(module, target, explode)
            result = extension.invoke(arm_id, action, payload)
        assert result.ok is False
        assert "private value" not in result.error
        assert "/operator" not in result.error


@pytest.mark.parametrize(
    "module,arm_id,handler",
    [
        (r43_arm, R43_ID, SecurityDetectionsMcpArm()),
        (r35_arm, R35_ID, AgentSealArm()),
        (r01_arm, R01_ID, VulnifyArm()),
        (r33_arm, R33_ID, LeonidasArm()),
        (r03_arm, R03_ID, SpecteropsSkillsArm()),
        (r34_arm, R34_ID, DetectionInTheCloudArm()),
        (r42_arm, R42_ID, PentestkitArm()),
        (r15_arm, R15_ID, CollinearArm()),
    ],
)
def test_every_success_path_uses_the_output_cap(
    module, arm_id: str, handler, monkeypatch: pytest.MonkeyPatch
) -> None:
    extension = _ext(arm_id, handler)
    baseline = extension.invoke(arm_id, "list_tools", {})
    assert baseline.ok is True
    cap = _rendered_output_bytes(baseline.output) - 1
    assert cap >= 64
    monkeypatch.setattr(module, "MAX_OUTPUT_CHARS", cap)
    result = extension.invoke(arm_id, "list_tools", {})
    assert result.ok is False
    assert result.output is None
    assert "output cap" in result.error


@pytest.mark.parametrize(
    "arm_id,handler",
    [
        (R43_ID, SecurityDetectionsMcpArm()),
        (R35_ID, AgentSealArm()),
        (R01_ID, VulnifyArm()),
        (R33_ID, LeonidasArm()),
        (R03_ID, SpecteropsSkillsArm()),
        (R34_ID, DetectionInTheCloudArm()),
        (R42_ID, PentestkitArm()),
        (R15_ID, CollinearArm()),
    ],
)
def test_every_batch7_arm_rejects_unknown_actions_and_list_tools_arguments(
    arm_id: str, handler
) -> None:
    extension = _ext(arm_id, handler)
    unknown = extension.invoke(arm_id, "definitely_not_allowed", {})
    discovery = extension.invoke(
        arm_id, "list_tools", {"unexpected": "caller data"}
    )
    assert unknown.ok is False
    assert "allowlist" in unknown.error
    assert discovery.ok is False
    assert "no caller arguments" in discovery.error


_ALL_BATCH7_DATA_ACTIONS = [
    (r43_arm, "detections_index", R43_ID, SecurityDetectionsMcpArm(), "list_rules", "index", {}),
    (r43_arm, "detections_index", R43_ID, SecurityDetectionsMcpArm(), "search_rules", "index", {"query": "auth"}),
    (r43_arm, "detections_index", R43_ID, SecurityDetectionsMcpArm(), "get_rule", "index", {"rule_id": "R001"}),
    (r35_arm, "agentseal_fixture", R35_ID, AgentSealArm(), "analyze", "fixture", {}),
    (r35_arm, "agentseal_fixture", R35_ID, AgentSealArm(), "list_scenarios", "fixture", {}),
    (r01_arm, "vulnify_feed", R01_ID, VulnifyArm(), "lookup", "feed", {"cve_id": "CVE-2024-0001"}),
    (r01_arm, "vulnify_feed", R01_ID, VulnifyArm(), "list_vulns", "feed", {}),
    (r33_arm, "leonidas_corpus", R33_ID, LeonidasArm(), "technique", "corpus", {"technique_id": "T-L01"}),
    (r33_arm, "leonidas_corpus", R33_ID, LeonidasArm(), "list_techniques", "corpus", {}),
    (r03_arm, "specterops_catalog", R03_ID, SpecteropsSkillsArm(), "skill", "catalog", {"skill_id": "SK01"}),
    (r03_arm, "specterops_catalog", R03_ID, SpecteropsSkillsArm(), "list_skills", "catalog", {}),
    (r34_arm, "detection_playbook_dir", R34_ID, DetectionInTheCloudArm(), "playbook", "playbook_dir", {"name": "aws-s3"}),
    (r34_arm, "detection_playbook_dir", R34_ID, DetectionInTheCloudArm(), "list_playbooks", "playbook_dir", {}),
    (r34_arm, "detection_playbook_dir", R34_ID, DetectionInTheCloudArm(), "list_rules", "playbook_dir", {}),
    (r42_arm, "pentestkit_ledger", R42_ID, PentestkitArm(), "result", "ledger", {"run_id": "run-001"}),
    (r42_arm, "pentestkit_ledger", R42_ID, PentestkitArm(), "list_results", "ledger", {}),
    (r42_arm, "pentestkit_ledger", R42_ID, PentestkitArm(), "summary", "ledger", {}),
    (r15_arm, "collinear_scenarios", R15_ID, CollinearArm(), "scenario", "scenarios_file", {"scenario_id": "C1"}),
    (r15_arm, "collinear_scenarios", R15_ID, CollinearArm(), "list_scenarios", "scenarios_file", {}),
    (
        r15_arm,
        "collinear_scenarios",
        R15_ID,
        CollinearArm(),
        "verify",
        "scenarios_file",
        {
            "scenario_id": "C1",
            "submission": {
                "findings": [{"bucket": "data-lab", "issue": "public-read"}]
            },
        },
    ),
]


def test_batch7_data_action_regression_roster_is_exact() -> None:
    pairs = [(row[2], row[4]) for row in _ALL_BATCH7_DATA_ACTIONS]
    expected = {
        (R43_ID, "list_rules"),
        (R43_ID, "search_rules"),
        (R43_ID, "get_rule"),
        (R35_ID, "analyze"),
        (R35_ID, "list_scenarios"),
        (R01_ID, "lookup"),
        (R01_ID, "list_vulns"),
        (R33_ID, "technique"),
        (R33_ID, "list_techniques"),
        (R03_ID, "skill"),
        (R03_ID, "list_skills"),
        (R34_ID, "playbook"),
        (R34_ID, "list_playbooks"),
        (R34_ID, "list_rules"),
        (R42_ID, "result"),
        (R42_ID, "list_results"),
        (R42_ID, "summary"),
        (R15_ID, "scenario"),
        (R15_ID, "list_scenarios"),
        (R15_ID, "verify"),
    }
    assert len(_ALL_BATCH7_DATA_ACTIONS) == 20
    assert len(pairs) == len(set(pairs))
    assert set(pairs) == expected


@pytest.mark.parametrize(
    "module,fixture_name,arm_id,handler,action,path_key,query",
    _ALL_BATCH7_DATA_ACTIONS,
)
def test_every_data_action_obeys_the_output_cap(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    module,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    query: dict,
) -> None:
    path = request.getfixturevalue(fixture_name)
    extension = _ext(arm_id, handler)
    baseline = extension.invoke(
        arm_id, action, {path_key: str(path), **query}
    )
    assert baseline.ok is True
    cap = _rendered_output_bytes(baseline.output) - 1
    assert cap >= 64
    monkeypatch.setattr(module, "MAX_OUTPUT_CHARS", cap)
    result = extension.invoke(arm_id, action, {path_key: str(path), **query})
    assert result.ok is False
    assert result.output is None
    assert "output cap" in result.error


@pytest.mark.parametrize(
    "module,fixture_name,arm_id,handler,action,path_key,query",
    [row for row in _ALL_BATCH7_DATA_ACTIONS if row[0] is not r34_arm],
)
def test_every_batch7_data_action_reports_exact_source(
    request: pytest.FixtureRequest,
    module,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    query: dict,
) -> None:
    # Detection-in-the-cloud binds two selected files and one canonical
    # directory listing; its three action tests above assert those exact forms.
    del module
    path = request.getfixturevalue(fixture_name)
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path), **query}
    )
    assert result.ok is True
    _assert_file_source(result.output, path)


@pytest.mark.parametrize(
    "module,fixture_name,arm_id,handler,action,path_key,query",
    _ALL_BATCH7_DATA_ACTIONS,
)
def test_every_batch7_data_action_rejects_undeclared_arguments(
    request: pytest.FixtureRequest,
    module,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    query: dict,
) -> None:
    del module
    path = request.getfixturevalue(fixture_name)
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: str(path), **query, "unexpected": "caller data"},
    )
    assert result.ok is False
    assert "unexpected" in result.error
    non_string = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: str(path), **query, 1: "caller data"},
    )
    assert non_string.ok is False
    assert non_string.error == "caller argument names must be strings"


@pytest.mark.parametrize(
    "module,fixture_name,key,arm_id,handler,action,path_key",
    [
        (r01_arm, "vulnify_feed", "cve_id", R01_ID, VulnifyArm(), "list_vulns", "feed"),
        (r42_arm, "pentestkit_ledger", "run_id", R42_ID, PentestkitArm(), "list_results", "ledger"),
    ],
)
def test_jsonl_duplicate_mapping_keys_are_refused(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    module,
    fixture_name: str,
    key: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    original = request.getfixturevalue(fixture_name)
    row = json.loads(original.read_text(encoding="utf-8"))[0]
    text = json.dumps(row)
    needle = f'"{key}":'
    assert needle in text
    path = tmp_path / f"{arm_id}.jsonl"
    path.write_text(
        text.replace(needle, f'"{key}": "shadowed", "{key}":', 1) + "\n",
        encoding="utf-8",
    )
    result = _ext(arm_id, handler).invoke(arm_id, action, {path_key: str(path)})
    assert result.ok is False
    assert "duplicate mapping key" in result.error


@pytest.mark.parametrize(
    "module,fixture_name,arm_id,handler,action,path_key",
    [
        (r01_arm, "vulnify_feed", R01_ID, VulnifyArm(), "list_vulns", "feed"),
        (r42_arm, "pentestkit_ledger", R42_ID, PentestkitArm(), "list_results", "ledger"),
    ],
)
def test_jsonl_record_cap_stops_before_parsing_excess_rows(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    tmp_path: Path,
    module,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    original = request.getfixturevalue(fixture_name)
    rows = json.loads(original.read_text(encoding="utf-8"))
    path = tmp_path / f"{arm_id}.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    calls = 0
    decode = module.strict_json_loads

    def counting_decode(document: str):
        nonlocal calls
        calls += 1
        return decode(document)

    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    monkeypatch.setattr(module, "strict_json_loads", counting_decode)
    result = _ext(arm_id, handler).invoke(arm_id, action, {path_key: str(path)})
    assert result.ok is False
    assert "cap" in result.error
    assert calls == 1


def test_vulnify_key_precedence_and_digest_provenance(tmp_path: Path) -> None:
    records = [
        {"cve_id": "CVE-A", "name": "Name Match", "severity": "low"},
        {"cve_id": "CVE-B", "name": "ID Match", "severity": "high"},
    ]
    feed = tmp_path / "do-not-echo-this-name.json"
    feed.write_text(json.dumps(records), encoding="utf-8")
    result = _ext(R01_ID, VulnifyArm()).invoke(
        R01_ID,
        "lookup",
        {"feed": str(feed), "cve_id": "CVE-B", "name": "Name Match"},
    )
    assert result.ok is True
    assert result.output["vulnerability"]["name"] == "ID Match"
    _assert_file_source(result.output, feed)
    assert result.output["provenance"]["snapshot_digest"] == result.output["source"]["sha256"]
    canonical = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    normalized_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    assert (
        result.output["provenance"]["normalization"]["records_sha256"]
        == normalized_digest
    )
    assert feed.name not in json.dumps(result.output)

    original_snapshot = result.output["provenance"]["snapshot_digest"]
    reordered = [dict(reversed(list(record.items()))) for record in records]
    feed.write_text(json.dumps(reordered, indent=2), encoding="utf-8")
    reordered_result = _ext(R01_ID, VulnifyArm()).invoke(
        R01_ID,
        "lookup",
        {"feed": str(feed), "cve_id": "CVE-B"},
    )
    assert reordered_result.ok is True
    assert reordered_result.output["provenance"]["snapshot_digest"] != original_snapshot
    assert (
        reordered_result.output["provenance"]["normalization"]["records_sha256"]
        == normalized_digest
    )

    result = _ext(R01_ID, VulnifyArm()).invoke(
        R01_ID,
        "lookup",
        {"feed": str(feed), "cve_id": "CVE-NOT-THERE", "name": "Name Match"},
    )
    assert result.ok is False
    assert "CVE-NOT-THERE" in result.error


def test_vulnify_name_lookup_refuses_ambiguous_matches(vulnify_feed: Path) -> None:
    records = json.loads(vulnify_feed.read_text(encoding="utf-8"))
    records[1]["name"] = records[0]["name"]
    vulnify_feed.write_text(json.dumps(records), encoding="utf-8")
    result = _ext(R01_ID, VulnifyArm()).invoke(
        R01_ID,
        "lookup",
        {"feed": str(vulnify_feed), "name": records[0]["name"]},
    )
    assert result.ok is False
    assert "multiple vulnerabilities" in result.error
    assert "args.cve_id" in result.error


def test_leonidas_name_lookup_refuses_ambiguous_matches(
    leonidas_corpus: Path,
) -> None:
    data = yaml.safe_load(leonidas_corpus.read_text(encoding="utf-8"))
    data["techniques"][1]["name"] = data["techniques"][0]["name"]
    leonidas_corpus.write_text(yaml.safe_dump(data), encoding="utf-8")
    result = _ext(R33_ID, LeonidasArm()).invoke(
        R33_ID,
        "technique",
        {"corpus": str(leonidas_corpus), "name": data["techniques"][0]["name"]},
    )
    assert result.ok is False
    assert "multiple techniques" in result.error
    assert "args.technique_id" in result.error


def test_specterops_name_lookup_refuses_ambiguous_matches(
    specterops_catalog: Path,
) -> None:
    data = json.loads(specterops_catalog.read_text(encoding="utf-8"))
    data["skills"][1]["name"] = data["skills"][0]["name"]
    specterops_catalog.write_text(json.dumps(data), encoding="utf-8")
    result = _ext(R03_ID, SpecteropsSkillsArm()).invoke(
        R03_ID,
        "skill",
        {"catalog": str(specterops_catalog), "name": data["skills"][0]["name"]},
    )
    assert result.ok is False
    assert "multiple skills" in result.error
    assert "args.skill_id" in result.error


def test_failure_output_is_redacted_and_capped(agentseal_fixture: Path) -> None:
    hostile_id = "secret-" + ("x" * (r35_arm.MAX_OUTPUT_CHARS + 1_000))
    result = _ext(R35_ID, AgentSealArm()).invoke(
        R35_ID,
        "analyze",
        {"fixture": str(agentseal_fixture), "scenario_id": hostile_id},
    )
    assert result.ok is False
    assert len(result.error) <= r35_arm.MAX_OUTPUT_CHARS
    assert "secret-" not in result.error


@pytest.mark.parametrize(
    "fixture_name,arm_id,handler,action,path_key,field,range_text",
    [
        ("vulnify_feed", R01_ID, VulnifyArm(), "list_vulns", "feed", "cvss", "0 to 10"),
        ("pentestkit_ledger", R42_ID, PentestkitArm(), "list_results", "ledger", "score", "0 to 1"),
    ],
)
def test_huge_bounded_numbers_fail_as_results_instead_of_raising(
    request: pytest.FixtureRequest,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    field: str,
    range_text: str,
) -> None:
    path = request.getfixturevalue(fixture_name)
    data = _fixture_data(path)
    rows = data["vulnerabilities"] if isinstance(data, dict) and "vulnerabilities" in data else data
    rows[0][field] = 10**400
    path = path.with_suffix(".json")
    path.write_text(json.dumps(data), encoding="utf-8")
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: str(path)},
    )
    assert result.ok is False
    assert range_text in result.error


def test_security_detections_refuses_yaml_integer_too_large_to_search(
    tmp_path: Path,
) -> None:
    index = tmp_path / "rules.yaml"
    index.write_text(
        "rules:\n"
        "  - rule_id: R1\n"
        "    name: Rule\n"
        f"    metadata: 0x{'f' * 5_000}\n",
        encoding="utf-8",
    )
    result = _ext(R43_ID, SecurityDetectionsMcpArm()).invoke(
        R43_ID,
        "search_rules",
        {"index": str(index), "query": "rule"},
    )
    assert result.ok is False
    assert "integer exceeding the magnitude cap" in result.error


def test_security_detections_rejects_lone_surrogate_before_action_selection(
    tmp_path: Path,
) -> None:
    index = tmp_path / "rules.json"
    index.write_text(
        json.dumps(
            [
                {
                    "rule_id": "R1",
                    "name": "Rule",
                    "metadata": "\ud800",
                }
            ]
        ),
        encoding="utf-8",
    )
    actions = [
        ("list_rules", {}),
        ("search_rules", {"query": "rule"}),
        ("get_rule", {"rule_id": "R1"}),
    ]
    for action, extra in actions:
        result = _ext(R43_ID, SecurityDetectionsMcpArm()).invoke(
            R43_ID, action, {"index": str(index), **extra}
        )
        assert result.ok is False
        assert "Unicode scalar" in result.error


@pytest.mark.parametrize(
    "module",
    [r43_arm, r35_arm, r01_arm, r33_arm, r03_arm, r34_arm, r42_arm, r15_arm],
    ids=lambda module: module.ARM_ID,
)
def test_every_batch7_yaml_loader_refuses_lone_surrogates(module) -> None:
    with pytest.raises(StrictDataError, match="Unicode scalar"):
        yaml.load('value: "\\uD800"\n', Loader=module._BoundedSafeLoader)


@pytest.mark.parametrize(
    "module",
    [r43_arm, r35_arm, r01_arm, r33_arm, r03_arm, r34_arm, r42_arm, r15_arm],
    ids=lambda module: module.ARM_ID,
)
@pytest.mark.parametrize(
    "document",
    ["value: -1.0e-9999\n", "value: 0:0." + ("0" * 400) + "1\n"],
    ids=["exponent", "sexagesimal"],
)
def test_every_batch7_yaml_loader_refuses_float_underflow(
    module, document: str
) -> None:
    with pytest.raises(StrictDataError, match="underflows"):
        yaml.load(document, Loader=module._BoundedSafeLoader)


@pytest.mark.parametrize(
    "arm_id,handler,path_key,document",
    [
        (
            R01_ID,
            VulnifyArm(),
            "feed",
            '[{"cve_id":"CVE-1","name":"One","cvss":-1e-9999}]',
        ),
        (
            R42_ID,
            PentestkitArm(),
            "ledger",
            '[{"run_id":"run-1","phase":"first_pass","status":"pass","score":-1e-9999}]',
        ),
    ],
)
def test_batch7_numeric_evidence_cannot_silently_underflow(
    tmp_path: Path,
    arm_id: str,
    handler,
    path_key: str,
    document: str,
) -> None:
    source = tmp_path / f"{arm_id}.json"
    source.write_text(document, encoding="utf-8")
    action = "list_vulns" if arm_id == R01_ID else "list_results"
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(source)}
    )
    assert result.ok is False
    assert "underflows" in result.error


@pytest.mark.parametrize(
    "finding",
    [
        {"value": 1 << 5_000},
        {"value": "x" * (r15_arm.MAX_OUTPUT_CHARS + 1)},
    ],
    ids=["huge-integer", "huge-string"],
)
def test_collinear_refuses_unsafe_submission_scalars(
    collinear_scenarios: Path, finding: dict[str, object]
) -> None:
    result = _ext(R15_ID, CollinearArm()).invoke(
        R15_ID,
        "verify",
        {
            "scenarios_file": str(collinear_scenarios),
            "scenario_id": "C1",
            "submission": {"findings": [finding]},
        },
    )
    assert result.ok is False
    assert "cap" in result.error


def test_collinear_refuses_yaml_expected_integer_too_large_to_compare(
    tmp_path: Path,
) -> None:
    scenarios = tmp_path / "scenarios.yaml"
    scenarios.write_text(
        "scenarios:\n"
        "  - scenario_id: C1\n"
        "    name: Giant integer\n"
        "    expected_findings:\n"
        f"      - value: 0x{'f' * 5_000}\n",
        encoding="utf-8",
    )
    result = _ext(R15_ID, CollinearArm()).invoke(
        R15_ID,
        "verify",
        {
            "scenarios_file": str(scenarios),
            "scenario_id": "C1",
            "submission": {"findings": []},
        },
    )
    assert result.ok is False
    assert "integer exceeding the magnitude cap" in result.error


@pytest.mark.parametrize(
    "secret_key",
    [
        "api_key",
        "db_pass",
        "dbpass",
        "user_pass",
        "userpass",
        "pass",
        "passcode",
        "master_key",
        "encryption_key",
        "recovery_key",
        "signing_key",
        "client_key",
    ],
)
def test_leonidas_refuses_nested_secret_shaped_fields_without_echo(
    leonidas_corpus: Path, secret_key: str
) -> None:
    data = yaml.safe_load(leonidas_corpus.read_text(encoding="utf-8"))
    data["techniques"][0]["metadata"] = {secret_key: "do-not-echo"}
    leonidas_corpus.write_text(yaml.safe_dump(data), encoding="utf-8")
    result = _ext(R33_ID, LeonidasArm()).invoke(
        R33_ID,
        "technique",
        {"corpus": str(leonidas_corpus), "technique_id": "T-L01"},
    )
    assert result.ok is False
    assert "shaped field" in result.error
    assert "do-not-echo" not in result.error


def test_collinear_name_lookup_refuses_ambiguous_matches(
    collinear_scenarios: Path,
) -> None:
    data = json.loads(collinear_scenarios.read_text(encoding="utf-8"))
    duplicate = dict(data["scenarios"][0])
    duplicate["scenario_id"] = "C2"
    data["scenarios"].append(duplicate)
    collinear_scenarios.write_text(json.dumps(data), encoding="utf-8")
    result = _ext(R15_ID, CollinearArm()).invoke(
        R15_ID,
        "scenario",
        {
            "scenarios_file": str(collinear_scenarios),
            "name": data["scenarios"][0]["name"],
        },
    )
    assert result.ok is False
    assert "multiple scenarios" in result.error
    assert "args.scenario_id" in result.error


@pytest.mark.parametrize(
    "arm_id,handler,action,path_key,extra",
    [
        (R43_ID, SecurityDetectionsMcpArm(), "list_rules", "index", {}),
        (R35_ID, AgentSealArm(), "analyze", "fixture", {}),
        (R01_ID, VulnifyArm(), "list_vulns", "feed", {}),
        (R33_ID, LeonidasArm(), "list_techniques", "corpus", {}),
        (R03_ID, SpecteropsSkillsArm(), "list_skills", "catalog", {}),
        (R34_ID, DetectionInTheCloudArm(), "list_playbooks", "playbook_dir", {}),
        (R42_ID, PentestkitArm(), "list_results", "ledger", {}),
        (R15_ID, CollinearArm(), "list_scenarios", "scenarios_file", {}),
    ],
)
def test_invalid_source_paths_are_not_echoed(
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    extra: dict,
) -> None:
    private_path = "/operator/private/customer-alpha/nonexistent.json"
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: private_path, **extra},
    )
    assert result.ok is False
    assert private_path not in result.error
    assert "/operator/private" not in result.error


@pytest.mark.parametrize("as_yaml", [False, True], ids=["json", "yaml"])
@pytest.mark.parametrize(
    "fixture_name,key,arm_id,handler,action,path_key",
    [
        ("detections_index", "rule_id", R43_ID, SecurityDetectionsMcpArm(), "list_rules", "index"),
        ("agentseal_fixture", "id", R35_ID, AgentSealArm(), "analyze", "fixture"),
        ("vulnify_feed", "cve_id", R01_ID, VulnifyArm(), "list_vulns", "feed"),
        ("leonidas_corpus", "technique_id", R33_ID, LeonidasArm(), "list_techniques", "corpus"),
        ("specterops_catalog", "skill_id", R03_ID, SpecteropsSkillsArm(), "list_skills", "catalog"),
        ("pentestkit_ledger", "run_id", R42_ID, PentestkitArm(), "list_results", "ledger"),
        ("collinear_scenarios", "scenario_id", R15_ID, CollinearArm(), "list_scenarios", "scenarios_file"),
    ],
)
def test_duplicate_mapping_keys_are_refused_before_schema_validation(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    fixture_name: str,
    key: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    as_yaml: bool,
) -> None:
    original = request.getfixturevalue(fixture_name)
    suffix = ".yaml" if as_yaml else ".json"
    path = tmp_path / f"{arm_id}{suffix}"
    _write_duplicate_mapping_key(
        path,
        _fixture_data(original),
        key,
        as_yaml=as_yaml,
    )
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: str(path)},
    )
    assert result.ok is False
    assert "duplicate mapping key" in result.error


@pytest.mark.parametrize("as_yaml", [False, True], ids=["json", "yaml"])
def test_playbook_duplicate_mapping_keys_are_refused(
    detection_playbook_dir: Path, as_yaml: bool
) -> None:
    original = detection_playbook_dir / "aws-s3.json"
    suffix = ".yaml" if as_yaml else ".json"
    duplicate = detection_playbook_dir / f"duplicate{suffix}"
    _write_duplicate_mapping_key(
        duplicate,
        _fixture_data(original),
        "name",
        as_yaml=as_yaml,
    )
    result = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
        R34_ID,
        "playbook",
        {"playbook_dir": str(detection_playbook_dir), "name": "duplicate"},
    )
    assert result.ok is False
    assert "duplicate mapping key" in result.error


@pytest.mark.parametrize(
    "fixture_name,arm_id,handler,action,path_key",
    [
        ("detections_index", R43_ID, SecurityDetectionsMcpArm(), "list_rules", "index"),
        ("agentseal_fixture", R35_ID, AgentSealArm(), "analyze", "fixture"),
        ("vulnify_feed", R01_ID, VulnifyArm(), "list_vulns", "feed"),
        ("leonidas_corpus", R33_ID, LeonidasArm(), "list_techniques", "corpus"),
        ("specterops_catalog", R03_ID, SpecteropsSkillsArm(), "list_skills", "catalog"),
        ("pentestkit_ledger", R42_ID, PentestkitArm(), "list_results", "ledger"),
        ("collinear_scenarios", R15_ID, CollinearArm(), "list_scenarios", "scenarios_file"),
    ],
)
def test_file_reads_preserve_and_hash_the_original_bytes(
    request: pytest.FixtureRequest,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    path = request.getfixturevalue(fixture_name)
    original_bytes = path.read_bytes()
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: str(path)},
    )
    assert result.ok is True
    _assert_file_source(result.output, path, original_bytes)


def test_playbook_read_preserves_and_hashes_the_original_bytes(
    detection_playbook_dir: Path,
) -> None:
    path = detection_playbook_dir / "aws-s3.json"
    original_bytes = path.read_bytes()
    result = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
        R34_ID,
        "playbook",
        {"playbook_dir": str(detection_playbook_dir), "name": "aws-s3"},
    )
    assert result.ok is True
    _assert_file_source(result.output, path, original_bytes)


def test_vulnify_refuses_unknown_record_fields_without_echoing_values(
    tmp_path: Path,
) -> None:
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps([{"cve_id": "CVE-1", "name": "One", "password": "top-secret"}]),
        encoding="utf-8",
    )
    result = _ext(R01_ID, VulnifyArm()).invoke(
        R01_ID, "lookup", {"feed": str(feed), "cve_id": "CVE-1"}
    )
    assert result.ok is False
    assert "unknown fields" in result.error
    assert "top-secret" not in result.error


def test_detection_limits_rules_and_surfaces_first_parse_error(
    detection_playbook_dir: Path, tmp_path: Path
) -> None:
    result = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
        R34_ID,
        "list_rules",
        {"playbook_dir": str(detection_playbook_dir), "limit": 1},
    )
    assert result.ok is True
    assert result.output["total"] == 2
    assert result.output["returned"] == 1
    assert result.output["capped"] is True

    directory = tmp_path / "broken"
    directory.mkdir()
    (directory / "rules.json").write_text("not-json", encoding="utf-8")
    result = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
        R34_ID, "list_rules", {"playbook_dir": str(directory)}
    )
    assert result.ok is False
    assert "not valid JSON" in result.error

    (directory / "detections.json").write_text(
        json.dumps([{"rule_id": "second", "name": "Ambiguous second source"}]),
        encoding="utf-8",
    )
    result = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
        R34_ID, "list_rules", {"playbook_dir": str(directory)}
    )
    assert result.ok is False
    assert "multiple rules/detections files" in result.error


def test_detection_explicit_playbook_suffix_cannot_select_a_longer_name(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "playbooks"
    directory.mkdir()
    (directory / "named.json").write_text(
        json.dumps({"name": "Exact"}), encoding="utf-8"
    )
    (directory / "named.json.yaml").write_text(
        "name: Wrong longer candidate\n", encoding="utf-8"
    )

    result = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
        R34_ID,
        "playbook",
        {"playbook_dir": str(directory), "name": "named.json"},
    )

    assert result.ok is True
    assert result.output["playbook"]["name"] == "Exact"


def test_detection_bare_playbook_name_refuses_multiple_formats(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "playbooks"
    directory.mkdir()
    (directory / "same.json").write_text(
        json.dumps({"name": "JSON"}), encoding="utf-8"
    )
    (directory / "same.yaml").write_text("name: YAML\n", encoding="utf-8")

    ambiguous = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
        R34_ID,
        "playbook",
        {"playbook_dir": str(directory), "name": "same"},
    )
    explicit = _ext(R34_ID, DetectionInTheCloudArm()).invoke(
        R34_ID,
        "playbook",
        {"playbook_dir": str(directory), "name": "same.yaml"},
    )

    assert ambiguous.ok is False
    assert "multiple playbook files" in ambiguous.error
    assert explicit.ok is True
    assert explicit.output["playbook"]["name"] == "YAML"


def test_pentestkit_summary_keeps_all_attempts_and_statuses(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.json"
    ledger.write_text(
        json.dumps(
            [
                {"run_id": "a", "phase": "first_pass", "status": "pass", "score": 0.8},
                {"run_id": "b", "phase": "first_pass", "status": "timeout"},
                {"run_id": "c", "phase": "tuned", "status": "fail", "score": None},
            ]
        ),
        encoding="utf-8",
    )
    result = _ext(R42_ID, PentestkitArm()).invoke(
        R42_ID, "summary", {"ledger": str(ledger)}
    )
    assert result.ok is True
    assert result.output["total_runs"] == 3
    assert result.output["scored_runs"] == 1
    assert result.output["missing_score_runs"] == 2
    assert result.output["by_status"] == {"fail": 1, "pass": 1, "timeout": 1}
    assert result.output["by_phase"]["first_pass"]["total"] == 2
    assert result.output["by_phase"]["first_pass"]["scored"] == 1
    assert result.output["by_phase"]["first_pass"]["missing_score"] == 1
    assert result.output["by_phase"]["first_pass"]["by_status"]["timeout"] == 1


def test_pentestkit_requires_status_and_rejects_boolean_score(tmp_path: Path) -> None:
    for index, record in enumerate(
        [
            {"run_id": "missing", "phase": "first_pass", "score": 0.5},
            {"run_id": "bool", "phase": "first_pass", "status": "pass", "score": True},
        ]
    ):
        ledger = tmp_path / f"bad-{index}.json"
        ledger.write_text(json.dumps([record]), encoding="utf-8")
        result = _ext(R42_ID, PentestkitArm()).invoke(
            R42_ID, "summary", {"ledger": str(ledger)}
        )
        assert result.ok is False


def test_collinear_requires_exact_complete_match_without_count_oracle(
    tmp_path: Path,
) -> None:
    scenarios = tmp_path / "scenarios.json"
    scenarios.write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "scenario_id": "C1",
                        "name": "Two findings",
                        "expected_findings": [{"id": "A"}, {"id": "B"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    extension = _ext(R15_ID, CollinearArm())
    partial = extension.invoke(
        R15_ID,
        "verify",
        {"scenarios_file": str(scenarios), "scenario_id": "C1", "submission": {"findings": [{"id": "A"}]}},
    )
    assert partial.ok is True
    assert partial.output["verdict"] == "fail"
    assert set(partial.output) == {"scenario_id", "verdict", "source"}

    exact = extension.invoke(
        R15_ID,
        "verify",
        {"scenarios_file": str(scenarios), "scenario_id": "C1", "submission": {"findings": [{"id": "B"}, {"id": "A"}]}},
    )
    assert exact.ok is True
    assert exact.output["verdict"] == "pass"

    extra = extension.invoke(
        R15_ID,
        "verify",
        {"scenarios_file": str(scenarios), "scenario_id": "C1", "submission": {"findings": [{"id": "A"}, {"id": "B"}, {"id": "C"}]}},
    )
    assert extra.ok is True
    assert extra.output["verdict"] == "fail"


@pytest.mark.parametrize(
    "submission",
    [
        {},
        {"findings": "not-a-list"},
        {"findings": ["not-a-mapping"]},
        {"findings": [], "extra": True},
    ],
)
def test_collinear_refuses_malformed_submissions(
    collinear_scenarios: Path, submission: object
) -> None:
    result = _ext(R15_ID, CollinearArm()).invoke(
        R15_ID,
        "verify",
        {
            "scenarios_file": str(collinear_scenarios),
            "scenario_id": "C1",
            "submission": submission,
        },
    )
    assert result.ok is False
    assert result.output is None


@pytest.mark.parametrize("expected_findings", [[], [{}]])
def test_collinear_refuses_absent_or_empty_instructor_answer_sets(
    tmp_path: Path, expected_findings: list[dict[str, object]]
) -> None:
    scenarios = tmp_path / "missing-answer-key.json"
    scenarios.write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "scenario_id": "C1",
                        "name": "Missing answer key",
                        "expected_findings": expected_findings,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    extension = _ext(R15_ID, CollinearArm())
    for action, extra in [
        ("list_scenarios", {}),
        ("scenario", {"scenario_id": "C1"}),
        (
            "verify",
            {"scenario_id": "C1", "submission": {"findings": []}},
        ),
    ]:
        result = extension.invoke(
            R15_ID,
            action,
            {"scenarios_file": str(scenarios), **extra},
        )
        assert result.ok is False
        assert "non-empty" in result.error


def test_collinear_recursively_strips_instructor_keys(tmp_path: Path) -> None:
    scenarios = tmp_path / "nested.json"
    scenarios.write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "scenario_id": "C1",
                        "name": "Nested",
                        "environment_config": {
                            "public": "ok",
                            "nested": {"expected_findings": [{"secret": True}]},
                        },
                        "expected_findings": [{"id": "answer"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = _ext(R15_ID, CollinearArm()).invoke(
        R15_ID, "scenario", {"scenarios_file": str(scenarios), "scenario_id": "C1"}
    )
    assert result.ok is True
    assert "expected_findings" not in json.dumps(result.output["scenario"])


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
