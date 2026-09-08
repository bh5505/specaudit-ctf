"""Curated arms Tier 4: R02, R08, R25, R17, R36, R38.

All six arms are in-process read arms (no binary, no endpoint).
Tests use synthetic fixture files to verify fail-closed behavior,
argument validation, output capping, and list_tools shape.
"""

from __future__ import annotations

import hashlib
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
from extension.arms.m365pwned.policy import cases_file_refusal
from extension.arms.strict_data import BoundedYamlNodeMixin, StrictDataError

import extension.arms.ad_pathfinder.arm as ad_pathfinder_module
import extension.arms.gpohound.arm as gpohound_module
import extension.arms.claude_ad.arm as claude_ad_module
import extension.arms.numasec.arm as numasec_module
import extension.arms.rubeus.arm as rubeus_module
import extension.arms.m365pwned.arm as m365pwned_module


def _spec(arm_id: str) -> ArmSpec:
    return ArmSpec(id=arm_id, protocols=("cli",), curated=True, notes="test", tier="research")


def _ext(arm_id: str, handler) -> Extension:
    entry = CatalogEntry(id=arm_id, kind="arm", protocols=("cli",), curated=True, notes="test", tier="research")
    return Extension(catalog=Catalog([entry]), arms={arm_id: handler})


def _assert_source(
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
    assert "path" not in output["source"]


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

    import yaml

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
        assert result.ok is True and result.output["path"]["source"] == "DC01"
        _assert_source(result.output, ad_export)

    def test_path_not_found(self, ad_export: Path) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(R02_ID, "path", {"export": str(ad_export), "path_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_path_by_endpoints_and_ambiguous_endpoints(self, ad_export: Path) -> None:
        ext = _ext(R02_ID, AdPathfinderArm())
        result = ext.invoke(
            R02_ID,
            "path",
            {"export": str(ad_export), "source": "DC01", "target": "SQL01"},
        )
        assert result.ok is True
        assert result.output["path"]["path_id"] == "P1"

        rows = json.loads(ad_export.read_text(encoding="utf-8"))
        duplicate = json.loads(json.dumps(rows[0]))
        duplicate["path_id"] = "P3"
        rows.append(duplicate)
        ad_export.write_text(json.dumps(rows), encoding="utf-8")
        ambiguous = ext.invoke(
            R02_ID,
            "path",
            {"export": str(ad_export), "source": "DC01", "target": "SQL01"},
        )
        assert ambiguous.ok is False
        assert "multiple paths" in ambiguous.error

    def test_path_refuses_conflicting_selector_families(self, ad_export: Path) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(
            R02_ID,
            "path",
            {
                "export": str(ad_export),
                "path_id": "P2",
                "source": "DC01",
                "target": "SQL01",
            },
        )
        assert result.ok is False
        assert "either args.path_id or both args.source" in result.error

    def test_list_paths(self, ad_export: Path) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(R02_ID, "list_paths", {"export": str(ad_export)})
        assert result.ok is True and result.output["total"] == 2
        assert result.output["paths"][1]["datasource"] == "not assessed"

    def test_list_datasources(self, ad_export: Path) -> None:
        result = _ext(R02_ID, AdPathfinderArm()).invoke(R02_ID, "list_datasources", {"export": str(ad_export)})
        assert result.ok is True
        assert result.output["datasources"] == ["BloodHound", "not assessed"]
        assert result.output["not_assessed_paths"] == 1
        assert result.output["coverage_status"] == "partially assessed"

    def test_all_missing_datasources_stay_explicit(self, ad_export: Path) -> None:
        data = json.loads(ad_export.read_text(encoding="utf-8"))
        for row in data:
            row["datasource"] = None
        ad_export.write_text(json.dumps(data), encoding="utf-8")
        result = _ext(R02_ID, AdPathfinderArm()).invoke(
            R02_ID,
            "list_datasources",
            {"export": str(ad_export)},
        )
        assert result.ok is True
        assert result.output["datasources"] == ["not assessed"]
        assert result.output["not_assessed_paths"] == 2
        assert result.output["coverage_status"] == "not assessed"

    def test_empty_export_is_not_reported_as_assessed(self, tmp_path: Path) -> None:
        export = tmp_path / "empty.json"
        export.write_text("[]", encoding="utf-8")
        result = _ext(R02_ID, AdPathfinderArm()).invoke(
            R02_ID, "list_datasources", {"export": str(export)}
        )
        assert result.ok is False
        assert "no paths" in result.error
        assert "not assessed" in result.error

    @pytest.mark.parametrize(
        "mutation,error_text",
        [
            (lambda row: row.update(length=99), "node count"),
            (lambda row: row.update(source="OTHER"), "path endpoints"),
            (lambda row: row["edges"][0].update(to="OTHER"), "adjacent nodes"),
            (lambda row: row["edges"].pop(), "connect each adjacent pair"),
        ],
    )
    def test_incoherent_path_evidence_is_refused(
        self, ad_export: Path, mutation, error_text: str
    ) -> None:
        data = json.loads(ad_export.read_text(encoding="utf-8"))
        mutation(data[0])
        ad_export.write_text(json.dumps(data), encoding="utf-8")
        result = _ext(R02_ID, AdPathfinderArm()).invoke(
            R02_ID,
            "list_paths",
            {"export": str(ad_export)},
        )
        assert result.ok is False
        assert error_text in result.error

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
        assert result.ok is True and result.output["policy"]["name"] == "Default Domain Policy"
        _assert_source(result.output, gpo_evidence)

    def test_policy_not_found(self, gpo_evidence: Path) -> None:
        result = _ext(R08_ID, GpohoundArm()).invoke(R08_ID, "policy", {"evidence": str(gpo_evidence), "policy_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_policy_by_name_and_ambiguous_name(self, gpo_evidence: Path) -> None:
        ext = _ext(R08_ID, GpohoundArm())
        result = ext.invoke(
            R08_ID,
            "policy",
            {"evidence": str(gpo_evidence), "name": "Default Domain Policy"},
        )
        assert result.ok is True
        assert result.output["policy"]["policy_id"] == "GPO-001"

        rows = json.loads(gpo_evidence.read_text(encoding="utf-8"))
        rows[1]["name"] = rows[0]["name"]
        gpo_evidence.write_text(json.dumps(rows), encoding="utf-8")
        ambiguous = ext.invoke(
            R08_ID,
            "policy",
            {"evidence": str(gpo_evidence), "name": rows[0]["name"]},
        )
        assert ambiguous.ok is False
        assert "multiple policies" in ambiguous.error

    def test_policy_refuses_more_than_one_selector(self, gpo_evidence: Path) -> None:
        result = _ext(R08_ID, GpohoundArm()).invoke(
            R08_ID,
            "policy",
            {
                "evidence": str(gpo_evidence),
                "policy_id": "GPO-001",
                "name": "Default Domain Policy",
            },
        )
        assert result.ok is False
        assert "exactly one" in result.error

    def test_list_policies(self, gpo_evidence: Path) -> None:
        result = _ext(R08_ID, GpohoundArm()).invoke(R08_ID, "list_policies", {"evidence": str(gpo_evidence)})
        assert result.ok is True and result.output["total"] == 2

    def test_list_policies_status_filter(self, gpo_evidence: Path) -> None:
        result = _ext(R08_ID, GpohoundArm()).invoke(
            R08_ID,
            "list_policies",
            {"evidence": str(gpo_evidence), "status": "active"},
        )
        assert result.ok is True
        assert result.output["total"] == result.output["returned"] == 1
        assert result.output["unfiltered_total"] == 2
        assert result.output["policies"][0]["policy_id"] == "GPO-001"

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
        technique = result.output["technique"]
        assert result.ok is True and technique["name"] == "Kerberoasting"
        assert technique["prerequisites"] == ["valid domain account", "SPN registered"]
        assert technique["observed_facts"] == ["TGS request for SPN"]
        assert technique["inference"] == "Service account password may be crackable"
        _assert_source(result.output, ad_method)

    def test_technique_not_found(self, ad_method: Path) -> None:
        result = _ext(R25_ID, ClaudeAdArm()).invoke(R25_ID, "technique", {"method_file": str(ad_method), "technique_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_technique_by_name_and_ambiguous_name(self, ad_method: Path) -> None:
        ext = _ext(R25_ID, ClaudeAdArm())
        result = ext.invoke(
            R25_ID,
            "technique",
            {"method_file": str(ad_method), "name": "Kerberoasting"},
        )
        assert result.ok is True
        assert result.output["technique"]["technique_id"] == "AD-01"

        data = json.loads(ad_method.read_text(encoding="utf-8"))
        data["techniques"][1]["name"] = data["techniques"][0]["name"]
        ad_method.write_text(json.dumps(data), encoding="utf-8")
        ambiguous = ext.invoke(
            R25_ID,
            "technique",
            {"method_file": str(ad_method), "name": "Kerberoasting"},
        )
        assert ambiguous.ok is False
        assert "multiple techniques" in ambiguous.error

    def test_technique_refuses_conflicting_selectors(self, ad_method: Path) -> None:
        result = _ext(R25_ID, ClaudeAdArm()).invoke(
            R25_ID,
            "technique",
            {
                "method_file": str(ad_method),
                "technique_id": "AD-02",
                "name": "Kerberoasting",
            },
        )
        assert result.ok is False
        assert "exactly one" in result.error

    def test_list_techniques(self, ad_method: Path) -> None:
        result = _ext(R25_ID, ClaudeAdArm()).invoke(R25_ID, "list_techniques", {"method_file": str(ad_method)})
        assert result.ok is True and result.output["count"] == 2
        assert set(result.output["techniques"][0]) == {
            "technique_id",
            "name",
            "category",
            "mitre_mapping",
        }

    def test_explicit_null_limit_keeps_the_default_cap(self, tmp_path: Path) -> None:
        techniques = [
            {
                "technique_id": f"AD-{index:03d}",
                "name": f"Technique {index}",
                "category": "credential",
                "prerequisites": [],
                "observed_facts": [],
                "inference": "synthetic test inference",
                "mitre_mapping": "T0000",
            }
            for index in range(201)
        ]
        path = tmp_path / "method.json"
        path.write_text(json.dumps({"techniques": techniques}), encoding="utf-8")

        result = _ext(R25_ID, ClaudeAdArm()).invoke(
            R25_ID,
            "list_techniques",
            {"method_file": str(path), "limit": None},
        )

        assert result.ok is True
        assert result.output["total"] == 201
        assert result.output["returned"] == 200
        assert result.output["capped"] is True

    def test_filtered_totals_distinguish_matches_from_the_full_input(
        self, tmp_path: Path
    ) -> None:
        techniques = [
            {
                "technique_id": f"AD-{index}",
                "name": f"Technique {index}",
                "category": category,
                "prerequisites": [],
                "observed_facts": [],
                "inference": "synthetic test inference",
                "mitre_mapping": "T0000",
            }
            for index, category in enumerate(("credential", "credential", "policy"))
        ]
        path = tmp_path / "method.json"
        path.write_text(json.dumps({"techniques": techniques}), encoding="utf-8")

        result = _ext(R25_ID, ClaudeAdArm()).invoke(
            R25_ID,
            "list_techniques",
            {"method_file": str(path), "category": "credential", "limit": 1},
        )

        assert result.ok is True
        assert result.output["unfiltered_total"] == 3
        assert result.output["total"] == 2
        assert result.output["returned"] == 1
        assert result.output["capped"] is True

    def test_non_primary_list_reports_its_full_denominator(self, tmp_path: Path) -> None:
        techniques = [
            {
                "technique_id": f"AD-{index:03d}",
                "name": f"Technique {index}",
                "category": "credential",
                "prerequisites": [f"prerequisite-{index:03d}"],
                "observed_facts": [],
                "inference": "synthetic test inference",
                "mitre_mapping": "T0000",
            }
            for index in range(201)
        ]
        path = tmp_path / "method.json"
        path.write_text(json.dumps({"techniques": techniques}), encoding="utf-8")

        result = _ext(R25_ID, ClaudeAdArm()).invoke(
            R25_ID,
            "list_prerequisites",
            {"method_file": str(path)},
        )

        assert result.ok is True
        assert result.output["total"] == 201
        assert result.output["returned"] == 200
        assert result.output["capped"] is True

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
        assert result.ok is True and result.output["finding"]["title"] == "Weak Password Policy"
        _assert_source(result.output, finding_ledger)

    def test_finding_not_found(self, finding_ledger: Path) -> None:
        result = _ext(R17_ID, NumasecArm()).invoke(R17_ID, "finding", {"ledger": str(finding_ledger), "finding_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_findings(self, finding_ledger: Path) -> None:
        result = _ext(R17_ID, NumasecArm()).invoke(R17_ID, "list_findings", {"ledger": str(finding_ledger)})
        assert result.ok is True and len(result.output["findings"]) == 2
        assert result.output["total"] == result.output["returned"] == 2

    def test_list_findings_status_filter(self, finding_ledger: Path) -> None:
        result = _ext(R17_ID, NumasecArm()).invoke(
            R17_ID,
            "list_findings",
            {"ledger": str(finding_ledger), "status": "open"},
        )
        assert result.ok is True
        assert result.output["total"] == result.output["returned"] == 1
        assert result.output["unfiltered_total"] == 2
        assert result.output["findings"][0]["finding_id"] == "F001"

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
        assert result.ok is True and result.output["telemetry"]["category"] == "kerberos"
        assert result.output["telemetry"]["indicators"] == [{"type": "encryption_type"}]
        assert "[REDACTED]" not in json.dumps(result.output)
        _assert_source(result.output, ad_telemetry)

    def test_telemetry_not_found(self, ad_telemetry: Path) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(R36_ID, "telemetry", {"telemetry_file": str(ad_telemetry), "event_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_list_telemetry(self, ad_telemetry: Path) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(R36_ID, "list_telemetry", {"telemetry_file": str(ad_telemetry)})
        assert result.ok is True and result.output["total"] == 2

    def test_list_telemetry_category_filter(self, ad_telemetry: Path) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(
            R36_ID,
            "list_telemetry",
            {"telemetry_file": str(ad_telemetry), "category": "kerberos"},
        )
        assert result.ok is True
        assert result.output["total"] == result.output["returned"] == 1
        assert result.output["unfiltered_total"] == 2
        assert result.output["events"][0]["event_id"] == "E001"

    def test_list_indicators(self, ad_telemetry: Path) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(R36_ID, "list_indicators", {"telemetry_file": str(ad_telemetry)})
        assert result.ok is True

    def test_list_indicators_type_filter(self, ad_telemetry: Path) -> None:
        result = _ext(R36_ID, RubeusArm()).invoke(
            R36_ID,
            "list_indicators",
            {
                "telemetry_file": str(ad_telemetry),
                "indicator_type": "encryption_type",
            },
        )
        assert result.ok is True
        assert result.output["total"] == result.output["returned"] == 1
        assert result.output["unfiltered_total"] == 2
        assert result.output["indicators"] == [{"type": "encryption_type", "count": 1}]


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
        assert result.ok is True and result.output["case_study"]["name"] == "Consent Phish"
        _assert_source(result.output, m365_cases)

    def test_case_study_not_found(self, m365_cases: Path) -> None:
        result = _ext(R38_ID, M365PwnedArm()).invoke(R38_ID, "case_study", {"cases_file": str(m365_cases), "case_id": "NOPE"})
        assert result.ok is False and "not found" in result.error

    def test_case_study_by_name_and_ambiguous_name(self, m365_cases: Path) -> None:
        ext = _ext(R38_ID, M365PwnedArm())
        result = ext.invoke(
            R38_ID,
            "case_study",
            {"cases_file": str(m365_cases), "name": "Consent Phish"},
        )
        assert result.ok is True
        assert result.output["case_study"]["case_id"] == "C001"

        rows = json.loads(m365_cases.read_text(encoding="utf-8"))
        rows[1]["name"] = rows[0]["name"]
        m365_cases.write_text(json.dumps(rows), encoding="utf-8")
        ambiguous = ext.invoke(
            R38_ID,
            "case_study",
            {"cases_file": str(m365_cases), "name": "Consent Phish"},
        )
        assert ambiguous.ok is False
        assert "multiple case studies" in ambiguous.error

    def test_case_study_refuses_more_than_one_selector(
        self, m365_cases: Path
    ) -> None:
        result = _ext(R38_ID, M365PwnedArm()).invoke(
            R38_ID,
            "case_study",
            {
                "cases_file": str(m365_cases),
                "case_id": "C001",
                "name": "Consent Phish",
            },
        )
        assert result.ok is False
        assert "exactly one" in result.error

    def test_list_case_studies(self, m365_cases: Path) -> None:
        result = _ext(R38_ID, M365PwnedArm()).invoke(R38_ID, "list_case_studies", {"cases_file": str(m365_cases)})
        assert result.ok is True and result.output["total"] == 2
        assert result.output["case_studies"][0]["risk_level"] == "high"
        assert result.output["case_studies"][1]["risk_level"] == "medium"

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


# ======================================================================
# Cross-arm contract and review regressions
# ======================================================================

_LIST_CASES = [
    ("ad_export", R02_ID, AdPathfinderArm(), "list_paths", "export"),
    ("gpo_evidence", R08_ID, GpohoundArm(), "list_policies", "evidence"),
    ("ad_method", R25_ID, ClaudeAdArm(), "list_techniques", "method_file"),
    ("finding_ledger", R17_ID, NumasecArm(), "list_findings", "ledger"),
    ("ad_telemetry", R36_ID, RubeusArm(), "list_telemetry", "telemetry_file"),
    ("m365_cases", R38_ID, M365PwnedArm(), "list_case_studies", "cases_file"),
]


@pytest.mark.parametrize(
    "module,constant,validator,fixture_name,arm_id,handler,action,path_key",
    [
        (ad_pathfinder_module, "_MAX_ITEMS", "_validate_paths", "ad_export", R02_ID, AdPathfinderArm(), "list_paths", "export"),
        (gpohound_module, "_MAX_TREE_NODES", "_validate_policies", "gpo_evidence", R08_ID, GpohoundArm(), "list_policies", "evidence"),
        (claude_ad_module, "_MAX_ITEMS", "_validate_techniques", "ad_method", R25_ID, ClaudeAdArm(), "list_techniques", "method_file"),
        (numasec_module, "_MAX_RECORDS", "_validate_findings", "finding_ledger", R17_ID, NumasecArm(), "list_findings", "ledger"),
        (rubeus_module, "_MAX_RECORDS", "_validate_events", "ad_telemetry", R36_ID, RubeusArm(), "list_telemetry", "telemetry_file"),
        (m365pwned_module, "_MAX_ITEMS", "_validate_cases", "m365_cases", R38_ID, M365PwnedArm(), "list_case_studies", "cases_file"),
    ],
)
def test_batch8_document_record_caps_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    module,
    constant: str,
    validator: str,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    source = request.getfixturevalue(fixture_name)
    monkeypatch.setattr(module, constant, 1)
    # Isolate the top-level record gate from nested validators that reuse the
    # same historical constant for their own list/tree budgets.
    monkeypatch.setattr(module, validator, lambda rows: rows)
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(source)}
    )
    assert result.ok is False
    assert "cap" in result.error


@pytest.mark.parametrize("bad_limit", [True, "1", 0, 201])
@pytest.mark.parametrize("fixture_name,arm_id,handler,action,path_key", _LIST_CASES)
def test_limits_are_strict_and_bounded(
    request: pytest.FixtureRequest,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    bad_limit: object,
) -> None:
    path = request.getfixturevalue(fixture_name)
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path), "limit": bad_limit}
    )
    assert result.ok is False
    assert "limit" in result.error


@pytest.mark.parametrize(
    "arm_id,handler,action,path_key",
    [
        (R02_ID, AdPathfinderArm(), "list_paths", "export"),
        (R08_ID, GpohoundArm(), "list_policies", "evidence"),
        (R25_ID, ClaudeAdArm(), "list_techniques", "method_file"),
        (R17_ID, NumasecArm(), "list_findings", "ledger"),
        (R36_ID, RubeusArm(), "list_telemetry", "telemetry_file"),
        (R38_ID, M365PwnedArm(), "list_case_studies", "cases_file"),
    ],
)
def test_invalid_source_paths_are_not_echoed(
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    private_path = "/operator/private/customer-alpha/nonexistent.json"
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: private_path},
    )
    assert result.ok is False
    assert private_path not in result.error
    assert "/operator/private" not in result.error


_DUPLICATE_KEY_CASES = [
    ("ad_export", "path_id", R02_ID, AdPathfinderArm(), "list_paths", "export"),
    ("gpo_evidence", "policy_id", R08_ID, GpohoundArm(), "list_policies", "evidence"),
    ("ad_method", "technique_id", R25_ID, ClaudeAdArm(), "list_techniques", "method_file"),
    ("finding_ledger", "finding_id", R17_ID, NumasecArm(), "list_findings", "ledger"),
    ("ad_telemetry", "event_id", R36_ID, RubeusArm(), "list_telemetry", "telemetry_file"),
    ("m365_cases", "case_id", R38_ID, M365PwnedArm(), "list_case_studies", "cases_file"),
]


@pytest.mark.parametrize(
    "fixture_name,key,arm_id,handler,action,path_key",
    _DUPLICATE_KEY_CASES,
)
def test_duplicate_json_mapping_keys_are_refused_before_schema_validation(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    fixture_name: str,
    key: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    original = request.getfixturevalue(fixture_name)
    path = tmp_path / f"{arm_id}.json"
    data = json.loads(original.read_text(encoding="utf-8"))
    _write_duplicate_mapping_key(path, data, key, as_yaml=False)
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: str(path)},
    )
    assert result.ok is False
    assert "duplicate mapping key" in result.error


@pytest.mark.parametrize(
    "fixture_name,key,arm_id,handler,action,path_key",
    [
        case
        for case in _DUPLICATE_KEY_CASES
        if case[2] not in {R17_ID, R36_ID}
    ],
)
def test_duplicate_yaml_mapping_keys_are_refused_before_schema_validation(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    fixture_name: str,
    key: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    original = request.getfixturevalue(fixture_name)
    path = tmp_path / f"{arm_id}.yaml"
    data = json.loads(original.read_text(encoding="utf-8"))
    _write_duplicate_mapping_key(path, data, key, as_yaml=True)
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: str(path)},
    )
    assert result.ok is False
    assert "duplicate mapping key" in result.error


@pytest.mark.parametrize(
    "fixture_name,arm_id,handler,action,path_key",
    _LIST_CASES,
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
    _assert_source(result.output, path, original_bytes)


@pytest.mark.parametrize("fixture_name,arm_id,handler,action,path_key", _LIST_CASES)
def test_list_denominators_and_source_are_honest(
    request: pytest.FixtureRequest,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    path = request.getfixturevalue(fixture_name)
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path), "limit": 1}
    )
    assert result.ok is True
    assert result.output["total"] == 2
    assert result.output["returned"] == 1
    assert result.output["capped"] is True
    _assert_source(result.output, path)


@pytest.mark.parametrize(
    "fixture_name,arm_id,handler,action,path_key,query,list_key,expected",
    [
        ("ad_export", R02_ID, AdPathfinderArm(), "list_datasources", "export", {}, "datasources", 2),
        ("gpo_evidence", R08_ID, GpohoundArm(), "list_links", "evidence", {"gpo_id": "GPO-001"}, "links", 1),
        ("ad_method", R25_ID, ClaudeAdArm(), "list_prerequisites", "method_file", {}, "prerequisites", 3),
        ("finding_ledger", R17_ID, NumasecArm(), "list_transitions", "ledger", {"finding_id": "F002"}, "transitions", 2),
        ("ad_telemetry", R36_ID, RubeusArm(), "list_indicators", "telemetry_file", {}, "indicators", 2),
        ("m365_cases", R38_ID, M365PwnedArm(), "list_permissions", "cases_file", {"case_id": "C001"}, "permissions", 2),
    ],
)
def test_non_primary_lists_report_denominators_and_source(
    request: pytest.FixtureRequest,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    query: dict,
    list_key: str,
    expected: int,
) -> None:
    path = request.getfixturevalue(fixture_name)
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path), **query}
    )
    assert result.ok is True
    assert len(result.output[list_key]) == expected
    assert result.output["total"] == expected
    assert result.output["returned"] == expected
    assert result.output["capped"] is False
    _assert_source(result.output, path)


@pytest.mark.parametrize(
    "module,fixture_name,arm_id,handler,action,path_key,query",
    [
        (ad_pathfinder_module, "ad_export", R02_ID, AdPathfinderArm(), "list_datasources", "export", {}),
        (gpohound_module, "gpo_evidence", R08_ID, GpohoundArm(), "list_links", "evidence", {"gpo_id": "GPO-001"}),
        (claude_ad_module, "ad_method", R25_ID, ClaudeAdArm(), "list_prerequisites", "method_file", {}),
        (numasec_module, "finding_ledger", R17_ID, NumasecArm(), "list_transitions", "ledger", {"finding_id": "F002"}),
        (rubeus_module, "ad_telemetry", R36_ID, RubeusArm(), "list_indicators", "telemetry_file", {}),
        (m365pwned_module, "m365_cases", R38_ID, M365PwnedArm(), "list_permissions", "cases_file", {"case_id": "C001"}),
    ],
)
def test_non_primary_lists_enforce_the_shared_result_cap(
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
    if arm_id == R08_ID:
        rows = json.loads(path.read_text(encoding="utf-8"))
        rows[0]["links"].append({"ou": "OU=Second,DC=corp,DC=local"})
        path.write_text(json.dumps(rows), encoding="utf-8")
    monkeypatch.setattr(module, "MAX_RESULTS", 1)
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path), **query}
    )
    assert result.ok is True
    assert result.output["total"] > 1
    assert result.output["returned"] == 1
    assert result.output["capped"] is True


@pytest.mark.parametrize(
    "fixture_name,container_key,arm_id,handler,action,path_key,query",
    [
        ("ad_export", None, R02_ID, AdPathfinderArm(), "path", "export", {"path_id": "P1"}),
        ("gpo_evidence", None, R08_ID, GpohoundArm(), "policy", "evidence", {"policy_id": "GPO-001"}),
        ("ad_method", "techniques", R25_ID, ClaudeAdArm(), "technique", "method_file", {"technique_id": "AD-01"}),
        ("finding_ledger", None, R17_ID, NumasecArm(), "finding", "ledger", {"finding_id": "F001"}),
        ("ad_telemetry", None, R36_ID, RubeusArm(), "telemetry", "telemetry_file", {"event_id": "E001"}),
        ("m365_cases", None, R38_ID, M365PwnedArm(), "case_study", "cases_file", {"case_id": "C001"}),
    ],
)
def test_malformed_later_record_refuses_whole_corpus(
    request: pytest.FixtureRequest,
    fixture_name: str,
    container_key: str | None,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    query: dict,
) -> None:
    path = request.getfixturevalue(fixture_name)
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data if container_key is None else data[container_key]
    rows.append({"api_token": "must-not-be-ignored"})
    path.write_text(json.dumps(data), encoding="utf-8")
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path), **query}
    )
    assert result.ok is False
    assert "unknown fields" in result.error
    assert "must-not-be-ignored" not in result.error


@pytest.mark.parametrize(
    "filename,arm_id,handler,action,path_key",
    [
        ("bad.json", R02_ID, AdPathfinderArm(), "list_paths", "export"),
        ("bad.json", R08_ID, GpohoundArm(), "list_policies", "evidence"),
        ("bad.json", R25_ID, ClaudeAdArm(), "list_techniques", "method_file"),
        ("bad.json", R17_ID, NumasecArm(), "list_findings", "ledger"),
        ("bad.json", R36_ID, RubeusArm(), "list_telemetry", "telemetry_file"),
        ("bad.json", R38_ID, M365PwnedArm(), "list_case_studies", "cases_file"),
    ],
)
def test_non_utf8_is_refused_without_replacement(
    tmp_path: Path,
    filename: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    path = tmp_path / f"{arm_id}-{filename}"
    path.write_bytes(b"[\xff]")
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path)}
    )
    assert result.ok is False
    assert "strict UTF-8" in result.error


@pytest.mark.parametrize(
    "module,fixture_name,arm_id,handler,action,path_key",
    [
        (ad_pathfinder_module, "ad_export", R02_ID, AdPathfinderArm(), "list_paths", "export"),
        (gpohound_module, "gpo_evidence", R08_ID, GpohoundArm(), "list_policies", "evidence"),
        (claude_ad_module, "ad_method", R25_ID, ClaudeAdArm(), "list_techniques", "method_file"),
        (numasec_module, "finding_ledger", R17_ID, NumasecArm(), "list_findings", "ledger"),
        (rubeus_module, "ad_telemetry", R36_ID, RubeusArm(), "list_telemetry", "telemetry_file"),
        (m365pwned_module, "m365_cases", R38_ID, M365PwnedArm(), "list_case_studies", "cases_file"),
    ],
)
def test_runtime_byte_cap_is_enforced_after_path_validation(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    module,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    path = request.getfixturevalue(fixture_name)
    cap_name = {
        R02_ID: "MAX_EXPORT_BYTES",
        R08_ID: "MAX_EVIDENCE_BYTES",
        R25_ID: "MAX_METHOD_BYTES",
        R17_ID: "MAX_LEDGER_BYTES",
        R36_ID: "MAX_TELEMETRY_BYTES",
        R38_ID: "MAX_CASE_BYTES",
    }[arm_id]
    monkeypatch.setattr(module, cap_name, 1)
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path)}
    )
    assert result.ok is False
    assert "byte read cap" in result.error


@pytest.mark.parametrize(
    "module,arm_id,handler",
    [
        (ad_pathfinder_module, R02_ID, AdPathfinderArm()),
        (gpohound_module, R08_ID, GpohoundArm()),
        (claude_ad_module, R25_ID, ClaudeAdArm()),
        (numasec_module, R17_ID, NumasecArm()),
        (rubeus_module, R36_ID, RubeusArm()),
        (m365pwned_module, R38_ID, M365PwnedArm()),
    ],
)
def test_list_tools_obeys_output_cap(
    monkeypatch: pytest.MonkeyPatch,
    module,
    arm_id: str,
    handler,
) -> None:
    monkeypatch.setattr(module, "MAX_OUTPUT_CHARS", 1)
    result = _ext(arm_id, handler).invoke(arm_id, "list_tools", {})
    assert result.ok is False
    assert result.output is None


_ALL_EVIDENCE_ACTIONS = [
    (ad_pathfinder_module, "ad_export", R02_ID, AdPathfinderArm(), "path", "export", {"path_id": "P1"}),
    (ad_pathfinder_module, "ad_export", R02_ID, AdPathfinderArm(), "list_paths", "export", {}),
    (ad_pathfinder_module, "ad_export", R02_ID, AdPathfinderArm(), "list_datasources", "export", {}),
    (gpohound_module, "gpo_evidence", R08_ID, GpohoundArm(), "policy", "evidence", {"policy_id": "GPO-001"}),
    (gpohound_module, "gpo_evidence", R08_ID, GpohoundArm(), "list_policies", "evidence", {}),
    (gpohound_module, "gpo_evidence", R08_ID, GpohoundArm(), "list_links", "evidence", {"gpo_id": "GPO-001"}),
    (claude_ad_module, "ad_method", R25_ID, ClaudeAdArm(), "technique", "method_file", {"technique_id": "AD-01"}),
    (claude_ad_module, "ad_method", R25_ID, ClaudeAdArm(), "list_techniques", "method_file", {}),
    (claude_ad_module, "ad_method", R25_ID, ClaudeAdArm(), "list_prerequisites", "method_file", {}),
    (numasec_module, "finding_ledger", R17_ID, NumasecArm(), "finding", "ledger", {"finding_id": "F001"}),
    (numasec_module, "finding_ledger", R17_ID, NumasecArm(), "list_findings", "ledger", {}),
    (numasec_module, "finding_ledger", R17_ID, NumasecArm(), "list_transitions", "ledger", {"finding_id": "F002"}),
    (rubeus_module, "ad_telemetry", R36_ID, RubeusArm(), "telemetry", "telemetry_file", {"event_id": "E001"}),
    (rubeus_module, "ad_telemetry", R36_ID, RubeusArm(), "list_telemetry", "telemetry_file", {}),
    (rubeus_module, "ad_telemetry", R36_ID, RubeusArm(), "list_indicators", "telemetry_file", {}),
    (m365pwned_module, "m365_cases", R38_ID, M365PwnedArm(), "case_study", "cases_file", {"case_id": "C001"}),
    (m365pwned_module, "m365_cases", R38_ID, M365PwnedArm(), "list_case_studies", "cases_file", {}),
    (m365pwned_module, "m365_cases", R38_ID, M365PwnedArm(), "list_permissions", "cases_file", {"case_id": "C001"}),
]


@pytest.mark.parametrize("module,fixture_name,arm_id,handler,action,path_key,query", _ALL_EVIDENCE_ACTIONS)
def test_every_evidence_action_obeys_output_cap(
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
    monkeypatch.setattr(module, "MAX_OUTPUT_CHARS", 1)
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path), **query}
    )
    assert result.ok is False
    assert result.output is None


@pytest.mark.parametrize(
    "arm_id,handler,action,path_key",
    [
        (R02_ID, AdPathfinderArm(), "list_paths", "export"),
        (R08_ID, GpohoundArm(), "list_policies", "evidence"),
        (R25_ID, ClaudeAdArm(), "list_techniques", "method_file"),
        (R38_ID, M365PwnedArm(), "list_case_studies", "cases_file"),
    ],
)
def test_yaml_aliases_are_refused(
    tmp_path: Path,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    path = tmp_path / f"{arm_id}.yaml"
    path.write_text("first: &shared []\nsecond: *shared\n", encoding="utf-8")
    result = _ext(arm_id, handler).invoke(
        arm_id, action, {path_key: str(path)}
    )
    assert result.ok is False
    assert "aliases and anchors are not allowed" in result.error


@pytest.mark.parametrize(
    "cap_name,error_text",
    [
        ("max_document_nodes", "node cap"),
        ("max_document_depth", "nesting-depth cap"),
    ],
)
@pytest.mark.parametrize(
    "arm_id,handler,action,path_key",
    [
        (R02_ID, AdPathfinderArm(), "list_paths", "export"),
        (R08_ID, GpohoundArm(), "list_policies", "evidence"),
        (R25_ID, ClaudeAdArm(), "list_techniques", "method_file"),
        (R38_ID, M365PwnedArm(), "list_case_studies", "cases_file"),
    ],
)
def test_shared_yaml_loader_enforces_composition_caps(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    cap_name: str,
    error_text: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    monkeypatch.setattr(BoundedYamlNodeMixin, cap_name, 1)
    path = tmp_path / f"{arm_id}.yaml"
    path.write_text("- nested:\n  - value\n", encoding="utf-8")
    result = _ext(arm_id, handler).invoke(arm_id, action, {path_key: str(path)})
    assert result.ok is False
    assert error_text in result.error


@pytest.mark.parametrize(
    "fixture_name,container_key,arm_id,handler,action,path_key",
    [
        ("ad_export", None, R02_ID, AdPathfinderArm(), "list_paths", "export"),
        ("gpo_evidence", None, R08_ID, GpohoundArm(), "list_policies", "evidence"),
        ("ad_method", "techniques", R25_ID, ClaudeAdArm(), "list_techniques", "method_file"),
        ("m365_cases", None, R38_ID, M365PwnedArm(), "list_case_studies", "cases_file"),
    ],
)
def test_valid_yaml_remains_supported(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    fixture_name: str,
    container_key: str | None,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    yaml = pytest.importorskip("yaml")
    original = request.getfixturevalue(fixture_name)
    data = json.loads(original.read_text(encoding="utf-8"))
    if container_key is not None and not isinstance(data, dict):
        data = {container_key: data}
    path = tmp_path / f"{arm_id}.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    result = _ext(arm_id, handler).invoke(arm_id, action, {path_key: str(path)})
    assert result.ok is True
    assert result.output["total"] == 2
    _assert_source(result.output, path)


@pytest.mark.parametrize(
    "fixture_name,arm_id,handler,action,path_key",
    [
        ("finding_ledger", R17_ID, NumasecArm(), "list_findings", "ledger"),
        ("ad_telemetry", R36_ID, RubeusArm(), "list_telemetry", "telemetry_file"),
    ],
)
def test_jsonl_remains_supported(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
) -> None:
    original = request.getfixturevalue(fixture_name)
    rows = json.loads(original.read_text(encoding="utf-8"))
    path = tmp_path / f"{arm_id}.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    result = _ext(arm_id, handler).invoke(arm_id, action, {path_key: str(path)})
    assert result.ok is True
    assert result.output["total"] == 2
    _assert_source(result.output, path)


@pytest.mark.parametrize(
    "fixture_name,key,arm_id,handler,action,path_key",
    [
        ("finding_ledger", "finding_id", R17_ID, NumasecArm(), "list_findings", "ledger"),
        ("ad_telemetry", "event_id", R36_ID, RubeusArm(), "list_telemetry", "telemetry_file"),
    ],
)
def test_jsonl_duplicate_mapping_keys_are_refused(
    request: pytest.FixtureRequest,
    tmp_path: Path,
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
        (numasec_module, "finding_ledger", R17_ID, NumasecArm(), "list_findings", "ledger"),
        (rubeus_module, "ad_telemetry", R36_ID, RubeusArm(), "list_telemetry", "telemetry_file"),
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

    monkeypatch.setattr(module, "_MAX_RECORDS", 1)
    monkeypatch.setattr(module, "strict_json_loads", counting_decode)
    result = _ext(arm_id, handler).invoke(
        arm_id,
        action,
        {path_key: str(path)},
    )
    assert result.ok is False
    assert "cap" in result.error
    assert calls == 1


@pytest.mark.parametrize(
    "secret_key",
    [
        "client_secret",
        "db_password",
        "user_passwd",
        "apiToken",
        "secretValue",
        "token_value",
        "passwordText",
        "credentialData",
        "hashBytes",
        "privateKeyMaterial",
        "clientsecretvalue",
        "oauthaccesstokenvalue",
        "databasepasswordvalue",
        "pwd",
        "user_pwd",
        "passphrase",
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
def test_gpohound_refuses_nonfinite_and_secret_settings(
    gpo_evidence: Path, secret_key: str
) -> None:
    data = json.loads(gpo_evidence.read_text(encoding="utf-8"))
    data[0]["settings"]["weight"] = float("nan")
    gpo_evidence.write_text(json.dumps(data), encoding="utf-8")
    result = _ext(R08_ID, GpohoundArm()).invoke(
        R08_ID, "policy", {"evidence": str(gpo_evidence), "policy_id": "GPO-001"}
    )
    assert result.ok is False
    assert "non-finite" in result.error

    del data[0]["settings"]["weight"]
    data[0]["settings"][secret_key] = "do-not-echo"
    gpo_evidence.write_text(json.dumps(data), encoding="utf-8")
    result = _ext(R08_ID, GpohoundArm()).invoke(
        R08_ID, "policy", {"evidence": str(gpo_evidence), "policy_id": "GPO-001"}
    )
    assert result.ok is False
    assert "shaped field" in result.error
    assert "do-not-echo" not in result.error


@pytest.mark.parametrize(
    "setting_key",
    [
        "minimum_password_length",
        "password_history_size",
        "password_complexity",
        "hash_algorithm",
        "CredentialGuard",
        "CredentialGuardEnabled",
        "password_min_length",
        "password_max_age",
        "password_min_age",
        "password_history_count",
        "password_policy_id",
        "passwordPolicyId",
        "compass",
        "bypass",
    ],
)
def test_gpohound_accepts_non_secret_policy_metadata(
    gpo_evidence: Path, setting_key: str
) -> None:
    data = json.loads(gpo_evidence.read_text(encoding="utf-8"))
    data[0]["settings"][setting_key] = "documented-setting"
    gpo_evidence.write_text(json.dumps(data), encoding="utf-8")
    result = _ext(R08_ID, GpohoundArm()).invoke(
        R08_ID, "policy", {"evidence": str(gpo_evidence), "policy_id": "GPO-001"}
    )
    assert result.ok is True
    assert result.output["policy"]["settings"][setting_key] == "documented-setting"


@pytest.mark.parametrize("as_yaml", [False, True], ids=["json", "yaml"])
def test_normalized_nested_mapping_key_collisions_are_refused(
    tmp_path: Path, gpo_evidence: Path, ad_method: Path, as_yaml: bool
) -> None:
    yaml = pytest.importorskip("yaml") if as_yaml else None
    suffix = ".yaml" if as_yaml else ".json"

    gpo_data = json.loads(gpo_evidence.read_text(encoding="utf-8"))
    gpo_data[0]["settings"] = {"enabled": False, " enabled ": True}
    gpo_path = tmp_path / f"gpo-collision{suffix}"
    gpo_path.write_text(
        yaml.safe_dump(gpo_data) if yaml else json.dumps(gpo_data),
        encoding="utf-8",
    )
    gpo_result = _ext(R08_ID, GpohoundArm()).invoke(
        R08_ID, "list_policies", {"evidence": str(gpo_path)}
    )
    assert gpo_result.ok is False
    assert "duplicate keys after normalization" in gpo_result.error

    method_data = json.loads(ad_method.read_text(encoding="utf-8"))
    method_data["techniques"][0]["mitre_mapping"] = {
        "T1558.003": "first",
        " T1558.003 ": "second",
    }
    method_path = tmp_path / f"method-collision{suffix}"
    method_path.write_text(
        yaml.safe_dump(method_data) if yaml else json.dumps(method_data),
        encoding="utf-8",
    )
    method_result = _ext(R25_ID, ClaudeAdArm()).invoke(
        R25_ID, "list_techniques", {"method_file": str(method_path)}
    )
    assert method_result.ok is False
    assert "duplicate keys after normalization" in method_result.error


def test_rubeus_rejects_unredacted_indicator_value(ad_telemetry: Path) -> None:
    data = json.loads(ad_telemetry.read_text(encoding="utf-8"))
    data[0]["indicators"][0]["value"] = "real-ticket-or-hash"
    ad_telemetry.write_text(json.dumps(data), encoding="utf-8")
    result = _ext(R36_ID, RubeusArm()).invoke(
        R36_ID, "telemetry", {"telemetry_file": str(ad_telemetry), "event_id": "E001"}
    )
    assert result.ok is False
    assert "redaction sentinel" in result.error
    assert "real-ticket-or-hash" not in result.error


def test_m365_consent_permissions_must_be_declared(m365_cases: Path) -> None:
    data = json.loads(m365_cases.read_text(encoding="utf-8"))
    data[0]["consent_flow"]["app_permissions"].append("Files.Read.All")
    m365_cases.write_text(json.dumps(data), encoding="utf-8")
    result = _ext(R38_ID, M365PwnedArm()).invoke(
        R38_ID,
        "case_study",
        {"cases_file": str(m365_cases), "case_id": "C001"},
    )
    assert result.ok is False
    assert "permissions absent" in result.error


@pytest.mark.parametrize("location", ["settings", "link-order"])
def test_gpohound_rejects_giant_yaml_integers_for_every_action(
    gpo_evidence: Path, tmp_path: Path, location: str
) -> None:
    yaml = pytest.importorskip("yaml")
    data = json.loads(gpo_evidence.read_text(encoding="utf-8"))
    sentinel = 4_242_424_242
    if location == "settings":
        data[0]["settings"]["retry_count"] = sentinel
    else:
        data[0]["links"][0]["order"] = sentinel
    text = yaml.safe_dump(data)
    assert str(sentinel) in text
    path = tmp_path / f"gpo-{location}.yaml"
    path.write_text(
        text.replace(str(sentinel), "0x" + ("f" * 5_000), 1),
        encoding="utf-8",
    )

    actions = [
        ("list_policies", {}),
        ("policy", {"policy_id": "GPO-001"}),
        ("list_links", {"gpo_id": "GPO-001"}),
    ]
    for action, extra in actions:
        result = _ext(R08_ID, GpohoundArm()).invoke(
            R08_ID, action, {"evidence": str(path), **extra}
        )
        assert result.ok is False
        assert "integer" in result.error


def test_m365_rejects_giant_yaml_access_count_for_every_action(
    m365_cases: Path, tmp_path: Path
) -> None:
    yaml = pytest.importorskip("yaml")
    data = json.loads(m365_cases.read_text(encoding="utf-8"))
    sentinel = 4_242_424_242
    data[0]["data_access"]["mailbox_count"] = sentinel
    text = yaml.safe_dump(data)
    assert str(sentinel) in text
    path = tmp_path / "m365-giant.yaml"
    path.write_text(
        text.replace(str(sentinel), "0x" + ("f" * 5_000), 1),
        encoding="utf-8",
    )

    actions = [
        ("list_case_studies", {}),
        ("case_study", {"case_id": "C001"}),
        ("list_permissions", {"case_id": "C001"}),
    ]
    for action, extra in actions:
        result = _ext(R38_ID, M365PwnedArm()).invoke(
            R38_ID, action, {"cases_file": str(path), **extra}
        )
        assert result.ok is False
        assert "bounded non-negative integer" in result.error


@pytest.mark.parametrize(
    "module",
    [
        ad_pathfinder_module,
        gpohound_module,
        claude_ad_module,
        m365pwned_module,
    ],
)
def test_every_batch8_yaml_loader_refuses_lone_surrogates_and_underflow(
    module,
) -> None:
    with pytest.raises(StrictDataError, match="Unicode scalar"):
        module._load_yaml('value: "\\uD800"\n')
    for document in (
        "value: -1.0e-9999\n",
        "value: 0:0." + ("0" * 400) + "1\n",
    ):
        with pytest.raises(StrictDataError, match="underflows"):
            module._load_yaml(document)


def test_ad_pathfinder_numeric_evidence_cannot_silently_underflow(
    ad_export: Path,
) -> None:
    text = ad_export.read_text(encoding="utf-8")
    assert '"risk_score": 8.5' in text
    ad_export.write_text(
        text.replace('"risk_score": 8.5', '"risk_score": -1e-9999', 1),
        encoding="utf-8",
    )
    result = _ext(R02_ID, AdPathfinderArm()).invoke(
        R02_ID, "list_paths", {"export": str(ad_export)}
    )
    assert result.ok is False
    assert "underflows" in result.error


def test_gpohound_rejects_lone_surrogate_before_action_selection(
    gpo_evidence: Path,
) -> None:
    data = json.loads(gpo_evidence.read_text(encoding="utf-8"))
    data[0]["settings"]["note"] = "\ud800"
    gpo_evidence.write_text(json.dumps(data), encoding="utf-8")
    actions = [
        ("list_policies", {}),
        ("policy", {"policy_id": "GPO-001"}),
        ("list_links", {"gpo_id": "GPO-001"}),
    ]
    for action, extra in actions:
        result = _ext(R08_ID, GpohoundArm()).invoke(
            R08_ID, action, {"evidence": str(gpo_evidence), **extra}
        )
        assert result.ok is False
        assert "Unicode scalar" in result.error


@pytest.mark.parametrize(
    "fixture_name,arm_id,handler,action,path_key,field,error_text",
    [
        ("ad_export", R02_ID, AdPathfinderArm(), "list_paths", "export", "risk_score", "0 to 10"),
        ("finding_ledger", R17_ID, NumasecArm(), "list_findings", "ledger", "severity", "severity"),
    ],
)
def test_huge_integers_never_escape_the_direct_arm_boundary(
    request: pytest.FixtureRequest,
    fixture_name: str,
    arm_id: str,
    handler,
    action: str,
    path_key: str,
    field: str,
    error_text: str,
) -> None:
    path = request.getfixturevalue(fixture_name)
    rows = json.loads(path.read_text(encoding="utf-8"))
    rows[0][field] = 10**400
    path.write_text(json.dumps(rows), encoding="utf-8")
    result = _ext(arm_id, handler).invoke(arm_id, action, {path_key: str(path)})
    assert result.ok is False
    assert error_text in result.error


def _invoke_ledger(tmp_path: Path, record: dict):
    path = tmp_path / "lifecycle.json"
    path.write_text(json.dumps([record]), encoding="utf-8")
    return _ext(R17_ID, NumasecArm()).invoke(
        R17_ID, "finding", {"ledger": str(path), "finding_id": record["finding_id"]}
    )


def _finding_record(*, status: str, transitions: list[dict]) -> dict:
    return {
        "finding_id": "F-VERIFY",
        "title": "Synthetic lifecycle",
        "status": status,
        "severity": "high",
        "transitions": transitions,
    }


def _transition(source: str, target: str, timestamp: str, **overrides: object) -> dict:
    value = {
        "from": source,
        "to": target,
        "actor": "analyst-1",
        "reason": "evidence reviewed",
        "ts": timestamp,
    }
    value.update(overrides)
    return value


def test_numasec_refuses_forged_empty_verified_state(tmp_path: Path) -> None:
    result = _invoke_ledger(tmp_path, _finding_record(status="verified", transitions=[]))
    assert result.ok is False
    assert "derived status 'new'" in result.error


@pytest.mark.parametrize(
    "transitions,error_text",
    [
        ([_transition("new", "verified", "2026-09-01T10:00:00Z")], "disallowed transition"),
        ([
            _transition("new", "open", "2026-09-01T10:00:00Z"),
            _transition("verified", "resolved", "2026-09-02T10:00:00Z"),
        ], "continuity"),
        ([_transition("new", "open", "2026-09-01T10:00:00Z", actor="")], "actor"),
        ([_transition("new", "open", "2026-09-01T10:00:00Z", reason="")], "reason"),
        ([
            _transition("new", "open", "2026-09-02T10:00:00Z"),
            _transition("open", "verified", "2026-09-01T10:00:00Z"),
        ], "later than"),
    ],
)
def test_numasec_refuses_invalid_lifecycle(
    tmp_path: Path, transitions: list[dict], error_text: str
) -> None:
    result = _invoke_ledger(tmp_path, _finding_record(status="verified", transitions=transitions))
    assert result.ok is False
    assert error_text in result.error


def test_numasec_accepts_structurally_valid_but_untrusted_verified_state(
    tmp_path: Path,
) -> None:
    transitions = [
        _transition("new", "open", "2026-09-01T10:00:00Z"),
        _transition("open", "verified", "2026-09-02T10:00:00Z"),
    ]
    result = _invoke_ledger(tmp_path, _finding_record(status="verified", transitions=transitions))
    assert result.ok is True
    assert result.output["finding"]["status"] == "verified"
    tools = _ext(R17_ID, NumasecArm()).invoke(R17_ID, "list_tools", {})
    caveats = " ".join(tools.output["caveats"])
    assert "does not authenticate" in caveats
    assert "not a trusted signature" in caveats


def test_numasec_requires_strictly_increasing_timestamps(tmp_path: Path) -> None:
    timestamp = "2026-09-01T10:00:00Z"
    transitions = [
        _transition("new", "open", timestamp),
        _transition("open", "verified", timestamp),
    ]
    result = _invoke_ledger(tmp_path, _finding_record(status="verified", transitions=transitions))
    assert result.ok is False
    assert "later than" in result.error


def test_m365_filesystem_root_is_explicitly_refused() -> None:
    path, refusal = cases_file_refusal("/")
    assert path is None
    assert refusal == "args.cases_file must not be a filesystem root"
