"""Per-arm minimal input fixtures for the containment matrix.

One builder per baseline arm materializes a realistic minimal input file
(or directory, for the one directory-kind arm) inside the operator's
approved root, plus per-action exact argument payloads whose key sets
match the frozen action keys exactly (the arms refuse any extra key).

Fidelity bar, stated honestly: fixtures mirror the shapes used by the
existing arm tests (``tests/test_arm_batch6/7/8.py``). An action whose
lookup arguments cannot be made to match still yields a valid containment
result -- the arm returns a policy refusal with ZERO denials -- and the
suite counts that as ``refusal``, never as a faked success.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import yaml

Fixture = tuple[str, dict[str, dict[str, Any]]]
"""(absolute input path, {action: exact args including the path argument})."""


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _with_path(args: Mapping[str, Mapping[str, Any]], path_argument: str,
               value: str) -> dict[str, dict[str, Any]]:
    """Insert the input path into every action's exact argument set."""
    return {
        action: {**payload, path_argument: value}
        for action, payload in args.items()
    }


def _ad_pathfinder(root: Path) -> Fixture:
    data = [
        {"path_id": "P1", "source": "DC01", "target": "SQL01", "length": 3,
         "risk_score": 8.5, "nodes": ["DC01", "FILE01", "SQL01"],
         "edges": [{"from": "DC01", "to": "FILE01"},
                   {"from": "FILE01", "to": "SQL01"}],
         "datasource": "BloodHound"},
    ]
    path = root / "ad-pathfinder" / "export.json"
    _write_json(path, data)
    args = {
        "list_datasources": {},
        "list_paths": {"limit": 5},
        "path": {"path_id": "P1", "source": "DC01", "target": "SQL01"},
    }
    return (str(path.resolve()), _with_path(args, "export", str(path.resolve())))


def _agentseal(root: Path) -> Fixture:
    data = {"scenarios": [
        {"id": "S1", "name": "SQL Injection",
         "findings": [{"type": "sqli", "path": "/api"}]},
        {"id": "S2", "name": "XSS Reflected",
         "findings": [{"type": "xss", "path": "/search"}]},
    ]}
    path = root / "agentseal" / "fixtures.json"
    _write_json(path, data)
    args = {
        "analyze": {"limit": 5},
        "list_scenarios": {"limit": 5},
    }
    return (str(path.resolve()), _with_path(args, "fixture", str(path.resolve())))


def _claude_ad(root: Path) -> Fixture:
    data = {"techniques": [
        {"technique_id": "AD-01", "name": "Kerberoasting", "category": "credential",
         "prerequisites": ["valid domain account", "SPN registered"],
         "observed_facts": ["TGS request for SPN"],
         "inference": "Service account password may be crackable",
         "mitre_mapping": "T1558.003"},
    ]}
    path = root / "claude-ad" / "method.json"
    _write_json(path, data)
    args = {
        "list_prerequisites": {},
        "list_techniques": {"category": "credential", "limit": 5},
        "technique": {"name": "Kerberoasting", "technique_id": "AD-01"},
    }
    return (str(path.resolve()), _with_path(args, "method_file", str(path.resolve())))


def _collinear(root: Path) -> Fixture:
    data = {"scenarios": [
        {"scenario_id": "C1", "name": "Cloud Misconfig",
         "prompt": "Assess the S3 exposure",
         "expected": {"finding": "public bucket"},
         "submission_template": {}},
    ]}
    path = root / "collinear" / "scenarios.json"
    _write_json(path, data)
    args = {
        "list_scenarios": {"limit": 5},
        "scenario": {"name": "Cloud Misconfig", "scenario_id": "C1"},
        "verify": {"scenario_id": "C1", "submission": {"finding": "public bucket"}},
    }
    return (str(path.resolve()), _with_path(args, "scenarios_file", str(path.resolve())))


def _detection_in_the_cloud(root: Path) -> Fixture:
    pdir = root / "detection-in-the-cloud" / "playbooks"
    _write_json(pdir / "aws-s3.json", {
        "name": "S3 Detection",
        "rules": [{"rule_id": "DR1", "name": "Public Bucket",
                   "category": "s3", "severity": "high"}],
    })
    _write_yaml(pdir / "aws-iam.yaml", {"name": "IAM Detection"})
    args = {
        "list_playbooks": {"limit": 5},
        "list_rules": {"category": "s3", "limit": 5},
        "playbook": {"name": "S3 Detection"},
    }
    return (str(pdir.resolve()), _with_path(args, "playbook_dir", str(pdir.resolve())))


def _gpohound(root: Path) -> Fixture:
    data = [
        {"policy_id": "GPO-001", "name": "Default Domain Policy",
         "status": "active",
         "links": [{"ou": "DC=corp,DC=local", "enforced": True}],
         "filters": {"security": ["S-1-5-21-123"], "wmi": []},
         "settings": {"password_policy": {"min_length": 12}}},
    ]
    path = root / "gpohound" / "gpo.json"
    _write_json(path, data)
    args = {
        "list_links": {"gpo_id": "GPO-001"},
        "list_policies": {"limit": 5, "status": "active"},
        "policy": {"name": "Default Domain Policy", "policy_id": "GPO-001"},
    }
    return (str(path.resolve()), _with_path(args, "evidence", str(path.resolve())))


def _leonidas(root: Path) -> Fixture:
    data = {"techniques": [
        {"technique_id": "T-L01", "name": "S3 Public Bucket", "platform": "aws",
         "severity": "high",
         "executor": "aws s3api put-bucket-acl --bucket {{bucket}} "
                     "--acl public-read"},
    ]}
    path = root / "leonidas" / "corpus.yaml"
    _write_yaml(path, data)
    args = {
        "list_techniques": {"limit": 5},
        "technique": {"name": "S3 Public Bucket", "technique_id": "T-L01"},
    }
    return (str(path.resolve()), _with_path(args, "corpus", str(path.resolve())))


def _m365pwned(root: Path) -> Fixture:
    data = [
        {"case_id": "C001", "name": "Consent Phish",
         "description": "OAuth consent phishing", "risk_level": "high",
         "consent_flow": {"user_action": "clicked approve",
                          "app_permissions": ["Mail.Read"]},
         "data_access": {"mailbox_count": 1, "files_accessed": 0},
         "permissions": ["Mail.Read", "User.Read"],
         "risk_assessment": "High risk: full mailbox read access"},
    ]
    path = root / "m365pwned" / "cases.json"
    _write_json(path, data)
    args = {
        "case_study": {"case_id": "C001", "name": "Consent Phish"},
        "list_case_studies": {"limit": 5},
        "list_permissions": {"case_id": "C001"},
    }
    return (str(path.resolve()), _with_path(args, "cases_file", str(path.resolve())))


def _numasec(root: Path) -> Fixture:
    data = [
        {"finding_id": "F001", "title": "Weak Password Policy",
         "status": "open", "severity": "high",
         "transitions": [{"from": "new", "to": "open", "actor": "analyst-1",
                          "reason": "validated",
                          "ts": "2026-09-01T10:00:00Z"}]},
    ]
    path = root / "numasec" / "ledger.json"
    _write_json(path, data)
    args = {
        "finding": {"finding_id": "F001"},
        "list_findings": {"limit": 5, "status": "open"},
        "list_transitions": {"finding_id": "F001"},
    }
    return (str(path.resolve()), _with_path(args, "ledger", str(path.resolve())))


def _pentestkit(root: Path) -> Fixture:
    data = [
        {"run_id": "run-001", "phase": "first_pass", "status": "pass",
         "score": 0.85},
    ]
    path = root / "pentestkit" / "ledger.json"
    _write_json(path, data)
    args = {
        "list_results": {"limit": 5, "phase": "first_pass"},
        "result": {"run_id": "run-001"},
        "summary": {},
    }
    return (str(path.resolve()), _with_path(args, "ledger", str(path.resolve())))


def _rubeus(root: Path) -> Fixture:
    data = [
        {"event_id": "E001", "category": "kerberos",
         "description": "AS-REQ with unusual encryption", "severity": "medium",
         "indicators": [{"type": "encryption_type", "value": "rc4"}]},
    ]
    path = root / "rubeus" / "telemetry.json"
    _write_json(path, data)
    args = {
        "list_indicators": {"indicator_type": "encryption_type"},
        "list_telemetry": {"category": "kerberos", "limit": 5},
        "telemetry": {"event_id": "E001"},
    }
    return (str(path.resolve()), _with_path(args, "telemetry_file", str(path.resolve())))


def _security_detections_mcp(root: Path) -> Fixture:
    data = [
        {"rule_id": "R001", "name": "Suspicious Login", "severity": "high",
         "category": "auth"},
    ]
    path = root / "security-detections-mcp" / "rules.json"
    _write_json(path, data)
    args = {
        "get_rule": {"rule_id": "R001"},
        "list_rules": {"limit": 5},
        "search_rules": {"limit": 5, "query": "login"},
    }
    return (str(path.resolve()), _with_path(args, "index", str(path.resolve())))


def _specterops_skills(root: Path) -> Fixture:
    data = {"skills": [
        {"skill_id": "SK01", "name": "BloodHound Recon", "category": "ad",
         "description": "AD graph recon", "tool_mapping": "bloodhound",
         "steps": ["collect", "analyze"]},
    ]}
    path = root / "specterops-skills" / "skills.json"
    _write_json(path, data)
    args = {
        "list_skills": {"category": "ad", "limit": 5},
        "skill": {"name": "BloodHound Recon", "skill_id": "SK01"},
    }
    return (str(path.resolve()), _with_path(args, "catalog", str(path.resolve())))


def _vulnify(root: Path) -> Fixture:
    data = [
        {"cve_id": "CVE-2024-0001", "name": "Buffer Overflow",
         "severity": "critical", "description": "Heap overflow"},
    ]
    path = root / "vulnify" / "feed.json"
    _write_json(path, data)
    args = {
        "list_vulns": {"limit": 5},
        "lookup": {"cve_id": "CVE-2024-0001", "name": "Buffer Overflow"},
    }
    return (str(path.resolve()), _with_path(args, "feed", str(path.resolve())))


# Every arm in the frozen baseline roster, keyed by arm id. Discovery
# actions (list_tools) carry no path argument and are handled by the
# harness directly, not here.
BUILDERS: Mapping[str, Any] = {
    "ad-pathfinder": _ad_pathfinder,
    "agentseal": _agentseal,
    "claude-ad": _claude_ad,
    "collinear": _collinear,
    "detection-in-the-cloud": _detection_in_the_cloud,
    "gpohound": _gpohound,
    "leonidas": _leonidas,
    "m365pwned": _m365pwned,
    "numasec": _numasec,
    "pentestkit": _pentestkit,
    "rubeus": _rubeus,
    "security-detections-mcp": _security_detections_mcp,
    "specterops-skills": _specterops_skills,
    "vulnify": _vulnify,
}

def build_fixture(arm_id: str, approved_root: Path) -> Fixture:
    """Materialize the arm's minimal input under the approved root.

    Returns ``(absolute_input_path, args_by_action)``. Raises KeyError for
    an arm outside the frozen roster.
    """
    return BUILDERS[arm_id](approved_root)
