"""Fail-closed checkout checker for the PR97 reader safety foundation.

This module records and cross-checks requirements.  It does not provision or
verify an operator environment, approve an input, or grant execution authority.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Mapping, Sequence

import jsonschema
import yaml

from governance.check import (
    RegisterLoadError as GovernanceLoadError,
    _UniqueKeyLoader as _GovernanceUniqueKeyLoader,
    _read_file_snapshot,
    _reject_json_constant,
    _reject_nonlocal_refs,
    _strict_utf8,
    _unique_json_object,
    _validate_bounded_tree,
    load_coverage_inventory,
    load_register as load_governance_register,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTER_PATH = Path(__file__).resolve().with_name("register.v1.yaml")
DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "register.v1.schema.json"
DEFAULT_COVERAGE_SCHEMA_PATH = REPOSITORY_ROOT / "extension" / "schema" / "coverage.schema.json"
DEFAULT_COVERAGE_PATH = REPOSITORY_ROOT / "extension" / "coverage.yaml"
DEFAULT_GOVERNANCE_REGISTER_PATH = REPOSITORY_ROOT / "governance" / "register.v1.yaml"
DEFAULT_GOVERNANCE_SCHEMA_PATH = (
    REPOSITORY_ROOT / "governance" / "schema" / "register.v1.schema.json"
)

REGISTER_SCHEMA_ID = "specaudit.ctf.safety.register.v1"
REPORT_SCHEMA_ID = "specaudit.ctf.safety.validation-report.v1"
ERROR_SCHEMA_ID = "specaudit.ctf.safety.validation-error.v1"
SCOPE_ID = "pr97-readers"
REGISTER_SCHEMA_VERSION = 1
REGISTER_REVISION = 1
REQUIREMENTS = ("integrity", "ready")

MAX_REGISTER_BYTES = 256 * 1024
MAX_SCHEMA_BYTES = 128 * 1024
MAX_RUNTIME_SOURCE_BYTES = 2 * 1024 * 1024
CANONICAL_SCHEMA_SHA256 = (
    "sha256:41231553822c06015c02b98372564d0b507d593ae96c3603fd7c7876288a00d9"
)
CANONICAL_GOVERNANCE_SCHEMA_SHA256 = (
    "sha256:8e8edbd7aadcb071dd997437256e9e6b56fbbd344763423172e1183993e60e53"
)
CANONICAL_COVERAGE_SCHEMA_SHA256 = (
    "sha256:481137fed428de6e2c2c8bce6c109fb9c98fdc654b7cfc0f88bbcfc823a306b3"
)
PROFILE_FIELDS = (
    "arm_id",
    "action",
    "capability_id",
    "tool_name",
    "tool_version",
    "authorized_scope",
    "touched_scope",
    "safety_class",
    "side_effects",
    "timeout_ms",
    "max_output_bytes",
    "max_tool_steps",
    "max_spend",
    "cleanup_required",
    "approval_ref",
    "roe_ref",
    "tier",
    "default_off",
    "synthetic_only",
)

RUNTIME_FIELDS = (
    "capability_id",
    "record_version",
    "arm_id",
    "action",
    "presence",
    "support_tier",
    "owner",
    "tool_version",
    "implementation_revision",
    "contract_ref",
    "input_keys",
    "result_schema",
    "supported_versions",
    "regression_cases",
    "currentness",
    "promotion_evidence",
    "known_limitations",
)

SOURCE_FIELDS = (
    "id",
    "record_version",
    "name",
    "url",
    "status",
    "owner",
    "selected_revision",
    "content_digests",
    "rights",
    "currentness",
    "replacement",
    "promotion_evidence",
    "limitations",
)

RELATIONSHIP_FIELDS = (
    "id",
    "record_version",
    "kind",
    "from",
    "to",
    "evidence_refs",
    "limitations",
)

CONTRACT_FIELDS = (
    "id",
    "safety_class",
    "side_effects",
    "egress",
    "cleanup_required",
    "default_off",
    "synthetic_only",
    "timeout_ms",
    "max_output_bytes",
    "max_tool_steps",
    "max_spend",
    "scope_mode",
    "input_binding",
    "approval_required",
    "limitations",
)

COMMON_POLICY_CONSTANTS = (
    "ARM_ID",
    "ALLOWED_ACTIONS",
    "LIST_ACTIONS",
    "ARG_KEYS",
    "CAVEATS",
    "ARMING",
    "MAX_OUTPUT_CHARS",
    "MAX_RESULTS",
)

ARM_BASELINES: Mapping[str, Mapping[str, Any]] = {
    "ad-pathfinder": {
        "source_id": "R02",
        "policy_module": "extension.arms.ad_pathfinder.policy",
        "path_argument": "export",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_EXPORT_BYTES",
        "suffixes_name": "EXPORT_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "export_refusal",
        "extra_constants": (),
        "actions": {
            "list_datasources": ("export",),
            "list_paths": ("export", "limit"),
            "path": ("export", "path_id", "source", "target"),
        },
    },
    "agentseal": {
        "source_id": "R35",
        "policy_module": "extension.arms.agentseal.policy",
        "path_argument": "fixture",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_FIXTURE_BYTES",
        "suffixes_name": "FIXTURE_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "fixture_refusal",
        "extra_constants": (
            "MAX_RECORDS",
            "MAX_DOCUMENT_NODES",
            "MAX_DOCUMENT_DEPTH",
        ),
        "actions": {
            "analyze": ("fixture", "limit", "scenario_id"),
            "list_scenarios": ("fixture", "limit"),
        },
    },
    "claude-ad": {
        "source_id": "R25",
        "policy_module": "extension.arms.claude_ad.policy",
        "path_argument": "method_file",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_METHOD_BYTES",
        "suffixes_name": "METHOD_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "method_refusal",
        "extra_constants": (),
        "actions": {
            "list_prerequisites": ("method_file",),
            "list_techniques": ("category", "limit", "method_file"),
            "technique": ("method_file", "name", "technique_id"),
        },
    },
    "collinear": {
        "source_id": "R15",
        "policy_module": "extension.arms.collinear.policy",
        "path_argument": "scenarios_file",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_SCENARIOS_BYTES",
        "suffixes_name": "SCENARIOS_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "scenarios_refusal",
        "extra_constants": (
            "MAX_RECORDS",
            "MAX_DOCUMENT_NODES",
            "MAX_DOCUMENT_DEPTH",
        ),
        "actions": {
            "list_scenarios": ("limit", "scenarios_file"),
            "scenario": ("name", "scenario_id", "scenarios_file"),
            "verify": ("scenario_id", "scenarios_file", "submission"),
        },
    },
    "detection-in-the-cloud": {
        "source_id": "R34",
        "policy_module": "extension.arms.detection_in_the_cloud.policy",
        "path_argument": "playbook_dir",
        "input_kind": "directory",
        "max_file_bytes_name": "MAX_PLAYBOOK_BYTES",
        "suffixes_name": "PLAYBOOK_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml", ".md"),
        "max_directory_entries": 10_000,
        "path_refusal_function": "playbook_dir_refusal",
        "extra_constants": (
            "MAX_RECORDS",
            "MAX_DIRECTORY_ENTRIES",
            "MAX_DOCUMENT_NODES",
            "MAX_DOCUMENT_DEPTH",
        ),
        "actions": {
            "list_playbooks": ("limit", "playbook_dir"),
            "list_rules": ("category", "limit", "playbook_dir"),
            "playbook": ("name", "playbook_dir"),
        },
    },
    "gpohound": {
        "source_id": "R08",
        "policy_module": "extension.arms.gpohound.policy",
        "path_argument": "evidence",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_EVIDENCE_BYTES",
        "suffixes_name": "EVIDENCE_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "evidence_refusal",
        "extra_constants": (),
        "actions": {
            "list_links": ("evidence", "gpo_id"),
            "list_policies": ("evidence", "limit", "status"),
            "policy": ("evidence", "name", "policy_id"),
        },
    },
    "leonidas": {
        "source_id": "R33",
        "policy_module": "extension.arms.leonidas.policy",
        "path_argument": "corpus",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_CORPUS_BYTES",
        "suffixes_name": "CORPUS_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "corpus_refusal",
        "extra_constants": (
            "MAX_RECORDS",
            "MAX_DOCUMENT_NODES",
            "MAX_DOCUMENT_DEPTH",
        ),
        "actions": {
            "list_techniques": ("corpus", "limit"),
            "technique": ("corpus", "name", "technique_id"),
        },
    },
    "m365pwned": {
        "source_id": "R38",
        "policy_module": "extension.arms.m365pwned.policy",
        "path_argument": "cases_file",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_CASE_BYTES",
        "suffixes_name": "CASE_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "cases_file_refusal",
        "extra_constants": (),
        "actions": {
            "case_study": ("case_id", "cases_file", "name"),
            "list_case_studies": ("cases_file", "limit"),
            "list_permissions": ("case_id", "cases_file"),
        },
    },
    "numasec": {
        "source_id": "R17",
        "policy_module": "extension.arms.numasec.policy",
        "path_argument": "ledger",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_LEDGER_BYTES",
        "suffixes_name": "LEDGER_SUFFIXES",
        "allowed_suffixes": (".json", ".jsonl"),
        "max_directory_entries": None,
        "path_refusal_function": "ledger_refusal",
        "extra_constants": ("ALLOWED_STATUSES",),
        "actions": {
            "finding": ("finding_id", "ledger"),
            "list_findings": ("ledger", "limit", "status"),
            "list_transitions": ("finding_id", "ledger"),
        },
    },
    "pentestkit": {
        "source_id": "R42",
        "policy_module": "extension.arms.pentestkit.policy",
        "path_argument": "ledger",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_LEDGER_BYTES",
        "suffixes_name": "LEDGER_SUFFIXES",
        "allowed_suffixes": (".json", ".jsonl", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "ledger_refusal",
        "extra_constants": (
            "MAX_RECORDS",
            "MAX_DOCUMENT_NODES",
            "MAX_DOCUMENT_DEPTH",
            "VALID_PHASES",
        ),
        "actions": {
            "list_results": ("ledger", "limit", "phase"),
            "result": ("ledger", "run_id"),
            "summary": ("ledger",),
        },
    },
    "rubeus": {
        "source_id": "R36",
        "policy_module": "extension.arms.rubeus.policy",
        "path_argument": "telemetry_file",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_TELEMETRY_BYTES",
        "suffixes_name": "TELEMETRY_SUFFIXES",
        "allowed_suffixes": (".json", ".jsonl"),
        "max_directory_entries": None,
        "path_refusal_function": "telemetry_refusal",
        "extra_constants": (),
        "actions": {
            "list_indicators": ("indicator_type", "telemetry_file"),
            "list_telemetry": ("category", "limit", "telemetry_file"),
            "telemetry": ("event_id", "telemetry_file"),
        },
    },
    "security-detections-mcp": {
        "source_id": "R43",
        "policy_module": "extension.arms.security_detections_mcp.policy",
        "path_argument": "index",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_INDEX_BYTES",
        "suffixes_name": "INDEX_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "index_refusal",
        "extra_constants": (
            "MAX_RECORDS",
            "MAX_DOCUMENT_NODES",
            "MAX_DOCUMENT_DEPTH",
        ),
        "actions": {
            "get_rule": ("index", "rule_id"),
            "list_rules": ("index", "limit"),
            "search_rules": ("index", "limit", "query"),
        },
    },
    "specterops-skills": {
        "source_id": "R03",
        "policy_module": "extension.arms.specterops_skills.policy",
        "path_argument": "catalog",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_CATALOG_BYTES",
        "suffixes_name": "CATALOG_SUFFIXES",
        "allowed_suffixes": (".json", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "catalog_refusal",
        "extra_constants": (
            "MAX_RECORDS",
            "MAX_DOCUMENT_NODES",
            "MAX_DOCUMENT_DEPTH",
        ),
        "actions": {
            "list_skills": ("catalog", "category", "limit"),
            "skill": ("catalog", "name", "skill_id"),
        },
    },
    "vulnify": {
        "source_id": "R01",
        "policy_module": "extension.arms.vulnify.policy",
        "path_argument": "feed",
        "input_kind": "file",
        "max_file_bytes_name": "MAX_FEED_BYTES",
        "suffixes_name": "FEED_SUFFIXES",
        "allowed_suffixes": (".json", ".jsonl", ".yaml", ".yml"),
        "max_directory_entries": None,
        "path_refusal_function": "feed_refusal",
        "extra_constants": (
            "MAX_RECORDS",
            "MAX_DOCUMENT_NODES",
            "MAX_DOCUMENT_DEPTH",
        ),
        "actions": {
            "list_vulns": ("feed", "limit"),
            "lookup": ("cve_id", "feed", "name"),
        },
    },
}

COMMON_HAZARD_IDS = (
    "HZ-INPUT-PATH-UNBOUND",
    "HZ-INPUT-IDENTITY-RACE",
    "HZ-INPUT-CUSTODY-UNPROVEN",
    "HZ-DATA-CLASSIFICATION-UNPROVEN",
    "HZ-NETWORK-DENY-UNPROVEN",
    "HZ-AMBIENT-CREDENTIAL-EXPOSURE",
    "HZ-HARD-LIMIT-UNPROVEN",
    "HZ-MONITORING-UNPROVEN",
    "HZ-UNTRUSTED-CONTENT",
    "HZ-SECRET-BEARING-INPUT",
)

COMMON_CONTROL_IDS = (
    "CTL-APPROVED-INPUT-ROOT",
    "CTL-STABLE-INPUT-SNAPSHOT",
    "CTL-TRUSTED-INPUT-CUSTODY",
    "CTL-DATA-CLASSIFICATION",
    "CTL-DENY-EGRESS",
    "CTL-NO-AMBIENT-CREDENTIALS",
    "CTL-HARD-RESOURCE-BOUND",
    "CTL-INDEPENDENT-MONITORING",
    "CTL-UNTRUSTED-CONTENT-BOUNDARY",
    "CTL-SECRET-EXCLUSION",
)

HAZARDS: tuple[Mapping[str, Any], ...] = (
    {
        "id": "HZ-AMBIENT-CREDENTIAL-EXPOSURE",
        "record_version": 1,
        "category": "credentials",
        "title": "Ambient credentials are reachable",
        "condition": "The reader or consuming agent may inherit host credentials, tokens, or provider profiles.",
        "impact": "A nominally local read can disclose or use authority outside the approved exercise.",
        "required_control_ids": ["CTL-NO-AMBIENT-CREDENTIALS"],
    },
    {
        "id": "HZ-DATA-CLASSIFICATION-UNPROVEN",
        "record_version": 1,
        "category": "data",
        "title": "Input and output classification is unproven",
        "condition": "No trusted classification decision is bound to the caller-selected artifact or derived output.",
        "impact": "Sensitive or prohibited data can enter learner, model, trace, or retained-artifact channels.",
        "required_control_ids": ["CTL-DATA-CLASSIFICATION"],
    },
    {
        "id": "HZ-DIRECTORY-SNAPSHOT-DRIFT",
        "record_version": 1,
        "category": "filesystem",
        "title": "Directory contents can drift during a read",
        "condition": "Directory enumeration and later child-file reads are not bound to one stable snapshot.",
        "impact": "The reported inventory or digest can describe different bytes from those parsed.",
        "required_control_ids": ["CTL-STABLE-INPUT-SNAPSHOT"],
    },
    {
        "id": "HZ-GROUND-TRUTH-COLOCATION",
        "record_version": 1,
        "category": "grading",
        "title": "Ground truth shares the learner or agent plane",
        "condition": "Expected findings or trace keys are readable by the same context whose submission is graded.",
        "impact": "A result can pass by reading the answer rather than performing the assessment.",
        "required_control_ids": ["CTL-GRADER-PLANE-ISOLATION"],
    },
    {
        "id": "HZ-HARD-LIMIT-UNPROVEN",
        "record_version": 1,
        "category": "availability",
        "title": "Resource and time limits are not independently enforced",
        "condition": "Manifest timeout and output values do not preempt an in-process reader or its consumer.",
        "impact": "A malformed or hostile input can outlive the attempt or exhaust shared resources.",
        "required_control_ids": ["CTL-HARD-RESOURCE-BOUND"],
    },
    {
        "id": "HZ-INPUT-CUSTODY-UNPROVEN",
        "record_version": 1,
        "category": "integrity",
        "title": "Input custody is unproven",
        "condition": "A caller path and digest do not establish origin, transfer history, or trusted admission.",
        "impact": "Unrelated, replayed, or substituted data can be treated as exercise evidence.",
        "required_control_ids": ["CTL-TRUSTED-INPUT-CUSTODY"],
    },
    {
        "id": "HZ-INPUT-IDENTITY-RACE",
        "record_version": 1,
        "category": "filesystem",
        "title": "Input identity can change between validation and use",
        "condition": "Path checks and parsing reopen the input without one stable no-follow descriptor or trusted copy.",
        "impact": "Validation can apply to different bytes or a different filesystem object than the parser consumes.",
        "required_control_ids": ["CTL-STABLE-INPUT-SNAPSHOT"],
    },
    {
        "id": "HZ-INPUT-PATH-UNBOUND",
        "record_version": 1,
        "category": "filesystem",
        "title": "Caller path is not bound to an approved root",
        "condition": "The admitted capability names only a static policy URI while the caller selects a local path.",
        "impact": "The reader can consume an unauthorized local artifact outside the intended exercise scope.",
        "required_control_ids": ["CTL-APPROVED-INPUT-ROOT"],
    },
    {
        "id": "HZ-MONITORING-UNPROVEN",
        "record_version": 1,
        "category": "integrity",
        "title": "Independent monitoring is absent",
        "condition": "The workload or consuming agent is the only source of execution and denial telemetry.",
        "impact": "Escapes, degradation, policy denials, or lost visibility can remain indistinguishable from a complete run.",
        "required_control_ids": ["CTL-INDEPENDENT-MONITORING"],
    },
    {
        "id": "HZ-NETWORK-DENY-UNPROVEN",
        "record_version": 1,
        "category": "network",
        "title": "Effective egress denial is unproven",
        "condition": "No environment-level denied-egress test is bound to the reader and consuming agent context.",
        "impact": "Unexpected code or untrusted content can reach unapproved destinations despite a local-read declaration.",
        "required_control_ids": ["CTL-DENY-EGRESS"],
    },
    {
        "id": "HZ-SECRET-BEARING-INPUT",
        "record_version": 1,
        "category": "data",
        "title": "Input may contain reusable secrets",
        "condition": "Caller-selected files can contain credentials, keys, tickets, tokens, or secret-shaped prose.",
        "impact": "Secrets can be disclosed through results, traces, prompts, logs, or retained artifacts.",
        "required_control_ids": ["CTL-SECRET-EXCLUSION"],
    },
    {
        "id": "HZ-UNTRUSTED-CONTENT",
        "record_version": 1,
        "category": "instruction",
        "title": "Untrusted content can be treated as instruction",
        "condition": "Parsed prose or structured fields may flow into an agent context without a data-only boundary.",
        "impact": "Hostile content can influence tool choice, scope, disclosure, or grading behavior.",
        "required_control_ids": ["CTL-UNTRUSTED-CONTENT-BOUNDARY"],
    },
)

CONTROLS: tuple[Mapping[str, Any], ...] = (
    {
        "id": "CTL-APPROVED-INPUT-ROOT",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["operator-environment", "trusted-input-custodian"],
        "objective": "Constrain every caller-selected input to a separately approved read-only root.",
        "verification_requirement": "From the actual reader context, prove allowed inputs open and traversal, alternate roots, and redirected paths fail closed.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["v1-has-no-approved-root-verifier"],
    },
    {
        "id": "CTL-DATA-CLASSIFICATION",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["trusted-input-custodian"],
        "objective": "Bind trusted input and output classifications to the exact admitted artifact and attempt.",
        "verification_requirement": "Show a trusted classification record covering exact bytes, derived outputs, model exposure, retention, and prohibited-data handling.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["v1-has-no-classification-verifier"],
    },
    {
        "id": "CTL-DENY-EGRESS",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["operator-environment"],
        "objective": "Deny network egress for both the reader and its consuming agent context.",
        "verification_requirement": "Exercise DNS, direct-address, redirect, proxy, and subresource attempts from inside the effective context and preserve independent denial evidence.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["v1-has-no-egress-verifier"],
    },
    {
        "id": "CTL-GRADER-PLANE-ISOLATION",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["operator-environment", "trusted-validator"],
        "objective": "Keep expected findings, trace keys, and grader authority outside the learner and agent plane.",
        "verification_requirement": "Prove the learner and agent identities cannot read grader material and that verification occurs in a separate trusted context.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["v1-has-no-grader-isolation-verifier"],
    },
    {
        "id": "CTL-HARD-RESOURCE-BOUND",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["operator-environment", "independent-supervisor"],
        "objective": "Enforce time, memory, process, filesystem, and output bounds outside the workload.",
        "verification_requirement": "Cause timeout, memory, output, and interruption cases and prove the independent supervisor terminates work while preserving degraded state.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["profile-budget-metadata-is-not-a-hard-limit"],
    },
    {
        "id": "CTL-INDEPENDENT-MONITORING",
        "record_version": 1,
        "type": "detective",
        "enforcement_owners": ["independent-supervisor"],
        "objective": "Observe execution, denials, resource use, and visibility loss outside the workload.",
        "verification_requirement": "Demonstrate independently protected attempt/action/denial records and an explicit alarm when monitoring is interrupted.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["v1-has-no-monitoring-verifier"],
    },
    {
        "id": "CTL-NO-AMBIENT-CREDENTIALS",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["operator-environment"],
        "objective": "Remove host, cloud, directory, provider, and model credentials from the effective context.",
        "verification_requirement": "Inspect the effective identity, environment, files, sockets, and metadata paths and prove seeded canary credentials are unreachable.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["v1-has-no-credential-isolation-verifier"],
    },
    {
        "id": "CTL-SECRET-EXCLUSION",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["trusted-input-custodian", "trusted-validator"],
        "objective": "Exclude reusable secrets from admitted inputs and all derived channels.",
        "verification_requirement": "Use canary secret cases to prove admission, results, traces, prompts, logs, and retained artifacts reject or redact secret-bearing data.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["v1-has-no-secret-exclusion-verifier"],
    },
    {
        "id": "CTL-STABLE-INPUT-SNAPSHOT",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["trusted-input-custodian"],
        "objective": "Bind validation and parsing to one stable no-follow descriptor, immutable copy, or directory snapshot.",
        "verification_requirement": "Exercise symlink, replacement, truncation, growth, and directory-child races and prove every identity change fails closed.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["runtime-readers-reopen-caller-paths"],
    },
    {
        "id": "CTL-TRUSTED-INPUT-CUSTODY",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["trusted-input-custodian"],
        "objective": "Bind source, transfer, exact bytes, admission, and attempt identity through a trusted custody channel.",
        "verification_requirement": "Show tampered, replayed, unrelated, missing, and post-admission substituted inputs are refused by a trusted verifier.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["reader-digests-do-not-establish-custody"],
    },
    {
        "id": "CTL-UNTRUSTED-CONTENT-BOUNDARY",
        "record_version": 1,
        "type": "preventive",
        "enforcement_owners": ["trusted-validator"],
        "objective": "Keep parsed caller content data-only and unable to widen tool, scope, disclosure, or grading authority.",
        "verification_requirement": "Run hostile-instruction fixtures and prove content cannot alter admitted actions, scope, evidence rules, or grader decisions.",
        "status": "unverified",
        "evidence_refs": [],
        "limitations": ["v1-has-no-content-boundary-verifier"],
    },
)

TOP_LEVEL_LIMITATIONS = (
    "v1-documents-requirements-but-verifies-no-environment-control",
    "register-integrity-does-not-grant-execution-or-data-access-authority",
    "reader-source-binding-is-not-a-transitive-runtime-proof",
    "caller-paths-remain-unbound-to-approved-input-roots",
    "safety-01-remains-open",
)

COMMON_ARM_LIMITATIONS = (
    "caller-path-not-bound-to-approved-root",
    "input-custody-and-classification-unverified",
    "environment-containment-and-monitoring-unverified",
)

# The integrity check binds these exact checkout sources as data.  It does not
# import them: a drifted extension module must not execute merely because a
# maintainer asked the safety checker to report that drift.  The paths cover
# the profile/dispatch/handler selection boundary, the two shared helpers used
# by all 14 readers, and each reader's package export, implementation, and
# policy.  Result-envelope and transport behavior beyond this named boundary
# remains outside the v1 claim.
EXPECTED_READER_SOURCE_SHA256: Mapping[str, str] = {
    "extension/contract.py": "sha256:7df80f67e2f5c6809dcfcf942db80cb6ae1a17a4c7d13a9780f3256684b5149a",
    "extension/dispatch.py": "sha256:e4db3d8981211818f2e699a36409adca1757de6b2efdf2af3b18301da37f25ef",
    "extension/invoke_profiles.py": "sha256:a5283da492db316b42d5bebfedf06b15ce0955ddbb88f7bfa3e0d12d84547894",
    "extension/arms/mcp_client.py": "sha256:0db4b795f70c55789558f5cd4f8beb230b6439e0a9ecabd6282055deaaeca8cd",
    "extension/arms/strict_data.py": "sha256:46f1a79ec954f3e4ee5e84811273314e997b11e9ff3b8237e17fb730e150f5a5",
    "extension/arms/ad_pathfinder/__init__.py": "sha256:c8c63a346c2b1b4e30b27ab4f13ea1238035e04490a9df6ea3b6946ba6526894",
    "extension/arms/ad_pathfinder/arm.py": "sha256:05f504a38cba18db0a17f6f8d0962b359b6185e70259e5df9ad04bd75958338c",
    "extension/arms/ad_pathfinder/policy.py": "sha256:7ea6e9e611e5a691a522fcac38d502018a26949657391cc8dab7b18966977ab1",
    "extension/arms/agentseal/__init__.py": "sha256:eed9c2a894b784fd7f2b524c8ffb6f83bf247d9909254988210abe0667a82329",
    "extension/arms/agentseal/arm.py": "sha256:068e0bdcbfdaf05659ea2a01baeddb3d42a2582d17544d0f24697b749d2b0ae8",
    "extension/arms/agentseal/policy.py": "sha256:3dc31cef3c3c5009431c9498bbe7a9850527d3be92fadb9d3fc406b643dd5a72",
    "extension/arms/claude_ad/__init__.py": "sha256:6218872d966134102e27cd0bcc07a70fa677b4d6571ec399e4a6f4331ee766f9",
    "extension/arms/claude_ad/arm.py": "sha256:b552df99dd6339f88adcfedde742ba6c6b5f279b9af5f86baed5832798f7cc59",
    "extension/arms/claude_ad/policy.py": "sha256:ab685a11e9bf9fc95543f7890115ba183d1fd59f0a91df5ad8644992f97ee237",
    "extension/arms/collinear/__init__.py": "sha256:f05a82de1949c6aa2c89ab0ef108217cd3bddd925a083a671a02eae454d82e03",
    "extension/arms/collinear/arm.py": "sha256:c18e462048fcb8b3a73c8b3290145122d54612453a1866d09a83b3172dcbc319",
    "extension/arms/collinear/policy.py": "sha256:d933176078abd80400bd9f56fc2bfdd3dbc32a8339e3a8180a338224f7155127",
    "extension/arms/detection_in_the_cloud/__init__.py": "sha256:eaddbc8dc6e71b7f19670b98a64abae173507b6e5f4a2a52c9fef49bd0a7d7be",
    "extension/arms/detection_in_the_cloud/arm.py": "sha256:efc6b43ef1c0d15e5790753edd733f3dec5d399349a14059e23032893606cbff",
    "extension/arms/detection_in_the_cloud/policy.py": "sha256:81d19ddb78274a5a1a91c371705c9bcff4a5ec973a85707513e8a84ca18e2158",
    "extension/arms/gpohound/__init__.py": "sha256:200b70b389bcbce4ce83918c672d3ba5fc5501dd963a95d6d99f3a663803b913",
    "extension/arms/gpohound/arm.py": "sha256:54cc75660514ce2d6f471d490e774bf2fd0ccf60fc491d58538ecc83be4fcfeb",
    "extension/arms/gpohound/policy.py": "sha256:fb4b5748b51fd681f4c9f30c7b8a48f2fc456053c845a75f3fab0beb844e30e4",
    "extension/arms/leonidas/__init__.py": "sha256:22f094cb0497be1ce6d02f432173e0a19990786af5df3fc3980d8981d5e3b407",
    "extension/arms/leonidas/arm.py": "sha256:970cffec0456e9328ea0bb4efe9b84528f8eb6c0e282482ed252df9e29f4b0eb",
    "extension/arms/leonidas/policy.py": "sha256:208437525288b5df4da5aec16fab7d7cc4942b508b63b087e4f6e09f9342f544",
    "extension/arms/m365pwned/__init__.py": "sha256:bb0b32107519480f71a7678150da93dd4c697d721c98b0bbe32450d7d7a9f29f",
    "extension/arms/m365pwned/arm.py": "sha256:139b49222a93b971eaac015e1c8add30591e1ed8c321147f71573e0c47692155",
    "extension/arms/m365pwned/policy.py": "sha256:89ccb8baa25b6bb51b1181717365c140101e0a5cfb70f9b437182f81900af9c9",
    "extension/arms/numasec/__init__.py": "sha256:747f8ba952ea38071c7cc184476d4fe3f93ab7504f71c7bf3010bcdb29a61a7a",
    "extension/arms/numasec/arm.py": "sha256:0eb86e51940e9323d2645798d73947bf6b54cf3b64191438a67e64e41809f305",
    "extension/arms/numasec/policy.py": "sha256:17d43a2204cba8cd549b122a29cf6620ae5e7e0f879212764072ed57955613d7",
    "extension/arms/pentestkit/__init__.py": "sha256:7d7a195f4a7591e0f6b5359bbe13a3a1770bd5ece1ce1fe82d068c12433ab7b2",
    "extension/arms/pentestkit/arm.py": "sha256:040e788522ded457d568f3f02ae33cd1b34901458f39022c4ab84a5569207296",
    "extension/arms/pentestkit/policy.py": "sha256:4168a98ecd6751156a3789d462b10e3fa8d87bbecd11efc46b2294e5fa136ad8",
    "extension/arms/rubeus/__init__.py": "sha256:a4cf8a696e282e617f040ebdd3552de355bccbbfc3c7fa80d311594e0d5ffc7a",
    "extension/arms/rubeus/arm.py": "sha256:4f76971e816b09d5f1a5541a9acc03d0c7dfb0bbbfedfeac4b418a9ac96ff94e",
    "extension/arms/rubeus/policy.py": "sha256:cbed922ce19573d9c3ed912aba6440516eeda3d59a73e58e35ae956cac4ba3bf",
    "extension/arms/security_detections_mcp/__init__.py": "sha256:66d3d16162719e6cdf692b4355dedf5e5bc450bd546cccb75afb7b444a4d3565",
    "extension/arms/security_detections_mcp/arm.py": "sha256:cc70d4606dc8f3e4ff76d7f6701f555bb766e04f2901dfd526e38a4e8e35e58b",
    "extension/arms/security_detections_mcp/policy.py": "sha256:fc89fb0e210aa3db7296812615882c9e1c79ba607a34d82beecb6d5bf0e35378",
    "extension/arms/specterops_skills/__init__.py": "sha256:9909cbcb1f949a3d12e23c394f5afcd031361cfe73cd9e8bfd6e398cc15133ef",
    "extension/arms/specterops_skills/arm.py": "sha256:e0fae21ce1a70e578a201e316c381856b70b59dffbdab0cc2dd47180821c9dc0",
    "extension/arms/specterops_skills/policy.py": "sha256:e154547db65a29e347c490a9deb8a12126166681ffc806b55a6bb9e3f5a4b9de",
    "extension/arms/vulnify/__init__.py": "sha256:b1d938106b64ce4c26275e1f3f99f4f2e95d5b92db9e1770fafac18c440db9d7",
    "extension/arms/vulnify/arm.py": "sha256:67f61785c2c260de674e23daad8df6d629f150cc8a47abdb43f7b566871e8486",
    "extension/arms/vulnify/policy.py": "sha256:70d52593eb9f79045a5114e7ec4c1c76dc793319e1475967d25bee69bac4a5e1",
}

HANDLER_CLASS_BY_ARM: Mapping[str, str] = {
    "ad-pathfinder": "extension.arms.ad_pathfinder.arm.AdPathfinderArm",
    "agentseal": "extension.arms.agentseal.arm.AgentSealArm",
    "claude-ad": "extension.arms.claude_ad.arm.ClaudeAdArm",
    "collinear": "extension.arms.collinear.arm.CollinearArm",
    "detection-in-the-cloud": (
        "extension.arms.detection_in_the_cloud.arm.DetectionInTheCloudArm"
    ),
    "gpohound": "extension.arms.gpohound.arm.GpohoundArm",
    "leonidas": "extension.arms.leonidas.arm.LeonidasArm",
    "m365pwned": "extension.arms.m365pwned.arm.M365PwnedArm",
    "numasec": "extension.arms.numasec.arm.NumasecArm",
    "pentestkit": "extension.arms.pentestkit.arm.PentestkitArm",
    "rubeus": "extension.arms.rubeus.arm.RubeusArm",
    "security-detections-mcp": (
        "extension.arms.security_detections_mcp.arm.SecurityDetectionsMcpArm"
    ),
    "specterops-skills": "extension.arms.specterops_skills.arm.SpecteropsSkillsArm",
    "vulnify": "extension.arms.vulnify.arm.VulnifyArm",
}

# Filled from the independently audited checkout snapshot after the projection
# shape above is fixed.  A register co-edit cannot redefine these values.
EXPECTED_SURFACE_SHA256: Mapping[str, str] = {
    "governance": "sha256:69e26496efa65e78272cc1774a162383e45f7be17e796f2d27d728239a9b5bd2",
    "coverage": "sha256:dc5304d5eee526f4c081a64090577b999ad75e230154b582b1a985a6e942494b",
    "invoke_profiles": "sha256:0e4564f9de9a705bbcd3d5e65d71d3f2353d5336005b8eee295026460c90e16b",
    "policies": "sha256:93e32e6028237e38ffa0132f5e269eb00c0fa1cf3b1edcf7f0a123697eacf987",
    "reader_runtime": "sha256:2bbb040a0602de6973fa56a807720592c9d4aa3485687e6ab8cbfeaf378f37a9",
}


class SafetyLoadError(ValueError):
    """The safety register, schema, or canonical checkout surface is invalid."""


class _SafetyUniqueKeyLoader(_GovernanceUniqueKeyLoader):
    document_label = "safety register"


@dataclass(frozen=True)
class SafetyRegistry:
    """One schema-valid safety register and the exact bytes loaded."""

    document: Mapping[str, Any]
    path: Path
    register_sha256: str
    schema_path: Path
    schema_sha256: str
    document_sha256: str


@dataclass(frozen=True)
class SurfaceInventory:
    """Scoped semantic snapshot of the five independent checkout authorities."""

    document: Mapping[str, Any]
    section_sha256: Mapping[str, str]
    raw_sha256: Mapping[str, str]
    raw_sha256_digest: str
    document_sha256: str


@dataclass(frozen=True, order=True)
class ValidationIssue:
    category: str
    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True)
class ValidationReport:
    requested_scope: str
    register_scope: str
    register_revision: int | None
    requirement: str
    as_of: date
    repository_complete: bool
    safety_complete: bool
    register_sha256: str
    schema_sha256: str
    surface_sha256: Mapping[str, str]
    surface_raw_sha256: Mapping[str, str]
    arm_count: int
    discovery_action_count: int
    data_action_count: int
    hazard_count: int
    control_count: int
    issues: tuple[ValidationIssue, ...]

    @property
    def integrity_ok(self) -> bool:
        return not any(issue.category == "integrity" for issue in self.issues)

    @property
    def ready_ok(self) -> bool:
        return (
            self.integrity_ok
            and self.repository_complete
            and self.safety_complete
            and not any(
                issue.category in {"readiness", "completeness"}
                for issue in self.issues
            )
        )

    @property
    def ok(self) -> bool:
        if self.requirement == "integrity":
            return self.integrity_ok
        if self.requirement == "ready":
            return self.ready_ok
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA_ID,
            "requested_scope": self.requested_scope,
            "register_scope": self.register_scope,
            "register_revision": self.register_revision,
            "requirement": self.requirement,
            "as_of": self.as_of.isoformat(),
            "ok": self.ok,
            "integrity_ok": self.integrity_ok,
            "ready_ok": self.ready_ok,
            "repository_complete": self.repository_complete,
            "safety_complete": self.safety_complete,
            "register_sha256": self.register_sha256,
            "schema_sha256": self.schema_sha256,
            "surface_sha256": dict(self.surface_sha256),
            "surface_raw_sha256": dict(self.surface_raw_sha256),
            "counts": {
                "arms": self.arm_count,
                "discovery_actions": self.discovery_action_count,
                "data_actions": self.data_action_count,
                "hazards": self.hazard_count,
                "controls": self.control_count,
                "issues": len(self.issues),
            },
            "issues": [issue.as_dict() for issue in self.issues],
        }


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        if not all(type(key) is str for key in value):
            raise ValueError("semantic snapshots require string mapping keys")
        return {key: _normalize(value[key]) for key in sorted(value)}
    if type(value) in {list, tuple}:
        return [_normalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_normalize(item) for item in value]
        return sorted(
            items,
            key=lambda item: json.dumps(
                item,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
    if value is None or type(value) in {str, bool, int, float}:
        return value
    raise ValueError(f"unsupported semantic snapshot type: {type(value).__name__}")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        _normalize(value),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _strict_equal(left: Any, right: Any) -> bool:
    """Compare JSON-shaped values without erasing schema-relevant types."""

    if type(left) is not type(right):
        return False
    if type(left) is dict:
        if set(left) != set(right):
            return False
        return all(_strict_equal(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(
            _strict_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    if left is None or type(left) in {str, bool, int, float}:
        return left == right
    return False


def _is_exact_json(value: Any) -> bool:
    """Reject tuples, sets, mapping subclasses, and non-string object keys."""

    if type(value) is dict:
        return all(
            type(key) is str and _is_exact_json(item)
            for key, item in value.items()
        )
    if type(value) is list:
        return all(_is_exact_json(item) for item in value)
    return value is None or type(value) in {str, bool, int, float}


def _is_sha256_digest(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _safe_snapshot(path: Path, *, label: str, max_bytes: int) -> Any:
    try:
        return _read_file_snapshot(path, label=label, max_bytes=max_bytes)
    except GovernanceLoadError as exc:
        raise SafetyLoadError(str(exc)) from exc


def _safe_utf8(data: bytes, *, label: str) -> str:
    try:
        return _strict_utf8(data, label=label)
    except GovernanceLoadError as exc:
        raise SafetyLoadError(str(exc)) from exc


def load_register(
    path: Path | str = DEFAULT_REGISTER_PATH,
    *,
    schema_path: Path | str = DEFAULT_SCHEMA_PATH,
) -> SafetyRegistry:
    """Load bounded stable bytes and validate the closed canonical v1 schema."""

    register_path = Path(path)
    schema_file = Path(schema_path)
    register_snapshot = _safe_snapshot(
        register_path, label="safety register", max_bytes=MAX_REGISTER_BYTES
    )
    raw = _safe_utf8(register_snapshot.data, label="safety register")
    try:
        document = yaml.load(raw, Loader=_SafetyUniqueKeyLoader)
    except GovernanceLoadError as exc:
        raise SafetyLoadError(str(exc)) from exc
    except (RecursionError, yaml.YAMLError) as exc:
        raise SafetyLoadError(f"invalid safety register YAML: {exc}") from exc
    if type(document) is not dict:
        raise SafetyLoadError("safety register must be an exact mapping")
    try:
        _validate_bounded_tree(document, label="safety register")
    except GovernanceLoadError as exc:
        raise SafetyLoadError(str(exc)) from exc

    schema_snapshot = _safe_snapshot(
        schema_file, label="safety register schema", max_bytes=MAX_SCHEMA_BYTES
    )
    if schema_snapshot.sha256 != CANONICAL_SCHEMA_SHA256:
        raise SafetyLoadError(
            "safety register schema does not match the canonical v1 digest: "
            f"expected {CANONICAL_SCHEMA_SHA256}, got {schema_snapshot.sha256}"
        )
    schema_raw = _safe_utf8(schema_snapshot.data, label="safety register schema")
    try:
        schema = json.loads(
            schema_raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        _validate_bounded_tree(schema, label="safety register schema")
        _reject_nonlocal_refs(schema)
        jsonschema.Draft7Validator.check_schema(schema)
        validator = jsonschema.Draft7Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except GovernanceLoadError as exc:
        raise SafetyLoadError(str(exc)) from exc
    except (RecursionError, json.JSONDecodeError) as exc:
        raise SafetyLoadError(f"invalid safety register schema: {exc}") from exc
    except jsonschema.SchemaError as exc:
        raise SafetyLoadError(f"invalid safety register schema: {exc.message}") from exc
    except Exception as exc:
        raise SafetyLoadError(
            "safety register schema validation failed closed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        raise SafetyLoadError(
            f"safety register schema error at {location}: {error.message}"
        )
    return SafetyRegistry(
        document=copy.deepcopy(document),
        path=register_path,
        register_sha256=register_snapshot.sha256,
        schema_path=schema_file,
        schema_sha256=schema_snapshot.sha256,
        document_sha256=_sha256(document),
    )


def _expected_profile_record(arm_id: str, action: str) -> dict[str, Any]:
    registry_key = f"{arm_id}.{action}"
    scope = [f"policy://extension/arms/{arm_id}"]
    return {
        "registry_key": registry_key,
        "arm_id": arm_id,
        "action": action,
        "capability_id": registry_key,
        "tool_name": "specaudit-ctf",
        "tool_version": "0.1.0",
        "authorized_scope": scope,
        "touched_scope": scope,
        "safety_class": "R0",
        "side_effects": ["local-read"],
        "timeout_ms": 30_000,
        "max_output_bytes": 1_048_576,
        "max_tool_steps": 1,
        "max_spend": None,
        "cleanup_required": False,
        "approval_ref": None,
        "roe_ref": None,
        "tier": "research",
        "default_off": True,
        "synthetic_only": action == "list_tools",
        "record_type": "extension.invoke_profiles.InvokeProfile",
    }


def _expected_profile_records() -> dict[str, Any]:
    records: dict[str, Any] = {}
    for arm_id in sorted(ARM_BASELINES):
        records[f"{arm_id}.list_tools"] = _expected_profile_record(
            arm_id, "list_tools"
        )
        for action in sorted(ARM_BASELINES[arm_id]["actions"]):
            records[f"{arm_id}.{action}"] = _expected_profile_record(arm_id, action)
    return records


def _policy_record(
    arm_id: str,
    baseline: Mapping[str, Any],
    reader_source_sha256: Mapping[str, str],
) -> dict[str, Any]:
    package_name = baseline["policy_module"].removesuffix(".policy").split(".")[-1]
    source_path = f"extension/arms/{package_name}/policy.py"
    return {
        "arm_id": arm_id,
        "module": baseline["policy_module"],
        "source_path": source_path,
        "source_sha256": reader_source_sha256[source_path],
        "path_refusal_function": baseline["path_refusal_function"],
        "required_functions": [
            baseline["path_refusal_function"],
            "args_refusal",
            "limit_refusal",
        ],
        "contract": {
            "allowed_actions": sorted(baseline["actions"]),
            "list_actions": ["list_tools", "tools/list"],
            "argument_keys": {
                action: list(baseline["actions"][action])
                for action in sorted(baseline["actions"])
            },
            "max_file_bytes": 64 * 1024 * 1024,
            "allowed_suffixes": list(baseline["allowed_suffixes"]),
            "max_directory_entries": baseline["max_directory_entries"],
            "max_output_chars": 200_000,
            "max_results": 200,
            "required_constant_names": sorted(
                {
                    *COMMON_POLICY_CONSTANTS,
                    baseline["max_file_bytes_name"],
                    baseline["suffixes_name"],
                    *baseline["extra_constants"],
                }
            ),
        },
    }


def _reader_source_sha256() -> dict[str, str]:
    return {
        relative_path: _safe_snapshot(
            REPOSITORY_ROOT / relative_path,
            label=f"reader source {relative_path}",
            max_bytes=MAX_RUNTIME_SOURCE_BYTES,
        ).sha256
        for relative_path in sorted(EXPECTED_READER_SOURCE_SHA256)
    }


def _current_raw_sha256(
    reader_source_sha256: Mapping[str, str] | None = None,
) -> dict[str, str]:
    if reader_source_sha256 is None:
        reader_source_sha256 = _reader_source_sha256()
    raw = {
        "governance_register": _safe_snapshot(
            DEFAULT_GOVERNANCE_REGISTER_PATH,
            label="governance register provenance",
            max_bytes=MAX_REGISTER_BYTES,
        ).sha256,
        "governance_schema": _safe_snapshot(
            DEFAULT_GOVERNANCE_SCHEMA_PATH,
            label="governance schema provenance",
            max_bytes=MAX_SCHEMA_BYTES,
        ).sha256,
        "coverage_catalog": _safe_snapshot(
            DEFAULT_COVERAGE_PATH,
            label="coverage catalog provenance",
            max_bytes=MAX_REGISTER_BYTES,
        ).sha256,
        "coverage_schema": _safe_snapshot(
            DEFAULT_COVERAGE_SCHEMA_PATH,
            label="coverage schema provenance",
            max_bytes=MAX_SCHEMA_BYTES,
        ).sha256,
    }
    raw.update(
        {
            f"reader_source:{relative_path}": digest
            for relative_path, digest in reader_source_sha256.items()
        }
    )
    return raw


def _snapshot_surfaces() -> SurfaceInventory:
    reader_source_sha256 = _reader_source_sha256()
    raw_sha256 = _current_raw_sha256(reader_source_sha256)
    try:
        governance_registry = load_governance_register()
        coverage_inventory = load_coverage_inventory()
    except (GovernanceLoadError, ValueError) as exc:
        raise SafetyLoadError(str(exc)) from exc

    coverage_schema_sha256 = raw_sha256["coverage_schema"]
    if coverage_schema_sha256 != CANONICAL_COVERAGE_SCHEMA_SHA256:
        raise SafetyLoadError(
            "coverage schema does not match the canonical safety digest: "
            f"expected {CANONICAL_COVERAGE_SCHEMA_SHA256}, "
            f"got {coverage_schema_sha256}"
        )
    if governance_registry.schema_sha256 != CANONICAL_GOVERNANCE_SCHEMA_SHA256:
        raise SafetyLoadError(
            "governance schema does not match the canonical safety digest: "
            f"expected {CANONICAL_GOVERNANCE_SCHEMA_SHA256}, "
            f"got {governance_registry.schema_sha256}"
        )
    if raw_sha256["governance_schema"] != governance_registry.schema_sha256:
        raise SafetyLoadError("governance schema changed while it was being read")
    if raw_sha256["governance_register"] != governance_registry.register_sha256:
        raise SafetyLoadError("governance register changed while it was being read")
    if raw_sha256["coverage_catalog"] != coverage_inventory.source_sha256:
        raise SafetyLoadError("coverage catalog changed while it was being read")

    arm_ids = frozenset(ARM_BASELINES)
    source_ids = frozenset(row["source_id"] for row in ARM_BASELINES.values())

    coverage_rows = [
        copy.deepcopy(dict(row))
        for row in coverage_inventory.records
        if type(row.get("id")) is str and row["id"] in arm_ids
    ]
    coverage_rows.sort(key=lambda row: (row.get("id", ""), _canonical_json(row)))
    coverage_document = {
        "version": coverage_inventory.version,
        "canonical_schema_sha256": coverage_schema_sha256,
        "records": coverage_rows,
    }

    policy_records = {
        arm_id: _policy_record(
            arm_id, ARM_BASELINES[arm_id], reader_source_sha256
        )
        for arm_id in sorted(ARM_BASELINES)
    }
    policies_document = {"records": policy_records}

    profile_records = _expected_profile_records()
    profile_capability_ids = sorted(profile_records)
    profiles_document = {
        "authority": "extension.invoke_profiles.INVOKE_PROFILES",
        "declared_fields": list(PROFILE_FIELDS),
        "expected_fields": list(PROFILE_FIELDS),
        "capability_ids": profile_capability_ids,
        "records": profile_records,
        "source_sha256": reader_source_sha256["extension/invoke_profiles.py"],
    }

    reader_runtime_document = {
        "source_boundary": (
            "Exact checkout bytes for PR97 reader admission, handler selection, "
            "policies, and parsing; not an execution, transport, or environment proof."
        ),
        "source_sha256": reader_source_sha256,
        "handler_registry": dict(HANDLER_CLASS_BY_ARM),
        "profile_capability_ids": profile_capability_ids,
        "positive_profile_lookups": {
            capability_id: capability_id
            for capability_id in profile_capability_ids
        },
        "negative_profile_lookups": [
            *(f"{arm_id}.__unlisted__" for arm_id in sorted(ARM_BASELINES)),
            "__unlisted__.list_tools",
        ],
        "authorities": {
            "handler_registry": "extension.contract._default_arms",
            "dispatch": "extension.dispatch.dispatch_invoke",
            "profile_registry": "extension.invoke_profiles.INVOKE_PROFILES",
            "profile_membership": "extension.invoke_profiles.INVOKE_CAPABILITY_IDS",
            "profile_lookup": "extension.invoke_profiles.invoke_profile",
        },
    }

    governance_document_raw = governance_registry.document
    runtime_rows = [
        copy.deepcopy(row)
        for row in governance_document_raw["runtime"]
        if row.get("arm_id") in arm_ids
        or (
            type(row.get("capability_id")) is str
            and row["capability_id"].split(".", 1)[0] in arm_ids
        )
    ]
    runtime_rows.sort(
        key=lambda row: (row.get("capability_id", ""), _canonical_json(row))
    )
    source_rows = [
        copy.deepcopy(row)
        for row in governance_document_raw["sources"]
        if row.get("id") in source_ids
    ]
    source_rows.sort(key=lambda row: (row.get("id", ""), _canonical_json(row)))
    relationship_rows = [
        copy.deepcopy(row)
        for row in governance_document_raw["relationships"]
        if row.get("kind") == "research-mapping"
        and (
            row.get("from") in {f"source:{source_id}" for source_id in source_ids}
            or any(
                type(target) is str
                and target.startswith("runtime:")
                and target.removeprefix("runtime:").split(".", 1)[0] in arm_ids
                for target in row.get("to", [])
            )
        )
    ]
    relationship_rows.sort(
        key=lambda row: (row.get("id", ""), _canonical_json(row))
    )
    contract_rows = [
        copy.deepcopy(row)
        for row in governance_document_raw["contract_templates"]
        if row.get("id") in {"policy-read-v1", "caller-file-read-v1"}
    ]
    contract_rows.sort(key=lambda row: (row.get("id", ""), _canonical_json(row)))
    governance_document = {
        "schema": governance_document_raw.get("schema"),
        "schema_version": governance_document_raw.get("schema_version"),
        "register_revision": governance_document_raw.get("register_revision"),
        "scope": copy.deepcopy(governance_document_raw.get("scope")),
        "canonical_schema_sha256": governance_registry.schema_sha256,
        "expected_runtime_fields": list(RUNTIME_FIELDS),
        "expected_source_fields": list(SOURCE_FIELDS),
        "expected_relationship_fields": list(RELATIONSHIP_FIELDS),
        "expected_contract_fields": list(CONTRACT_FIELDS),
        "contract_templates": contract_rows,
        "sources": source_rows,
        "runtime": runtime_rows,
        "relationships": relationship_rows,
    }

    document = _normalize(
        {
            "governance": governance_document,
            "coverage": coverage_document,
            "invoke_profiles": profiles_document,
            "policies": policies_document,
            "reader_runtime": reader_runtime_document,
        }
    )
    section_sha256 = {
        section: _sha256(document[section])
        for section in (
            "governance",
            "coverage",
            "invoke_profiles",
            "policies",
            "reader_runtime",
        )
    }
    return SurfaceInventory(
        document=copy.deepcopy(document),
        section_sha256=copy.deepcopy(section_sha256),
        raw_sha256=copy.deepcopy(raw_sha256),
        raw_sha256_digest=_sha256(raw_sha256),
        document_sha256=_sha256(document),
    )


def snapshot_surfaces() -> SurfaceInventory:
    """Snapshot PR97 surfaces without executing governed extension modules."""

    try:
        return _snapshot_surfaces()
    except SafetyLoadError:
        raise
    except BaseException as exc:
        raise SafetyLoadError(
            "cannot snapshot safety surfaces: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _arm_hazard_ids(arm_id: str) -> list[str]:
    values = list(COMMON_HAZARD_IDS)
    if arm_id == "detection-in-the-cloud":
        values.append("HZ-DIRECTORY-SNAPSHOT-DRIFT")
    if arm_id == "collinear":
        values.append("HZ-GROUND-TRUTH-COLOCATION")
    return values


def _arm_control_ids(arm_id: str) -> list[str]:
    values = list(COMMON_CONTROL_IDS)
    if arm_id == "collinear":
        values.append("CTL-GRADER-PLANE-ISOLATION")
    return values


def _expected_arm(arm_id: str) -> dict[str, Any]:
    baseline = ARM_BASELINES[arm_id]
    limitations = list(COMMON_ARM_LIMITATIONS)
    if arm_id == "detection-in-the-cloud":
        limitations.append("directory-snapshot-stability-unverified")
    if arm_id == "collinear":
        limitations.append("grader-plane-isolation-unverified")
    data_actions = [
        {
            "capability_id": f"{arm_id}.{action}",
            "action": action,
            "input_keys": list(baseline["actions"][action]),
            "path_argument": baseline["path_argument"],
            "input_kind": baseline["input_kind"],
        }
        for action in sorted(baseline["actions"])
    ]
    return {
        "record_version": 1,
        "arm_id": arm_id,
        "source_id": baseline["source_id"],
        "policy_module": baseline["policy_module"],
        "state": "documented-unverified",
        "input_contract": {
            "path_argument": baseline["path_argument"],
            "input_kind": baseline["input_kind"],
            "max_file_bytes": 64 * 1024 * 1024,
            "allowed_suffixes": list(baseline["allowed_suffixes"]),
            "max_directory_entries": baseline["max_directory_entries"],
        },
        "discovery_capability_id": f"{arm_id}.list_tools",
        "data_actions": data_actions,
        "hazard_ids": _arm_hazard_ids(arm_id),
        "required_control_ids": _arm_control_ids(arm_id),
        "limitations": limitations,
    }


EXPECTED_SCOPE = {
    "id": SCOPE_ID,
    "description": (
        "Checkout-only safety-requirement foundation for the 14 PR97 "
        "caller-file readers; no control is verified or provisioned."
    ),
    "repository_complete": False,
    "safety_complete": False,
    "arm_count": 14,
    "discovery_action_count": 14,
    "data_action_count": 38,
}

EXPECTED_REGISTER_KEYS = {
    "schema",
    "schema_version",
    "register_revision",
    "scope",
    "surface_anchors",
    "hazards",
    "controls",
    "arms",
    "limitations",
}


def _add(
    issues: list[ValidationIssue],
    category: str,
    code: str,
    path: str,
    message: str,
) -> None:
    issues.append(ValidationIssue(category, code, path, message))


def _index_rows(
    rows: Any,
    *,
    label: str,
    issues: list[ValidationIssue],
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    if type(rows) is not list:
        _add(issues, "integrity", "register-metadata-mismatch", label, "must be an exact list")
        return indexed
    for position, row in enumerate(rows):
        if type(row) is not dict or type(row.get("id")) is not str:
            _add(
                issues,
                "integrity",
                "register-metadata-mismatch",
                f"{label}[{position}]",
                "must be an exact mapping with a string id",
            )
            continue
        row_id = row["id"]
        if row_id in indexed:
            _add(
                issues,
                "integrity",
                "register-metadata-mismatch",
                f"{label}[{position}].id",
                f"duplicate id {row_id}",
            )
        else:
            indexed[row_id] = row
    return indexed


def _check_register_document(
    document: Mapping[str, Any], issues: list[ValidationIssue]
) -> None:
    if type(document) is not dict:
        _add(
            issues,
            "integrity",
            "register-metadata-mismatch",
            "$",
            "register must remain an exact mapping",
        )
        return
    if set(document) != EXPECTED_REGISTER_KEYS:
        _add(
            issues,
            "integrity",
            "register-metadata-mismatch",
            "$",
            "register top-level keys differ from the closed v1 schema",
        )
    expected_metadata = {
        "schema": REGISTER_SCHEMA_ID,
        "schema_version": REGISTER_SCHEMA_VERSION,
        "register_revision": REGISTER_REVISION,
    }
    for key, expected in expected_metadata.items():
        if not _strict_equal(document.get(key), expected):
            _add(
                issues,
                "integrity",
                "register-metadata-mismatch",
                key,
                f"expected {expected!r}, got {document.get(key)!r}",
            )
    if not _strict_equal(
        document.get("surface_anchors"), dict(EXPECTED_SURFACE_SHA256)
    ):
        _add(
            issues,
            "integrity",
            "surface-anchor-mismatch",
            "surface_anchors",
            "surface anchors differ from the complete independent v1 baseline",
        )
    if not _strict_equal(document.get("scope"), EXPECTED_SCOPE):
        _add(
            issues,
            "integrity",
            "register-metadata-mismatch",
            "scope",
            "scope does not match the independently frozen partial PR97 baseline",
        )
    if not _strict_equal(document.get("limitations"), list(TOP_LEVEL_LIMITATIONS)):
        _add(
            issues,
            "integrity",
            "register-metadata-mismatch",
            "limitations",
            "top-level limitations do not match the independent v1 baseline",
        )
    if not _strict_equal(document.get("hazards"), list(HAZARDS)):
        _add(
            issues,
            "integrity",
            "hazard-definition-mismatch",
            "hazards",
            "hazard records differ from the independent v1 baseline",
        )
    if not _strict_equal(document.get("controls"), list(CONTROLS)):
        _add(
            issues,
            "integrity",
            "control-definition-mismatch",
            "controls",
            "control records differ from the independent permanently-unverified baseline",
        )

    arms = document.get("arms")
    actual_arm_ids = (
        [row.get("arm_id") for row in arms if type(row) is dict]
        if type(arms) is list
        else []
    )
    expected_arm_ids = sorted(ARM_BASELINES)
    if not _strict_equal(actual_arm_ids, expected_arm_ids):
        _add(
            issues,
            "integrity",
            "arm-roster-mismatch",
            "arms",
            f"expected exact ordered arm roster {expected_arm_ids!r}, got {actual_arm_ids!r}",
        )
    actual_by_arm: dict[str, Mapping[str, Any]] = {}
    if type(arms) is list:
        for position, row in enumerate(arms):
            if type(row) is not dict or type(row.get("arm_id")) is not str:
                continue
            if row["arm_id"] in actual_by_arm:
                _add(
                    issues,
                    "integrity",
                    "arm-roster-mismatch",
                    f"arms[{position}].arm_id",
                    f"duplicate arm id {row['arm_id']}",
                )
            else:
                actual_by_arm[row["arm_id"]] = row
    for arm_id in expected_arm_ids:
        actual = actual_by_arm.get(arm_id)
        expected = _expected_arm(arm_id)
        if actual is None:
            continue
        if not _strict_equal(actual.get("source_id"), expected["source_id"]):
            _add(
                issues,
                "integrity",
                "source-mapping-mismatch",
                f"arms.{arm_id}.source_id",
                f"expected {expected['source_id']}",
            )
        if not _strict_equal(actual.get("input_contract"), expected["input_contract"]):
            _add(
                issues,
                "integrity",
                "input-contract-mismatch",
                f"arms.{arm_id}.input_contract",
                "input contract differs from the independent path authority",
            )
        if not _strict_equal(actual.get("data_actions"), expected["data_actions"]):
            _add(
                issues,
                "integrity",
                "action-roster-mismatch",
                f"arms.{arm_id}.data_actions",
                "data actions or exact input/path keys differ from the frozen PR97 surface",
            )
        if not _strict_equal(actual.get("hazard_ids"), expected["hazard_ids"]):
            _add(
                issues,
                "integrity",
                "arm-hazard-mismatch",
                f"arms.{arm_id}.hazard_ids",
                "arm hazard assignment differs from the independent baseline",
            )
        if not _strict_equal(
            actual.get("required_control_ids"), expected["required_control_ids"]
        ):
            _add(
                issues,
                "integrity",
                "arm-control-mismatch",
                f"arms.{arm_id}.required_control_ids",
                "arm control assignment differs from the independent baseline",
            )
        if not _strict_equal(actual, expected):
            _add(
                issues,
                "integrity",
                "register-metadata-mismatch",
                f"arms.{arm_id}",
                "arm record differs from the complete independent v1 baseline",
            )

    hazard_index = _index_rows(document.get("hazards"), label="hazards", issues=issues)
    control_index = _index_rows(document.get("controls"), label="controls", issues=issues)
    for hazard_id, hazard in hazard_index.items():
        for control_id in hazard.get("required_control_ids", []):
            if control_id not in control_index:
                _add(
                    issues,
                    "integrity",
                    "control-definition-mismatch",
                    f"hazards.{hazard_id}.required_control_ids",
                    f"unknown control {control_id}",
                )
    for arm_id, arm in actual_by_arm.items():
        for hazard_id in arm.get("hazard_ids", []):
            if hazard_id not in hazard_index:
                _add(
                    issues,
                    "integrity",
                    "arm-hazard-mismatch",
                    f"arms.{arm_id}.hazard_ids",
                    f"unknown hazard {hazard_id}",
                )
        for control_id in arm.get("required_control_ids", []):
            if control_id not in control_index:
                _add(
                    issues,
                    "integrity",
                    "arm-control-mismatch",
                    f"arms.{arm_id}.required_control_ids",
                    f"unknown control {control_id}",
                )


def _reload_registry_for_validation(
    registry: SafetyRegistry, issues: list[ValidationIssue]
) -> SafetyRegistry:
    """Re-establish on-disk provenance instead of trusting dataclass fields."""

    expected_path_type = type(DEFAULT_REGISTER_PATH)
    if (
        type(registry.path) is not expected_path_type
        or type(registry.schema_path) is not expected_path_type
    ):
        raise ValueError("registry provenance paths must be exact pathlib paths")
    current = load_register(registry.path, schema_path=registry.schema_path)
    if not all(
        (
            _strict_equal(registry.document, current.document),
            type(registry.path) is type(current.path)
            and registry.path == current.path,
            _is_sha256_digest(registry.register_sha256),
            registry.register_sha256 == current.register_sha256,
            type(registry.schema_path) is type(current.schema_path)
            and registry.schema_path == current.schema_path,
            _is_sha256_digest(registry.schema_sha256),
            registry.schema_sha256 == current.schema_sha256,
            _is_sha256_digest(registry.document_sha256),
            registry.document_sha256 == current.document_sha256,
        )
    ):
        _add(
            issues,
            "integrity",
            "register-provenance-mismatch",
            "$",
            "supplied register snapshot differs from freshly loaded on-disk bytes",
        )
    return current


def _check_surfaces(
    document: Mapping[str, Any],
    surfaces: SurfaceInventory,
    issues: list[ValidationIssue],
) -> tuple[Mapping[str, str], Mapping[str, str]]:
    current_surfaces = snapshot_surfaces()
    expected_sections = set(EXPECTED_SURFACE_SHA256)
    if type(surfaces.document) is not dict or set(surfaces.document) != expected_sections:
        _add(
            issues,
            "integrity",
            "surface-shape-mismatch",
            "surfaces",
            "surface document must contain exactly the five v1 sections",
        )
    if not _is_exact_json(surfaces.document):
        _add(
            issues,
            "integrity",
            "surface-shape-mismatch",
            "surfaces",
            "surface document must retain exact JSON container and scalar types",
        )
    if (
        type(surfaces.section_sha256) is not dict
        or set(surfaces.section_sha256) != expected_sections
    ):
        _add(
            issues,
            "integrity",
            "surface-shape-mismatch",
            "surfaces.section_sha256",
            "section digest keys must exactly match the five v1 sections",
        )
    if (
        not _is_sha256_digest(surfaces.document_sha256)
        or not _is_sha256_digest(surfaces.raw_sha256_digest)
        or type(surfaces.raw_sha256) is not dict
        or not all(
            type(key) is str and _is_sha256_digest(value)
            for key, value in surfaces.raw_sha256.items()
        )
        or type(surfaces.section_sha256) is not dict
        or not all(
            type(key) is str and _is_sha256_digest(value)
            for key, value in surfaces.section_sha256.items()
        )
    ):
        _add(
            issues,
            "integrity",
            "surface-shape-mismatch",
            "surfaces",
            "surface provenance fields must use exact paths, keys, and SHA-256 strings",
        )
    if _sha256(surfaces.document) != surfaces.document_sha256:
        _add(
            issues,
            "integrity",
            "surface-snapshot-mutated",
            "surfaces",
            "surface document changed after its semantic snapshot was created",
        )
    if _sha256(surfaces.raw_sha256) != surfaces.raw_sha256_digest:
        _add(
            issues,
            "integrity",
            "surface-snapshot-mutated",
            "surfaces.raw_sha256",
            "raw provenance hashes changed after the surface snapshot was created",
        )
    if not all(
        (
            _strict_equal(surfaces.document, current_surfaces.document),
            _strict_equal(
                surfaces.section_sha256, current_surfaces.section_sha256
            ),
            _strict_equal(surfaces.raw_sha256, current_surfaces.raw_sha256),
            surfaces.raw_sha256_digest == current_surfaces.raw_sha256_digest,
            surfaces.document_sha256 == current_surfaces.document_sha256,
        )
    ):
        _add(
            issues,
            "integrity",
            "surface-provenance-mismatch",
            "surfaces",
            "supplied surface snapshot differs from freshly projected on-disk inputs",
        )
    current_reader_sources = current_surfaces.document["reader_runtime"][
        "source_sha256"
    ]
    if not _strict_equal(
        current_reader_sources, dict(EXPECTED_READER_SOURCE_SHA256)
    ):
        _add(
            issues,
            "integrity",
            "reader-runtime-mismatch",
            "surfaces.reader_runtime.source_sha256",
            "reader source paths or digests differ from the independent v1 manifest",
        )
    computed: dict[str, str] = {}
    code_by_section = {
        "governance": "governance-mismatch",
        "coverage": "coverage-mismatch",
        "invoke_profiles": "profile-mismatch",
        "policies": "policy-mismatch",
        "reader_runtime": "reader-runtime-mismatch",
    }
    anchors = document.get("surface_anchors")
    if type(anchors) is not dict:
        anchors = {}
    for section, code in code_by_section.items():
        supplied_document = surfaces.document.get(section)
        supplied_digest = _sha256(supplied_document)
        current_digest = _sha256(current_surfaces.document[section])
        computed[section] = current_digest
        if surfaces.section_sha256.get(section) != supplied_digest:
            _add(
                issues,
                "integrity",
                "surface-snapshot-mutated",
                f"surfaces.{section}",
                "section changed after its semantic digest was created",
            )
        expected = EXPECTED_SURFACE_SHA256[section]
        if supplied_digest != expected or current_digest != expected:
            _add(
                issues,
                "integrity",
                code,
                f"surfaces.{section}",
                "scoped semantic digest differs: "
                f"expected {expected}, current {current_digest}, "
                f"supplied {supplied_digest}",
            )
        if anchors.get(section) not in {current_digest, supplied_digest} or (
            current_digest != supplied_digest
        ):
            _add(
                issues,
                "integrity",
                "surface-anchor-mismatch",
                f"surface_anchors.{section}",
                "register anchor does not bind both the current and supplied "
                "scoped digests",
            )
        if anchors.get(section) != expected:
            _add(
                issues,
                "integrity",
                "surface-anchor-mismatch",
                f"surface_anchors.{section}",
                "register anchor differs from the independent checker literal",
            )
    return computed, current_surfaces.raw_sha256


def validate_register(
    registry: SafetyRegistry,
    surfaces: SurfaceInventory | None = None,
    *,
    scope: str = SCOPE_ID,
    require: str = "ready",
    as_of: date,
) -> ValidationReport:
    """Validate integrity and report deliberately unmet safety readiness."""

    if type(registry) is not SafetyRegistry:
        raise ValueError("registry must be an exact SafetyRegistry")
    if surfaces is None:
        surfaces = snapshot_surfaces()
    if type(surfaces) is not SurfaceInventory:
        raise ValueError("surfaces must be an exact SurfaceInventory")
    if type(scope) is not str or scope != SCOPE_ID:
        raise ValueError(f"scope must be {SCOPE_ID!r}")
    if type(require) is not str or require not in REQUIREMENTS:
        raise ValueError(f"require must be one of {REQUIREMENTS!r}")
    if type(as_of) is not date:
        raise ValueError("as_of must be an exact datetime.date")

    document = registry.document
    issues: list[ValidationIssue] = []
    current_registry = _reload_registry_for_validation(registry, issues)
    if _sha256(document) != registry.document_sha256:
        _add(
            issues,
            "integrity",
            "register-snapshot-mutated",
            "$",
            "register document changed after its semantic snapshot was created",
    )
    _check_register_document(document, issues)
    computed_surface_sha256, current_raw_sha256 = _check_surfaces(
        document, surfaces, issues
    )

    arms = document.get("arms") if type(document.get("arms")) is list else []
    controls = (
        document.get("controls") if type(document.get("controls")) is list else []
    )
    hazards = document.get("hazards") if type(document.get("hazards")) is list else []
    data_action_count = sum(
        len(row.get("data_actions", []))
        for row in arms
        if type(row) is dict and type(row.get("data_actions")) is list
    )
    counts = {
        "arms": len(arms),
        "discovery_actions": sum(
            type(row) is dict and type(row.get("discovery_capability_id")) is str
            for row in arms
        ),
        "data_actions": data_action_count,
        "hazards": len(hazards),
        "controls": len(controls),
    }
    expected_counts = {
        "arms": 14,
        "discovery_actions": 14,
        "data_actions": 38,
        "hazards": 12,
        "controls": 11,
    }
    for name, expected in expected_counts.items():
        if counts[name] != expected:
            _add(
                issues,
                "integrity",
                "count-mismatch",
                f"counts.{name}",
                f"expected {expected}, got {counts[name]}",
            )

    _add(
        issues,
        "readiness",
        "safety-verifier-unimplemented",
        "$",
        "v1 has no verifier capable of authenticating or accepting control evidence",
    )
    for control in controls:
        if type(control) is dict and type(control.get("id")) is str:
            _add(
                issues,
                "readiness",
                "required-control-unverified",
                f"controls.{control['id']}",
                "the required control is permanently unverified in v1",
            )
    _add(
        issues,
        "completeness",
        "repository-scope-partial",
        "scope.repository_complete",
        "the register covers only the 14 PR97 readers, not the repository",
    )
    _add(
        issues,
        "readiness",
        "safety-scope-incomplete",
        "scope.safety_complete",
        "the register documents requirements but provisions and verifies none of them",
    )

    scope_document = document.get("scope")
    if type(scope_document) is not dict:
        scope_document = {}
    register_scope = scope_document.get("id")
    if type(register_scope) is not str:
        register_scope = "invalid"
    register_revision = document.get("register_revision")
    if type(register_revision) is not int:
        register_revision = None
    repository_complete = scope_document.get("repository_complete") is True
    safety_complete = scope_document.get("safety_complete") is True
    return ValidationReport(
        requested_scope=scope,
        register_scope=register_scope,
        register_revision=register_revision,
        requirement=require,
        as_of=as_of,
        repository_complete=repository_complete,
        safety_complete=safety_complete,
        register_sha256=current_registry.register_sha256,
        schema_sha256=current_registry.schema_sha256,
        surface_sha256=copy.deepcopy(computed_surface_sha256),
        surface_raw_sha256=copy.deepcopy(current_raw_sha256),
        arm_count=counts["arms"],
        discovery_action_count=counts["discovery_actions"],
        data_action_count=counts["data_actions"],
        hazard_count=counts["hazards"],
        control_count=counts["controls"],
        issues=tuple(sorted(set(issues))),
    )


def _iso_date(value: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from exc
    if parsed.isoformat() != value:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD")
    return parsed


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise SafetyLoadError(f"argument error: {message}")


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="validate reader safety state")
    check.add_argument("--register", type=Path, default=DEFAULT_REGISTER_PATH)
    check.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help="path to byte-identical canonical v1 schema",
    )
    check.add_argument("--scope", choices=(SCOPE_ID,), default=SCOPE_ID)
    check.add_argument("--require", choices=REQUIREMENTS, default="ready")
    check.add_argument("--as-of", type=_iso_date, required=True)
    check.add_argument("--format", choices=("json",), default="json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the checker: 0 satisfied, 1 explicit gaps, 2 invalid/failure."""

    try:
        args = _parser().parse_args(argv)
    except SafetyLoadError as exc:
        payload = {"schema": ERROR_SCHEMA_ID, "ok": False, "error": str(exc)}
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2

    try:
        registry = load_register(args.register, schema_path=args.schema)
        surfaces = snapshot_surfaces()
        report = validate_register(
            registry,
            surfaces,
            scope=args.scope,
            require=args.require,
            as_of=args.as_of,
        )
    except (SafetyLoadError, ValueError) as exc:
        payload = {"schema": ERROR_SCHEMA_ID, "ok": False, "error": str(exc)}
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2
    except BaseException as exc:
        payload = {
            "schema": ERROR_SCHEMA_ID,
            "ok": False,
            "error": f"validation failed closed: {type(exc).__name__}: {exc}",
        }
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), allow_nan=False, indent=2, sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
