"""Strict, offline validation for the versioned governance register.

The executable admission authority remains
``extension.invoke_profiles.INVOKE_PROFILES``.  This module snapshots that
authority for drift detection and validates governance metadata around it; it
is never imported by dispatch or the sealed runtime.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import copy
import hashlib
import importlib
import inspect
import json
import math
import os
import re
import stat
import sys
import textwrap
import unicodedata
from dataclasses import dataclass, fields
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

import jsonschema
import yaml
from markdown_it import MarkdownIt
from yaml.events import AliasEvent

DEFAULT_REGISTER_PATH = Path(__file__).resolve().with_name("register.v1.yaml")
DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "register.v1.schema.json"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COVERAGE_PATH = REPOSITORY_ROOT / "extension" / "coverage.yaml"
DEFAULT_COVERAGE_SCHEMA_PATH = (
    REPOSITORY_ROOT / "extension" / "schema" / "coverage.schema.json"
)

REGISTER_SCHEMA_ID = "specaudit.ctf.governance.register.v1"
REGISTER_SCHEMA_VERSION = 1
INVENTORY_AUTHORITY_ID = "extension.invoke_profiles.INVOKE_PROFILES"
EXECUTION_RESULT_SCHEMA_ID = "specaudit.ctf.execution-result.v1"
CANONICAL_SCHEMA_SHA256 = (
    "sha256:8e8edbd7aadcb071dd997437256e9e6b56fbbd344763423172e1183993e60e53"
)
CANONICAL_COVERAGE_SCHEMA_SHA256 = (
    "sha256:481137fed428de6e2c2c8bce6c109fb9c98fdc654b7cfc0f88bbcfc823a306b3"
)
REGISTER_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "register_revision",
        "scope",
        "runtime_inventory",
        "contract_templates",
        "modules",
        "sources",
        "runtime",
        "relationships",
        "promotion_events",
    }
)
PR97_SCOPE_ID = "pr97-readers"
FULL_SCOPE_ID = "full"
REQUIREMENTS = ("integrity", "current", "complete")
PR97_IMPLEMENTATION_REVISION = "9c6819c4709397d1d91f68cbb4ae13901d6d85f1"
PR97_LIST_ACTIONS = frozenset({"list_tools", "tools/list"})
# Landed discovery extras: the vulnify snapshot/batch layer advertises the
# bundled demo snapshot in its zero-argument discovery metadata.  A frozen
# per-arm record keeps the shape exact instead of admitting arbitrary extra
# keys; every listed key must be a nonempty built-in string.
PR97_DISCOVERY_EXTRA_KEYS: Mapping[str, tuple[str, ...]] = {
    "vulnify": ("demo_bundle",),
}
PR97_CATALOG_ROW_KEYS = frozenset(
    {"id", "kind", "protocols", "curated", "tier", "notes"}
)
MAX_REGISTER_BYTES = 256 * 1024
# The complete-inventory v2 register is substantially larger than the v1
# PR97 slice; these budgets apply only to the v2 loader and never relax the
# v1 or coverage caps.
MAX_REGISTER_V2_BYTES = 1024 * 1024
MAX_REGISTER_V2_NODES = 40_000
MAX_REGISTER_V2_TOTAL_STRING_BYTES = 1024 * 1024
MAX_SCHEMA_BYTES = 128 * 1024
MAX_COVERAGE_BYTES = 128 * 1024
MAX_COVERAGE_SCHEMA_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 128 * 1024
MAX_EVIDENCE_LINES = 20_000
MAX_DOCUMENT_NODES = 20_000
MAX_DOCUMENT_DEPTH = 48
MAX_STRING_BYTES = 16 * 1024
MAX_TOTAL_STRING_BYTES = 512 * 1024
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")

PR97_ARM_IDS = frozenset(
    {
        "ad-pathfinder",
        "agentseal",
        "claude-ad",
        "collinear",
        "detection-in-the-cloud",
        "gpohound",
        "leonidas",
        "m365pwned",
        "numasec",
        "pentestkit",
        "rubeus",
        "security-detections-mcp",
        "specterops-skills",
        "vulnify",
    }
)

# Literal coverage signatures are independent of coverage.yaml, the governance
# register, and InvokeProfile objects.  All four surfaces must agree before the
# checker can report the PR97 reader slice as integrity-clean.
PR97_COVERAGE_SIGNATURES: Mapping[
    str, tuple[str, tuple[str, ...], bool, str]
] = {
    "ad-pathfinder": ("arm", ("cli",), True, "research"),
    "agentseal": ("arm", ("cli",), True, "research"),
    "claude-ad": ("arm", ("cli",), True, "research"),
    "collinear": ("arm", ("cli",), True, "research"),
    "detection-in-the-cloud": ("arm", ("cli",), True, "research"),
    "gpohound": ("arm", ("cli",), True, "research"),
    "leonidas": ("arm", ("cli",), True, "research"),
    "m365pwned": ("arm", ("cli",), True, "research"),
    "numasec": ("arm", ("cli",), True, "research"),
    "pentestkit": ("arm", ("cli",), True, "research"),
    "rubeus": ("arm", ("cli",), True, "research"),
    "security-detections-mcp": ("arm", ("cli",), True, "research"),
    "specterops-skills": ("arm", ("cli",), True, "research"),
    "vulnify": ("arm", ("cli",), True, "research"),
}

# Explicit imports are intentionally named rather than discovered by walking
# ``extension.arms``.  Each policy is an independent action-input authority.
PR97_POLICY_MODULES: Mapping[str, str] = {
    "security-detections-mcp": "extension.arms.security_detections_mcp.policy",
    "agentseal": "extension.arms.agentseal.policy",
    "vulnify": "extension.arms.vulnify.policy",
    "leonidas": "extension.arms.leonidas.policy",
    "specterops-skills": "extension.arms.specterops_skills.policy",
    "detection-in-the-cloud": "extension.arms.detection_in_the_cloud.policy",
    "pentestkit": "extension.arms.pentestkit.policy",
    "collinear": "extension.arms.collinear.policy",
    "ad-pathfinder": "extension.arms.ad_pathfinder.policy",
    "gpohound": "extension.arms.gpohound.policy",
    "claude-ad": "extension.arms.claude_ad.policy",
    "numasec": "extension.arms.numasec.policy",
    "rubeus": "extension.arms.rubeus.policy",
    "m365pwned": "extension.arms.m365pwned.policy",
}

# This is deliberately an independent, literal admission anchor.  It must not
# be derived from the register it validates: removal or narrowing of a reader
# must produce a mismatch rather than silently redefining the expected scope.
PR97_ACTION_ARGUMENTS: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "security-detections-mcp": {
        "list_tools": (),
        "list_rules": ("index", "limit"),
        "search_rules": ("index", "limit", "query"),
        "get_rule": ("index", "rule_id"),
    },
    "agentseal": {
        "list_tools": (),
        "analyze": ("fixture", "limit", "scenario_id"),
        "list_scenarios": ("fixture", "limit"),
    },
    "vulnify": {
        "list_tools": (),
        "lookup": ("bundle_path", "cve_id", "cve_ids", "feed", "name"),
        "list_vulns": ("feed", "limit"),
    },
    "leonidas": {
        "list_tools": (),
        "technique": ("corpus", "name", "technique_id"),
        "list_techniques": ("corpus", "limit"),
    },
    "specterops-skills": {
        "list_tools": (),
        "skill": ("catalog", "name", "skill_id"),
        "list_skills": ("catalog", "category", "limit"),
    },
    "detection-in-the-cloud": {
        "list_tools": (),
        "playbook": ("name", "playbook_dir"),
        "list_playbooks": ("limit", "playbook_dir"),
        "list_rules": ("category", "limit", "playbook_dir"),
    },
    "pentestkit": {
        "list_tools": (),
        "result": ("ledger", "run_id"),
        "list_results": ("ledger", "limit", "phase"),
        "summary": ("ledger",),
    },
    "collinear": {
        "list_tools": (),
        "scenario": ("name", "scenario_id", "scenarios_file"),
        "list_scenarios": ("limit", "scenarios_file"),
        "verify": ("scenario_id", "scenarios_file", "submission"),
    },
    "ad-pathfinder": {
        "list_tools": (),
        "path": ("export", "path_id", "source", "target"),
        "list_paths": ("export", "limit"),
        "list_datasources": ("export",),
    },
    "gpohound": {
        "list_tools": (),
        "policy": ("evidence", "name", "policy_id"),
        "list_policies": ("evidence", "limit", "status"),
        "list_links": ("evidence", "gpo_id"),
    },
    "claude-ad": {
        "list_tools": (),
        "technique": ("method_file", "name", "technique_id"),
        "list_techniques": ("category", "limit", "method_file"),
        "list_prerequisites": ("method_file",),
    },
    "numasec": {
        "list_tools": (),
        "finding": ("finding_id", "ledger"),
        "list_findings": ("ledger", "limit", "status"),
        "list_transitions": ("finding_id", "ledger"),
    },
    "rubeus": {
        "list_tools": (),
        "telemetry": ("event_id", "telemetry_file"),
        "list_telemetry": ("category", "limit", "telemetry_file"),
        "list_indicators": ("indicator_type", "telemetry_file"),
    },
    "m365pwned": {
        "list_tools": (),
        "case_study": ("case_id", "cases_file", "name"),
        "list_case_studies": ("cases_file", "limit"),
        "list_permissions": ("case_id", "cases_file"),
    },
}

PR97_SOURCE_BY_ARM: Mapping[str, str] = {
    "security-detections-mcp": "R43",
    "agentseal": "R35",
    "vulnify": "R01",
    "leonidas": "R33",
    "specterops-skills": "R03",
    "detection-in-the-cloud": "R34",
    "pentestkit": "R42",
    "collinear": "R15",
    "ad-pathfinder": "R02",
    "gpohound": "R08",
    "claude-ad": "R25",
    "numasec": "R17",
    "rubeus": "R36",
    "m365pwned": "R38",
}

PR97_SOURCE_IDENTITIES: Mapping[str, tuple[str, str]] = {
    "R01": ("vulnify", "https://github.com/mez-0/vulnify/"),
    "R02": ("AD-PathFinder", "https://github.com/NetSPI/AD-PathFinder"),
    "R03": ("SpecterOps skills", "https://github.com/SpecterOps/skills"),
    "R08": ("GPOHound", "https://github.com/cogiceo/GPOHound"),
    "R15": (
        "Collinear cybersecurity simulated worlds",
        "https://blog.collinear.ai/p/cybersecurity-simulated-worlds-agi",
    ),
    "R17": ("numasec", "https://github.com/FrancescoStabile/numasec"),
    "R25": ("Claude-AD", "https://github.com/ADScanPro/Claude-AD"),
    "R33": ("Leonidas", "https://github.com/reverseclabs/leonidas"),
    "R34": ("Detection in the Cloud", "https://detectioninthe.cloud"),
    "R35": ("AgentSeal", "https://github.com/getagentseal/agentseal"),
    "R36": ("Rubeus", "https://github.com/ghostpack/rubeus"),
    "R38": ("M365Pwned", "https://github.com/OtterHacker/M365Pwned"),
    "R42": ("pentestkit", "https://github.com/lordx64/pentestkit"),
    "R43": (
        "Security-Detections-MCP",
        "https://github.com/mhaggis/security-detections-mcp",
    ),
}

PR97_SOURCE_IDS = frozenset(
    {
        "R01",
        "R02",
        "R03",
        "R08",
        "R15",
        "R17",
        "R25",
        "R33",
        "R34",
        "R35",
        "R36",
        "R38",
        "R42",
        "R43",
    }
)

PR97_CONTRACT_TEMPLATE_IDS = frozenset(
    {"policy-read-v1", "caller-file-read-v1"}
)
PR97_CONTRACT_TEMPLATES: Mapping[str, Mapping[str, Any]] = {
    "policy-read-v1": {
        "id": "policy-read-v1",
        "safety_class": "R0",
        "side_effects": ("local-read",),
        "egress": "none",
        "cleanup_required": False,
        "default_off": True,
        "synthetic_only": True,
        "timeout_ms": 30_000,
        "max_output_bytes": 1_048_576,
        "max_tool_steps": 1,
        "max_spend": None,
        "scope_mode": "static-policy-uri",
        "input_binding": "not-applicable",
        "approval_required": False,
        "limitations": (
            "policy-metadata-only",
            "catalog-presence-does-not-imply-support",
        ),
    },
    "caller-file-read-v1": {
        "id": "caller-file-read-v1",
        "safety_class": "R0",
        "side_effects": ("local-read",),
        "egress": "none",
        "cleanup_required": False,
        "default_off": True,
        "synthetic_only": False,
        "timeout_ms": 30_000,
        "max_output_bytes": 1_048_576,
        "max_tool_steps": 1,
        "max_spend": None,
        "scope_mode": "static-policy-uri",
        "input_binding": "caller-selected-unbound",
        "approval_required": False,
        "limitations": (
            "caller-selected-path-is-not-bound-in-capability-manifest-v1",
            "input-custody-and-upstream-equivalence-are-not-attested",
        ),
    },
}

PR97_CAPABILITY_IDS = frozenset(
    f"{arm_id}.{action}"
    for arm_id, actions in PR97_ACTION_ARGUMENTS.items()
    for action in actions
)

_PROFILE_SEQUENCE_FIELDS = {
    "authorized_scope",
    "touched_scope",
    "side_effects",
}
_PROFILE_FIELDS = (
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
_ENTITY_REF_RE = re.compile(r"^(module|source|runtime):[^*?\[\]]+$")


class RegisterLoadError(ValueError):
    """The register or its schema could not be parsed and validated."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader with duplicate, alias, node, and depth refusal."""

    document_label = "register"
    node_cap = MAX_DOCUMENT_NODES

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._node_count = 0
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
            raise RegisterLoadError(
                "YAML aliases and anchors are not allowed in "
                f"the {self.document_label}"
            )
        self._node_count += 1
        if self._node_count > self.node_cap:
            raise RegisterLoadError(
                f"{self.document_label} YAML exceeds the node cap"
            )
        self._depth += 1
        if self._depth > MAX_DOCUMENT_DEPTH:
            self._depth -= 1
            raise RegisterLoadError(
                f"{self.document_label} YAML exceeds the nesting-depth cap"
            )
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise RegisterLoadError(
                f"{loader.document_label} mapping key is not hashable"
            ) from exc
        if duplicate:
            raise RegisterLoadError(
                f"duplicate YAML mapping key in {loader.document_label}: {key!r}"
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


class _CoverageUniqueKeyLoader(_UniqueKeyLoader):
    """Apply the register's safe YAML rules with coverage-specific errors."""

    document_label = "coverage catalog"


class _V2UniqueKeyLoader(_UniqueKeyLoader):
    """Register v2 parsing with the larger v2-only node budget."""

    document_label = "register v2"
    node_cap = MAX_REGISTER_V2_NODES


@dataclass(frozen=True)
class _FileSnapshot:
    data: bytes
    sha256: str


@dataclass(frozen=True)
class Registry:
    """A schema-valid governance document and its source path."""

    document: Mapping[str, Any]
    path: Path
    register_sha256: str | None = None
    schema_path: Path | None = None
    schema_sha256: str | None = None
    document_sha256: str | None = None


@dataclass(frozen=True)
class Inventory:
    """Canonical snapshot of the authoritative invoke-profile registry."""

    capability_ids: tuple[str, ...]
    contract_sha256: str
    records: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class CoverageInventory:
    """Strict semantic snapshot of the shipped coverage catalog."""

    version: int
    contract_sha256: str
    records: tuple[Mapping[str, Any], ...]
    source_sha256: str | None = None


@dataclass(frozen=True, order=True)
class ValidationIssue:
    """One deterministic integrity, currentness, or completeness issue."""

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
    """Complete validation outcome; silence is never interpreted as success."""

    requested_scope: str
    register_scope: str
    register_revision: int | None
    register_sha256: str | None
    schema_sha256: str | None
    authoritative_inventory_contract_sha256: str
    coverage_contract_sha256: str
    coverage_sha256: str | None
    requirement: str
    as_of: date
    repository_complete: bool
    inventory_count: int
    governed_runtime_count: int
    source_count: int
    module_count: int
    issues: tuple[ValidationIssue, ...]

    @property
    def integrity_ok(self) -> bool:
        return not any(issue.category == "integrity" for issue in self.issues)

    @property
    def current_ok(self) -> bool:
        return self.integrity_ok and not any(
            issue.category == "currentness" for issue in self.issues
        )

    @property
    def complete_ok(self) -> bool:
        return (
            self.current_ok
            and self.repository_complete
            and not any(issue.category == "completeness" for issue in self.issues)
        )

    @property
    def ok(self) -> bool:
        if self.requirement == "integrity":
            return self.integrity_ok
        if self.requirement == "current":
            return self.current_ok
        if self.requirement == "complete":
            return self.complete_ok
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "specaudit.ctf.governance.validation-report.v1",
            "requested_scope": self.requested_scope,
            "register_scope": self.register_scope,
            "register_revision": self.register_revision,
            "register_sha256": self.register_sha256,
            "schema_sha256": self.schema_sha256,
            "authoritative_inventory_contract_sha256": (
                self.authoritative_inventory_contract_sha256
            ),
            "coverage_contract_sha256": self.coverage_contract_sha256,
            "coverage_sha256": self.coverage_sha256,
            "requirement": self.requirement,
            "as_of": self.as_of.isoformat(),
            "ok": self.ok,
            "integrity_ok": self.integrity_ok,
            "current_ok": self.current_ok,
            "complete_ok": self.complete_ok,
            "repository_complete": self.repository_complete,
            "counts": {
                "inventory_capabilities": self.inventory_count,
                "governed_runtime_records": self.governed_runtime_count,
                "sources": self.source_count,
                "modules": self.module_count,
                "issues": len(self.issues),
            },
            "issues": [issue.as_dict() for issue in self.issues],
        }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _strict_json_equal(left: Any, right: Any) -> bool:
    """Compare JSON-like values without Python's bool/int/float equivalence."""

    try:
        return _canonical_json(left) == _canonical_json(right)
    except (TypeError, ValueError):
        return False


def _profile_record(profile: Any) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for field in _PROFILE_FIELDS:
        value = getattr(profile, field)
        if field in _PROFILE_SEQUENCE_FIELDS:
            value = sorted(value)
        record[field] = value
    return record


def snapshot_invoke_profiles(profiles: Mapping[str, Any]) -> Inventory:
    """Build a stable semantic snapshot of ``INVOKE_PROFILES``.

    The expected snapshot lives in the versioned register.  The actual snapshot
    is always recomputed from the independently authoritative profile mapping.
    """

    # Bind the serializer to the authoritative type itself. A newly added
    # authorization/egress field must stop the check until this explicit
    # snapshot contract and the stored digest are deliberately updated.
    from extension.invoke_profiles import InvokeProfile

    declared_fields = tuple(field.name for field in fields(InvokeProfile))
    if declared_fields != _PROFILE_FIELDS:
        raise ValueError(
            "InvokeProfile field roster differs from the governance snapshot: "
            f"declared={declared_fields!r}, snapshotted={_PROFILE_FIELDS!r}"
        )

    records: dict[str, Mapping[str, Any]] = {}
    for capability_id in sorted(profiles):
        profile = profiles[capability_id]
        if type(profile) is not InvokeProfile:
            raise ValueError(
                f"{capability_id!r} is not an exact InvokeProfile instance"
            )
        record = _profile_record(profile)
        if record["capability_id"] != capability_id:
            # Preserve the mismatch in the digest and expose the actual key so a
            # malformed mapping cannot collapse two records silently.
            record = {"registry_key": capability_id, **record}
        records[capability_id] = record
    ids = tuple(records)
    snapshot = [records[capability_id] for capability_id in ids]
    return Inventory(ids, _sha256(snapshot), records)


def snapshot_coverage_catalog(
    document: Mapping[str, Any], *, source_sha256: str | None = None
) -> CoverageInventory:
    """Freeze a parsed coverage document without normalizing its row values."""

    if type(document) is not dict:
        raise ValueError("coverage catalog must be an exact mapping")
    version = document.get("version")
    rows = document.get("entries")
    if type(version) is not int:
        raise ValueError("coverage catalog version must be an exact integer")
    if type(rows) is not list:
        raise ValueError("coverage catalog entries must be an exact list")
    if not all(type(row) is dict for row in rows):
        raise ValueError("coverage catalog entries must be exact mappings")
    snapshot = {"version": version, "entries": copy.deepcopy(rows)}
    return CoverageInventory(
        version=version,
        contract_sha256=_sha256(snapshot),
        records=tuple(snapshot["entries"]),
        source_sha256=source_sha256,
    )


def _read_file_snapshot(path: Path, *, label: str, max_bytes: int) -> _FileSnapshot:
    """Read one bounded regular final path through a stable no-follow fd."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags |= nofollow
    try:
        initial_path_stat = os.lstat(path)
        if stat.S_ISLNK(initial_path_stat.st_mode):
            raise RegisterLoadError(f"{label} must not be a symlink: {path}")
        if not stat.S_ISREG(initial_path_stat.st_mode):
            raise RegisterLoadError(f"{label} must be a regular file: {path}")
        fd = os.open(path, flags)
    except RegisterLoadError:
        raise
    except OSError as exc:
        raise RegisterLoadError(f"cannot open {label} {path}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise RegisterLoadError(f"{label} must be a regular file: {path}")
        if (before.st_dev, before.st_ino) != (
            initial_path_stat.st_dev,
            initial_path_stat.st_ino,
        ):
            raise RegisterLoadError(f"{label} path changed while opening: {path}")
        if before.st_size > max_bytes:
            raise RegisterLoadError(
                f"{label} exceeds the {max_bytes}-byte input cap: {path}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65_536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise RegisterLoadError(
                    f"{label} exceeds the {max_bytes}-byte input cap: {path}"
                )
        after = os.fstat(fd)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or total != after.st_size:
            raise RegisterLoadError(f"{label} changed while being read: {path}")
    except OSError as exc:
        raise RegisterLoadError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        os.close(fd)
    data = b"".join(chunks)
    return _FileSnapshot(
        data=data,
        sha256="sha256:" + hashlib.sha256(data).hexdigest(),
    )


def _strict_utf8(data: bytes, *, label: str) -> str:
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RegisterLoadError(f"{label} must be strict UTF-8: {exc}") from exc


def _validate_bounded_tree(
    value: Any,
    *,
    label: str,
    max_nodes: int = MAX_DOCUMENT_NODES,
    max_total_string_bytes: int = MAX_TOTAL_STRING_BYTES,
) -> None:
    nodes = 0
    total_string_bytes = 0

    def visit(item: Any, depth: int, path: str) -> None:
        nonlocal nodes, total_string_bytes
        nodes += 1
        if nodes > max_nodes:
            raise RegisterLoadError(f"{label} exceeds the node cap")
        if depth > MAX_DOCUMENT_DEPTH:
            raise RegisterLoadError(f"{label} exceeds the nesting-depth cap")
        if isinstance(item, str):
            try:
                encoded = item.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise RegisterLoadError(
                    f"{label} contains an invalid Unicode scalar at {path}"
                ) from exc
            if len(encoded) > MAX_STRING_BYTES:
                raise RegisterLoadError(
                    f"{label} string exceeds the {MAX_STRING_BYTES}-byte cap at {path}"
                )
            total_string_bytes += len(encoded)
            if total_string_bytes > max_total_string_bytes:
                raise RegisterLoadError(f"{label} exceeds the total string-byte cap")
            for character in item:
                if unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
                    raise RegisterLoadError(
                        f"{label} contains a control, format, or surrogate "
                        f"character at {path}"
                    )
            return
        if isinstance(item, float) and not math.isfinite(item):
            raise RegisterLoadError(f"{label} contains a non-finite number at {path}")
        if isinstance(item, Mapping):
            for key, child in item.items():
                visit(key, depth + 1, f"{path}.<key>")
                visit(child, depth + 1, f"{path}.{key}")
            return
        if isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                visit(child, depth + 1, f"{path}[{index}]")
            return
        if item is None or isinstance(item, (bool, int, float)):
            return
        raise RegisterLoadError(
            f"{label} contains unsupported {type(item).__name__} at {path}"
        )

    try:
        visit(value, 0, "$")
    except RecursionError as exc:
        raise RegisterLoadError(f"{label} exceeds the nesting-depth cap") from exc


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegisterLoadError(f"duplicate JSON schema key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise RegisterLoadError(f"JSON schema contains non-finite number {value}")


def _reject_nonlocal_refs(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key == "$ref":
                if not isinstance(child, str) or not (
                    child == "#" or child.startswith("#/")
                ):
                    raise RegisterLoadError(
                        f"schema has non-local $ref at {child_path}: {child!r}"
                    )
            _reject_nonlocal_refs(child, path=child_path)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_nonlocal_refs(child, path=f"{path}[{index}]")


def load_coverage_inventory(
    path: Path | str = DEFAULT_COVERAGE_PATH,
    *,
    schema_path: Path | str = DEFAULT_COVERAGE_SCHEMA_PATH,
) -> CoverageInventory:
    """Load a bounded, schema-valid snapshot of ``extension/coverage.yaml``."""

    coverage_path = Path(path)
    coverage_snapshot = _read_file_snapshot(
        coverage_path, label="coverage catalog", max_bytes=MAX_COVERAGE_BYTES
    )
    raw = _strict_utf8(coverage_snapshot.data, label="coverage catalog")
    try:
        document = yaml.load(raw, Loader=_CoverageUniqueKeyLoader)
    except RegisterLoadError:
        raise
    except (RecursionError, yaml.YAMLError) as exc:
        raise RegisterLoadError(f"invalid coverage catalog YAML: {exc}") from exc
    if type(document) is not dict:
        raise RegisterLoadError("coverage catalog must be a mapping")
    _validate_bounded_tree(document, label="coverage catalog")

    schema_file = Path(schema_path)
    schema_snapshot = _read_file_snapshot(
        schema_file,
        label="coverage schema",
        max_bytes=MAX_COVERAGE_SCHEMA_BYTES,
    )
    schema_raw = _strict_utf8(schema_snapshot.data, label="coverage schema")
    try:
        schema = json.loads(
            schema_raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except RegisterLoadError:
        raise
    except (RecursionError, json.JSONDecodeError) as exc:
        raise RegisterLoadError(
            f"cannot load coverage schema {schema_file}: {exc}"
        ) from exc
    _validate_bounded_tree(schema, label="coverage schema")
    _reject_nonlocal_refs(schema)
    if schema_snapshot.sha256 != CANONICAL_COVERAGE_SCHEMA_SHA256:
        raise RegisterLoadError(
            "coverage schema does not match the canonical schema digest: "
            f"expected {CANONICAL_COVERAGE_SCHEMA_SHA256}, "
            f"got {schema_snapshot.sha256}"
        )
    try:
        jsonschema.Draft7Validator.check_schema(schema)
        validator = jsonschema.Draft7Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except jsonschema.SchemaError as exc:
        raise RegisterLoadError(f"invalid coverage schema: {exc.message}") from exc
    except Exception as exc:
        raise RegisterLoadError(
            "coverage schema validation failed closed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        raise RegisterLoadError(
            f"coverage schema error at {location}: {error.message}"
        )
    try:
        return snapshot_coverage_catalog(
            document, source_sha256=coverage_snapshot.sha256
        )
    except ValueError as exc:
        raise RegisterLoadError(str(exc)) from exc


def load_register(
    path: Path | str = DEFAULT_REGISTER_PATH,
    *,
    schema_path: Path | str = DEFAULT_SCHEMA_PATH,
) -> Registry:
    """Load bounded snapshots and validate the closed v1 schema offline."""

    register_path = Path(path)
    schema_file = Path(schema_path)
    register_snapshot = _read_file_snapshot(
        register_path, label="register", max_bytes=MAX_REGISTER_BYTES
    )
    raw = _strict_utf8(register_snapshot.data, label="register")
    try:
        document = yaml.load(raw, Loader=_UniqueKeyLoader)
    except RegisterLoadError:
        raise
    except (RecursionError, yaml.YAMLError) as exc:
        raise RegisterLoadError(f"invalid register YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise RegisterLoadError("register must be a mapping")
    _validate_bounded_tree(document, label="register")

    schema_snapshot = _read_file_snapshot(
        schema_file, label="register schema", max_bytes=MAX_SCHEMA_BYTES
    )
    schema_raw = _strict_utf8(schema_snapshot.data, label="register schema")
    try:
        schema = json.loads(
            schema_raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except RegisterLoadError:
        raise
    except (RecursionError, json.JSONDecodeError) as exc:
        raise RegisterLoadError(f"cannot load register schema {schema_file}: {exc}") from exc
    _validate_bounded_tree(schema, label="register schema")
    _reject_nonlocal_refs(schema)
    if schema_snapshot.sha256 != CANONICAL_SCHEMA_SHA256:
        raise RegisterLoadError(
            "register schema does not match the canonical v1 schema digest: "
            f"expected {CANONICAL_SCHEMA_SHA256}, got {schema_snapshot.sha256}"
        )
    try:
        jsonschema.Draft7Validator.check_schema(schema)
        validator = jsonschema.Draft7Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except jsonschema.SchemaError as exc:
        raise RegisterLoadError(f"invalid register schema: {exc.message}") from exc
    except Exception as exc:
        raise RegisterLoadError(
            f"register schema validation failed closed: {type(exc).__name__}: {exc}"
        ) from exc
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        raise RegisterLoadError(f"register schema error at {location}: {error.message}")
    return Registry(
        copy.deepcopy(document),
        register_path,
        register_sha256=register_snapshot.sha256,
        schema_path=schema_file,
        schema_sha256=schema_snapshot.sha256,
        document_sha256=_sha256(document),
    )


def _parse_date(value: Any, *, path: str, issues: list[ValidationIssue]) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str) or _DATE_RE.fullmatch(value) is None:
        issues.append(
            ValidationIssue("integrity", "invalid-date", path, "must be YYYY-MM-DD")
        )
        return None
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        issues.append(
            ValidationIssue("integrity", "invalid-date", path, "must be YYYY-MM-DD")
        )
        return None


def _add(
    issues: list[ValidationIssue],
    category: str,
    code: str,
    path: str,
    message: str,
) -> None:
    issues.append(ValidationIssue(category, code, path, message))


def _index_unique(
    rows: Sequence[Mapping[str, Any]],
    *,
    name: str,
    issues: list[ValidationIssue],
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for position, row in enumerate(rows):
        row_id = row["id"]
        if row_id in indexed:
            _add(
                issues,
                "integrity",
                "duplicate-id",
                f"{name}[{position}].id",
                f"duplicate {name} id {row_id}",
            )
        else:
            indexed[row_id] = row
    return indexed


def _contract_signature(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": contract["id"],
        "safety_class": contract["safety_class"],
        "side_effects": tuple(contract["side_effects"]),
        "egress": contract["egress"],
        "cleanup_required": contract["cleanup_required"],
        "default_off": contract["default_off"],
        "synthetic_only": contract["synthetic_only"],
        "timeout_ms": contract["timeout_ms"],
        "max_output_bytes": contract["max_output_bytes"],
        "max_tool_steps": contract["max_tool_steps"],
        "max_spend": contract["max_spend"],
        "scope_mode": contract["scope_mode"],
        "input_binding": contract["input_binding"],
        "approval_required": contract["approval_required"],
        "limitations": tuple(contract["limitations"]),
    }


def _load_policy_action_arguments(
    issues: list[ValidationIssue],
) -> tuple[
    dict[str, dict[str, tuple[str, ...]]],
    dict[str, tuple[tuple[str, ...], str]],
]:
    result: dict[str, dict[str, tuple[str, ...]]] = {}
    discovery_metadata: dict[str, tuple[tuple[str, ...], str]] = {}
    for arm_id in sorted(PR97_ARM_IDS):
        module_name = PR97_POLICY_MODULES.get(arm_id)
        if module_name is None:
            _add(
                issues,
                "integrity",
                "policy-anchor-missing",
                f"policy:{arm_id}",
                "no explicit authoritative policy module is bound for this PR97 arm",
            )
            continue
        try:
            module = importlib.import_module(module_name)
            policy_path = f"policy:{arm_id}"
            declared_arm_id = getattr(module, "ARM_ID", None)
            if type(declared_arm_id) is not str or declared_arm_id != arm_id:
                _add(
                    issues,
                    "integrity",
                    "policy-arm-id-mismatch",
                    policy_path,
                    f"ARM_ID must be the exact built-in string {arm_id!r}",
                )

            raw = getattr(module, "ARG_KEYS", None)
            args_valid = type(raw) is dict
            normalized: dict[str, tuple[str, ...]] = {}
            if args_valid:
                for action, keys in raw.items():
                    if (
                        type(action) is not str
                        or not action
                        or type(keys) is not frozenset
                        or not all(type(key) is str and key for key in keys)
                    ):
                        args_valid = False
                        break
                    normalized[action] = tuple(sorted(keys))
            if not args_valid:
                normalized = {}
                _add(
                    issues,
                    "integrity",
                    "policy-arg-keys-invalid",
                    policy_path,
                    "ARG_KEYS must be an exact dict from nonempty built-in strings "
                    "to frozensets of nonempty built-in strings",
                )

            raw_allowed = getattr(module, "ALLOWED_ACTIONS", None)
            allowed_valid = type(raw_allowed) is frozenset and all(
                type(action) is str and action for action in raw_allowed
            )
            if not allowed_valid:
                _add(
                    issues,
                    "integrity",
                    "policy-allowed-actions-invalid",
                    policy_path,
                    "ALLOWED_ACTIONS must be a frozenset of nonempty built-in strings",
                )

            expected_actions = PR97_ACTION_ARGUMENTS.get(arm_id, {})
            expected_data_actions = {
                action: keys
                for action, keys in expected_actions.items()
                if action != "list_tools"
            }
            if normalized != expected_data_actions:
                _add(
                    issues,
                    "integrity",
                    "policy-action-surface-mismatch",
                    policy_path,
                    "ARG_KEYS does not match the independently frozen PR97 data-action surface",
                )
            if allowed_valid and raw_allowed != frozenset(expected_data_actions):
                _add(
                    issues,
                    "integrity",
                    "policy-allowed-action-surface-mismatch",
                    policy_path,
                    "ALLOWED_ACTIONS does not match the independently frozen PR97 data actions",
                )
            if allowed_valid and args_valid and set(normalized) != set(raw_allowed):
                _add(
                    issues,
                    "integrity",
                    "policy-allowed-action-surface-mismatch",
                    policy_path,
                    "ALLOWED_ACTIONS and ARG_KEYS must name the same data actions",
                )

            raw_list_actions = getattr(module, "LIST_ACTIONS", None)
            list_actions_valid = type(raw_list_actions) is frozenset and all(
                type(action) is str and action for action in raw_list_actions
            )
            if not list_actions_valid:
                _add(
                    issues,
                    "integrity",
                    "policy-list-actions-invalid",
                    policy_path,
                    "LIST_ACTIONS must be a frozenset of nonempty built-in strings",
                )
            elif raw_list_actions != PR97_LIST_ACTIONS:
                _add(
                    issues,
                    "integrity",
                    "policy-list-action-surface-mismatch",
                    policy_path,
                    "LIST_ACTIONS must remain exactly ['list_tools', 'tools/list']",
                )
            else:
                # The governed zero-argument capability exists only when the
                # imported policy proves the exact primary action and alias.
                normalized["list_tools"] = ()

            caveats = getattr(module, "CAVEATS", None)
            caveats_valid = (
                type(caveats) is tuple
                and caveats
                and all(type(item) is str and item.strip() for item in caveats)
            )
            if not caveats_valid:
                _add(
                    issues,
                    "integrity",
                    "policy-caveats-invalid",
                    policy_path,
                    "CAVEATS must be a nonempty tuple of nonempty built-in strings",
                )
            arming = getattr(module, "ARMING", None)
            arming_valid = type(arming) is str and bool(arming.strip())
            if not arming_valid:
                _add(
                    issues,
                    "integrity",
                    "policy-arming-invalid",
                    policy_path,
                    "ARMING must be a nonempty built-in string",
                )
            if caveats_valid and arming_valid:
                discovery_metadata[arm_id] = (caveats, arming)
            result[arm_id] = normalized
        except SystemExit as exc:
            raise RegisterLoadError(
                f"cannot read {module_name} action policy: "
                f"SystemExit({exc.code!r})"
            ) from exc
        except Exception as exc:
            _add(
                issues,
                "integrity",
                "policy-action-surface-unreadable",
                f"policy:{arm_id}",
                f"cannot read {module_name} action policy: "
                f"{type(exc).__name__}: {exc}",
            )
    return result, discovery_metadata


def _handler_zero_argument_source_contract(handler: Any) -> tuple[bool, str]:
    """Prove the common list-action routing and truthy-payload refusal shape."""

    def parse_method(method: Any, name: str) -> tuple[ast.FunctionDef | None, str]:
        try:
            source = inspect.getsource(method)
            tree = ast.parse(textwrap.dedent(source))
        except (Exception, SystemExit) as exc:
            return None, f"{name} source is unreadable: {type(exc).__name__}: {exc}"
        if len(tree.body) != 1 or type(tree.body[0]) is not ast.FunctionDef:
            return None, f"{name} source is not one function definition"
        function = tree.body[0]
        if function.decorator_list:
            return None, f"{name} must not be wrapped by a decorator"
        return function, ""

    def exact_arguments(function: ast.FunctionDef, expected: tuple[str, ...]) -> bool:
        arguments = function.args
        return (
            tuple(arg.arg for arg in arguments.posonlyargs + arguments.args)
            == expected
            and not arguments.kwonlyargs
            and arguments.vararg is None
            and arguments.kwarg is None
            and not arguments.defaults
            and not arguments.kw_defaults
        )

    def name(node: ast.AST, expected: str) -> bool:
        return type(node) is ast.Name and node.id == expected

    def attribute(node: ast.AST, base: str, expected: str) -> bool:
        return (
            type(node) is ast.Attribute
            and node.attr == expected
            and name(node.value, base)
        )

    invoke_method = getattr(handler, "invoke", None)
    invoke_function = getattr(invoke_method, "__func__", invoke_method)
    invoke_code = getattr(invoke_function, "__code__", None)
    if invoke_code is None or invoke_code.co_freevars:
        return False, "invoke must be a closure-free module-level method"
    invoke_globals = getattr(invoke_function, "__globals__", None)
    if type(invoke_globals) is not dict:
        return False, "invoke globals are unavailable"
    if invoke_globals.get("dict", builtins.dict) is not builtins.dict:
        return False, "invoke's dict name does not resolve to builtins.dict"
    invoke_builtins = getattr(invoke_function, "__builtins__", None)
    if (
        type(invoke_builtins) is not dict
        or invoke_builtins.get("dict") is not builtins.dict
    ):
        return False, "invoke's builtins do not bind the canonical dict"
    handler_list_actions = invoke_globals.get("LIST_ACTIONS")
    if (
        type(handler_list_actions) is not frozenset
        or handler_list_actions != PR97_LIST_ACTIONS
    ):
        return False, "invoke's LIST_ACTIONS does not match the frozen aliases"

    list_method_object = getattr(handler, "_list_tools", None)
    list_function = getattr(list_method_object, "__func__", list_method_object)
    list_code = getattr(list_function, "__code__", None)
    if list_code is None or list_code.co_freevars:
        return False, "_list_tools must be a closure-free module-level method"

    invoke, problem = parse_method(invoke_method, "invoke")
    if invoke is None:
        return False, problem
    list_method, problem = parse_method(list_method_object, "_list_tools")
    if list_method is None:
        return False, problem
    if not exact_arguments(invoke, ("self", "spec", "action", "args")):
        return False, "invoke has a noncanonical argument contract"
    if not exact_arguments(
        list_method, ("self", "spec", "action", "payload")
    ):
        return False, "_list_tools has a noncanonical argument contract"
    if len(invoke.body) < 3:
        return False, "invoke is missing the canonical list-action routing prefix"

    spec_gate = invoke.body[0]
    valid_spec_gate = (
        type(spec_gate) is ast.If
        and type(spec_gate.test) is ast.Compare
        and attribute(spec_gate.test.left, "spec", "id")
        and len(spec_gate.test.ops) == 1
        and type(spec_gate.test.ops[0]) is ast.NotEq
        and len(spec_gate.test.comparators) == 1
        and name(spec_gate.test.comparators[0], "ARM_ID")
        and len(spec_gate.body) == 1
        and type(spec_gate.body[0]) is ast.Raise
        and not spec_gate.orelse
    )
    if not valid_spec_gate:
        return False, "invoke must begin with the canonical arm-id refusal"

    payload_assignment = invoke.body[1]
    valid_payload_assignment = (
        type(payload_assignment) is ast.Assign
        and len(payload_assignment.targets) == 1
        and name(payload_assignment.targets[0], "payload")
        and type(payload_assignment.value) is ast.Call
        and name(payload_assignment.value.func, "dict")
        and len(payload_assignment.value.args) == 1
        and name(payload_assignment.value.args[0], "args")
        and not payload_assignment.value.keywords
    )
    if not valid_payload_assignment:
        return False, "invoke must copy args directly into a built-in payload"

    list_gate = invoke.body[2]
    valid_list_gate = (
        type(list_gate) is ast.If
        and type(list_gate.test) is ast.Compare
        and name(list_gate.test.left, "action")
        and len(list_gate.test.ops) == 1
        and type(list_gate.test.ops[0]) is ast.In
        and len(list_gate.test.comparators) == 1
        and name(list_gate.test.comparators[0], "LIST_ACTIONS")
        and len(list_gate.body) == 1
        and type(list_gate.body[0]) is ast.Return
        and type(list_gate.body[0].value) is ast.Call
        and attribute(list_gate.body[0].value.func, "self", "_list_tools")
        and len(list_gate.body[0].value.args) == 3
        and name(list_gate.body[0].value.args[0], "spec")
        and name(list_gate.body[0].value.args[1], "action")
        and name(list_gate.body[0].value.args[2], "payload")
        and not list_gate.body[0].value.keywords
        and not list_gate.orelse
    )
    if not valid_list_gate:
        return False, "invoke must route LIST_ACTIONS directly to _list_tools"

    if not list_method.body:
        return False, "_list_tools has no payload refusal"
    payload_gate = list_method.body[0]
    valid_payload_gate = (
        type(payload_gate) is ast.If
        and name(payload_gate.test, "payload")
        and len(payload_gate.body) == 1
        and type(payload_gate.body[0]) is ast.Return
        and type(payload_gate.body[0].value) is ast.Call
        and name(payload_gate.body[0].value.func, "_fail")
        and len(payload_gate.body[0].value.args) == 3
        and name(payload_gate.body[0].value.args[0], "spec")
        and name(payload_gate.body[0].value.args[1], "action")
        and type(payload_gate.body[0].value.args[2]) is ast.Constant
        and type(payload_gate.body[0].value.args[2].value) is str
        and bool(payload_gate.body[0].value.args[2].value.strip())
        and not payload_gate.body[0].value.keywords
        and not payload_gate.orelse
    )
    if not valid_payload_gate:
        return False, "_list_tools must first refuse every truthy payload via _fail"
    return True, ""


def _check_pr97_handler_list_actions(
    issues: list[ValidationIssue],
    policy_discovery_metadata: Mapping[str, tuple[tuple[str, ...], str]],
) -> None:
    """Exercise both discovery routes and their zero-argument contract."""

    try:
        from extension.contract import ArmSpec, Result, _default_arms

        handlers = _default_arms()
    except (Exception, SystemExit) as exc:
        _add(
            issues,
            "integrity",
            "handler-registry-unreadable",
            "handlers:pr97-readers",
            "cannot construct the runtime handler registry: "
            f"{type(exc).__name__}: {exc}",
        )
        return

    for arm_id in sorted(PR97_ARM_IDS):
        handler = handlers.get(arm_id)
        handler_path = f"handler:{arm_id}"
        if handler is None:
            _add(
                issues,
                "integrity",
                "handler-missing",
                handler_path,
                "the runtime handler registry has no PR97 specialized handler",
            )
            continue
        expected_actions = PR97_ACTION_ARGUMENTS.get(arm_id)
        if not isinstance(expected_actions, Mapping):
            continue
        expected_arg_keys = {
            action: list(keys)
            for action, keys in sorted(expected_actions.items())
            if action != "list_tools"
        }
        expected_read_actions = sorted(
            set(expected_arg_keys) | set(PR97_LIST_ACTIONS)
        )
        expected_metadata = policy_discovery_metadata.get(arm_id)
        spec = ArmSpec(
            id=arm_id,
            protocols=("cli",),
            curated=True,
            notes="governance integrity probe",
            tier="research",
        )
        try:
            installed = handler.installed(spec)
        except (Exception, SystemExit) as exc:
            _add(
                issues,
                "integrity",
                "handler-install-probe-unreadable",
                handler_path,
                "specialized-handler selection probe raised: "
                f"{type(exc).__name__}: {exc}",
            )
            continue
        if installed is not True:
            _add(
                issues,
                "integrity",
                "handler-not-selectable",
                handler_path,
                "the public extension path would not select this PR97 handler",
            )
            continue
        source_contract_ok, source_contract_problem = (
            _handler_zero_argument_source_contract(handler)
        )
        if not source_contract_ok:
            _add(
                issues,
                "integrity",
                "handler-list-zero-argument-source-mismatch",
                handler_path,
                source_contract_problem,
            )
        outputs: dict[str, Any] = {}
        for action in sorted(PR97_LIST_ACTIONS):
            action_path = f"{handler_path}.{action}"
            try:
                refusal = handler.invoke(spec, action, {"unexpected": True})
            except (Exception, SystemExit) as exc:
                _add(
                    issues,
                    "integrity",
                    "handler-list-argument-refusal-unreadable",
                    action_path,
                    "nonempty-argument discovery probe raised instead of "
                    "returning a refusal: "
                    f"{type(exc).__name__}: {exc}",
                )
            else:
                valid_refusal = (
                    type(refusal) is Result
                    and refusal.ok is False
                    and type(refusal.arm_id) is str
                    and refusal.arm_id == arm_id
                    and type(refusal.action) is str
                    and refusal.action == action
                    and refusal.output is None
                    and type(refusal.error) is str
                    and bool(refusal.error.strip())
                )
                if not valid_refusal:
                    _add(
                        issues,
                        "integrity",
                        "handler-list-argument-refusal-mismatch",
                        action_path,
                        "zero-argument discovery route accepted or silently "
                        "ignored caller arguments",
                    )
            try:
                result = handler.invoke(spec, action, {})
            except (Exception, SystemExit) as exc:
                _add(
                    issues,
                    "integrity",
                    "handler-list-action-unreadable",
                    action_path,
                    "zero-argument discovery raised instead of returning a result: "
                    f"{type(exc).__name__}: {exc}",
                )
                continue
            valid_result = (
                type(result) is Result
                and result.ok is True
                and type(result.arm_id) is str
                and result.arm_id == arm_id
                and type(result.action) is str
                and result.action == action
                and result.error is None
                and type(result.output) is dict
            )
            if not valid_result:
                _add(
                    issues,
                    "integrity",
                    "handler-list-action-mismatch",
                    action_path,
                    "runtime handler did not return an exact successful discovery result",
                )
                continue
            output = result.output
            extra_keys = PR97_DISCOVERY_EXTRA_KEYS.get(arm_id, ())
            valid_output_shape = set(output) == {
                "read_actions",
                "dispatch_actions",
                "arg_keys",
                "caveats",
                "arming",
                *extra_keys,
            }
            valid_extra_keys = all(
                type(output[key]) is str and bool(output[key].strip())
                for key in extra_keys
            )
            valid_read_actions = (
                type(output.get("read_actions")) is list
                and all(
                    type(value) is str for value in output["read_actions"]
                )
                and output["read_actions"] == expected_read_actions
            )
            valid_dispatch_actions = (
                type(output.get("dispatch_actions")) is list
                and output["dispatch_actions"] == []
            )
            arg_keys = output.get("arg_keys")
            valid_arg_keys = (
                type(arg_keys) is dict
                and all(
                    type(key) is str
                    and type(values) is list
                    and all(type(value) is str for value in values)
                    for key, values in arg_keys.items()
                )
                and _strict_json_equal(arg_keys, expected_arg_keys)
            )
            caveats = output.get("caveats")
            valid_caveats = (
                type(caveats) is list
                and bool(caveats)
                and all(type(value) is str and value.strip() for value in caveats)
                and (
                    expected_metadata is None
                    or _strict_json_equal(caveats, list(expected_metadata[0]))
                )
            )
            arming = output.get("arming")
            valid_arming = (
                type(arming) is str
                and bool(arming.strip())
                and (
                    expected_metadata is None
                    or arming == expected_metadata[1]
                )
            )
            if not all(
                (
                    valid_output_shape,
                    valid_extra_keys,
                    valid_read_actions,
                    valid_dispatch_actions,
                    valid_arg_keys,
                    valid_caveats,
                    valid_arming,
                )
            ):
                _add(
                    issues,
                    "integrity",
                    "handler-list-output-mismatch",
                    action_path,
                    "runtime discovery metadata does not match the frozen PR97 "
                    "read surface",
                )
                continue
            outputs[action] = output
        if set(outputs) == set(PR97_LIST_ACTIONS) and not _strict_json_equal(
            outputs["list_tools"], outputs["tools/list"]
        ):
            _add(
                issues,
                "integrity",
                "handler-list-alias-divergence",
                handler_path,
                "list_tools and tools/list returned different discovery metadata",
            )


def _check_pr97_coverage(
    coverage: CoverageInventory,
    runtime: Mapping[str, Mapping[str, Any]],
    inventory: Inventory,
    issues: list[ValidationIssue],
) -> None:
    """Reconcile frozen PR97 facts across catalog and runtime surfaces."""

    coverage_path = "coverage:pr97-readers"
    if type(coverage.version) is not int or coverage.version != 1:
        _add(
            issues,
            "integrity",
            "coverage-version-mismatch",
            f"{coverage_path}.version",
            "the PR97 coverage catalog must use exact integer version 1",
        )

    try:
        coverage_records = list(coverage.records)
        observed_digest = _sha256(
            {"version": coverage.version, "entries": coverage_records}
        )
    except (TypeError, ValueError) as exc:
        coverage_records = []
        observed_digest = None
        _add(
            issues,
            "integrity",
            "coverage-snapshot-invalid",
            coverage_path,
            "cannot recompute the coverage snapshot: "
            f"{type(exc).__name__}: {exc}",
        )
    if (
        observed_digest is not None
        and observed_digest != coverage.contract_sha256
    ):
        _add(
            issues,
            "integrity",
            "coverage-snapshot-mutated",
            coverage_path,
            "coverage rows changed after their semantic snapshot",
        )

    rows_by_id: dict[str, list[Mapping[str, Any]]] = {}
    for position, row in enumerate(coverage_records):
        row_path = f"coverage.entries[{position}]"
        if type(row) is not dict:
            _add(
                issues,
                "integrity",
                "coverage-row-invalid",
                row_path,
                "coverage entries must be exact mappings",
            )
            continue
        row_id = row.get("id")
        if type(row_id) is not str or not row_id:
            _add(
                issues,
                "integrity",
                "coverage-row-id-invalid",
                f"{row_path}.id",
                "coverage entry id must be a nonempty built-in string",
            )
            continue
        rows_by_id.setdefault(row_id, []).append(row)

    for row_id, matches in sorted(rows_by_id.items()):
        if len(matches) > 1:
            _add(
                issues,
                "integrity",
                "coverage-duplicate-id",
                f"coverage:{row_id}",
                f"coverage entry id occurs {len(matches)} times",
            )

    for arm_id in sorted(PR97_COVERAGE_SIGNATURES):
        row_path = f"coverage:{arm_id}"
        matching = rows_by_id.get(arm_id, [])
        if not matching:
            _add(
                issues,
                "integrity",
                "coverage-reader-missing",
                row_path,
                "the independently frozen PR97 arm is absent from coverage.yaml",
            )
            continue
        if len(matching) != 1:
            continue
        row = matching[0]
        if set(row) != PR97_CATALOG_ROW_KEYS:
            _add(
                issues,
                "integrity",
                "coverage-reader-field-roster-mismatch",
                row_path,
                "PR97 coverage rows must contain exactly id, kind, protocols, "
                "curated, tier, and notes",
            )

        expected_kind, expected_protocols, expected_curated, expected_tier = (
            PR97_COVERAGE_SIGNATURES[arm_id]
        )
        expected_fields: Mapping[str, Any] = {
            "id": arm_id,
            "kind": expected_kind,
            "protocols": list(expected_protocols),
            "curated": expected_curated,
            "tier": expected_tier,
        }
        for field, expected in expected_fields.items():
            observed = row.get(field)
            exact_type = (
                type(observed) is list
                and all(type(item) is str for item in observed)
                if field == "protocols"
                else type(observed) is type(expected)
            )
            if not exact_type or not _strict_json_equal(observed, expected):
                _add(
                    issues,
                    "integrity",
                    f"coverage-reader-{field.replace('_', '-')}-mismatch",
                    f"{row_path}.{field}",
                    f"expected independently frozen value {expected!r}, "
                    f"got {observed!r}",
                )
        notes = row.get("notes")
        if type(notes) is not str or not notes.strip():
            _add(
                issues,
                "integrity",
                "coverage-reader-notes-invalid",
                f"{row_path}.notes",
                "notes must be a nonempty built-in string",
            )

        coverage_tier = row.get("tier")
        expected_actions = PR97_ACTION_ARGUMENTS.get(arm_id)
        if not isinstance(expected_actions, Mapping):
            continue
        expected_capabilities = sorted(
            f"{arm_id}.{action}" for action in expected_actions
        )
        runtime_mismatches = [
            (capability_id, runtime.get(capability_id, {}).get("support_tier"))
            for capability_id in expected_capabilities
            if not _strict_json_equal(
                runtime.get(capability_id, {}).get("support_tier"),
                coverage_tier,
            )
        ]
        if runtime_mismatches:
            _add(
                issues,
                "integrity",
                "coverage-runtime-tier-mismatch",
                f"{row_path}.tier",
                "coverage tier does not match every detailed PR97 runtime row: "
                f"coverage={coverage_tier!r}, mismatches={runtime_mismatches!r}",
            )
        profile_mismatches = [
            (capability_id, inventory.records.get(capability_id, {}).get("tier"))
            for capability_id in expected_capabilities
            if not _strict_json_equal(
                inventory.records.get(capability_id, {}).get("tier"),
                coverage_tier,
            )
        ]
        if profile_mismatches:
            _add(
                issues,
                "integrity",
                "coverage-profile-tier-mismatch",
                f"{row_path}.tier",
                "coverage tier does not match every authoritative PR97 "
                "InvokeProfile: "
                f"coverage={coverage_tier!r}, mismatches={profile_mismatches!r}",
            )


def _expected_relationship_signatures() -> dict[str, tuple[Any, ...]]:
    signatures: dict[str, tuple[Any, ...]] = {}
    for arm_id, source_id in PR97_SOURCE_BY_ARM.items():
        relationship_id = f"map-{source_id.lower()}-{arm_id}"
        targets = tuple(
            sorted(
                f"runtime:{arm_id}.{action}"
                for action in PR97_ACTION_ARGUMENTS.get(arm_id, {})
            )
        )
        signatures[relationship_id] = (
            1,
            "research-mapping",
            f"source:{source_id}",
            targets,
            ("PROGRAM.md#candidate-register-42-unique-candidates",),
            ("mapping-does-not-assert-upstream-consumption-or-provenance",),
        )
    signatures["cyb-05-proposed-source-r01"] = (
        1,
        "proposed-source",
        "module:CYB-05",
        ("source:R01",),
        ("CURRICULUM.md#t03--risk-based-vulnerability-prioritization",),
        ("source-is-unselected-and-unadmitted",),
    )
    signatures["cyb-05-proposed-use-vulnify-lookup"] = (
        1,
        "proposed-use",
        "module:CYB-05",
        ("runtime:vulnify.lookup",),
        ("PROGRAM.md#first-proposed-vertical-slice",),
        (
            "proposed-use-grants-no-execution-or-grading-authority",
            "trusted-observation-and-frozen-source-work-remain-separate",
        ),
    )
    return signatures


def _github_heading_anchors(markdown: str) -> set[str]:
    anchors: set[str] = set()
    logical_lines = (
        markdown.count("\n")
        + markdown.count("\r")
        - markdown.count("\r\n")
        + (1 if markdown and not markdown.endswith(("\n", "\r")) else 0)
    )
    if logical_lines > MAX_EVIDENCE_LINES:
        raise RegisterLoadError(
            "evidence Markdown exceeds maximum logical line count "
            f"of {MAX_EVIDENCE_LINES}"
        )
    occurrences: dict[str, int] = {}
    try:
        tokens = MarkdownIt("commonmark").parse(markdown)
    except (Exception, SystemExit) as exc:
        raise RegisterLoadError(
            f"cannot parse evidence Markdown: {type(exc).__name__}: {exc}"
        ) from exc
    for position, token in enumerate(tokens):
        if token.type != "heading_open":
            continue
        if position + 1 >= len(tokens) or tokens[position + 1].type != "inline":
            continue
        inline = tokens[position + 1]
        pieces: list[str] = []
        pending = list(reversed(inline.children or ()))
        while pending:
            child = pending.pop()
            if child.type in {"text", "text_special", "code_inline"}:
                pieces.append(child.content)
            elif child.type == "image":
                pending.extend(reversed(child.children or ()))
        title = "".join(pieces)
        unsupported = sorted(
            {
                character
                for character in title
                if ord(character) > 0x7F
                and unicodedata.category(character) != "Pd"
            }
        )
        if unsupported:
            codepoints = ", ".join(f"U+{ord(char):04X}" for char in unsupported)
            raise RegisterLoadError(
                "evidence Markdown heading contains unsupported non-ASCII "
                f"slug characters: {codepoints}"
            )
        title = "".join(
            character
            for character in title.lower()
            if "a" <= character <= "z"
            or "0" <= character <= "9"
            or character in {" ", "-", "_"}
        )
        base = title.replace(" ", "-")
        if not base:
            continue
        unique = base
        while unique in occurrences:
            occurrences[base] += 1
            unique = f"{base}-{occurrences[base]}"
        occurrences[unique] = 0
        if token.markup.startswith("#"):
            anchors.add(unique)
    return anchors


def _check_evidence_ref(
    evidence_ref: Any,
    *,
    path: str,
    cache: dict[Path, set[str] | str],
    issues: list[ValidationIssue],
) -> None:
    if not isinstance(evidence_ref, str) or evidence_ref.count("#") != 1:
        _add(
            issues,
            "integrity",
            "invalid-evidence-ref",
            path,
            "evidence reference must be repo-relative Markdown path#anchor",
        )
        return
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in evidence_ref):
        _add(
            issues,
            "integrity",
            "invalid-evidence-ref",
            path,
            "evidence reference contains a control, format, or surrogate character",
        )
        return
    relative_text, anchor = evidence_ref.split("#", 1)
    relative = PurePosixPath(relative_text)
    if (
        not relative_text
        or not anchor
        or "\\" in relative_text
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.suffix.lower() != ".md"
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", anchor) is None
    ):
        _add(
            issues,
            "integrity",
            "invalid-evidence-ref",
            path,
            "evidence reference must be a bounded repo-relative Markdown path#anchor",
        )
        return
    candidate = REPOSITORY_ROOT.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(REPOSITORY_ROOT)
        cached = cache.get(resolved)
        if isinstance(cached, str):
            raise RegisterLoadError(cached)
        anchors = cached
        if anchors is None:
            try:
                snapshot = _read_file_snapshot(
                    resolved,
                    label="evidence document",
                    max_bytes=MAX_EVIDENCE_BYTES,
                )
                anchors = _github_heading_anchors(
                    _strict_utf8(snapshot.data, label="evidence document")
                )
            except (OSError, RegisterLoadError, ValueError) as exc:
                cache[resolved] = str(exc)
                raise
            cache[resolved] = anchors
    except (OSError, RegisterLoadError, ValueError) as exc:
        _add(
            issues,
            "integrity",
            "invalid-evidence-ref",
            path,
            f"evidence document is unavailable or escapes the repository: {exc}",
        )
        return
    if anchor not in anchors:
        _add(
            issues,
            "integrity",
            "evidence-anchor-missing",
            path,
            f"heading anchor {anchor!r} does not exist in {relative_text}",
        )


def _check_promotion_test_ref(
    value: Any,
    *,
    path: str,
    code: str,
    issues: list[ValidationIssue],
) -> None:
    """Bound a promotion regression/exercised path to a real repo test file.

    This checks citation resolvability only: the file must be a bounded
    repo-relative ``tests/*.py`` file path that resolves inside the repository to
    a real regular file. Absolute paths, traversal segments, backslashes,
    symlink escapes, directories, and missing files all fail. Existence is
    never execution proof: it does not claim the test ran or covered the
    promotion.
    """

    if not isinstance(value, str):
        _add(
            issues, "integrity", code, path,
            "promotion test reference must be a string",
        )
        return
    if any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value
    ):
        _add(
            issues, "integrity", code, path,
            "promotion test reference contains a control, format, or surrogate character",
        )
        return
    # These event citations identify files. Accepting an unchecked pytest
    # selector would let a nonexistent test node masquerade as a resolved ref.
    if ":" in value:
        _add(
            issues, "integrity", code, path,
            "promotion test reference must identify a file, not a test selector or drive",
        )
        return
    file_text = value
    relative = PurePosixPath(file_text)
    if (
        not file_text
        or "\\" in file_text
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in file_text.split("/"))
        or relative.suffix.lower() != ".py"
        or len(relative.parts) < 2
        or relative.parts[0] != "tests"
    ):
        _add(
            issues, "integrity", code, path,
            "promotion test reference must be a bounded repo-relative tests/*.py path",
        )
        return
    candidate = REPOSITORY_ROOT.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(REPOSITORY_ROOT)
        if not resolved.is_file():
            raise OSError(f"not a regular file: {resolved}")
    except (OSError, ValueError, RuntimeError) as exc:
        _add(
            issues, "integrity", code, path,
            f"promotion test file is unavailable or escapes the repository: {exc}",
        )
        return


def _check_currentness(
    owner_ref: str,
    currentness: Mapping[str, Any],
    *,
    as_of: date,
    path: str,
    issues: list[ValidationIssue],
) -> None:
    reviewed = _parse_date(
        currentness["reviewed_on"], path=f"{path}.reviewed_on", issues=issues
    )
    due = _parse_date(
        currentness["review_due_on"], path=f"{path}.review_due_on", issues=issues
    )
    if (reviewed is None) != (due is None):
        _add(
            issues,
            "integrity",
            "incomplete-currentness-window",
            path,
            "reviewed_on and review_due_on must both be set or both be null",
        )
        return
    if reviewed is None:
        _add(
            issues,
            "currentness",
            "unreviewed",
            path,
            f"{owner_ref} has no completed currentness review",
        )
        return
    if reviewed > as_of:
        _add(
            issues,
            "integrity",
            "review-in-future",
            path,
            f"review date {reviewed.isoformat()} is later than as-of {as_of.isoformat()}",
        )
    if reviewed > due:
        _add(
            issues,
            "integrity",
            "inverted-currentness-window",
            path,
            "reviewed_on is later than review_due_on",
        )
    elif as_of > due:
        _add(
            issues,
            "currentness",
            "stale",
            path,
            f"review was due {due.isoformat()}",
        )
    _add(
        issues,
        "currentness",
        "drift-triggers-unverified",
        path,
        "v1 records review triggers but binds no observations proving they did not fire",
    )


def _profile_digest(record: Mapping[str, Any]) -> str:
    return _sha256(record)


def _contract_digest(contract: Mapping[str, Any]) -> str:
    return _sha256(contract)


def _governance_subject_digest(row: Mapping[str, Any]) -> str:
    """Bind record content without creating a promotion-reference hash cycle."""

    return _sha256(
        {key: value for key, value in row.items() if key != "promotion_evidence"}
    )


def _source_contract_digest(row: Mapping[str, Any]) -> str:
    return _sha256(
        {
            "selected_revision": row["selected_revision"],
            "content_digests": row["content_digests"],
            "rights": row["rights"],
            "currentness": row["currentness"],
            "replacement": row["replacement"],
            "limitations": row["limitations"],
        }
    )


def _module_contract_digest(row: Mapping[str, Any]) -> str:
    return _sha256(
        {
            "outcomes": row["outcomes"],
            "dependencies": row["dependencies"],
            "deliverables": row["deliverables"],
            "validation_evidence": row["validation_evidence"],
            "currentness": row["currentness"],
            "limitations": row["limitations"],
        }
    )


def _check_generic_promotion_refs(
    *,
    subject_ref: str,
    row: Mapping[str, Any],
    target_status: str,
    contract_digest: str,
    events: Mapping[str, Mapping[str, Any]],
    referenced_events: set[str],
    issues: list[ValidationIssue],
) -> None:
    """Require every attached event to bind this exact record and target."""

    if row["promotion_evidence"]:
        _add(
            issues,
            "integrity",
            "promotion-verifier-unimplemented",
            subject_ref,
            "v1 cannot verify promotion evidence or authorize a promotion",
        )
    for evidence_ref in row["promotion_evidence"]:
        event = events.get(evidence_ref)
        if event is None:
            _add(
                issues,
                "integrity",
                "unknown-promotion-evidence",
                subject_ref,
                f"unknown promotion event {evidence_ref}",
            )
            continue
        referenced_events.add(evidence_ref)
        if event["subject"] != subject_ref:
            _add(
                issues,
                "integrity",
                "promotion-subject-mismatch",
                subject_ref,
                f"event {evidence_ref} is bound to {event['subject']}",
            )
        if event["to_status"] != target_status:
            _add(
                issues,
                "integrity",
                "promotion-target-mismatch",
                subject_ref,
                f"event {evidence_ref} targets {event['to_status']}, not {target_status}",
            )
        if event["from_status"] == event["to_status"]:
            _add(
                issues,
                "integrity",
                "promotion-no-transition",
                subject_ref,
                f"event {evidence_ref} does not change status",
            )
        if event["subject_digest"] != _governance_subject_digest(row):
            _add(
                issues,
                "integrity",
                "promotion-subject-digest-mismatch",
                subject_ref,
                f"event {evidence_ref} does not bind the current governance record",
            )
        if event["contract_digest"] != contract_digest:
            _add(
                issues,
                "integrity",
                "promotion-contract-digest-mismatch",
                subject_ref,
                f"event {evidence_ref} does not bind the current governance contract",
            )
        if tuple(event["limitations_accepted"]) != tuple(row["limitations"]):
            _add(
                issues,
                "integrity",
                "promotion-limitations-mismatch",
                subject_ref,
                f"event {evidence_ref} does not accept the exact limitation set",
            )


def validate_register(
    registry: Registry | Mapping[str, Any],
    inventory: Inventory,
    coverage: CoverageInventory | None = None,
    *,
    as_of: date,
    scope: str = FULL_SCOPE_ID,
    require: str = "complete",
) -> ValidationReport:
    """Validate referential, profile, promotion, and currentness semantics.

    Schema validation belongs to :func:`load_register`.  This function accepts
    a raw mapping as a testing convenience, but still fails closed on semantic
    mismatches and never mutates its input.  Omitting ``coverage`` preserves the
    original package call shape by loading the strict canonical catalog.
    """

    if scope not in (PR97_SCOPE_ID, FULL_SCOPE_ID):
        raise ValueError(f"unknown scope: {scope}")
    if require not in REQUIREMENTS:
        raise ValueError(f"unknown requirement: {require}")
    if coverage is None:
        coverage = load_coverage_inventory()
    loaded_registry = registry if isinstance(registry, Registry) else None
    document = loaded_registry.document if loaded_registry is not None else registry
    if (
        loaded_registry is not None
        and loaded_registry.document_sha256 is not None
        and _sha256(document) != loaded_registry.document_sha256
    ):
        raise ValueError("loaded register document changed after its byte snapshot")
    issues: list[ValidationIssue] = []
    register_scope = document["scope"]["id"]
    register_revision = document.get("register_revision")
    observed_top_level_keys = set(document)
    if observed_top_level_keys != REGISTER_TOP_LEVEL_KEYS:
        _add(
            issues,
            "integrity",
            "register-top-level-shape-mismatch",
            "$",
            f"missing={sorted(REGISTER_TOP_LEVEL_KEYS - observed_top_level_keys)!r}; "
            f"added={sorted(observed_top_level_keys - REGISTER_TOP_LEVEL_KEYS)!r}",
        )
    if document.get("schema") != REGISTER_SCHEMA_ID:
        _add(
            issues,
            "integrity",
            "register-schema-id-mismatch",
            "schema",
            f"expected {REGISTER_SCHEMA_ID!r}",
        )
    if (
        type(document.get("schema_version")) is not int
        or document["schema_version"] != REGISTER_SCHEMA_VERSION
    ):
        _add(
            issues,
            "integrity",
            "register-schema-version-mismatch",
            "schema_version",
            f"expected {REGISTER_SCHEMA_VERSION}",
        )
    valid_register_revision = (
        isinstance(register_revision, int)
        and not isinstance(register_revision, bool)
        and register_revision >= 1
    )
    if not valid_register_revision:
        _add(
            issues,
            "integrity",
            "register-revision-invalid",
            "register_revision",
            "must be an integer greater than or equal to one",
        )
    if register_scope != PR97_SCOPE_ID:
        _add(
            issues,
            "integrity",
            "unsupported-register-scope",
            "scope.id",
            f"v1 register scope must remain {PR97_SCOPE_ID!r}, got {register_scope!r}",
        )

    anchor_keysets = (
        (
            "pr97-arm-source-anchor-mismatch",
            "PR97_SOURCE_BY_ARM",
            set(PR97_SOURCE_BY_ARM),
            PR97_ARM_IDS,
        ),
        (
            "pr97-action-anchor-mismatch",
            "PR97_ACTION_ARGUMENTS",
            set(PR97_ACTION_ARGUMENTS),
            PR97_ARM_IDS,
        ),
        (
            "pr97-policy-anchor-mismatch",
            "PR97_POLICY_MODULES",
            set(PR97_POLICY_MODULES),
            PR97_ARM_IDS,
        ),
        (
            "pr97-coverage-anchor-mismatch",
            "PR97_COVERAGE_SIGNATURES",
            set(PR97_COVERAGE_SIGNATURES),
            PR97_ARM_IDS,
        ),
        (
            "pr97-source-identity-anchor-mismatch",
            "PR97_SOURCE_IDENTITIES",
            set(PR97_SOURCE_IDENTITIES),
            PR97_SOURCE_IDS,
        ),
        (
            "pr97-source-id-anchor-mismatch",
            "PR97_SOURCE_BY_ARM values",
            set(PR97_SOURCE_BY_ARM.values()),
            PR97_SOURCE_IDS,
        ),
        (
            "pr97-contract-anchor-mismatch",
            "PR97_CONTRACT_TEMPLATES",
            set(PR97_CONTRACT_TEMPLATES),
            PR97_CONTRACT_TEMPLATE_IDS,
        ),
    )
    for code, name, observed, expected in anchor_keysets:
        if observed != set(expected):
            _add(
                issues,
                "integrity",
                code,
                f"anchor:{name}",
                f"missing={sorted(set(expected) - observed)!r}; "
                f"added={sorted(observed - set(expected))!r}",
            )

    policy_action_arguments, policy_discovery_metadata = (
        _load_policy_action_arguments(issues)
    )
    _check_pr97_handler_list_actions(issues, policy_discovery_metadata)
    for arm_id in sorted(PR97_ARM_IDS):
        literal_actions = PR97_ACTION_ARGUMENTS.get(arm_id)
        policy_actions = policy_action_arguments.get(arm_id)
        if literal_actions is None or policy_actions != dict(literal_actions):
            _add(
                issues,
                "integrity",
                "policy-action-surface-mismatch",
                f"policy:{arm_id}",
                "policy ARG_KEYS plus empty list_tools do not match the frozen PR97 action anchor",
            )

    inventory_doc = document["runtime_inventory"]
    if inventory_doc.get("authority") != INVENTORY_AUTHORITY_ID:
        _add(
            issues,
            "integrity",
            "inventory-authority-mismatch",
            "runtime_inventory.authority",
            f"expected {INVENTORY_AUTHORITY_ID!r}",
        )
    inventory_record_ids: tuple[str, ...] = ()
    try:
        inventory_record_ids = tuple(sorted(inventory.records))
        missing_record_ids = sorted(
            set(inventory.capability_ids) - set(inventory_record_ids)
        )
        added_record_ids = sorted(
            set(inventory_record_ids) - set(inventory.capability_ids)
        )
        if missing_record_ids or added_record_ids:
            _add(
                issues,
                "integrity",
                "authoritative-inventory-record-roster-mismatch",
                "inventory.records",
                f"missing={missing_record_ids!r}; added={added_record_ids!r}",
            )
        inventory_snapshot = [
            inventory.records[capability_id]
            for capability_id in inventory_record_ids
        ]
        inventory_object_sha256 = _sha256(inventory_snapshot)
    except (KeyError, TypeError, ValueError) as exc:
        inventory_object_sha256 = None
        _add(
            issues,
            "integrity",
            "authoritative-inventory-object-invalid",
            "inventory",
            f"cannot recompute authoritative inventory snapshot: {exc}",
        )
    if (
        inventory_object_sha256 is not None
        and inventory_object_sha256 != inventory.contract_sha256
    ):
        _add(
            issues,
            "integrity",
            "authoritative-inventory-object-mutated",
            "inventory",
            "authoritative inventory records no longer match their contract digest",
        )
    expected_ids = tuple(inventory_doc["capability_ids"])
    if (
        type(inventory_doc.get("expected_count")) is not int
        or inventory_doc["expected_count"] != len(expected_ids)
    ):
        _add(
            issues,
            "integrity",
            "inventory-self-count-mismatch",
            "runtime_inventory.expected_count",
            "expected_count does not equal the stored ID inventory length",
        )
    if len(set(expected_ids)) != len(expected_ids):
        _add(
            issues,
            "integrity",
            "inventory-duplicate-id",
            "runtime_inventory.capability_ids",
            "stored capability inventory contains duplicates",
        )
    if expected_ids != tuple(sorted(expected_ids)):
        _add(
            issues,
            "integrity",
            "inventory-not-canonical",
            "runtime_inventory.capability_ids",
            "stored capability IDs must be sorted",
        )
    missing = sorted(set(expected_ids) - set(inventory.capability_ids))
    added = sorted(set(inventory.capability_ids) - set(expected_ids))
    if missing or added or len(expected_ids) != len(inventory.capability_ids):
        _add(
            issues,
            "integrity",
            "inventory-id-mismatch",
            "runtime_inventory.capability_ids",
            f"missing={missing!r}; added={added!r}",
        )
    if inventory_doc["contract_sha256"] != inventory.contract_sha256:
        _add(
            issues,
            "integrity",
            "inventory-contract-mismatch",
            "runtime_inventory.contract_sha256",
            f"expected {inventory_doc['contract_sha256']}, got {inventory.contract_sha256}",
        )
    for capability_id, profile_record in inventory.records.items():
        if profile_record.get("capability_id") != capability_id:
            _add(
                issues,
                "integrity",
                "authoritative-profile-key-mismatch",
                f"inventory:{capability_id}",
                "INVOKE_PROFILES key differs from profile.capability_id",
            )
        structural_id = (
            f"{profile_record.get('arm_id')}.{profile_record.get('action')}"
        )
        if profile_record.get("capability_id") != structural_id:
            _add(
                issues,
                "integrity",
                "authoritative-profile-structural-id-mismatch",
                f"inventory:{capability_id}",
                "profile.capability_id must equal profile.arm_id + '.' + profile.action",
            )

    authoritative_pr97_ids = {
        capability_id
        for capability_id, profile_record in inventory.records.items()
        if profile_record.get("arm_id") in PR97_ARM_IDS
    }
    if authoritative_pr97_ids != PR97_CAPABILITY_IDS:
        _add(
            issues,
            "integrity",
            "authoritative-pr97-profile-roster-mismatch",
            "inventory:pr97-readers",
            "authoritative profiles for the frozen PR97 arms differ from the "
            "independent capability baseline: "
            f"missing={sorted(PR97_CAPABILITY_IDS - authoritative_pr97_ids)!r}; "
            f"added={sorted(authoritative_pr97_ids - PR97_CAPABILITY_IDS)!r}",
        )

    contracts = _index_unique(
        document["contract_templates"], name="contract_templates", issues=issues
    )
    if set(contracts) != PR97_CONTRACT_TEMPLATE_IDS:
        _add(
            issues,
            "integrity",
            "contract-template-roster-mismatch",
            "contract_templates",
            f"expected exact v1 contract IDs {sorted(PR97_CONTRACT_TEMPLATE_IDS)!r}",
        )
    for contract_id in sorted(PR97_CONTRACT_TEMPLATE_IDS):
        contract = contracts.get(contract_id)
        expected_contract = PR97_CONTRACT_TEMPLATES.get(contract_id)
        if contract is None or expected_contract is None:
            continue
        if not _strict_json_equal(_contract_signature(contract), expected_contract):
            _add(
                issues,
                "integrity",
                "contract-template-mismatch",
                f"contract_template:{contract_id}",
                "contract does not match the independently frozen v1 template",
            )
    modules = _index_unique(document["modules"], name="modules", issues=issues)
    sources = _index_unique(document["sources"], name="sources", issues=issues)
    runtime_rows = document["runtime"]
    runtime: dict[str, Mapping[str, Any]] = {}
    for position, row in enumerate(runtime_rows):
        capability_id = row["capability_id"]
        if capability_id in runtime:
            _add(
                issues,
                "integrity",
                "duplicate-id",
                f"runtime[{position}].capability_id",
                f"duplicate runtime capability {capability_id}",
            )
        else:
            runtime[capability_id] = row
    events = _index_unique(
        document["promotion_events"], name="promotion_events", issues=issues
    )
    referenced_events: set[str] = set()
    for event_id in events:
        _add(
            issues,
            "integrity",
            "promotion-verifier-unimplemented",
            f"promotion_event:{event_id}",
            "v1 cannot verify promotion evidence or authorize a promotion",
        )

    runtime_ids = set(runtime)
    _check_pr97_coverage(coverage, runtime, inventory, issues)
    if runtime_ids != PR97_CAPABILITY_IDS:
        _add(
            issues,
            "integrity",
            "pr97-runtime-roster-mismatch",
            "runtime",
            f"missing={sorted(PR97_CAPABILITY_IDS - runtime_ids)!r}; "
            f"added={sorted(runtime_ids - PR97_CAPABILITY_IDS)!r}",
        )
    expected_source_ids = set(PR97_SOURCE_IDS)
    if set(sources) != expected_source_ids:
        _add(
            issues,
            "integrity",
            "pr97-source-roster-mismatch",
            "sources",
            f"missing={sorted(expected_source_ids - set(sources))!r}; "
            f"added={sorted(set(sources) - expected_source_ids)!r}",
        )
    if set(modules) != {"CYB-05"}:
        _add(
            issues,
            "integrity",
            "foundation-module-roster-mismatch",
            "modules",
            "the v1 foundation module roster must be exactly CYB-05",
        )

    for capability_id, row in runtime.items():
        row_path = f"runtime:{capability_id}"
        if type(row.get("record_version")) is not int or row["record_version"] != 1:
            _add(
                issues,
                "integrity",
                "unsupported-record-version",
                f"{row_path}.record_version",
                "v1 supports only runtime record_version 1",
            )
        if row.get("presence") != "admitted":
            _add(
                issues,
                "integrity",
                "runtime-presence-mismatch",
                f"{row_path}.presence",
                "v1 runtime records must have presence 'admitted'",
            )
        if row.get("result_schema") != EXECUTION_RESULT_SCHEMA_ID:
            _add(
                issues,
                "integrity",
                "runtime-result-schema-mismatch",
                f"{row_path}.result_schema",
                f"expected {EXECUTION_RESULT_SCHEMA_ID!r}",
            )
        if capability_id != f"{row['arm_id']}.{row['action']}":
            _add(
                issues,
                "integrity",
                "runtime-structural-id-mismatch",
                row_path,
                "capability_id must equal arm_id + '.' + action",
            )
        actual = inventory.records.get(capability_id)
        if actual is None:
            _add(
                issues,
                "integrity",
                "missing-authoritative-profile",
                row_path,
                "governed capability is absent from INVOKE_PROFILES",
            )
            continue
        if row["arm_id"] != actual["arm_id"] or row["action"] != actual["action"]:
            _add(
                issues,
                "integrity",
                "runtime-identity-mismatch",
                row_path,
                "arm_id/action do not match the authoritative profile",
            )
        if row["tool_version"] != actual["tool_version"]:
            _add(
                issues,
                "integrity",
                "runtime-version-mismatch",
                row_path,
                "tool_version does not match the authoritative profile",
            )
        if (
            capability_id in PR97_CAPABILITY_IDS
            and row["implementation_revision"] != PR97_IMPLEMENTATION_REVISION
        ):
            _add(
                issues,
                "integrity",
                "runtime-implementation-revision-mismatch",
                row_path,
                "implementation_revision does not match the frozen PR97 merge revision",
            )
        if row["support_tier"] != actual["tier"]:
            _add(
                issues,
                "integrity",
                "runtime-tier-mismatch",
                row_path,
                "support tier does not match the authoritative profile",
            )
        contract = contracts.get(row["contract_ref"])
        if contract is None:
            _add(
                issues,
                "integrity",
                "unknown-contract",
                row_path,
                f"unknown contract_ref {row['contract_ref']}",
            )
        else:
            expected_scope = [f"policy://extension/arms/{row['arm_id']}"]
            comparisons = {
                "safety_class": contract["safety_class"],
                "side_effects": sorted(contract["side_effects"]),
                "cleanup_required": contract["cleanup_required"],
                "default_off": contract["default_off"],
                "synthetic_only": contract["synthetic_only"],
                "timeout_ms": contract["timeout_ms"],
                "max_output_bytes": contract["max_output_bytes"],
                "max_tool_steps": contract["max_tool_steps"],
                "max_spend": contract["max_spend"],
                "authorized_scope": expected_scope,
                "touched_scope": expected_scope,
                "approval_ref": None if not contract["approval_required"] else "required",
                "roe_ref": None if not contract["approval_required"] else "required",
            }
            for field, expected in comparisons.items():
                observed = actual[field]
                if expected == "required":
                    matches = observed is not None
                else:
                    matches = _strict_json_equal(observed, expected)
                if not matches:
                    _add(
                        issues,
                        "integrity",
                        "runtime-contract-mismatch",
                        f"{row_path}.{field}",
                        f"expected {expected!r}, got {observed!r}",
                    )
            if tuple(row["known_limitations"]) != tuple(contract["limitations"]):
                _add(
                    issues,
                    "integrity",
                    "runtime-limitations-mismatch",
                    f"{row_path}.known_limitations",
                    "runtime limitations must exactly match its frozen contract template",
                )
        expected_args = PR97_ACTION_ARGUMENTS.get(row["arm_id"], {}).get(row["action"])
        policy_args = policy_action_arguments.get(row["arm_id"], {}).get(row["action"])
        observed_args = tuple(row["input_keys"])
        if capability_id in PR97_CAPABILITY_IDS:
            if observed_args != expected_args:
                _add(
                    issues,
                    "integrity",
                    "runtime-action-surface-mismatch",
                    f"{row_path}.input_keys",
                    f"expected literal {expected_args!r}, got {observed_args!r}",
                )
            if observed_args != policy_args:
                _add(
                    issues,
                    "integrity",
                    "runtime-policy-action-surface-mismatch",
                    f"{row_path}.input_keys",
                    f"expected policy ARG_KEYS {policy_args!r}, got {observed_args!r}",
                )
        _check_currentness(
            row_path,
            row["currentness"],
            as_of=as_of,
            path=f"{row_path}.currentness",
            issues=issues,
        )
        evidence_refs = row["promotion_evidence"]
        if evidence_refs or row["support_tier"] in ("experimental", "maintained"):
            _add(
                issues,
                "integrity",
                "promotion-verifier-unimplemented",
                row_path,
                "v1 cannot verify promotion evidence or authorize a promotion",
            )
        if row["support_tier"] == "maintained":
            if not row["supported_versions"]:
                _add(
                    issues,
                    "integrity",
                    "maintained-without-supported-versions",
                    row_path,
                    "maintained capability requires supported_versions",
                )
            if not row["regression_cases"]:
                _add(
                    issues,
                    "integrity",
                    "maintained-without-regression",
                    row_path,
                    "maintained capability requires a regression case",
                )
            if not evidence_refs:
                _add(
                    issues,
                    "integrity",
                    "promotion-evidence-missing",
                    row_path,
                    "maintained capability requires promotion evidence",
                )
        for evidence_ref in evidence_refs:
            event = events.get(evidence_ref)
            if event is None:
                _add(
                    issues,
                    "integrity",
                    "unknown-promotion-evidence",
                    row_path,
                    f"unknown promotion event {evidence_ref}",
                )
                continue
            referenced_events.add(evidence_ref)
            expected_subject = f"runtime:{capability_id}"
            if event["subject"] != expected_subject:
                _add(
                    issues,
                    "integrity",
                    "promotion-subject-mismatch",
                    row_path,
                    f"event {evidence_ref} is bound to {event['subject']}",
                )
            if event["to_status"] != row["support_tier"]:
                _add(
                    issues,
                    "integrity",
                    "promotion-target-mismatch",
                    row_path,
                    f"event {evidence_ref} targets {event['to_status']}, "
                    f"not {row['support_tier']}",
                )
            if event["from_status"] == event["to_status"]:
                _add(
                    issues,
                    "integrity",
                    "promotion-no-transition",
                    row_path,
                    f"event {evidence_ref} does not change status",
                )
            if event["subject_digest"] != _profile_digest(actual):
                _add(
                    issues,
                    "integrity",
                    "promotion-subject-digest-mismatch",
                    row_path,
                    f"event {evidence_ref} does not bind the current profile",
                )
            if contract is not None and event["contract_digest"] != _contract_digest(contract):
                _add(
                    issues,
                    "integrity",
                    "promotion-contract-digest-mismatch",
                    row_path,
                    f"event {evidence_ref} does not bind the current contract",
                )
            if event["implementation_revision"] != row["implementation_revision"]:
                _add(
                    issues,
                    "integrity",
                    "promotion-revision-mismatch",
                    row_path,
                    f"event {evidence_ref} does not bind the implementation revision",
                )
            if event["regression_case"] not in row["regression_cases"]:
                _add(
                    issues,
                    "integrity",
                    "promotion-regression-mismatch",
                    row_path,
                    f"event {evidence_ref} regression is not registered on the capability",
                )
            if set(event["supported_versions"]) != set(row["supported_versions"]):
                _add(
                    issues,
                    "integrity",
                    "promotion-version-mismatch",
                    row_path,
                    f"event {evidence_ref} does not bind the supported version set",
                )
            if tuple(event["limitations_accepted"]) != tuple(row["known_limitations"]):
                _add(
                    issues,
                    "integrity",
                    "promotion-limitations-mismatch",
                    row_path,
                    f"event {evidence_ref} does not accept the exact limitation set",
                )

    for source_id, row in sources.items():
        row_path = f"source:{source_id}"
        if type(row.get("record_version")) is not int or row["record_version"] != 1:
            _add(
                issues,
                "integrity",
                "unsupported-record-version",
                f"{row_path}.record_version",
                "v1 supports only source record_version 1",
            )
        expected_identity = PR97_SOURCE_IDENTITIES.get(source_id)
        if expected_identity is None:
            _add(
                issues,
                "integrity",
                "source-identity-anchor-missing",
                row_path,
                "no independent canonical source name/URL anchor exists",
            )
        elif (row["name"], row["url"]) != expected_identity:
            _add(
                issues,
                "integrity",
                "source-identity-mismatch",
                row_path,
                f"expected canonical name/URL {expected_identity!r}",
            )
        if source_id in PR97_SOURCE_IDS and row["status"] != "research":
            _add(
                issues,
                "integrity",
                "source-status-baseline-mismatch",
                row_path,
                "the v1 PR97 source baseline must remain research",
            )
        _check_currentness(
            row_path,
            row["currentness"],
            as_of=as_of,
            path=f"{row_path}.currentness",
            issues=issues,
        )
        admitted = row["status"] in ("selected", "admitted")
        if admitted:
            _add(
                issues,
                "integrity",
                "promotion-verifier-unimplemented",
                row_path,
                "v1 cannot verify source selection/admission evidence",
            )
        if admitted:
            selected_revision = row["selected_revision"]
            if (
                not isinstance(selected_revision, str)
                or not selected_revision.strip()
                or not row["content_digests"]
            ):
                _add(
                    issues,
                    "integrity",
                    "source-pin-missing",
                    row_path,
                    "selected/admitted source requires a revision and content digest",
                )
            rights = row["rights"]
            if rights["license_review"] != "reviewed" or rights["data_rights_review"] != "reviewed":
                _add(
                    issues,
                    "integrity",
                    "source-rights-unreviewed",
                    row_path,
                    "selected/admitted source requires reviewed license and data rights",
                )
        if row["status"] == "admitted" and not row["promotion_evidence"]:
            _add(
                issues,
                "integrity",
                "promotion-evidence-missing",
                row_path,
                "admitted source requires promotion evidence",
            )
        _check_generic_promotion_refs(
            subject_ref=row_path,
            row=row,
            target_status=row["status"],
            contract_digest=_source_contract_digest(row),
            events=events,
            referenced_events=referenced_events,
            issues=issues,
        )

    for module_id, row in modules.items():
        row_path = f"module:{module_id}"
        if type(row.get("record_version")) is not int or row["record_version"] != 1:
            _add(
                issues,
                "integrity",
                "unsupported-record-version",
                f"{row_path}.record_version",
                "v1 supports only module record_version 1",
            )
        if module_id == "CYB-05" and row["status"] != "design-ready":
            _add(
                issues,
                "integrity",
                "module-status-baseline-mismatch",
                row_path,
                "the v1 CYB-05 baseline must remain design-ready",
            )
        _check_currentness(
            row_path,
            row["currentness"],
            as_of=as_of,
            path=f"{row_path}.currentness",
            issues=issues,
        )
        if row["status"] == "shipped":
            _add(
                issues,
                "integrity",
                "promotion-verifier-unimplemented",
                row_path,
                "v1 cannot verify module shipment evidence",
            )
            if not row["validation_evidence"] or not row["promotion_evidence"]:
                _add(
                    issues,
                    "integrity",
                    "shipped-module-evidence-missing",
                    row_path,
                    "shipped module requires validation and promotion evidence",
                )
        _check_generic_promotion_refs(
            subject_ref=row_path,
            row=row,
            target_status=row["status"],
            contract_digest=_module_contract_digest(row),
            events=events,
            referenced_events=referenced_events,
            issues=issues,
        )

    entity_refs = {
        *(f"module:{module_id}" for module_id in modules),
        *(f"source:{source_id}" for source_id in sources),
        *(f"runtime:{capability_id}" for capability_id in runtime),
    }
    relationship_ids: set[str] = set()
    relationship_signatures: dict[str, tuple[Any, ...]] = {}
    expected_relationships = _expected_relationship_signatures()
    research_targets: dict[str, set[str]] = {}
    proposed_source_pairs: set[tuple[str, str]] = set()
    proposed_use_pairs: set[tuple[str, str]] = set()
    replacement_targets: dict[str, list[str]] = {}
    evidence_anchor_cache: dict[Path, set[str] | str] = {}
    allowed_pairs = {
        "research-mapping": ("source", "runtime"),
        "proposed-source": ("module", "source"),
        "proposed-use": ("module", "runtime"),
        "depends-on": ("module", "module"),
        "replaces": ("source", "source"),
        "consumes": ("runtime", "source"),
    }
    for position, relationship in enumerate(document["relationships"]):
        rel_path = f"relationships[{position}]"
        rel_id = relationship["id"]
        if rel_id in relationship_ids:
            _add(issues, "integrity", "duplicate-id", f"{rel_path}.id", rel_id)
        relationship_ids.add(rel_id)
        source_ref = relationship["from"]
        targets = relationship["to"]
        record_version = relationship["record_version"]
        if type(record_version) is not int or record_version != 1:
            _add(
                issues,
                "integrity",
                "unsupported-record-version",
                f"{rel_path}.record_version",
                "v1 supports only relationship record_version 1",
            )
        relationship_signatures.setdefault(
            rel_id,
            (
                record_version,
                relationship["kind"],
                source_ref,
                tuple(targets),
                tuple(relationship["evidence_refs"]),
                tuple(relationship["limitations"]),
            ),
        )
        if source_ref not in entity_refs:
            _add(
                issues,
                "integrity",
                "dangling-relationship",
                f"{rel_path}.from",
                source_ref,
            )
        if not _ENTITY_REF_RE.fullmatch(source_ref):
            _add(
                issues,
                "integrity",
                "implicit-selector-refused",
                f"{rel_path}.from",
                source_ref,
            )
        source_kind = source_ref.split(":", 1)[0]
        target_kind_expected = allowed_pairs[relationship["kind"]][1]
        if source_kind != allowed_pairs[relationship["kind"]][0]:
            _add(
                issues,
                "integrity",
                "relationship-kind-endpoints",
                rel_path,
                "relationship kind is incompatible with its source endpoint",
            )
        if len(set(targets)) != len(targets):
            _add(
                issues,
                "integrity",
                "duplicate-relationship-target",
                f"{rel_path}.to",
                "relationship targets must be unique",
            )
        for target_ref in targets:
            if target_ref not in entity_refs:
                _add(
                    issues,
                    "integrity",
                    "dangling-relationship",
                    f"{rel_path}.to",
                    target_ref,
                )
            if not _ENTITY_REF_RE.fullmatch(target_ref):
                _add(
                    issues,
                    "integrity",
                    "implicit-selector-refused",
                    f"{rel_path}.to",
                    target_ref,
                )
            target_kind = target_ref.split(":", 1)[0]
            if target_kind != target_kind_expected:
                _add(
                    issues,
                    "integrity",
                    "relationship-kind-endpoints",
                    rel_path,
                    "relationship kind is incompatible with a target endpoint",
                )
            if relationship["kind"] == "research-mapping":
                research_targets.setdefault(source_ref, set()).add(target_ref)
            elif relationship["kind"] == "proposed-source":
                proposed_source_pairs.add((source_ref, target_ref))
            elif relationship["kind"] == "proposed-use":
                proposed_use_pairs.add((source_ref, target_ref))
            elif relationship["kind"] == "replaces":
                replacement_targets.setdefault(source_ref, []).append(target_ref)
            elif relationship["kind"] == "consumes" and target_ref.startswith("source:"):
                target_source = sources.get(target_ref.split(":", 1)[1])
                runtime_row = runtime.get(source_ref.split(":", 1)[1])
                if target_source is not None and target_source["status"] != "admitted":
                    _add(
                        issues,
                        "integrity",
                        "consumes-unadmitted-source",
                        rel_path,
                        "consumes requires an admitted source",
                    )
                if runtime_row is not None:
                    contract = contracts.get(runtime_row["contract_ref"])
                    if contract is not None and contract["input_binding"] != "governed-source-pin":
                        _add(
                            issues,
                            "integrity",
                            "consumes-unbound-input",
                            rel_path,
                            "consumes requires an exact governed source binding",
                        )

    if set(relationship_signatures) != set(expected_relationships):
        _add(
            issues,
            "integrity",
            "relationship-roster-mismatch",
            "relationships",
            f"missing={sorted(set(expected_relationships) - set(relationship_signatures))!r}; "
            f"added={sorted(set(relationship_signatures) - set(expected_relationships))!r}",
        )
    for relationship_id in sorted(set(relationship_signatures) & set(expected_relationships)):
        observed_signature = relationship_signatures[relationship_id]
        expected_signature = expected_relationships[relationship_id]
        if not _strict_json_equal(observed_signature, expected_signature):
            _add(
                issues,
                "integrity",
                "relationship-baseline-mismatch",
                f"relationship:{relationship_id}",
                "version, kind, endpoints, evidence refs, or limitations differ "
                "from the exact v1 baseline",
            )

    relationships_exact = (
        len(document["relationships"]) == len(expected_relationships)
        and set(relationship_signatures) == set(expected_relationships)
        and all(
            _strict_json_equal(
                relationship_signatures[relationship_id],
                expected_relationships[relationship_id],
            )
            for relationship_id in expected_relationships
        )
    )
    if relationships_exact:
        for position, relationship in enumerate(document["relationships"]):
            for evidence_index, evidence_ref in enumerate(
                relationship["evidence_refs"]
            ):
                _check_evidence_ref(
                    evidence_ref,
                    path=f"relationships[{position}].evidence_refs[{evidence_index}]",
                    cache=evidence_anchor_cache,
                    issues=issues,
                )

    for source_id, row in sources.items():
        source_ref = f"source:{source_id}"
        targets = replacement_targets.get(source_ref, [])
        replacement = row["replacement"]
        if replacement is None:
            if targets:
                _add(
                    issues,
                    "integrity",
                    "source-replacement-relationship-mismatch",
                    source_ref,
                    "replaces relationship exists without a matching source replacement field",
                )
            continue
        if not isinstance(replacement, str) or replacement not in sources:
            _add(
                issues,
                "integrity",
                "source-replacement-unknown",
                source_ref,
                f"replacement {replacement!r} is not a governed source",
            )
        if replacement == source_id:
            _add(
                issues,
                "integrity",
                "source-replacement-self",
                source_ref,
                "a source cannot replace itself",
            )
        expected_target = f"source:{replacement}"
        if targets != [expected_target]:
            _add(
                issues,
                "integrity",
                "source-replacement-relationship-mismatch",
                source_ref,
                f"expected exactly one replaces target {expected_target!r}",
            )

    for arm_id, source_id in PR97_SOURCE_BY_ARM.items():
        source_ref = f"source:{source_id}"
        expected_targets = {
            f"runtime:{arm_id}.{action}"
            for action in PR97_ACTION_ARGUMENTS.get(arm_id, {})
        }
        if research_targets.get(source_ref, set()) != expected_targets:
            _add(
                issues,
                "integrity",
                "research-mapping-mismatch",
                source_ref,
                f"expected exact targets {sorted(expected_targets)!r}",
            )
    if ("module:CYB-05", "source:R01") not in proposed_source_pairs:
        _add(
            issues,
            "integrity",
            "foundation-relationship-missing",
            "relationships",
            "CYB-05 must retain its proposed-source relationship to R01",
        )
    if ("module:CYB-05", "runtime:vulnify.lookup") not in proposed_use_pairs:
        _add(
            issues,
            "integrity",
            "foundation-relationship-missing",
            "relationships",
            "CYB-05 must retain its proposed-use relationship to vulnify.lookup",
        )

    for event_id, event in events.items():
        event_path = f"promotion_event:{event_id}"
        if event["subject"] not in entity_refs:
            _add(
                issues,
                "integrity",
                "promotion-subject-missing",
                event_path,
                event["subject"],
            )
        decided_on = _parse_date(
            event["decided_on"], path=f"{event_path}.decided_on", issues=issues
        )
        if decided_on is not None and decided_on > as_of:
            _add(
                issues,
                "integrity",
                "promotion-decision-in-future",
                f"{event_path}.decided_on",
                f"decision date {decided_on.isoformat()} is later than "
                f"as-of {as_of.isoformat()}",
            )
        if event_id not in referenced_events:
            _add(
                issues,
                "integrity",
                "orphan-promotion-evidence",
                event_path,
                "promotion event is not referenced by its subject record",
            )

    repository_complete_value = document["scope"]["repository_complete"]
    if type(repository_complete_value) is not bool:
        _add(
            issues,
            "integrity",
            "scope-repository-complete-type-mismatch",
            "scope.repository_complete",
            "repository_complete must be a JSON boolean",
        )
    if repository_complete_value is not True:
        _add(
            issues,
            "completeness",
            "repository-partial",
            "scope.repository_complete",
            "this foundation intentionally governs only the PR97 reader slice",
        )
    if scope == FULL_SCOPE_ID and len(runtime) != len(inventory.capability_ids):
        _add(
            issues,
            "completeness",
            "runtime-governance-partial",
            "runtime",
            f"{len(runtime)} of {len(inventory.capability_ids)} capabilities have detailed records",
        )
    declared_repository_complete = repository_complete_value is True
    if declared_repository_complete:
        _add(
            issues,
            "integrity",
            "unsupported-complete-claim",
            "scope.repository_complete",
            "v1 cannot prove full module/source/runtime coverage and refuses a complete claim",
        )
    effective_repository_complete = False

    return ValidationReport(
        requested_scope=scope,
        register_scope=register_scope,
        register_revision=(
            register_revision if valid_register_revision else None
        ),
        register_sha256=(
            loaded_registry.register_sha256 if loaded_registry is not None else None
        ),
        schema_sha256=(
            loaded_registry.schema_sha256 if loaded_registry is not None else None
        ),
        authoritative_inventory_contract_sha256=inventory.contract_sha256,
        coverage_contract_sha256=coverage.contract_sha256,
        coverage_sha256=coverage.source_sha256,
        requirement=require,
        as_of=as_of,
        repository_complete=effective_repository_complete,
        inventory_count=len(inventory.capability_ids),
        governed_runtime_count=len(runtime),
        source_count=len(sources),
        module_count=len(modules),
        issues=tuple(sorted(set(issues))),
    )


REGISTER_V2_SCHEMA_ID = "specaudit.ctf.governance.register.v2"
REGISTER_V2_SCHEMA_VERSION = 2
V2_SCOPE_ID = "full-v2"
V2_CANONICAL_SCHEMA_SHA256 = (
    "sha256:5f28b7e523058afaa90938319d628680976e71a010722bdc1dee6a98a925c9c5"
)
DEFAULT_REGISTER_V2_PATH = Path(__file__).resolve().with_name("register.v2.yaml")
DEFAULT_REGISTER_V2_SCHEMA_PATH = (
    Path(__file__).resolve().parent / "schema" / "register.v2.schema.json"
)
V2_REGISTER_TOP_LEVEL_KEYS = frozenset(
    REGISTER_TOP_LEVEL_KEYS | {"currentness_queue"}
)
# The governed-as-of baseline for non-PR97 runtime rows.  It is a snapshot
# pin, not a claim about when each capability was introduced; the honest
# limitation is carried inside every v2 contract template.
V2_BASELINE_IMPLEMENTATION_REVISION = "dc43b85c3ce3439c74fd39296d530294cf5f7f40"
V2_TRIGGER_CHECK_METHODS = frozenset(
    {
        "checker-rederived-inventory-reconciliation",
        "primary-source-review",
        "architecture-review",
    }
)
# Independently frozen v2 rosters.  They are literals by design: they must
# not be derived from the register they validate.
V2_EXPECTED_MODULE_IDS = frozenset(
    {
        "AUD-01", "AUD-02", "AUD-03", "AUD-04", "CAP-IA", "CAP-TEL",
        "CYB-01", "CYB-02", "CYB-03", "CYB-04", "CYB-05", "CYB-06",
        "CYB-07", "CYB-08", "CYB-09", "CYB-10", "CYB-11", "FND-01",
        "FND-02", "FND-03", "TEL-01", "TEL-02", "TEL-03", "TEL-04",
        "TEL-05", "TEL-06", "TEL-07", "TEL-08", "TEL-09",
    }
)
# --- Operator-authorized source promotions (2026-10-14) -----------------------
# Frozen allowlist of the ONLY promotions validate_register_v2 accepts. It is
# an allowlist, not evidence: each decision traces to a heading in the
# authorization document (the operator's recorded instruction), a pin verified
# in the 2026-10-13 primary-source evidence, and — for admitted rows — digests
# re-derivable from bytes on disk. Adding a promotion requires editing this
# code (review- and test-gated); a register edit alone can never authorize.
V2_AUTHORIZATION_DOC = "docs/governance/promotion-authorization-2026-10-14.md"
V2_AUTHORIZATION_DATE = "2026-10-14"
# Corrected citation (U-GOV.a, 2026-10-18): the 2026-10-14 source-event records
# recorded "tests/test_synthetic_readers.py" for the ten selected families,
# but that file is absent from the verified public baseline. The per-source
# pointers below preserve the original pins/terms and only correct the
# citation to a real, source-relevant regression file in the verified baseline.
# The correction itself is documented in
# docs/governance/w1a-source-evidence-and-inventory-2026-10-18.md; it asserts
# no new admission and no claim that the corrected file ran on 2026-10-14.
V2_SELECTED_TEST_PATH: Mapping[str, str] = {
    "R02": "tests/test_arm_batch8.py",
    "R03": "tests/test_arm_batch7.py",
    "R08": "tests/test_arm_batch8.py",
    "R17": "tests/test_arm_batch8.py",
    "R25": "tests/test_arm_batch8.py",
    "R33": "tests/test_arm_batch7.py",
    "R34": "tests/test_arm_batch7.py",
    "R35": "tests/test_arm_batch7.py",
    "R36": "tests/test_arm_batch8.py",
    "R42": "tests/test_arm_batch7.py",
}
V2_AUTHORIZED_PROMOTIONS: Mapping[str, Mapping[str, Any]] = {
    "R01": {
        "to_status": "admitted",
        "permitted_uses": (
            "internal-training-use",
            "recorded-export-import-only",
            "synthetic-slice-only",
            "no-upstream-redistribution",
        ),
        "authorization_anchor": V2_AUTHORIZATION_DOC + "#r01-vulnify-admitted",
        "required_pin": "ba039dd1c902135796c14b12dbf2915eb5ca8514",
        "required_digests": (
            "sha256:a9a42f040c4a3c6fb761f9019736107e96ff6948c3f291f26ddb749026bcf62b",
        ),
        "regression_case": "tests/test_vulnify_lookup.py",
        "exercised_path": "tests/test_vulnify_lookup.py",
    },
    "R43": {
        "to_status": "admitted",
        "permitted_uses": (
            "internal-training-use",
            "recorded-export-import-only",
            "synthetic-slice-only",
            "no-upstream-redistribution",
        ),
        "authorization_anchor": V2_AUTHORIZATION_DOC + "#r43-security-detections-mcp-admitted",
        "required_pin": "54a588cad9cae3026279716a6dc8b75af43a4d0a",
        "required_digests": (
            "sha256:c148a5185543f1d7c7c4d4c8bbd9f1659612f9e5b2844cba9822bbc4a2581fcf",
        ),
        "regression_case": "tests/test_reader_evidence.py",
        "exercised_path": "tests/test_reader_evidence.py",
    },
    **{
        source_id: {
            "to_status": "selected",
            "permitted_uses": (
                "internal-training-use",
                "recorded-export-import-only",
                "no-upstream-redistribution",
            ),
            "authorization_anchor": (
                V2_AUTHORIZATION_DOC
                + "#ten-families-selected-for-recorded-export-import"
            ),
            "required_pin": pin,
            "required_digests": (),
            "regression_case": V2_SELECTED_TEST_PATH[source_id],
            "exercised_path": V2_SELECTED_TEST_PATH[source_id],
        }
        for source_id, pin in {
            "R02": "110ce06aeb182dff11b51abd3047b0157f290a64",
            "R03": "e655f93ab694c446b76672efe6e71e62aac0b7b8",
            "R08": "096d0effbee28653c4705a9ea973266b24d6e2a5",
            "R17": "1237a2f3515aebbd5260383c7088aa0ea806b600",
            "R25": "73efec51207f6f740cb398e1c490e5edd60c1113",
            "R33": "77ec6bd17e65a111b30fc490476f28cb29308a0f",
            "R34": "77ec6bd17e65a111b30fc490476f28cb29308a0f",
            "R35": "7c2a22891465ac4c00bd45f4a50c742aa4651275",
            "R36": "74215f68ea70bd6a66c008da91bf5fe21d20b154",
            "R42": "ac492b2a8613c85acee4d7b6cdec1a7abd14ce7f",
        }.items()
    },
}
V2_PROMOTED_SOURCE_IDS = frozenset(V2_AUTHORIZED_PROMOTIONS)
# Fields an authorized promotion may change on an otherwise v1-frozen row.
_V2_PROMOTION_AFFECTED_FIELDS = (
    "status",
    "selected_revision",
    "content_digests",
    "rights",
    "promotion_evidence",
)
V2_PROMOTION_REVIEWER = "repository-operator"
V2_PROMOTION_IMPLEMENTATION_REVISION = "a8f595d8b9c9a03ea76b49f32b071b732cc85538"
V2_EXPECTED_SOURCE_IDS = frozenset(
    {
        *(f"R{n:02d}" for n in range(1, 44) if n != 10),
        *(f"S{n:02d}" for n in range(1, 13)),
        *(f"SD{n:02d}" for n in range(1, 10)),
        *(f"SP-{n:02d}" for n in range(1, 47)),
    }
)
V2_EXPECTED_DEPENDS_ON: Mapping[str, tuple[str, ...]] = {
    "CAP-IA": ("AUD-04", "CYB-02"),
    "CAP-TEL": ("TEL-01", "TEL-09"),
    **{f"TEL-{n:02d}": ("TEL-01",) for n in range(2, 10)},
}
V2_EXPECTED_RELATIONSHIP_IDS = frozenset(
    {
        *(f"map-{sid.lower()}-{arm}" for arm, sid in {
            "security-detections-mcp": "R43",
            "agentseal": "R35",
            "vulnify": "R01",
            "leonidas": "R33",
            "specterops-skills": "R03",
            "detection-in-the-cloud": "R34",
            "pentestkit": "R42",
            "collinear": "R15",
            "ad-pathfinder": "R02",
            "gpohound": "R08",
            "claude-ad": "R25",
            "numasec": "R17",
            "rubeus": "R36",
            "m365pwned": "R38",
        }.items()),
        "cyb-05-proposed-source-r01",
        "cyb-05-proposed-use-vulnify-lookup",
        *(f"{mid.lower().replace('-', '')}-depends-on" for mid in V2_EXPECTED_DEPENDS_ON),
    }
)
V2_CONTRACT_TEMPLATES: Mapping[str, Mapping[str, Any]] = {
    "read-local-v1": {"id": "read-local-v1", "safety_class": "R0", "side_effects": ("local-read",), "egress": "none", "cleanup_required": False, "default_off": True, "synthetic_only": True, "timeout_ms": 30000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "static-policy-uri", "input_binding": "not-applicable", "approval_required": False, "limitations": ("local-read-only", "catalog-presence-does-not-imply-support", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "read-local-v2": {"id": "read-local-v2", "safety_class": "R0", "side_effects": ("local-read",), "egress": "none", "cleanup_required": False, "default_off": True, "synthetic_only": True, "timeout_ms": 30000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "static-policy-uri", "input_binding": "not-applicable", "approval_required": False, "limitations": ("local-read-only", "catalog-presence-does-not-imply-support", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "read-local-v3": {"id": "read-local-v3", "safety_class": "R0", "side_effects": ("local-read",), "egress": "none", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 30000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "static-policy-uri", "input_binding": "caller-selected-unbound", "approval_required": False, "limitations": ("local-read-only", "catalog-presence-does-not-imply-support", "input-custody-and-upstream-equivalence-are-not-attested", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "read-local-v4": {"id": "read-local-v4", "safety_class": "R0", "side_effects": ("local-read",), "egress": "none", "cleanup_required": False, "default_off": True, "synthetic_only": True, "timeout_ms": 30000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "static-policy-uri", "input_binding": "not-applicable", "approval_required": False, "limitations": ("local-read-only", "catalog-presence-does-not-imply-support", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "read-local-v5": {"id": "read-local-v5", "safety_class": "R0", "side_effects": ("local-read",), "egress": "none", "cleanup_required": False, "default_off": True, "synthetic_only": True, "timeout_ms": 60000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "static-policy-uri", "input_binding": "not-applicable", "approval_required": False, "limitations": ("local-read-only", "catalog-presence-does-not-imply-support", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "declared-v1": {"id": "declared-v1", "safety_class": "R1", "side_effects": ("local-read", "local-write"), "egress": "none", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 30000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("declared-side-effects", "operator-controls-required", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-net-v1": {"id": "dispatch-subprocess-net-v1", "safety_class": "R1", "side_effects": ("local-read", "network-egress", "subprocess"), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 60000, "max_output_bytes": 1048576, "max_tool_steps": 32, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-and-network-egress-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-egress-rate-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-net-v2": {"id": "dispatch-subprocess-net-v2", "safety_class": "R1", "side_effects": ("local-write", "network-egress", "subprocess"), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 300000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-and-network-egress-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-egress-rate-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "endpoint-read-v1": {"id": "endpoint-read-v1", "safety_class": "R1", "side_effects": ("network-egress",), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 5000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "endpoint-policy-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("network-egress-declared", "endpoint-policy-union-admitted", "operator-must-enforce-egress-and-rate-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "endpoint-read-v2": {"id": "endpoint-read-v2", "safety_class": "R1", "side_effects": ("network-egress",), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 10000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "endpoint-policy-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("network-egress-declared", "endpoint-policy-union-admitted", "operator-must-enforce-egress-and-rate-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "endpoint-read-v3": {"id": "endpoint-read-v3", "safety_class": "R1", "side_effects": ("network-egress",), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 120000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "endpoint-policy-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("network-egress-declared", "endpoint-policy-union-admitted", "operator-must-enforce-egress-and-rate-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-net-v3": {"id": "dispatch-subprocess-net-v3", "safety_class": "R1", "side_effects": ("network-egress", "subprocess"), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 30000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-and-network-egress-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-egress-rate-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-net-v4": {"id": "dispatch-subprocess-net-v4", "safety_class": "R1", "side_effects": ("network-egress", "subprocess"), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 60000, "max_output_bytes": 1048576, "max_tool_steps": 32, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-and-network-egress-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-egress-rate-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-net-v5": {"id": "dispatch-subprocess-net-v5", "safety_class": "R1", "side_effects": ("network-egress", "subprocess"), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 60000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-and-network-egress-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-egress-rate-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-net-v6": {"id": "dispatch-subprocess-net-v6", "safety_class": "R1", "side_effects": ("network-egress", "subprocess"), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 120000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-and-network-egress-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-egress-rate-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-net-v7": {"id": "dispatch-subprocess-net-v7", "safety_class": "R1", "side_effects": ("network-egress", "subprocess"), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 180000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-and-network-egress-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-egress-rate-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-net-v8": {"id": "dispatch-subprocess-net-v8", "safety_class": "R1", "side_effects": ("network-egress", "subprocess"), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 300000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-and-network-egress-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-egress-rate-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-net-v9": {"id": "dispatch-subprocess-net-v9", "safety_class": "R1", "side_effects": ("network-egress", "subprocess"), "egress": "declared", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 600000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-and-network-egress-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-egress-rate-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-v1": {"id": "dispatch-subprocess-v1", "safety_class": "R1", "side_effects": ("subprocess",), "egress": "none", "cleanup_required": False, "default_off": True, "synthetic_only": True, "timeout_ms": 60000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-filesystem-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
    "dispatch-subprocess-v2": {"id": "dispatch-subprocess-v2", "safety_class": "R1", "side_effects": ("subprocess",), "egress": "none", "cleanup_required": False, "default_off": True, "synthetic_only": False, "timeout_ms": 120000, "max_output_bytes": 1048576, "max_tool_steps": 1, "max_spend": None, "scope_mode": "dispatch-scope-gated", "input_binding": "not-applicable", "approval_required": True, "limitations": ("subprocess-declared", "default-off-until-explicit-scope-arming", "operator-must-enforce-filesystem-and-cleanup-outside-the-agent", "implementation-revision-pinned-to-governed-as-of-baseline-not-introduction-history")},
}
V2_SOURCE_ROW_KEYS = (
    "id", "record_version", "name", "url", "status", "owner",
    "selected_revision", "content_digests", "rights", "currentness",
    "replacement", "promotion_evidence", "limitations",
)
V2_MODULE_ROW_KEYS = (
    "id", "record_version", "title", "status", "owner", "audiences",
    "level", "outcomes", "dependencies", "deliverables", "validation_evidence",
    "currentness", "promotion_evidence", "limitations",
)
V2_RUNTIME_ROW_KEYS = (
    "capability_id", "record_version", "arm_id", "action", "presence",
    "support_tier", "owner", "tool_version", "implementation_revision",
    "contract_ref", "input_keys", "result_schema", "supported_versions",
    "regression_cases", "currentness", "promotion_evidence",
    "known_limitations",
)
_V1_CURRENTNESS_KEYS = ("reviewed_on", "review_due_on", "triggers")


@dataclass(frozen=True)
class ValidationReportV2(ValidationReport):
    """v2 outcome; currentness is attributed review plus re-derived checks."""

    currentness_basis: str = "attributed-review-and-rederived-checks"

    def as_dict(self) -> dict[str, Any]:
        payload = super().as_dict()
        payload["schema"] = "specaudit.ctf.governance.validation-report.v2"
        payload["currentness_basis"] = self.currentness_basis
        return payload


def _v1_currentness(currentness: Mapping[str, Any]) -> dict[str, Any]:
    return {key: currentness[key] for key in _V1_CURRENTNESS_KEYS}


def _project_v1_row(
    row: Mapping[str, Any], keys: Sequence[str]
) -> dict[str, Any]:
    projected = {key: copy.deepcopy(row[key]) for key in keys}
    if "currentness" in projected:
        projected["currentness"] = _v1_currentness(row["currentness"])
    return projected


def _v1_baseline_source_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project a v2 PR97 source row to v1 shape, restoring baseline values
    for fields an authorized promotion may change.

    Only rows in the frozen promotion anchor table get restored values; any
    other row with promotion-affected drift reaches the v1 checker as-is and
    fails both the v1 rules and the copy-fidelity comparison.
    """
    projected = _project_v1_row(row, V2_SOURCE_ROW_KEYS)
    if row.get("id") in V2_PROMOTED_SOURCE_IDS:
        projected["status"] = "research"
        projected["selected_revision"] = None
        projected["content_digests"] = []
        projected["rights"] = {
            "license_review": "unreviewed",
            "data_rights_review": "unreviewed",
            "permitted_uses": ["reference-link-only"],
        }
        projected["promotion_evidence"] = []
    return projected


def _check_currentness_v2(
    owner_ref: str,
    currentness: Mapping[str, Any],
    *,
    as_of: date,
    path: str,
    issues: list[ValidationIssue],
    evidence_cache: dict[Path, set[str] | str],
) -> None:
    reviewed = _parse_date(
        currentness.get("reviewed_on"), path=f"{path}.reviewed_on", issues=issues
    )
    due = _parse_date(
        currentness.get("review_due_on"), path=f"{path}.review_due_on", issues=issues
    )
    if reviewed is None or due is None:
        _add(
            issues,
            "currentness",
            "unreviewed",
            path,
            f"{owner_ref} has no completed v2 currentness review",
        )
        return
    if reviewed > as_of:
        _add(
            issues,
            "integrity",
            "review-in-future",
            path,
            f"review date {reviewed.isoformat()} is later than as-of {as_of.isoformat()}",
        )
    if reviewed >= due:
        _add(
            issues,
            "integrity",
            "inverted-currentness-window",
            path,
            "reviewed_on must be earlier than review_due_on",
        )
    elif as_of > due:
        _add(
            issues,
            "currentness",
            "stale",
            path,
            f"review was due {due.isoformat()}",
        )
    triggers = currentness.get("triggers")
    checks = currentness.get("trigger_checks")
    trigger_list = list(triggers) if isinstance(triggers, list) else []
    check_list = list(checks) if isinstance(checks, list) else []
    checked_triggers = [item.get("trigger") for item in check_list if isinstance(item, dict)]
    for trigger in trigger_list:
        if checked_triggers.count(trigger) != 1:
            _add(
                issues,
                "currentness",
                "trigger-check-missing",
                path,
                f"trigger {trigger!r} must have exactly one recorded trigger check",
            )
    for item in check_list:
        if not isinstance(item, dict):
            _add(issues, "integrity", "trigger-check-invalid", path, "trigger checks must be mappings")
            continue
        if item.get("trigger") not in trigger_list:
            _add(
                issues,
                "integrity",
                "trigger-check-orphan",
                path,
                f"trigger check names unknown trigger {item.get('trigger')!r}",
            )
        method = item.get("checked_via")
        if method not in V2_TRIGGER_CHECK_METHODS:
            _add(
                issues,
                "integrity",
                "trigger-check-method-unknown",
                path,
                f"checked_via {method!r} is not a recognized check method",
            )
        _check_evidence_ref(
            item.get("evidence_ref"),
            path=path,
            cache=evidence_cache,
            issues=issues,
        )


def load_register_v2(
    path: Path | str = DEFAULT_REGISTER_V2_PATH,
    *,
    schema_path: Path | str = DEFAULT_REGISTER_V2_SCHEMA_PATH,
) -> Registry:
    """Load bounded snapshots and validate the closed v2 schema offline."""

    register_path = Path(path)
    schema_file = Path(schema_path)
    register_snapshot = _read_file_snapshot(
        register_path, label="register v2", max_bytes=MAX_REGISTER_V2_BYTES
    )
    raw = _strict_utf8(register_snapshot.data, label="register v2")
    try:
        document = yaml.load(raw, Loader=_V2UniqueKeyLoader)
    except RegisterLoadError:
        raise
    except (RecursionError, yaml.YAMLError) as exc:
        raise RegisterLoadError(f"invalid register v2 YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise RegisterLoadError("register v2 must be a mapping")
    _validate_bounded_tree(
        document,
        label="register v2",
        max_nodes=MAX_REGISTER_V2_NODES,
        max_total_string_bytes=MAX_REGISTER_V2_TOTAL_STRING_BYTES,
    )

    schema_snapshot = _read_file_snapshot(
        schema_file, label="register v2 schema", max_bytes=MAX_SCHEMA_BYTES
    )
    schema_raw = _strict_utf8(schema_snapshot.data, label="register v2 schema")
    try:
        schema = json.loads(
            schema_raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except RegisterLoadError:
        raise
    except (RecursionError, json.JSONDecodeError) as exc:
        raise RegisterLoadError(
            f"cannot load register v2 schema {schema_file}: {exc}"
        ) from exc
    _validate_bounded_tree(schema, label="register v2 schema")
    _reject_nonlocal_refs(schema)
    if schema_snapshot.sha256 != V2_CANONICAL_SCHEMA_SHA256:
        raise RegisterLoadError(
            "register v2 schema does not match the canonical v2 schema digest: "
            f"expected {V2_CANONICAL_SCHEMA_SHA256}, got {schema_snapshot.sha256}"
        )
    try:
        jsonschema.Draft7Validator.check_schema(schema)
        validator = jsonschema.Draft7Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except jsonschema.SchemaError as exc:
        raise RegisterLoadError(f"invalid register v2 schema: {exc.message}") from exc
    except Exception as exc:
        raise RegisterLoadError(
            f"register v2 schema validation failed closed: {type(exc).__name__}: {exc}"
        ) from exc
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        raise RegisterLoadError(
            f"register v2 schema error at {location}: {error.message}"
        )
    return Registry(
        copy.deepcopy(document),
        register_path,
        register_sha256=register_snapshot.sha256,
        schema_path=schema_file,
        schema_sha256=schema_snapshot.sha256,
        document_sha256=_sha256(document),
    )


def validate_register_v2(
    registry: Registry | Mapping[str, Any],
    inventory: Inventory,
    coverage: CoverageInventory | None = None,
    *,
    as_of: date,
    scope: str = V2_SCOPE_ID,
    require: str = "complete",
    baseline_registry: Registry | None = None,
) -> ValidationReportV2:
    """Validate the complete-inventory v2 register.

    The PR97 slice is re-validated with the untouched v1 checker through a
    strict v1 projection, then cross-checked against the frozen v1 register
    file.  v2 adds full-inventory roster/reconciliation checks, currentness
    reviews with per-trigger checks, the review queue, and keeps every
    promotion path refused: no row, event, or provenance note can promote.
    """

    if scope != V2_SCOPE_ID:
        raise ValueError(f"unknown v2 scope: {scope}")
    if require not in REQUIREMENTS:
        raise ValueError(f"unknown requirement: {require}")
    if coverage is None:
        coverage = load_coverage_inventory()
    loaded_registry = registry if isinstance(registry, Registry) else None
    document = loaded_registry.document if loaded_registry is not None else registry
    if (
        loaded_registry is not None
        and loaded_registry.document_sha256 is not None
        and _sha256(document) != loaded_registry.document_sha256
    ):
        raise ValueError("loaded register v2 document changed after its byte snapshot")

    issues: list[ValidationIssue] = []
    evidence_cache: dict[Path, set[str] | str] = {}
    observed_top_level_keys = set(document)
    if observed_top_level_keys != V2_REGISTER_TOP_LEVEL_KEYS:
        _add(
            issues,
            "integrity",
            "register-top-level-shape-mismatch",
            "$",
            f"missing={sorted(V2_REGISTER_TOP_LEVEL_KEYS - observed_top_level_keys)!r}; "
            f"added={sorted(observed_top_level_keys - V2_REGISTER_TOP_LEVEL_KEYS)!r}",
        )
    if document.get("schema") != REGISTER_V2_SCHEMA_ID:
        _add(
            issues,
            "integrity",
            "register-schema-id-mismatch",
            "schema",
            f"expected {REGISTER_V2_SCHEMA_ID!r}",
        )
    if document.get("schema_version") != REGISTER_V2_SCHEMA_VERSION:
        _add(
            issues,
            "integrity",
            "register-schema-version-mismatch",
            "schema_version",
            f"expected {REGISTER_V2_SCHEMA_VERSION}",
        )
    if document.get("scope", {}).get("id") != V2_SCOPE_ID:
        _add(
            issues,
            "integrity",
            "unsupported-register-scope",
            "scope.id",
            f"v2 register scope must remain {V2_SCOPE_ID!r}",
        )
    if document.get("scope", {}).get("repository_complete") is not True:
        _add(
            issues,
            "integrity",
            "scope-repository-complete-mismatch",
            "scope.repository_complete",
            "the v2 register must carry repository_complete: true; the claim is "
            "bounded by every completeness check below and is never a shipping claim",
        )

    # --- v1 projection: the PR97 slice re-validated by the untouched v1 rules ---
    pr97_runtime = [
        row for row in document.get("runtime", []) if row.get("capability_id") in PR97_CAPABILITY_IDS
    ]
    pr97_sources = [
        row for row in document.get("sources", []) if row.get("id") in PR97_SOURCE_IDS
    ]
    baseline_document: Mapping[str, Any]
    if baseline_registry is None:
        baseline_registry = load_register()
    baseline_document = baseline_registry.document
    v1_relationship_ids = {row["id"] for row in baseline_document["relationships"]}
    projection = {
        "schema": REGISTER_SCHEMA_ID,
        "schema_version": REGISTER_SCHEMA_VERSION,
        "register_revision": baseline_document.get("register_revision", 1),
        "scope": copy.deepcopy(baseline_document["scope"]),
        "runtime_inventory": copy.deepcopy(document.get("runtime_inventory", {})),
        "contract_templates": [
            copy.deepcopy(row)
            for row in document.get("contract_templates", [])
            if row.get("id") in PR97_CONTRACT_TEMPLATE_IDS
        ],
        "modules": [
            _project_v1_row(row, V2_MODULE_ROW_KEYS)
            for row in document.get("modules", [])
            if row.get("id") == "CYB-05"
        ],
        "sources": [
            # Authorized promotions change status/pin/rights/evidence on
            # otherwise v1-frozen rows; the projection reconstructs the
            # v1-baseline values for exactly those fields so the untouched
            # v1 rules validate the slice as v1 froze it, while the v2
            # verifier below owns every sanctioned delta.
            _v1_baseline_source_projection(row)
            for row in pr97_sources
        ],
        "runtime": [
            _project_v1_row(row, V2_RUNTIME_ROW_KEYS) for row in pr97_runtime
        ],
        "relationships": [
            _project_v1_row(row, ("id", "record_version", "kind", "from", "to", "evidence_refs", "limitations"))
            for row in document.get("relationships", [])
            if row.get("id") in v1_relationship_ids
        ],
        "promotion_events": [],
    }
    v1_report = validate_register(
        projection, inventory, coverage, as_of=as_of,
        scope=PR97_SCOPE_ID, require="integrity",
    )
    issues.extend(
        issue for issue in v1_report.issues if issue.category == "integrity"
    )

    # --- copy fidelity: the v2 PR97 rows must equal the frozen v1 file rows ---
    if _sha256(projection["runtime_inventory"]) != _sha256(baseline_document["runtime_inventory"]):
        _add(
            issues,
            "integrity",
            "v1-baseline-copy-mismatch",
            "runtime_inventory",
            "v2 runtime inventory no longer equals the v1 authority snapshot",
        )
    def _row_fidelity_equal(
        projected: Mapping[str, Any],
        expected: Mapping[str, Any],
        *,
        extra_masks: frozenset[str] = frozenset(),
    ) -> bool:
        # currentness is deliberately upgraded in v2 (real reviews with trigger
        # checks); authorized promotions change their sanctioned fields; every
        # other v1 field must remain byte-equal, including the trigger lists.
        masks = {"currentness", *extra_masks}
        trimmed = {
            key: value for key, value in projected.items() if key not in masks
        }
        expected_trimmed = {
            key: value for key, value in expected.items() if key not in masks
        }
        if not _strict_json_equal(trimmed, expected_trimmed):
            return False
        return _strict_json_equal(
            projected.get("currentness", {}).get("triggers"),
            expected.get("currentness", {}).get("triggers"),
        )

    baseline_module = next(
        (row for row in baseline_document["modules"] if row.get("id") == "CYB-05"), None
    )
    v2_cyb05 = next(
        (row for row in document.get("modules", []) if row.get("id") == "CYB-05"), None
    )
    if baseline_module is None or v2_cyb05 is None or not _row_fidelity_equal(
        _project_v1_row(v2_cyb05, V2_MODULE_ROW_KEYS), baseline_module
    ):
        _add(
            issues,
            "integrity",
            "v1-baseline-copy-mismatch",
            "module:CYB-05",
            "v2 CYB-05 row differs from the frozen v1 register row",
        )
    baseline_sources = {row["id"]: row for row in baseline_document["sources"]}
    for row in pr97_sources:
        expected = baseline_sources.get(row["id"])
        promoted = row.get("id") in V2_PROMOTED_SOURCE_IDS
        if expected is None or not _row_fidelity_equal(
            _project_v1_row(row, V2_SOURCE_ROW_KEYS),
            expected,
            extra_masks=frozenset(_V2_PROMOTION_AFFECTED_FIELDS) if promoted else frozenset(),
        ):
            _add(
                issues,
                "integrity",
                "v1-baseline-copy-mismatch",
                f"source:{row.get('id')}",
                "v2 PR97 source row differs from the frozen v1 register row"
                + (" outside the authorized promotion fields" if promoted else ""),
            )
    baseline_runtime = {row["capability_id"]: row for row in baseline_document["runtime"]}
    for row in pr97_runtime:
        expected = baseline_runtime.get(row["capability_id"])
        if expected is None or not _row_fidelity_equal(
            _project_v1_row(row, V2_RUNTIME_ROW_KEYS), expected
        ):
            _add(
                issues,
                "integrity",
                "v1-baseline-copy-mismatch",
                f"runtime:{row.get('capability_id')}",
                "v2 PR97 runtime row differs from the frozen v1 register row",
            )

    # --- roster checks ----------------------------------------------------------
    modules = _index_unique(document.get("modules", []), name="modules", issues=issues)
    sources = _index_unique(document.get("sources", []), name="sources", issues=issues)
    runtime: dict[str, Mapping[str, Any]] = {}
    for position, row in enumerate(document.get("runtime", [])):
        capability_id = row.get("capability_id")
        if capability_id in runtime:
            _add(
                issues,
                "integrity",
                "duplicate-id",
                f"runtime[{position}].capability_id",
                f"duplicate runtime capability {capability_id}",
            )
        else:
            runtime[capability_id] = row
    if set(modules) != set(V2_EXPECTED_MODULE_IDS):
        _add(
            issues,
            "integrity",
            "v2-module-roster-mismatch",
            "modules",
            f"missing={sorted(set(V2_EXPECTED_MODULE_IDS) - set(modules))!r}; "
            f"added={sorted(set(modules) - set(V2_EXPECTED_MODULE_IDS))!r}",
        )
    if set(sources) != set(V2_EXPECTED_SOURCE_IDS):
        _add(
            issues,
            "integrity",
            "v2-source-roster-mismatch",
            "sources",
            f"missing={sorted(set(V2_EXPECTED_SOURCE_IDS) - set(sources))[:12]!r} "
            f"(truncated); added={sorted(set(sources) - set(V2_EXPECTED_SOURCE_IDS))[:12]!r} (truncated)",
        )
    if set(runtime) != set(inventory.capability_ids):
        _add(
            issues,
            "integrity",
            "v2-runtime-roster-mismatch",
            "runtime",
            f"missing={sorted(set(inventory.capability_ids) - set(runtime))[:12]!r} "
            f"(truncated); added={sorted(set(runtime) - set(inventory.capability_ids))[:12]!r} (truncated)",
        )

    # --- promotion refusal: v2 creates no promotions of any kind ---------------
    for module_id, row in modules.items():
        if row.get("promotion_evidence"):
            _add(
                issues,
                "integrity",
                "promotion-verifier-unimplemented",
                f"module:{module_id}",
                "v2 cannot verify module promotion evidence",
            )
        if row.get("status") == "shipped":
            _add(
                issues,
                "integrity",
                "module-shipped-refused",
                f"module:{module_id}",
                "a v2 register row can never record a shipped module without a "
                "verified promotion path, which v2 does not implement",
            )
    # --- source promotions: the frozen anchor table is the only path ----------
    # The v1 checker's generic binding logic (subject/contract digests,
    # limitations, target status) validates each event against its row; the
    # anchor discipline below adds the operator-authorization invariants.
    promotion_events = document.get("promotion_events", [])
    events_by_id = _index_unique(
        promotion_events, name="promotion_events", issues=issues
    )
    for anchor_source_id, anchor in sorted(V2_AUTHORIZED_PROMOTIONS.items()):
        _check_evidence_ref(
            anchor["authorization_anchor"],
            path=f"anchor:{anchor_source_id}",
            cache=evidence_cache,
            issues=issues,
        )
    referenced_event_ids: set[str] = set()
    for source_id, row in sources.items():
        anchor = V2_AUTHORIZED_PROMOTIONS.get(source_id)
        status = row.get("status")
        if status in ("selected", "admitted"):
            if anchor is None:
                _add(
                    issues,
                    "integrity",
                    "source-selection-refused",
                    f"source:{source_id}",
                    "no authorized promotion anchor exists for this source",
                )
                continue
            if status != anchor["to_status"]:
                _add(
                    issues,
                    "integrity",
                    "promotion-anchor-mismatch",
                    f"source:{source_id}",
                    f"authorized target status is {anchor['to_status']!r}, got {status!r}",
                )
            if list(row.get("rights", {}).get("permitted_uses", [])) != list(
                anchor["permitted_uses"]
            ):
                _add(
                    issues,
                    "integrity",
                    "promotion-anchor-mismatch",
                    f"source:{source_id}",
                    "permitted uses differ from the authorized decision terms",
                )
            selected_revision = row.get("selected_revision")
            if (
                not isinstance(selected_revision, str)
                or anchor["required_pin"] not in selected_revision
            ):
                _add(
                    issues,
                    "integrity",
                    "promotion-anchor-mismatch",
                    f"source:{source_id}",
                    "selected revision does not bind the verified upstream pin",
                )
            digests = row.get("content_digests") or []
            if status == "admitted":
                for required in anchor["required_digests"]:
                    if required not in digests:
                        _add(
                            issues,
                            "integrity",
                            "promotion-anchor-mismatch",
                            f"source:{source_id}",
                            "admitted source must pin the re-derivable slice digest",
                        )
            rights = row.get("rights", {})
            if rights.get("license_review") != "reviewed" or rights.get(
                "data_rights_review"
            ) != "reviewed":
                _add(
                    issues,
                    "integrity",
                    "source-rights-unreviewed",
                    f"source:{source_id}",
                    "promoted source requires recorded license and data-rights reviews",
                )
            if not row.get("promotion_evidence"):
                _add(
                    issues,
                    "integrity",
                    "promotion-evidence-missing",
                    f"source:{source_id}",
                    "promoted source requires its promotion event",
                )
        elif row.get("promotion_evidence"):
            _add(
                issues,
                "integrity",
                "promotion-verifier-unimplemented",
                f"source:{source_id}",
                "promotion evidence on a non-promoted source has no verifier",
            )
        for evidence_ref in row.get("promotion_evidence", []):
            event = events_by_id.get(evidence_ref)
            if event is None:
                _add(
                    issues,
                    "integrity",
                    "unknown-promotion-evidence",
                    f"source:{source_id}",
                    f"unknown promotion event {evidence_ref}",
                )
                continue
            referenced_event_ids.add(evidence_ref)
            if anchor is not None:
                if event.get("reviewer") != V2_PROMOTION_REVIEWER:
                    _add(
                        issues,
                        "integrity",
                        "promotion-anchor-mismatch",
                        f"source:{source_id}",
                        "promotion reviewer must be the recorded repository-operator",
                    )
                if event.get("decided_on") != V2_AUTHORIZATION_DATE:
                    _add(
                        issues,
                        "integrity",
                        "promotion-anchor-mismatch",
                        f"source:{source_id}",
                        "promotion decision date must match the authorization date",
                    )
                if event.get("implementation_revision") != V2_PROMOTION_IMPLEMENTATION_REVISION:
                    _add(
                        issues,
                        "integrity",
                        "promotion-anchor-mismatch",
                        f"source:{source_id}",
                        "promotion must bind the authorized implementation revision",
                    )
                if event.get("subject") != f"source:{source_id}":
                    _add(
                        issues,
                        "integrity",
                        "promotion-subject-mismatch",
                        f"source:{source_id}",
                        f"event {evidence_ref} is bound to {event.get('subject')!r}",
                    )
                if event.get("to_status") != status:
                    _add(
                        issues,
                        "integrity",
                        "promotion-target-mismatch",
                        f"source:{source_id}",
                        f"event {evidence_ref} targets {event.get('to_status')!r}",
                    )
                if event.get("subject_digest") != _governance_subject_digest(row):
                    _add(
                        issues,
                        "integrity",
                        "promotion-subject-digest-mismatch",
                        f"source:{source_id}",
                        f"event {evidence_ref} does not bind the current governance record",
                    )
                if event.get("contract_digest") != _source_contract_digest(row):
                    _add(
                        issues,
                        "integrity",
                        "promotion-contract-digest-mismatch",
                        f"source:{source_id}",
                        f"event {evidence_ref} does not bind the current governance contract",
                    )
                if tuple(event.get("limitations_accepted", ())) != tuple(row["limitations"]):
                    _add(
                        issues,
                        "integrity",
                        "promotion-limitations-mismatch",
                        f"source:{source_id}",
                        f"event {evidence_ref} does not accept the exact limitation set",
                    )
                if event.get("regression_case") != anchor["regression_case"]:
                    _add(
                        issues,
                        "integrity",
                        "promotion-anchor-mismatch",
                        f"source:{source_id}",
                        "promotion must cite its anchor regression case",
                    )
                if event.get("exercised_path") != anchor["exercised_path"]:
                    _add(
                        issues,
                        "integrity",
                        "promotion-anchor-mismatch",
                        f"source:{source_id}",
                        "promotion must cite its anchor exercised path",
                    )
                # Citation resolvability only: both references must name a
                # bounded repo-contained real test file. This never proves
                # the test ran or covered the promotion.
                _check_promotion_test_ref(
                    event.get("regression_case"),
                    path=f"source:{source_id}",
                    code="invalid-regression-ref",
                    issues=issues,
                )
                _check_promotion_test_ref(
                    event.get("exercised_path"),
                    path=f"source:{source_id}",
                    code="invalid-exercised-path-ref",
                    issues=issues,
                )
    anchor_event_ids = {
        evidence_ref
        for source_id, row in sources.items()
        if source_id in V2_PROMOTED_SOURCE_IDS
        for evidence_ref in row.get("promotion_evidence", [])
    }
    promoted_with_evidence = {
        source_id
        for source_id in V2_PROMOTED_SOURCE_IDS
        if (sources.get(source_id, {}).get("promotion_evidence") or [])
    }
    if promoted_with_evidence != set(V2_PROMOTED_SOURCE_IDS):
        _add(
            issues,
            "integrity",
            "promotion-anchor-coverage-mismatch",
            "promotion_events",
            "every authorized promotion must be exercised exactly once; "
            f"missing={sorted(set(V2_PROMOTED_SOURCE_IDS) - promoted_with_evidence)!r}",
        )
    for event_id in sorted(set(events_by_id) - anchor_event_ids):
        _add(
            issues,
            "integrity",
            "promotion-verifier-unimplemented",
            f"promotion_event:{event_id}",
            "event is not bound to an authorized promotion anchor",
        )
    for event_id in sorted(set(events_by_id) - referenced_event_ids):
        _add(
            issues,
            "integrity",
            "orphan-promotion-evidence",
            f"promotion_event:{event_id}",
            "promotion event is not referenced by its subject record",
        )
    for source_id, row in sources.items():
        if row.get("status") == "reference":
            if list(row.get("rights", {}).get("permitted_uses", [])) != ["reference-link-only"]:
                _add(
                    issues,
                    "integrity",
                    "reference-source-permitted-use-mismatch",
                    f"source:{source_id}",
                    "reference sources must be reference-link-only",
                )
            if row.get("schema_correspondence") is not None or row.get("verified_revision") is not None:
                _add(
                    issues,
                    "integrity",
                    "reference-source-overclaim",
                    f"source:{source_id}",
                    "reference sources must not carry verified revisions or schema correspondence",
                )

    # --- runtime reconciliation against the authoritative profiles --------------
    contracts = _index_unique(
        document.get("contract_templates", []), name="contract_templates", issues=issues
    )
    for contract_id, expected in V2_CONTRACT_TEMPLATES.items():
        contract = contracts.get(contract_id)
        if contract is None:
            _add(
                issues,
                "integrity",
                "v2-contract-template-missing",
                f"contract_template:{contract_id}",
                "a v2 frozen contract template is absent from the register",
            )
            continue
        if not _strict_json_equal(_contract_signature(contract), expected):
            _add(
                issues,
                "integrity",
                "v2-contract-template-mismatch",
                f"contract_template:{contract_id}",
                "contract does not match the independently frozen v2 template",
            )
    for capability_id, row in runtime.items():
        row_path = f"runtime:{capability_id}"
        actual = inventory.records.get(capability_id)
        if actual is None:
            _add(
                issues,
                "integrity",
                "missing-authoritative-profile",
                row_path,
                "governed capability is absent from INVOKE_PROFILES",
            )
            continue
        if row.get("arm_id") != actual["arm_id"] or row.get("action") != actual["action"]:
            _add(
                issues,
                "integrity",
                "runtime-identity-mismatch",
                row_path,
                "arm_id/action do not match the authoritative profile",
            )
        if row.get("support_tier") != actual["tier"]:
            _add(
                issues,
                "integrity",
                "runtime-tier-mismatch",
                row_path,
                "support tier does not match the authoritative profile; the live "
                "profile is the tier authority and no register note can override it",
            )
        if row.get("tool_version") != actual["tool_version"]:
            _add(
                issues,
                "integrity",
                "runtime-version-mismatch",
                row_path,
                "tool_version does not match the authoritative profile",
            )
        if row.get("promotion_evidence"):
            _add(
                issues,
                "integrity",
                "promotion-verifier-unimplemented",
                row_path,
                "v2 cannot verify runtime promotion evidence",
            )
        if capability_id in PR97_CAPABILITY_IDS:
            if row.get("implementation_revision") != PR97_IMPLEMENTATION_REVISION:
                _add(
                    issues,
                    "integrity",
                    "runtime-implementation-revision-mismatch",
                    row_path,
                    "PR97 implementation_revision must remain the frozen v1 merge revision",
                )
        elif row.get("implementation_revision") != V2_BASELINE_IMPLEMENTATION_REVISION:
            _add(
                issues,
                "integrity",
                "v2-baseline-revision-mismatch",
                row_path,
                "non-PR97 implementation_revision must equal the v2 governed-as-of baseline",
            )
        contract = contracts.get(row.get("contract_ref"))
        if contract is None:
            _add(
                issues,
                "integrity",
                "unknown-contract",
                row_path,
                f"unknown contract_ref {row.get('contract_ref')}",
            )
        else:
            comparisons = {
                "safety_class": contract["safety_class"],
                "side_effects": sorted(contract["side_effects"]),
                "cleanup_required": contract["cleanup_required"],
                "default_off": contract["default_off"],
                "synthetic_only": contract["synthetic_only"],
                "timeout_ms": contract["timeout_ms"],
                "max_output_bytes": contract["max_output_bytes"],
                "max_tool_steps": contract["max_tool_steps"],
                "max_spend": contract["max_spend"],
            }
            for field, expected_value in comparisons.items():
                observed = actual[field]
                if not _strict_json_equal(observed, expected_value):
                    _add(
                        issues,
                        "integrity",
                        "runtime-contract-mismatch",
                        f"{row_path}.{field}",
                        f"expected {expected_value!r}, got {observed!r}",
                    )
            approval_expected = bool(contract["approval_required"])
            if (actual["approval_ref"] is not None) != approval_expected:
                _add(
                    issues,
                    "integrity",
                    "runtime-contract-mismatch",
                    f"{row_path}.approval_ref",
                    f"approval presence expected {approval_expected!r}",
                )
            if tuple(row.get("known_limitations", ())) != tuple(contract["limitations"]):
                _add(
                    issues,
                    "integrity",
                    "runtime-limitations-mismatch",
                    f"{row_path}.known_limitations",
                    "runtime limitations must exactly match its frozen contract template",
                )
        tier = row.get("support_tier")
        if tier == "maintained":
            if not row.get("supported_versions"):
                _add(
                    issues,
                    "integrity",
                    "maintained-without-supported-versions",
                    row_path,
                    "maintained capability requires supported_versions",
                )
            if not row.get("regression_cases"):
                _add(
                    issues,
                    "integrity",
                    "maintained-without-regression",
                    row_path,
                    "maintained capability requires a regression case",
                )
        provenance = row.get("tier_provenance")
        if provenance is not None:
            if not isinstance(provenance, Mapping):
                _add(
                    issues,
                    "integrity",
                    "tier-provenance-invalid",
                    row_path,
                    "tier_provenance must be a mapping or null",
                )
            else:
                note = provenance.get("note")
                if not isinstance(note, str) or not note.strip():
                    _add(
                        issues,
                        "integrity",
                        "tier-provenance-invalid",
                        row_path,
                        "tier_provenance note must be a nonempty string",
                    )
                decided_on = _parse_date(
                    provenance.get("decided_on"),
                    path=f"{row_path}.tier_provenance.decided_on",
                    issues=issues,
                )
                if decided_on is not None and decided_on > as_of:
                    _add(
                        issues,
                        "integrity",
                        "tier-provenance-in-future",
                        row_path,
                        "tier_provenance decision date is later than as-of",
                    )
                _check_evidence_ref(
                    provenance.get("evidence_ref"),
                    path=f"{row_path}.tier_provenance.evidence_ref",
                    cache=evidence_cache,
                    issues=issues,
                )

    # --- currentness and queue ---------------------------------------------------
    queue = document.get("currentness_queue")
    queue_valid = isinstance(queue, Mapping)
    cadences: Mapping[str, int | None] = {"source": None, "module": None, "runtime": None}
    if not queue_valid:
        _add(
            issues,
            "completeness",
            "currentness-queue-missing",
            "currentness_queue",
            "the v2 register must document its recurring review queue",
        )
    else:
        for label, key in (
            ("source", "source_cadence_days"),
            ("module", "module_cadence_days"),
            ("runtime", "runtime_cadence_days"),
        ):
            value = queue.get(key)
            if type(value) is not int or value < 1:
                _add(
                    issues,
                    "integrity",
                    "currentness-queue-cadence-invalid",
                    f"currentness_queue.{key}",
                    "cadence must be a positive integer",
                )
            else:
                cadences[label] = value
        next_review = _parse_date(
            queue.get("next_review_on"),
            path="currentness_queue.next_review_on",
            issues=issues,
        )
        if next_review is not None and next_review < as_of:
            _add(
                issues,
                "currentness",
                "queue-overdue",
                "currentness_queue.next_review_on",
                "the documented next review date is already due",
            )

    def check_row_currentness(
        owner_ref: str, row: Mapping[str, Any], cadence: int | None, path: str
    ) -> None:
        _check_currentness_v2(
            owner_ref,
            row.get("currentness", {}),
            as_of=as_of,
            path=path,
            issues=issues,
            evidence_cache=evidence_cache,
        )
        currentness = row.get("currentness", {})
        reviewed = _parse_date(
            currentness.get("reviewed_on"), path=f"{path}.reviewed_on", issues=issues
        )
        due = _parse_date(
            currentness.get("review_due_on"), path=f"{path}.review_due_on", issues=issues
        )
        if cadence is not None and reviewed is not None and due is not None:
            if (due - reviewed).days != cadence:
                _add(
                    issues,
                    "integrity",
                    "cadence-window-mismatch",
                    path,
                    f"review window {(due - reviewed).days} days does not match the "
                    f"queue cadence {cadence} days",
                )

    for source_id, row in sources.items():
        check_row_currentness(
            f"source:{source_id}", row, cadences["source"], f"source:{source_id}.currentness"
        )
    for module_id, row in modules.items():
        check_row_currentness(
            f"module:{module_id}", row, cadences["module"], f"module:{module_id}.currentness"
        )
    for capability_id, row in runtime.items():
        check_row_currentness(
            f"runtime:{capability_id}",
            row,
            cadences["runtime"],
            f"runtime:{capability_id}.currentness",
        )

    # --- relationships -------------------------------------------------------------
    entity_refs = {
        *(f"module:{module_id}" for module_id in modules),
        *(f"source:{source_id}" for source_id in sources),
        *(f"runtime:{capability_id}" for capability_id in runtime),
    }
    relationship_ids: set[str] = set()
    depends_on_observed: dict[str, list[str]] = {}
    allowed_pairs = {
        "research-mapping": ("source", "runtime"),
        "proposed-source": ("module", "source"),
        "proposed-use": ("module", "runtime"),
        "depends-on": ("module", "module"),
        "replaces": ("source", "source"),
        "consumes": ("runtime", "source"),
    }
    for position, relationship in enumerate(document.get("relationships", [])):
        rel_path = f"relationships[{position}]"
        rel_id = relationship.get("id")
        if rel_id in relationship_ids:
            _add(issues, "integrity", "duplicate-id", f"{rel_path}.id", str(rel_id))
        relationship_ids.add(rel_id)
        kind = relationship.get("kind")
        if kind not in allowed_pairs:
            _add(
                issues,
                "integrity",
                "relationship-kind-unknown",
                rel_path,
                f"unknown relationship kind {kind!r}",
            )
            continue
        source_ref = relationship.get("from")
        targets = relationship.get("to", [])
        if source_ref not in entity_refs or not _ENTITY_REF_RE.fullmatch(str(source_ref)):
            _add(issues, "integrity", "dangling-relationship", f"{rel_path}.from", str(source_ref))
        if str(source_ref).split(":", 1)[0] != allowed_pairs[kind][0]:
            _add(
                issues,
                "integrity",
                "relationship-kind-endpoints",
                rel_path,
                "relationship kind is incompatible with its source endpoint",
            )
        for target_ref in targets:
            if target_ref not in entity_refs or not _ENTITY_REF_RE.fullmatch(str(target_ref)):
                _add(issues, "integrity", "dangling-relationship", f"{rel_path}.to", str(target_ref))
            if str(target_ref).split(":", 1)[0] != allowed_pairs[kind][1]:
                _add(
                    issues,
                    "integrity",
                    "relationship-kind-endpoints",
                    rel_path,
                    "relationship kind is incompatible with a target endpoint",
                )
        if kind == "depends-on":
            depends_on_observed[str(source_ref).split(":", 1)[1]] = [
                str(t).split(":", 1)[1] for t in targets
            ]
        for evidence_index, evidence_ref in enumerate(relationship.get("evidence_refs", [])):
            _check_evidence_ref(
                evidence_ref,
                path=f"{rel_path}.evidence_refs[{evidence_index}]",
                cache=evidence_cache,
                issues=issues,
            )
    if set(relationship_ids) != set(V2_EXPECTED_RELATIONSHIP_IDS):
        _add(
            issues,
            "integrity",
            "v2-relationship-roster-mismatch",
            "relationships",
            f"missing={sorted(set(V2_EXPECTED_RELATIONSHIP_IDS) - relationship_ids)!r}; "
            f"added={sorted(relationship_ids - set(V2_EXPECTED_RELATIONSHIP_IDS))!r}",
        )
    for module_id, expected_targets in V2_EXPECTED_DEPENDS_ON.items():
        if tuple(depends_on_observed.get(module_id, ())) != tuple(expected_targets):
            _add(
                issues,
                "integrity",
                "v2-depends-on-mismatch",
                f"module:{module_id}",
                f"expected depends-on targets {expected_targets!r}",
            )

    deduped = tuple(sorted(set(issues)))
    report = ValidationReportV2(
        requested_scope=scope,
        register_scope=document.get("scope", {}).get("id"),
        register_revision=document.get("register_revision"),
        register_sha256=(
            loaded_registry.register_sha256 if loaded_registry is not None else None
        ),
        schema_sha256=(
            loaded_registry.schema_sha256 if loaded_registry is not None else None
        ),
        authoritative_inventory_contract_sha256=inventory.contract_sha256,
        coverage_contract_sha256=coverage.contract_sha256,
        coverage_sha256=coverage.source_sha256,
        requirement=require,
        as_of=as_of,
        repository_complete=True,
        inventory_count=len(inventory.capability_ids),
        governed_runtime_count=len(runtime),
        source_count=len(sources),
        module_count=len(modules),
        issues=deduped,
    )
    return report


def _iso_date(value: str) -> date:
    if _DATE_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="validate governance state")
    check.add_argument("--register", type=Path, default=None)
    check.add_argument(
        "--schema",
        type=Path,
        default=None,
        help="path to the canonical schema for the selected register version",
    )
    check.add_argument(
        "--coverage",
        type=Path,
        default=DEFAULT_COVERAGE_PATH,
        help="path to the coverage catalog snapshot",
    )
    check.add_argument(
        "--coverage-schema",
        type=Path,
        default=DEFAULT_COVERAGE_SCHEMA_PATH,
        help="path to the byte-identical canonical coverage schema",
    )
    check.add_argument(
        "--register-version",
        type=int,
        choices=(1, 2),
        default=1,
        help="explicit register schema version to validate (no auto-detection)",
    )
    check.add_argument("--scope", choices=(PR97_SCOPE_ID, FULL_SCOPE_ID, V2_SCOPE_ID), default=FULL_SCOPE_ID)
    check.add_argument("--require", choices=REQUIREMENTS, default="complete")
    check.add_argument("--as-of", type=_iso_date, required=True)
    check.add_argument("--format", choices=("json",), default="json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fail-closed checker: 0 satisfied, 1 gaps, 2 invalid input."""

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.register_version == 2:
            register_path = (
                args.register if args.register is not None else DEFAULT_REGISTER_V2_PATH
            )
            schema_path = (
                args.schema if args.schema is not None else DEFAULT_REGISTER_V2_SCHEMA_PATH
            )
            if args.scope != V2_SCOPE_ID:
                raise ValueError(
                    "register version 2 requires --scope full-v2; the v2 register "
                    "is the full register"
                )
            registry = load_register_v2(register_path, schema_path=schema_path)
            coverage = load_coverage_inventory(
                args.coverage,
                schema_path=args.coverage_schema,
            )
            # Import only in the maintainer command, never on extension/runtime paths.
            from extension.invoke_profiles import INVOKE_PROFILES

            inventory = snapshot_invoke_profiles(INVOKE_PROFILES)
            report = validate_register_v2(
                registry,
                inventory,
                coverage,
                as_of=args.as_of,
                scope=args.scope,
                require=args.require,
            )
        else:
            registry = load_register(
                args.register if args.register is not None else DEFAULT_REGISTER_PATH,
                schema_path=args.schema if args.schema is not None else DEFAULT_SCHEMA_PATH,
            )
            coverage = load_coverage_inventory(
                args.coverage,
                schema_path=args.coverage_schema,
            )
            # Import only in the maintainer command, never on extension/runtime paths.
            from extension.invoke_profiles import INVOKE_PROFILES

            inventory = snapshot_invoke_profiles(INVOKE_PROFILES)
            report = validate_register(
                registry,
                inventory,
                coverage,
                as_of=args.as_of,
                scope=args.scope,
                require=args.require,
            )
    except (RegisterLoadError, ValueError) as exc:
        payload = {
            "schema": "specaudit.ctf.governance.validation-error.v1",
            "ok": False,
            "error": str(exc),
        }
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2
    except (Exception, SystemExit) as exc:
        payload = {
            "schema": "specaudit.ctf.governance.validation-error.v1",
            "ok": False,
            "error": (
                "validation failed closed: "
                f"{type(exc).__name__}: {exc}"
            ),
        }
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), allow_nan=False, indent=2, sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
