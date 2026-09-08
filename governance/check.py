"""Strict, offline validation for the versioned governance register.

The executable admission authority remains
``extension.invoke_profiles.INVOKE_PROFILES``.  This module snapshots that
authority for drift detection and validates governance metadata around it; it
is never imported by dispatch or the sealed runtime.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import json
import math
import os
import re
import stat
import sys
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

REGISTER_SCHEMA_ID = "specaudit.ctf.governance.register.v1"
REGISTER_SCHEMA_VERSION = 1
INVENTORY_AUTHORITY_ID = "extension.invoke_profiles.INVOKE_PROFILES"
EXECUTION_RESULT_SCHEMA_ID = "specaudit.ctf.execution-result.v1"
CANONICAL_SCHEMA_SHA256 = (
    "sha256:8e8edbd7aadcb071dd997437256e9e6b56fbbd344763423172e1183993e60e53"
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
MAX_REGISTER_BYTES = 256 * 1024
MAX_SCHEMA_BYTES = 128 * 1024
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
        "lookup": ("cve_id", "feed", "name"),
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

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._node_count = 0
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
            raise RegisterLoadError("YAML aliases and anchors are not allowed")
        self._node_count += 1
        if self._node_count > MAX_DOCUMENT_NODES:
            raise RegisterLoadError("register YAML exceeds the node cap")
        self._depth += 1
        if self._depth > MAX_DOCUMENT_DEPTH:
            self._depth -= 1
            raise RegisterLoadError("register YAML exceeds the nesting-depth cap")
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
            raise RegisterLoadError("register mapping key is not hashable") from exc
        if duplicate:
            raise RegisterLoadError(f"duplicate YAML mapping key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


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


def _validate_bounded_tree(value: Any, *, label: str) -> None:
    nodes = 0
    total_string_bytes = 0

    def visit(item: Any, depth: int, path: str) -> None:
        nonlocal nodes, total_string_bytes
        nodes += 1
        if nodes > MAX_DOCUMENT_NODES:
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
            if total_string_bytes > MAX_TOTAL_STRING_BYTES:
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
) -> dict[str, dict[str, tuple[str, ...]]]:
    result: dict[str, dict[str, tuple[str, ...]]] = {}
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
            raw = getattr(module, "ARG_KEYS")
            if not isinstance(raw, Mapping):
                raise TypeError("ARG_KEYS is not a mapping")
            raw_allowed = getattr(module, "ALLOWED_ACTIONS")
            if not isinstance(raw_allowed, (set, frozenset)) or not all(
                isinstance(action, str) for action in raw_allowed
            ):
                raise TypeError("ALLOWED_ACTIONS is not a string set")
            normalized: dict[str, tuple[str, ...]] = {}
            for action, keys in raw.items():
                if not isinstance(action, str) or isinstance(keys, (str, bytes)):
                    raise TypeError("ARG_KEYS has an invalid action or key set")
                normalized[action] = tuple(sorted(keys))
            if set(normalized) != set(raw_allowed):
                _add(
                    issues,
                    "integrity",
                    "policy-allowed-action-surface-mismatch",
                    f"policy:{arm_id}",
                    "ALLOWED_ACTIONS and ARG_KEYS must name the same data actions",
                )
            # list_tools is served by the common policy surface and accepts no args.
            normalized.setdefault("list_tools", ())
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
    return result


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
    *,
    as_of: date,
    scope: str = FULL_SCOPE_ID,
    require: str = "complete",
) -> ValidationReport:
    """Validate referential, profile, promotion, and currentness semantics.

    Schema validation belongs to :func:`load_register`.  This function accepts
    a raw mapping as a testing convenience, but still fails closed on semantic
    mismatches and never mutates its input.
    """

    if scope not in (PR97_SCOPE_ID, FULL_SCOPE_ID):
        raise ValueError(f"unknown scope: {scope}")
    if require not in REQUIREMENTS:
        raise ValueError(f"unknown requirement: {require}")
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

    policy_action_arguments = _load_policy_action_arguments(issues)
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
        requirement=require,
        as_of=as_of,
        repository_complete=effective_repository_complete,
        inventory_count=len(inventory.capability_ids),
        governed_runtime_count=len(runtime),
        source_count=len(sources),
        module_count=len(modules),
        issues=tuple(sorted(set(issues))),
    )


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
    check.add_argument("--register", type=Path, default=DEFAULT_REGISTER_PATH)
    check.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help="path to byte-identical canonical v1 schema",
    )
    check.add_argument("--scope", choices=(PR97_SCOPE_ID, FULL_SCOPE_ID), default=FULL_SCOPE_ID)
    check.add_argument("--require", choices=REQUIREMENTS, default="complete")
    check.add_argument("--as-of", type=_iso_date, required=True)
    check.add_argument("--format", choices=("json",), default="json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fail-closed checker: 0 satisfied, 1 gaps, 2 invalid input."""

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        registry = load_register(args.register, schema_path=args.schema)
        # Import only in the maintainer command, never on extension/runtime paths.
        from extension.invoke_profiles import INVOKE_PROFILES

        inventory = snapshot_invoke_profiles(INVOKE_PROFILES)
        report = validate_register(
            registry,
            inventory,
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
