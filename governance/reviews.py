"""Attributed review-history verifier (bounded unit U-GOV.b).

A real verifier, not an unused validator: it reconciles the full
authoritative population (109 sources + 29 modules + 227 runtimes = 365
entities, each with three declared triggers = 1,095 entity/trigger
pairs) against revision-bound history, re-hashes sha256-bound evidence
from offline local Git blobs, checks heading anchors, enforces
hash-linked record chains against the independently pinned initial
digest, refuses future observations and unsupported positive outcomes,
and reports integrity, coverage, and recurrence separately in
deterministic JSON.

Revision binding: every record's evidence files and
its authoritative ``governance/register.v2.yaml`` resolve from offline
local Git objects at that record's exact 40-hex ``inspected_revision``,
never from the working tree and never from a caller-supplied register
(the former ``--register`` override is removed). The closed
review-evidence schema is canonical and pinned (the former
``--review-schema`` override is removed). Schema/history v1 defines no
independently verifiable executed-result protocol, so
``recurring_operation_ok`` remains false for every history: replays,
same-day copies, date-only rewrites, historical declarations, and even
a different/descendant/unrelated commit with all 1,095 observations
relabeled to ``executed-check`` never complete a cycle. A future version
enables recurrence only by defining and binding a closed
executed-result artifact whose dated results reconcile one-to-one to
all governed pairs. Strict date chronology (including ``recorded_on >=
reviewed_on`` and forward-only successor dates) is integrity,
independent of recurrence. The immutable envelope identity (``schema``,
``schema_version``, exact ``history_id``) is pinned together with the
canonical genesis record.

The 2026-10-13 attribution is imported history (``reviewed_on``); the
2026-10-18 import is the actual record (``recorded_on``). This module,
its history JSON, and their hashes did not exist on October 13.
Reviewer attribution is evidence, not authentication. No W2, admission,
or promotion logic lives here; the twelve frozen 2026-10-14 promotion
snapshots are never rewritten and no effective currentness is overlaid.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

import jsonschema
import yaml
from markdown_it import MarkdownIt

from governance.check import V2_EXPECTED_MODULE_IDS, V2_EXPECTED_SOURCE_IDS

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
# The Git executable is resolved once at import: the test suite runs with a
# scrubbed PATH, so late shutil.which lookups would fail. A missing binary
# fails closed at verification time, never silently.
GIT_BIN = shutil.which("git")
DEFAULT_HISTORY_PATH = Path(__file__).resolve().parent / "reviews" / "2026-10-13.attributed.json"
DEFAULT_REVIEW_SCHEMA_PATH = (
    Path(__file__).resolve().parent / "schema" / "review-evidence.v1.schema.json"
)

REVIEW_SCHEMA_ID = "specaudit.ctf.governance.review-evidence.v1"
REVIEW_SCHEMA_VERSION = 1
HISTORY_ID = "attributed-review-history-v1"
REPORT_SCHEMA_ID = "specaudit.ctf.governance.review-verification-report.v1"
ERROR_SCHEMA_ID = "specaudit.ctf.governance.validation-error.v1"

# Independently pinned bytes: the closed review-evidence schema as committed.
CANONICAL_REVIEW_SCHEMA_SHA256 = (
    "sha256:73da26b7c1923627102b5262c2f23d53b7805da9402add70822613cf77c30811"
)
# Independently pinned canonical digest of the genesis record object in the
# committed initial artifact (canonical JSON, not file whitespace). Later
# records bind their predecessor digest to this chain head.
INITIAL_HISTORY_RECORD_DIGEST = (
    "sha256:26efd27f0e6b45db8c081af29f7443c5453bb19d19507b02667f47e7f9b708f5"
)

# The v2 register schema digest is the single source of truth in
# governance.check; it is re-pinned here so epoch-register validation has
# no working-tree dependency beyond the revision-bound schema blob itself.
REGISTER_V2_SCHEMA_ID = "specaudit.ctf.governance.register.v2"
REGISTER_V2_SCHEMA_VERSION = 2
REGISTER_V2_SCOPE_ID = "full-v2"

REQUIREMENTS = ("integrity", "coverage", "recurrence")
EXPECTED_SOURCES = 109
EXPECTED_MODULES = 29
EXPECTED_RUNTIMES = 227
EXPECTED_ENTITIES = 365
EXPECTED_PAIRS = 1095
# One full source/runtime cadence. Reserved for a future version that defines
# a closed executed-result protocol; v1 recurrence is always false.
RECURRENCE_MIN_SPAN_DAYS = 90
# Governed per-class trigger sets for schema/history v1. A policy change
# needs a later explicit schema/register version, not silent acceptance.
SOURCE_TRIGGERS = frozenset(
    {
        "upstream-revision-change",
        "license-or-data-rights-change",
        "link-or-availability-change",
    }
)
MODULE_TRIGGERS = frozenset(
    {
        "criteria-or-threat-change",
        "scenario-or-grading-change",
        "dependency-or-source-change",
    }
)
RUNTIME_TRIGGERS = frozenset(
    {
        "profile-contract-change",
        "implementation-or-dependency-change",
        "supported-version-change",
    }
)
CLASS_TRIGGERS: dict[str, frozenset[str]] = {
    "source": SOURCE_TRIGGERS,
    "module": MODULE_TRIGGERS,
    "runtime": RUNTIME_TRIGGERS,
}
# Schema/history v1 freezes the recorded queue policy as well as its trigger
# vocabulary. A cadence change needs a later explicit version; otherwise an
# internally consistent rewrite could silently postpone every obligation.
CLASS_CADENCE_DAYS: dict[str, int] = {
    "source": 90,
    "module": 182,
    "runtime": 90,
}

REGISTER_V2_REL = "governance/register.v2.yaml"
REGISTER_V2_SCHEMA_REL = "governance/schema/register.v2.schema.json"
REQUIRED_EVIDENCE_PATHS = (
    REGISTER_V2_REL,
    "docs/governance/source-verification-2026-10-13.md",
    REGISTER_V2_SCHEMA_REL,
)
EVIDENCE_SUFFIXES = (".md", ".yaml", ".json")
BASIS_VALUES = frozenset({"historical-declaration", "executed-check", "unknown"})
OUTCOME_VALUES = frozenset({"reviewed", "unknown"})
CHECKED_VIA_VALUES = frozenset(
    {
        "checker-rederived-inventory-reconciliation",
        "primary-source-review",
        "architecture-review",
    }
)
# ls-tree modes for regular files. Symlinks (0120000), submodules (0160000),
# directories (0040000), and anything else are refused as evidence.
REGULAR_BLOB_MODES = frozenset({"100644", "100755"})
# Canonical bytes of governance/schema/register.v2.schema.json, re-pinned here
# so epoch-register validation never depends on the working tree. This must
# equal the V2_CANONICAL_SCHEMA_SHA256 pin in governance/check.py.
V2_CANONICAL_SCHEMA_SHA256 = (
    "sha256:5f28b7e523058afaa90938319d628680976e71a010722bdc1dee6a98a925c9c5"
)

MAX_HISTORY_BYTES = 1024 * 1024
MAX_HISTORY_NODES = 40_000
MAX_HISTORY_STRING_BYTES = 1024 * 1024
MAX_REVIEW_SCHEMA_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_EVIDENCE_LINES = 20_000
MAX_REGISTER_BLOB_BYTES = 1024 * 1024
MAX_REGISTER_SCHEMA_BLOB_BYTES = 128 * 1024
MAX_REGISTER_NODES = 40_000
MAX_REGISTER_STRING_BYTES = 1024 * 1024
MAX_BLOB_CACHE_BYTES = 8 * 1024 * 1024
MAX_DOCUMENT_NODES = 20_000
MAX_DOCUMENT_DEPTH = 48
MAX_STRING_BYTES = 16 * 1024
MAX_TOTAL_STRING_BYTES = 512 * 1024
MAX_GIT_BLOB_LINE_BYTES = 4096
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_ANCHOR_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_PATH_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ReviewLoadError(ValueError):
    """The history or its schema could not be parsed and validated."""


class _GitFailure(Exception):
    """One revision-bound object could not be resolved (fail closed)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _GitUnavailable(ReviewLoadError):
    """Git itself is unusable, so nothing can be revision-verified."""


@dataclass(frozen=True, order=True)
class ReviewIssue:
    """One deterministic integrity, coverage, or recurrence issue."""

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
class ReviewReport:
    """Complete review-history verification outcome."""

    requirement: str
    as_of: date
    history_path: str
    history_sha256: str | None
    register_revision: int | None
    register_sha256: str | None
    review_schema_sha256: str | None
    integrity_ok: bool
    coverage_ok: bool
    recurring_operation_ok: bool
    entities_expected: int
    entities_observed: int
    sources_expected: int
    sources_observed: int
    modules_expected: int
    modules_observed: int
    runtimes_expected: int
    runtimes_observed: int
    pairs_expected: int
    pairs_observed: int
    record_count: int
    next_due_source: str | None
    next_due_runtime: str | None
    next_due_module: str | None
    queue_next_review_on: str | None
    executed_checks: tuple[Mapping[str, Any], ...]
    unknown_outcomes: tuple[str, ...]
    limitations: tuple[str, ...]
    issues: tuple[ReviewIssue, ...]

    @property
    def ok(self) -> bool:
        if self.requirement == "integrity":
            return self.integrity_ok
        if self.requirement == "coverage":
            return self.coverage_ok
        if self.requirement == "recurrence":
            return self.recurring_operation_ok
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA_ID,
            "requirement": self.requirement,
            "as_of": self.as_of.isoformat(),
            "ok": self.ok,
            "integrity_ok": self.integrity_ok,
            "coverage_ok": self.coverage_ok,
            "recurring_operation_ok": self.recurring_operation_ok,
            "history_path": self.history_path,
            "history_sha256": self.history_sha256,
            "register_revision": self.register_revision,
            "register_sha256": self.register_sha256,
            "review_schema_sha256": self.review_schema_sha256,
            "counts": {
                "entities_expected": self.entities_expected,
                "entities_observed": self.entities_observed,
                "sources_expected": self.sources_expected,
                "sources_observed": self.sources_observed,
                "modules_expected": self.modules_expected,
                "modules_observed": self.modules_observed,
                "runtimes_expected": self.runtimes_expected,
                "runtimes_observed": self.runtimes_observed,
                "pairs_expected": self.pairs_expected,
                "pairs_observed": self.pairs_observed,
                "records": self.record_count,
                "issues": len(self.issues),
            },
            "next_due": {
                "source": self.next_due_source,
                "runtime": self.next_due_runtime,
                "module": self.next_due_module,
                "queue_next_review_on": self.queue_next_review_on,
            },
            "executed_checks": [dict(check) for check in self.executed_checks],
            "unknown_outcomes": list(self.unknown_outcomes),
            "limitations": list(self.limitations),
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


def _canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewLoadError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ReviewLoadError(f"JSON history contains non-finite number {value}")


def _reject_non_finite_json(value: Any, *, label: str) -> None:
    """Reject NaN, infinities, and overflow-to-infinity floats recursively.

    ``parse_constant`` only rejects literal ``NaN``/``Infinity`` tokens;
    ``1e999`` parses to a float ``inf`` without invoking it, so the parsed
    tree is walked before schema validation.
    """

    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ReviewLoadError(
                    f"{label} contains a non-finite number (NaN, infinity, "
                    "or overflow-to-infinity)"
                )
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


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
            raise ReviewLoadError(f"{label} exceeds the node cap")
        if depth > MAX_DOCUMENT_DEPTH:
            raise ReviewLoadError(f"{label} exceeds the nesting-depth cap")
        if isinstance(item, str):
            try:
                encoded = item.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise ReviewLoadError(
                    f"{label} contains an invalid Unicode scalar at {path}"
                ) from exc
            if len(encoded) > MAX_STRING_BYTES:
                raise ReviewLoadError(
                    f"{label} string exceeds the {MAX_STRING_BYTES}-byte cap at {path}"
                )
            total_string_bytes += len(encoded)
            if total_string_bytes > max_total_string_bytes:
                raise ReviewLoadError(f"{label} exceeds the total-string cap")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ReviewLoadError(f"{label} has a non-string key at {path}")
                visit(child, depth + 1, f"{path}.{key}")
        elif isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                visit(child, depth + 1, f"{path}[{index}]")

    visit(value, 0, "$")


@dataclass(frozen=True)
class _FileSnapshot:
    data: bytes
    sha256: str


def _read_file_snapshot(path: Path, *, label: str, max_bytes: int) -> _FileSnapshot:
    """Read one bounded regular file through a stable no-follow descriptor.

    This opens exactly the caller-selected input path: it refuses symlinks,
    requires a regular file, and fails when the file changes while being
    read. It claims no repository custody and resolves nothing.
    """

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        initial_path_stat = os.lstat(path)
        if stat.S_ISLNK(initial_path_stat.st_mode):
            raise ReviewLoadError(f"{label} must not be a symlink: {path}")
        if not stat.S_ISREG(initial_path_stat.st_mode):
            raise ReviewLoadError(f"{label} must be a regular file: {path}")
        fd = os.open(path, flags)
    except ReviewLoadError:
        raise
    except OSError as exc:
        raise ReviewLoadError(f"cannot open {label} {path}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ReviewLoadError(f"{label} must be a regular file: {path}")
        if (before.st_dev, before.st_ino) != (
            initial_path_stat.st_dev,
            initial_path_stat.st_ino,
        ):
            raise ReviewLoadError(f"{label} path changed while opening: {path}")
        if before.st_size > max_bytes:
            raise ReviewLoadError(
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
                raise ReviewLoadError(
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
            raise ReviewLoadError(f"{label} changed while being read: {path}")
    except OSError as exc:
        raise ReviewLoadError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        os.close(fd)
    data = b"".join(chunks)
    return _FileSnapshot(
        data=data,
        sha256="sha256:" + hashlib.sha256(data).hexdigest(),
    )


def _read_canonical_repo_bytes(
    relative: str, *, label: str, max_bytes: int, expected_sha256: str
) -> bytes:
    """Read a pinned repository file with no-follow semantics per component.

    Traversal starts at an anchored directory fd for the repository root and
    every path component is opened with ``O_NOFOLLOW`` (directories included),
    so a parent-directory swap or symlink substitution cannot redirect the
    read. There is no resolve/check/reopen step. The bytes must then match
    the independently pinned digest exactly.
    """

    parts = PurePosixPath(relative).parts
    if (
        not parts
        or len(parts) > 8
        or any(_PATH_PART_RE.fullmatch(part) is None for part in parts)
    ):
        raise ReviewLoadError(f"{label} has an invalid repository path: {relative!r}")
    if not relative.endswith(EVIDENCE_SUFFIXES):
        raise ReviewLoadError(f"{label} has an unsupported suffix: {relative!r}")
    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    no_follow = open_flags | getattr(os, "O_NOFOLLOW", 0)
    # The final component opens non-blocking so a FIFO/device substitution
    # is rejected without hanging; regularity is checked before any read.
    no_follow_nonblock = no_follow | getattr(os, "O_NONBLOCK", 0)
    try:
        current_fd = os.open(
            REPOSITORY_ROOT, open_flags | getattr(os, "O_DIRECTORY", 0)
        )
    except OSError as exc:
        raise ReviewLoadError(
            f"cannot anchor the repository root for {label}: {exc}"
        ) from exc
    try:
        for part in parts[:-1]:
            try:
                child_fd = os.open(
                    part,
                    no_follow | getattr(os, "O_DIRECTORY", 0),
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise ReviewLoadError(
                    f"{label} traversal refused at {part!r}: {exc}"
                ) from exc
            child_stat = os.fstat(child_fd)
            os.close(current_fd)
            if not stat.S_ISDIR(child_stat.st_mode):
                os.close(child_fd)
                raise ReviewLoadError(
                    f"{label} traversal refused: {part!r} is not a directory"
                )
            current_fd = child_fd
        try:
            fd = os.open(parts[-1], no_follow_nonblock, dir_fd=current_fd)
            file_stat = os.fstat(fd)
        except OSError as exc:
            raise ReviewLoadError(
                f"{label} cannot be opened without following symlinks: {exc}"
            ) from exc
        try:
            if not stat.S_ISREG(file_stat.st_mode):
                raise ReviewLoadError(f"{label} must be a regular file")
            if file_stat.st_size > max_bytes:
                raise ReviewLoadError(
                    f"{label} exceeds the {max_bytes}-byte input cap"
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
                    raise ReviewLoadError(
                        f"{label} exceeds the {max_bytes}-byte input cap"
                    )
            closing = os.fstat(fd)
            if (
                closing.st_dev,
                closing.st_ino,
                closing.st_size,
            ) != (file_stat.st_dev, file_stat.st_ino, file_stat.st_size):
                raise ReviewLoadError(f"{label} changed while being read")
        finally:
            os.close(fd)
    finally:
        os.close(current_fd)
    data = b"".join(chunks)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise ReviewLoadError(
            f"{label} does not match the canonical digest: expected "
            f"{expected_sha256}, got {digest}"
        )
    return data


def _strict_utf8(data: bytes, *, label: str) -> str:
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReviewLoadError(f"{label} must be strict UTF-8: {exc}") from exc


def _evidence_heading_anchors(markdown: str) -> set[str]:
    """GitHub-style heading anchors, matching the governance checker rules."""

    logical_lines = (
        markdown.count("\n")
        + markdown.count("\r")
        - markdown.count("\r\n")
        + (1 if markdown and not markdown.endswith(("\n", "\r")) else 0)
    )
    if logical_lines > MAX_EVIDENCE_LINES:
        raise ReviewLoadError(
            "evidence Markdown exceeds maximum logical line count "
            f"of {MAX_EVIDENCE_LINES}"
        )
    occurrences: dict[str, int] = {}
    try:
        tokens = MarkdownIt("commonmark").parse(markdown)
    except (Exception, SystemExit) as exc:
        raise ReviewLoadError(
            f"cannot parse evidence Markdown: {type(exc).__name__}: {exc}"
        ) from exc
    anchors: set[str] = set()
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
            raise ReviewLoadError(
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


def _reject_nonlocal_refs(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key == "$ref":
                if not isinstance(child, str) or not (
                    child == "#" or child.startswith("#/")
                ):
                    raise ReviewLoadError(
                        f"schema has non-local $ref at {child_path}: {child!r}"
                    )
            _reject_nonlocal_refs(child, path=child_path)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_nonlocal_refs(child, path=f"{path}[{index}]")


class _StrictYamlLoader(yaml.SafeLoader):
    """YAML loader that refuses duplicate mapping keys."""


def _construct_no_duplicate_keys(loader: yaml.Loader, node: yaml.Node, deep: bool = False) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in mapping:
            raise yaml.YAMLError(f"duplicate YAML mapping key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


_StrictYamlLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_no_duplicate_keys,
)


def _load_strict_yaml(text: str, *, label: str) -> Any:
    """Parse YAML with duplicate-key, alias, and non-finite refusal."""

    try:
        events = list(yaml.parse(text))
    except yaml.YAMLError as exc:
        raise ReviewLoadError(f"invalid {label} YAML: {exc}") from exc
    for event in events:
        if isinstance(event, yaml.events.AliasEvent):
            raise ReviewLoadError(f"{label} YAML must not contain aliases")
    try:
        document = yaml.load(text, Loader=_StrictYamlLoader)
    except ReviewLoadError:
        raise
    except (RecursionError, yaml.YAMLError) as exc:
        raise ReviewLoadError(f"invalid {label} YAML: {exc}") from exc
    _reject_non_finite_json(document, label=label)
    return document


def _load_strict_json(raw: str, *, label: str) -> Any:
    """Parse JSON with duplicate-key and non-finite refusal."""

    try:
        document = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except ReviewLoadError:
        raise
    except (RecursionError, json.JSONDecodeError) as exc:
        raise ReviewLoadError(f"cannot parse {label}: {exc}") from exc
    _reject_non_finite_json(document, label=label)
    return document


@dataclass
class _RevisionBlobStore:
    """Bounded cache of revision-bound blobs read from local Git objects.

    All Git access uses subprocess argv (never a shell) and only local
    object reads (``cat-file``, ``ls-tree``); no fetch and no network.
    One Git pipeline per unique (revision, path) pair: repeated
    observations sharing an evidence file reuse the cached bytes, so
    verification never runs Git per observation.
    """

    repo_root: Path
    blobs: dict[tuple[str, str], bytes] = field(default_factory=dict)
    failures: dict[tuple[str, str], _GitFailure] = field(default_factory=dict)
    revision_is_commit: dict[str, bool] = field(default_factory=dict)
    cached_bytes: int = 0
    fetches: int = 0
    git_calls: int = 0

    def _run_git(self, *args: str) -> tuple[int, bytes, str]:
        if GIT_BIN is None:
            raise _GitUnavailable(
                "git is unavailable, so revision-bound evidence cannot be verified"
            )
        # Only local object reads are admitted; nothing here may fetch or
        # invoke a remote helper. Replacement objects are disabled via the
        # leading --no-replace-objects flag, not via mutable config.
        if not args or args[0] not in ("cat-file", "ls-tree"):
            raise _GitFailure(
                "git-command-refused",
                f"refused git subcommand {args[:1]!r}: only local "
                "cat-file/ls-tree reads are admitted",
            )
        # Fresh closed environment: no ambient copy is inherited, so
        # GIT_DIR/GIT_WORK_TREE/GIT_OBJECT_DIRECTORY, global/system config
        # overrides, and lazy promisor fetches cannot redirect the read.
        # Linked-worktree discovery still works because it resolves from the
        # filesystem (-C root plus its local .git file/commondir), not env.
        closed_env = {
            "PATH": str(Path(GIT_BIN).resolve().parent),
            "LC_ALL": "C",
            "LANG": "C",
            "LANGUAGE": "C",
            "TZ": "UTC",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
        if os.name == "nt":
            # Windows process startup may require the side-by-side assembly
            # directory. Match the one documented non-secret bootstrap key
            # case-insensitively and emit it canonically; inherit nothing else.
            for key, value in os.environ.items():
                if key.lower() == "systemroot":
                    closed_env["SystemRoot"] = value
                    break
        try:
            proc = subprocess.run(
                [GIT_BIN, "--no-replace-objects", "-C", str(self.repo_root), *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                env=closed_env,
                check=False,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise _GitUnavailable(
                "git is unavailable, so revision-bound evidence cannot "
                f"be verified: {exc}"
            ) from exc
        except OSError as exc:
            raise _GitUnavailable(f"cannot run git: {exc}") from exc
        self.git_calls += 1
        return (
            proc.returncode,
            proc.stdout,
            proc.stderr.decode("utf-8", errors="replace").strip(),
        )

    def check_revision_is_commit(self, revision: str) -> None:
        """Verify a 40-hex revision names a commit object, fail closed."""

        cached = self.revision_is_commit.get(revision)
        if cached is not None:
            if not cached:
                raise _GitFailure(
                    "revision-not-commit",
                    f"revision {revision} is not a commit object",
                )
            return
        returncode, stdout, stderr = self._run_git("cat-file", "-t", revision)
        if returncode != 0:
            self.revision_is_commit[revision] = False
            raise _GitFailure(
                "revision-unknown",
                f"revision {revision} is not a known local Git object"
                + (f": {stderr}" if stderr else ""),
            )
        if stdout.decode("ascii", errors="replace").strip() != "commit":
            self.revision_is_commit[revision] = False
            raise _GitFailure(
                "revision-not-commit",
                f"revision {revision} is not a commit object",
            )
        self.revision_is_commit[revision] = True

    def read_blob(self, revision: str, relative: str, *, max_bytes: int) -> bytes:
        """Read one bounded regular blob at (revision, path), fail closed."""

        key = (revision, relative)
        if key in self.blobs:
            return self.blobs[key]
        if key in self.failures:
            raise self.failures[key]
        try:
            data = self._fetch_blob(revision, relative, max_bytes=max_bytes)
        except _GitFailure as exc:
            self.failures[key] = exc
            raise
        except _GitUnavailable:
            raise
        if self.cached_bytes + len(data) > MAX_BLOB_CACHE_BYTES:
            failure = _GitFailure(
                "blob-cache-budget-exceeded",
                f"revision blob cache exceeds {MAX_BLOB_CACHE_BYTES} bytes",
            )
            self.failures[key] = failure
            raise failure
        self.blobs[key] = data
        self.cached_bytes += len(data)
        self.fetches += 1
        return data

    def _fetch_blob(self, revision: str, relative: str, *, max_bytes: int) -> bytes:
        self.check_revision_is_commit(revision)
        returncode, stdout, stderr = self._run_git("ls-tree", revision, "--", relative)
        if returncode != 0:
            raise _GitFailure(
                "evidence-path-missing",
                f"cannot list tree entry for {relative} at {revision}"
                + (f": {stderr}" if stderr else ""),
            )
        lines = stdout.split(b"\n")
        entries: list[tuple[str, str, str]] = []
        for line in lines:
            if not line:
                continue
            if len(line) > MAX_GIT_BLOB_LINE_BYTES:
                raise _GitFailure(
                    "evidence-ambiguous-entry",
                    f"tree entry for {relative} at {revision} is not a single blob",
                )
            try:
                meta, name = line.split(b"\t", 1)
                mode, kind, obj_hash = meta.decode("ascii").split(" ")
            except (ValueError, UnicodeDecodeError) as exc:
                raise _GitFailure(
                    "evidence-ambiguous-entry",
                    f"tree entry for {relative} at {revision} is unparseable: {exc}",
                ) from exc
            entries.append((mode, kind, obj_hash))
            if name.decode("utf-8", errors="replace") != relative:
                raise _GitFailure(
                    "evidence-ambiguous-entry",
                    f"tree entry for {relative} at {revision} names an unexpected path",
                )
        if not entries:
            raise _GitFailure(
                "evidence-path-missing",
                f"path {relative} is absent at revision {revision}",
            )
        if len(entries) > 1:
            raise _GitFailure(
                "evidence-ambiguous-entry",
                f"path {relative} is ambiguous at revision {revision}",
            )
        mode, kind, obj_hash = entries[0]
        if _HEX40_RE.fullmatch(obj_hash) is None:
            raise _GitFailure(
                "evidence-ambiguous-entry",
                f"path {relative} at {revision} has a non-blob object id",
            )
        if kind != "blob" or mode not in REGULAR_BLOB_MODES:
            raise _GitFailure(
                "evidence-non-blob",
                f"path {relative} at {revision} is not a regular file blob "
                f"(mode {mode} type {kind}); symlinks and submodules are refused",
            )
        returncode, stdout, stderr = self._run_git("cat-file", "-s", obj_hash)
        if returncode != 0:
            raise _GitFailure(
                "evidence-path-missing",
                f"cannot size blob for {relative} at {revision}"
                + (f": {stderr}" if stderr else ""),
            )
        try:
            size = int(stdout.decode("ascii").strip())
        except ValueError as exc:
            raise _GitFailure(
                "evidence-path-missing",
                f"cannot size blob for {relative} at {revision}: {exc}",
            ) from exc
        if size > max_bytes:
            raise _GitFailure(
                "evidence-oversized",
                f"blob for {relative} at {revision} is {size} bytes, "
                f"over the {max_bytes}-byte cap",
            )
        returncode, data, stderr = self._run_git("cat-file", "blob", obj_hash)
        if returncode != 0:
            raise _GitFailure(
                "evidence-path-missing",
                f"cannot read blob for {relative} at {revision}"
                + (f": {stderr}" if stderr else ""),
            )
        if len(data) != size:
            raise _GitFailure(
                "evidence-path-missing",
                f"blob for {relative} at {revision} changed while being read",
            )
        return data


def _resolve_repo_root(repo_root: Path | str | None) -> Path:
    root = REPOSITORY_ROOT if repo_root is None else Path(repo_root)
    if not root.is_absolute():
        raise ReviewLoadError(f"repository root must be absolute: {root}")
    if not root.is_dir() or root.is_symlink():
        raise ReviewLoadError(f"repository root is not a directory: {root}")
    return root


def load_review_schema() -> tuple[Mapping[str, Any], str]:
    """Load the canonical closed review-evidence schema.

    There is no path override: the bytes are traversed from the anchored
    repository root with no-follow semantics for every component and must
    match the independently pinned canonical digest exactly.
    """

    data = _read_canonical_repo_bytes(
        "governance/schema/review-evidence.v1.schema.json",
        label="review schema",
        max_bytes=MAX_REVIEW_SCHEMA_BYTES,
        expected_sha256=CANONICAL_REVIEW_SCHEMA_SHA256,
    )
    raw = _strict_utf8(data, label="review schema")
    schema = _load_strict_json(raw, label="review schema")
    _validate_bounded_tree(schema, label="review schema")
    _reject_nonlocal_refs(schema)
    try:
        jsonschema.Draft7Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        raise ReviewLoadError(f"invalid review schema: {exc.message}") from exc
    if schema.get("$id", "").endswith("review-evidence.v1.schema.json") is False:
        raise ReviewLoadError("review schema has an unexpected $id")
    if schema.get("title") != REVIEW_SCHEMA_ID:
        raise ReviewLoadError("review schema title must be " + REVIEW_SCHEMA_ID)
    return schema, CANONICAL_REVIEW_SCHEMA_SHA256


def load_history(
    path: Path | str = DEFAULT_HISTORY_PATH,
) -> tuple[Mapping[str, Any], str, str]:
    """Load a history file through strict parsing and the closed schema.

    The history file itself is an explicit caller-selected input: it is
    opened boundedly with no-follow semantics and no repository-custody
    claim. The schema is always the pinned canonical one.
    """

    schema, schema_sha256 = load_review_schema()
    history_file = Path(path)
    snapshot = _read_file_snapshot(
        history_file, label="review history", max_bytes=MAX_HISTORY_BYTES
    )
    raw = _strict_utf8(snapshot.data, label="review history")
    document = _load_strict_json(raw, label="review history")
    if not isinstance(document, dict):
        raise ReviewLoadError("review history must be a JSON object")
    _validate_bounded_tree(
        document,
        label="review history",
        max_nodes=MAX_HISTORY_NODES,
        max_total_string_bytes=MAX_HISTORY_STRING_BYTES,
    )
    try:
        validator = jsonschema.Draft7Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except jsonschema.SchemaError as exc:
        raise ReviewLoadError(f"invalid review schema: {exc.message}") from exc
    except Exception as exc:
        raise ReviewLoadError(
            f"review schema validation failed closed: {type(exc).__name__}: {exc}"
        ) from exc
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        raise ReviewLoadError(
            f"review history schema error at {location}: {error.message}"
        )
    if document.get("schema") != REVIEW_SCHEMA_ID:
        raise ReviewLoadError("review history has an unexpected schema id")
    if document.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise ReviewLoadError("review history has an unexpected schema version")
    if document.get("history_id") != HISTORY_ID:
        raise ReviewLoadError("review history has an unexpected history id")
    return document, snapshot.sha256, schema_sha256


def _parse_date(value: Any, *, path: str, issues: list[ReviewIssue]) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str) or _DATE_RE.fullmatch(value) is None:
        issues.append(
            ReviewIssue("integrity", "invalid-date", path, "must be YYYY-MM-DD")
        )
        return None
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        issues.append(
            ReviewIssue("integrity", "invalid-date", path, "must be YYYY-MM-DD")
        )
        return None


def _add(
    issues: list[ReviewIssue], category: str, code: str, path: str, message: str
) -> None:
    issues.append(ReviewIssue(category, code, path, message))


def _check_repo_relative_file(
    value: Any, *, allowed_suffixes: tuple[str, ...] = EVIDENCE_SUFFIXES
) -> PurePosixPath | None:
    if not isinstance(value, str) or not value:
        return None
    if "\\" in value:
        return None
    relative = PurePosixPath(value)
    if relative.is_absolute():
        return None
    if any(part in {"", ".", ".."} for part in relative.parts):
        return None
    if any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value
    ):
        return None
    if not value.endswith(allowed_suffixes):
        return None
    return relative


@dataclass
class _EpochRegister:
    """One record's revision-bound, validated register population."""

    document: Mapping[str, Any]
    sha256: str
    expected: dict[str, dict[str, Any]]
    class_counts: dict[str, int]
    dues: dict[str, str | None]
    queue_next: str | None


def _build_expected_map(
    register_document: Mapping[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, int],
    dict[str, str | None],
    str | None,
]:
    """Index the authoritative population: entity -> class/triggers/checks."""

    expected: dict[str, dict[str, Any]] = {}
    for row in register_document.get("modules", []):
        if not isinstance(row, dict):
            continue
        entity = f"module:{row.get('id')}"
        currentness = row.get("currentness", {})
        if not isinstance(currentness, Mapping):
            currentness = {}
        checks = {
            item["trigger"]: item
            for item in currentness.get("trigger_checks", [])
            if isinstance(item, dict) and "trigger" in item
        }
        expected[entity] = {
            "class": "module",
            "triggers": frozenset(currentness.get("triggers", [])),
            "checks": checks,
            "reviewed_on": currentness.get("reviewed_on"),
            "review_due_on": currentness.get("review_due_on"),
        }
    for row in register_document.get("sources", []):
        if not isinstance(row, dict):
            continue
        entity = f"source:{row.get('id')}"
        currentness = row.get("currentness", {})
        if not isinstance(currentness, Mapping):
            currentness = {}
        checks = {
            item["trigger"]: item
            for item in currentness.get("trigger_checks", [])
            if isinstance(item, dict) and "trigger" in item
        }
        expected[entity] = {
            "class": "source",
            "triggers": frozenset(currentness.get("triggers", [])),
            "checks": checks,
            "reviewed_on": currentness.get("reviewed_on"),
            "review_due_on": currentness.get("review_due_on"),
        }
    for row in register_document.get("runtime", []):
        if not isinstance(row, dict):
            continue
        entity = f"runtime:{row.get('capability_id')}"
        currentness = row.get("currentness", {})
        if not isinstance(currentness, Mapping):
            currentness = {}
        checks = {
            item["trigger"]: item
            for item in currentness.get("trigger_checks", [])
            if isinstance(item, dict) and "trigger" in item
        }
        expected[entity] = {
            "class": "runtime",
            "triggers": frozenset(currentness.get("triggers", [])),
            "checks": checks,
            "reviewed_on": currentness.get("reviewed_on"),
            "review_due_on": currentness.get("review_due_on"),
        }
    class_counts = {"module": 0, "source": 0, "runtime": 0}
    for entity, info in expected.items():
        class_counts[info["class"]] += 1
    dues: dict[str, str | None] = {"source": None, "runtime": None, "module": None}
    for cls in ("source", "runtime", "module"):
        due_dates = sorted(
            {
                info["review_due_on"]
                for entity, info in expected.items()
                if info["class"] == cls and isinstance(info["review_due_on"], str)
            }
        )
        # "Next due" is the earliest outstanding obligation in the class.
        # Using the maximum would hide an earlier row in a staggered epoch.
        dues[cls] = due_dates[0] if due_dates else None
    queue = register_document.get("currentness_queue", {})
    queue_next = queue.get("next_review_on") if isinstance(queue, Mapping) else None
    return expected, class_counts, dues, queue_next if isinstance(queue_next, str) else None


def _parse_epoch_date(
    value: Any, *, path: str, issues: list[ReviewIssue]
) -> date | None:
    """Parse one epoch currentness date as a real calendar date (fail closed)."""

    if not isinstance(value, str) or _DATE_RE.fullmatch(value) is None:
        _add(issues, "integrity", "register-invalid-date", path, "must be YYYY-MM-DD")
        return None
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        _add(issues, "integrity", "register-invalid-date", path, "must be a real calendar date")
        return None


def _validate_epoch_register(
    register_bytes: bytes,
    schema_bytes: bytes,
    *,
    rpath: str,
    issues: list[ReviewIssue],
    recorded: date | None = None,
    expected_entity_roster: frozenset[str] | None = None,
) -> _EpochRegister | None:
    """Parse and semantically validate one epoch's register bytes.

    The bytes are the exact revision-bound blob, already digest-checked
    against the record's evidence binding. Governed per-class trigger sets
    are exact for v1 (a policy change needs a later explicit version),
    exactly one trigger check is required per declared trigger (duplicates
    fail even when other fields differ, orphans fail), exactly 1,095 pairs
    are required per epoch, every reviewed_on/review_due_on must be a real
    calendar date with reviewed_on < review_due_on and reviewed_on not after
    the enclosing record's recorded_on, each due must equal reviewed_on plus
    the epoch queue cadence, and next_review_on must equal the earliest
    governed due date. Duplicate identities, roster drift, and cadence drift
    all fail closed. Dates are additionally enforced with Draft7
    FormatChecker at the schema layer.
    """

    try:
        schema = _load_strict_json(
            _strict_utf8(schema_bytes, label="register v2 schema"),
            label="register v2 schema",
        )
    except ReviewLoadError as exc:
        _add(
            issues, "integrity", "register-schema-invalid", f"{rpath}.register",
            f"epoch register schema cannot be parsed: {exc}",
        )
        return None
    try:
        _validate_bounded_tree(schema, label="register v2 schema")
        _reject_nonlocal_refs(schema)
    except ReviewLoadError as exc:
        _add(
            issues, "integrity", "register-schema-invalid", f"{rpath}.register",
            f"epoch register schema is not bounded and local: {exc}",
        )
        return None
    try:
        jsonschema.Draft7Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        _add(
            issues, "integrity", "register-schema-invalid", f"{rpath}.register",
            f"epoch register schema is invalid: {exc.message}",
        )
        return None
    try:
        text = register_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        _add(
            issues, "integrity", "register-epoch-unavailable", f"{rpath}.register",
            f"epoch register bytes are not strict UTF-8: {exc}",
        )
        return None
    try:
        register_document = _load_strict_yaml(text, label="register v2")
    except ReviewLoadError as exc:
        _add(
            issues, "integrity", "register-invalid", f"{rpath}.register",
            f"epoch register cannot be parsed: {exc}",
        )
        return None
    if not isinstance(register_document, dict):
        _add(
            issues, "integrity", "register-invalid", f"{rpath}.register",
            "epoch register must be a mapping",
        )
        return None
    try:
        _validate_bounded_tree(
            register_document,
            label="register v2",
            max_nodes=MAX_REGISTER_NODES,
            max_total_string_bytes=MAX_REGISTER_STRING_BYTES,
        )
    except ReviewLoadError as exc:
        _add(
            issues, "integrity", "register-invalid", f"{rpath}.register",
            f"epoch register exceeds its bounds: {exc}",
        )
        return None
    try:
        validator = jsonschema.Draft7Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        schema_errors = sorted(
            validator.iter_errors(register_document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except Exception as exc:
        _add(
            issues, "integrity", "register-epoch-unavailable", f"{rpath}.register",
            f"epoch register validation failed closed: {type(exc).__name__}: {exc}",
        )
        return None
    if schema_errors:
        error = schema_errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        _add(
            issues, "integrity", "register-schema-violation", f"{rpath}.register",
            f"epoch register violates its schema at {location}: {error.message}",
        )
        return None
    if register_document.get("schema") != REGISTER_V2_SCHEMA_ID:
        _add(
            issues, "integrity", "register-schema-violation", f"{rpath}.register",
            "epoch register has an unexpected schema id",
        )
        return None
    if register_document.get("schema_version") != REGISTER_V2_SCHEMA_VERSION:
        _add(
            issues, "integrity", "register-schema-violation", f"{rpath}.register",
            "epoch register has an unexpected schema version",
        )
        return None
    valid = True
    queue = register_document.get("currentness_queue", {})
    cadences: dict[str, int | None] = {"source": None, "module": None, "runtime": None}
    if isinstance(queue, Mapping):
        for cls_key, field in (
            ("source", "source_cadence_days"),
            ("module", "module_cadence_days"),
            ("runtime", "runtime_cadence_days"),
        ):
            value = queue.get(field)
            cadences[cls_key] = value if isinstance(value, int) and value >= 1 else None
            if value != CLASS_CADENCE_DAYS[cls_key]:
                _add(
                    issues, "integrity", "register-cadence-unexpected",
                    f"{rpath}.register.currentness_queue.{field}",
                    f"schema/history v1 requires {cls_key} cadence "
                    f"{CLASS_CADENCE_DAYS[cls_key]} days, got {value!r}",
                )
                valid = False
    else:
        queue = {}
    section_class = {"modules": "module", "sources": "source", "runtime": "runtime"}
    all_dues: list[date] = []
    for section, key in (
        ("modules", "id"),
        ("sources", "id"),
        ("runtime", "capability_id"),
    ):
        cls = section_class[section]
        governed = CLASS_TRIGGERS[cls]
        rows = register_document.get(section, [])
        seen: set[Any] = set()
        if not isinstance(rows, list):
            continue
        for position, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            identity = row.get(key)
            if identity in seen:
                _add(
                    issues, "integrity", "register-duplicate-id",
                    f"{rpath}.register.{section}[{position}].{key}",
                    f"duplicate {section} identity {identity!r} in the epoch register",
                )
                valid = False
            seen.add(identity)
            if cls == "runtime":
                structural_id = f"{row.get('arm_id')}.{row.get('action')}"
                if identity != structural_id:
                    _add(
                        issues, "integrity", "register-runtime-structural-id-mismatch",
                        f"{rpath}.register.{section}[{position}].{key}",
                        f"runtime identity {identity!r} must equal arm_id + '.' + "
                        f"action ({structural_id!r})",
                    )
                    valid = False
            currentness = row.get("currentness", {})
            if not isinstance(currentness, Mapping):
                currentness = {}
            triggers = currentness.get("triggers", [])
            checks_raw = currentness.get("trigger_checks", [])
            if not isinstance(triggers, list):
                triggers = []
            if not isinstance(checks_raw, list):
                checks_raw = []
            if isinstance(triggers, list) and len(set(triggers)) != len(triggers):
                _add(
                    issues, "integrity", "register-duplicate-trigger",
                    f"{rpath}.register.{section}[{position}]",
                    f"duplicate triggers for {identity!r} in the epoch register",
                )
                valid = False
            # Exact governed per-class trigger set for v1; silent policy
            # drift needs a later explicit version.
            if set(triggers) != set(governed):
                _add(
                    issues, "integrity", "register-trigger-set-unexpected",
                    f"{rpath}.register.{section}[{position}]",
                    f"trigger set for {identity!r} is not the governed "
                    f"{cls} set {sorted(governed)!r}",
                )
                valid = False
            check_names_list = [
                item.get("trigger") for item in checks_raw if isinstance(item, dict)
            ]
            if len(check_names_list) != len(set(check_names_list)):
                _add(
                    issues, "integrity", "register-duplicate-check",
                    f"{rpath}.register.{section}[{position}]",
                    f"duplicate trigger checks for {identity!r}; exactly one "
                    "check is required per declared trigger",
                )
                valid = False
            check_names = set(check_names_list)
            for trigger in triggers:
                if trigger not in check_names:
                    _add(
                        issues, "integrity", "register-trigger-check-missing",
                        f"{rpath}.register.{section}[{position}]",
                        f"trigger {trigger!r} for {identity!r} has no trigger check "
                        "in the epoch register",
                    )
                    valid = False
            for name in check_names_list:
                if name not in set(triggers):
                    _add(
                        issues, "integrity", "register-orphan-check",
                        f"{rpath}.register.{section}[{position}]",
                        f"orphan trigger check {name!r} for {identity!r}: not a "
                        "declared trigger in the epoch register",
                    )
                    valid = False
            # Epoch currentness dates: real calendar dates, ordered window,
            # reviewed_on not after the enclosing record, due equals reviewed
            # plus the epoch queue cadence for the class.
            reviewed = _parse_epoch_date(
                currentness.get("reviewed_on"),
                path=f"{rpath}.register.{section}[{position}].currentness.reviewed_on",
                issues=issues,
            )
            due = _parse_epoch_date(
                currentness.get("review_due_on"),
                path=f"{rpath}.register.{section}[{position}].currentness.review_due_on",
                issues=issues,
            )
            if reviewed is None or due is None:
                valid = False
            else:
                if not reviewed < due:
                    _add(
                        issues, "integrity", "register-window-inverted",
                        f"{rpath}.register.{section}[{position}]",
                        f"review window is not ordered for {identity!r}: "
                        f"reviewed_on {reviewed.isoformat()} must be before "
                        f"review_due_on {due.isoformat()}",
                    )
                    valid = False
                if recorded is not None and reviewed > recorded:
                    _add(
                        issues, "integrity", "register-window-future",
                        f"{rpath}.register.{section}[{position}]",
                        f"reviewed_on {reviewed.isoformat()} for {identity!r} is "
                        f"after the enclosing record recorded_on "
                        f"{recorded.isoformat()}",
                    )
                    valid = False
                cadence = cadences[cls]
                if cadence is not None:
                    if due != reviewed + timedelta(days=cadence):
                        _add(
                            issues, "integrity", "register-due-cadence-mismatch",
                            f"{rpath}.register.{section}[{position}]",
                            f"review_due_on {due.isoformat()} for {identity!r} is "
                            f"not reviewed_on plus the {cls} cadence "
                            f"({cadence} days)",
                        )
                        valid = False
                all_dues.append(due)
    if not valid:
        return None
    expected, class_counts, dues, queue_next = _build_expected_map(register_document)
    if (
        class_counts["source"] != EXPECTED_SOURCES
        or class_counts["module"] != EXPECTED_MODULES
        or class_counts["runtime"] != EXPECTED_RUNTIMES
        or len(expected) != EXPECTED_ENTITIES
    ):
        _add(
            issues, "integrity", "register-roster-unexpected", f"{rpath}.register",
            f"epoch register population is not the governed 109/29/227 "
            f"(got sources={class_counts['source']} modules={class_counts['module']} "
            f"runtimes={class_counts['runtime']})",
        )
        return None
    source_ids = frozenset(
        entity.removeprefix("source:")
        for entity, info in expected.items()
        if info["class"] == "source"
    )
    module_ids = frozenset(
        entity.removeprefix("module:")
        for entity, info in expected.items()
        if info["class"] == "module"
    )
    runtime_ids = frozenset(
        entity.removeprefix("runtime:")
        for entity, info in expected.items()
        if info["class"] == "runtime"
    )
    for cls, actual, authoritative in (
        ("source", source_ids, V2_EXPECTED_SOURCE_IDS),
        ("module", module_ids, V2_EXPECTED_MODULE_IDS),
    ):
        if actual != authoritative:
            _add(
                issues, "integrity", f"register-{cls}-roster-mismatch",
                f"{rpath}.register.{cls}s",
                f"epoch {cls} roster differs from the frozen v2 authority: "
                f"missing={sorted(authoritative - actual)!r}; "
                f"added={sorted(actual - authoritative)!r}",
            )
            valid = False

    inventory = register_document.get("runtime_inventory", {})
    inventory_ids_raw = (
        inventory.get("capability_ids", []) if isinstance(inventory, Mapping) else []
    )
    inventory_ids = (
        frozenset(inventory_ids_raw)
        if isinstance(inventory_ids_raw, list)
        and all(isinstance(value, str) for value in inventory_ids_raw)
        else frozenset()
    )
    expected_count = (
        inventory.get("expected_count") if isinstance(inventory, Mapping) else None
    )
    if expected_count != EXPECTED_RUNTIMES or len(inventory_ids_raw) != EXPECTED_RUNTIMES:
        _add(
            issues, "integrity", "register-runtime-inventory-count-mismatch",
            f"{rpath}.register.runtime_inventory",
            f"runtime inventory must contain exactly {EXPECTED_RUNTIMES} IDs and "
            f"record that count; got expected_count={expected_count!r}, "
            f"ids={len(inventory_ids_raw) if isinstance(inventory_ids_raw, list) else 'invalid'}",
        )
        valid = False
    if isinstance(inventory_ids_raw, list) and inventory_ids_raw != sorted(inventory_ids_raw):
        _add(
            issues, "integrity", "register-runtime-inventory-not-canonical",
            f"{rpath}.register.runtime_inventory.capability_ids",
            "runtime inventory capability IDs must be sorted canonically",
        )
        valid = False
    if inventory_ids != runtime_ids:
        _add(
            issues, "integrity", "register-runtime-inventory-mismatch",
            f"{rpath}.register.runtime_inventory.capability_ids",
            f"runtime rows and inventory differ: "
            f"missing_rows={sorted(inventory_ids - runtime_ids)[:12]!r}; "
            f"unlisted_rows={sorted(runtime_ids - inventory_ids)[:12]!r}",
        )
        valid = False
    entity_roster = frozenset(expected)
    if expected_entity_roster is not None and entity_roster != expected_entity_roster:
        _add(
            issues, "integrity", "register-runtime-roster-mismatch",
            f"{rpath}.register.runtime",
            "epoch entity roster differs from the independently pinned genesis "
            f"roster: missing={sorted(expected_entity_roster - entity_roster)[:12]!r}; "
            f"added={sorted(entity_roster - expected_entity_roster)[:12]!r}",
        )
        valid = False
    if not valid:
        return None
    total_pairs = sum(len(info["triggers"]) for info in expected.values())
    if total_pairs != EXPECTED_PAIRS:
        _add(
            issues, "integrity", "register-pair-count-unexpected", f"{rpath}.register",
            f"epoch register has {total_pairs} entity/trigger pairs, expected "
            f"{EXPECTED_PAIRS}; exactly one trigger check is required per "
            "declared trigger",
        )
        return None
    # next_review_on must be the earliest governed due date so the recorded
    # cadence is actually verified rather than merely reported.
    queue_next_raw = queue.get("next_review_on") if isinstance(queue, Mapping) else None
    if isinstance(queue_next_raw, str) and all_dues:
        try:
            queue_next_date = date.fromisoformat(queue_next_raw)
        except (TypeError, ValueError):
            queue_next_date = None
        earliest = min(all_dues)
        if queue_next_date != earliest:
            _add(
                issues, "integrity", "register-queue-next-mismatch", f"{rpath}.register",
                f"queue next_review_on {queue_next_raw!r} is not the earliest "
                f"governed due date {earliest.isoformat()}",
            )
            return None
    return _EpochRegister(
        document=register_document,
        sha256="sha256:" + hashlib.sha256(register_bytes).hexdigest(),
        expected=expected,
        class_counts=class_counts,
        dues=dues,
        queue_next=queue_next,
    )


@dataclass
class _RecordView:
    """Per-record data retained for recurrence evaluation."""

    position: int
    record: Mapping[str, Any]
    reviewed: date | None
    recorded: date | None
    inspected: str | None
    observations: list[Mapping[str, Any]]
    evidence_paths: set[str]
    anchors: dict[str, set[str]]
    seen_pairs: set[tuple[str, str]]
    epoch: _EpochRegister | None


def _record_is_operated_cycle(
    view: _RecordView,
    predecessor: _RecordView,
    genesis_reviewed: date | None,
    *,
    as_of: date,
) -> bool:
    """Decide whether one later record is a genuine operated cycle.

    Schema/history v1 defines no independently verifiable
    executed-result protocol: an empty commit with byte-identical evidence
    plus relabeled ``basis=executed-check`` observations is not newly
    evidenced operation, so this predicate remains false for every
    history. A future version enables recurrence only by defining and
    binding a closed executed-result artifact whose dated results
    reconcile one-to-one to all governed pairs. ``--require recurrence``
    therefore stays an honest explicit exit-1 requirement in v1.
    """

    return False


def verify_history(
    document: Mapping[str, Any],
    *,
    as_of: date,
    history_path: str,
    history_sha256: str | None,
    review_schema_sha256: str | None,
    requirement: str = "integrity",
    repo_root: Path | str | None = None,
    blob_store: _RevisionBlobStore | None = None,
) -> ReviewReport:
    """Reconcile one history against revision-bound registers at ``as_of``.

    Each record's evidence and authoritative register resolve from offline
    local Git objects at that record's exact ``inspected_revision``. No
    caller-supplied register is accepted and the working tree is never
    consulted for evidence: current working-tree edits neither invalidate
    nor replace revision-bound history. Missing commits/paths, ambiguous
    or non-blob entries, decode/parse failures, oversized blobs, and digest
    differences all fail closed. A missing git executable or an unusable
    repository root raises :class:`ReviewLoadError`.
    """

    if requirement not in REQUIREMENTS:
        raise ValueError(f"unknown requirement: {requirement}")
    root = _resolve_repo_root(repo_root)
    store = blob_store if blob_store is not None else _RevisionBlobStore(root)
    if store.repo_root != root:
        raise ReviewLoadError(
            f"blob store is rooted at {store.repo_root}, not {root}"
        )
    issues: list[ReviewIssue] = []
    anchor_cache: dict[tuple[str, str], set[str] | str] = {}

    # Immutable envelope identity: schema, schema_version, and the exact
    # history_id are anchored together with the canonical genesis record.
    # Only records may append; the envelope itself never changes.
    if (
        document.get("schema") != REVIEW_SCHEMA_ID
        or document.get("schema_version") != REVIEW_SCHEMA_VERSION
        or document.get("history_id") != HISTORY_ID
    ):
        _add(
            issues, "integrity", "history-identity-mismatch", "$",
            "the history envelope (schema, schema_version, history_id) does "
            "not match the anchored review-history identity; only records "
            "may append",
        )

    records = document.get("records", [])
    if not isinstance(records, list) or not records:
        _add(issues, "integrity", "history-has-no-records", "records", "history must hold at least one record")
        records = []
    record_ids: set[Any] = set()
    record_digests: list[str] = []
    for position, record in enumerate(records):
        rpath = f"records[{position}]"
        if not isinstance(record, dict):
            _add(issues, "integrity", "record-not-a-mapping", rpath, "record must be a mapping")
            record_digests.append("")
            continue
        record_id = record.get("record_id")
        if record_id in record_ids:
            _add(issues, "integrity", "duplicate-record-id", f"{rpath}.record_id", f"duplicate record id {record_id!r}")
        record_ids.add(record_id)
        try:
            record_digests.append(_canonical_digest(record))
        except (TypeError, ValueError) as exc:
            _add(issues, "integrity", "record-undigestible", rpath, f"record cannot be canonically digested: {exc}")
            record_digests.append("")

    if records:
        first = records[0] if isinstance(records[0], dict) else {}
        if first.get("predecessor_digest") is not None:
            _add(
                issues, "integrity", "genesis-predecessor-nonnull", "records[0].predecessor_digest",
                "the genesis record must carry a null predecessor digest",
            )
        if record_digests and record_digests[0] != INITIAL_HISTORY_RECORD_DIGEST:
            _add(
                issues, "integrity", "initial-pin-mismatch", "records[0]",
                "the genesis record does not match the independently pinned initial history digest",
            )
    for position in range(1, len(records)):
        record = records[position]
        rpath = f"records[{position}]"
        if not isinstance(record, dict):
            continue
        predecessor = record.get("predecessor_digest")
        if not isinstance(predecessor, str) or not predecessor.startswith("sha256:"):
            _add(
                issues, "integrity", "predecessor-mismatch", f"{rpath}.predecessor_digest",
                "a non-genesis record must bind its predecessor digest",
            )
        elif predecessor != (record_digests[position - 1] if position - 1 < len(record_digests) else ""):
            _add(
                issues, "integrity", "predecessor-mismatch", f"{rpath}.predecessor_digest",
                "predecessor digest does not bind the previous record",
            )

    views: list[_RecordView | None] = []
    observed_pairs_union: set[tuple[str, str]] = set()
    observed_entities_union: set[str] = set()
    unknown_outcome_count = 0
    executed_checks: list[dict[str, Any]] = []
    unknown_outcomes: list[str] = []
    limitations: list[str] = []
    prior_reviewed: date | None = None
    prior_recorded: date | None = None
    genesis_entity_roster: frozenset[str] | None = None

    for position, record in enumerate(records):
        rpath = f"records[{position}]"
        if not isinstance(record, dict):
            views.append(None)
            continue
        reviewed = _parse_date(record.get("reviewed_on"), path=f"{rpath}.reviewed_on", issues=issues)
        recorded = _parse_date(record.get("recorded_on"), path=f"{rpath}.recorded_on", issues=issues)
        if reviewed is not None and recorded is not None and reviewed > recorded:
            _add(
                issues, "integrity", "recorded-before-reviewed", rpath,
                "reviewed_on is later than recorded_on; every record needs "
                "recorded_on >= reviewed_on",
            )
        if reviewed is not None and reviewed > as_of:
            _add(
                issues, "integrity", "review-in-future", f"{rpath}.reviewed_on",
                f"review date {reviewed.isoformat()} is later than as-of {as_of.isoformat()}",
            )
        if recorded is not None and recorded > as_of:
            _add(
                issues, "integrity", "recorded-in-future", f"{rpath}.recorded_on",
                f"record date {recorded.isoformat()} is later than as-of {as_of.isoformat()}",
            )
        # Strict cross-record chronology is integrity: a correctly linked
        # successor that moves backwards fails even when its chain binds.
        if position > 0:
            if (
                reviewed is not None
                and prior_reviewed is not None
                and reviewed <= prior_reviewed
            ):
                _add(
                    issues, "integrity", "review-chronology-regression",
                    f"{rpath}.reviewed_on",
                    f"successor reviewed_on {reviewed.isoformat()} does not move "
                    f"strictly forward from {prior_reviewed.isoformat()}",
                )
            if (
                recorded is not None
                and prior_recorded is not None
                and recorded <= prior_recorded
            ):
                _add(
                    issues, "integrity", "record-chronology-regression",
                    f"{rpath}.recorded_on",
                    f"successor recorded_on {recorded.isoformat()} does not move "
                    f"strictly forward from {prior_recorded.isoformat()}",
                )
            if (
                reviewed is not None
                and prior_recorded is not None
                and reviewed <= prior_recorded
            ):
                _add(
                    issues, "integrity", "cross-record-chronology", rpath,
                    f"successor reviewed_on {reviewed.isoformat()} is not strictly "
                    f"after the predecessor recorded_on {prior_recorded.isoformat()}",
                )
        prior_reviewed = reviewed if reviewed is not None else prior_reviewed
        prior_recorded = recorded if recorded is not None else prior_recorded
        reviewer = record.get("reviewer")
        if not isinstance(reviewer, str) or not reviewer.strip():
            _add(issues, "integrity", "reviewer-missing", f"{rpath}.reviewer", "reviewer attribution must be a nonempty string")
        inspected = record.get("inspected_revision")
        inspected_valid = (
            isinstance(inspected, str) and _HEX40_RE.fullmatch(inspected) is not None
        )
        if not inspected_valid:
            _add(
                issues, "integrity", "inspected-revision-invalid", f"{rpath}.inspected_revision",
                "inspected revision must be a 40-hex checkout revision",
            )
            inspected = None

        # --- revision-bound evidence -------------------------------------
        evidence = record.get("evidence", [])
        seen_evidence_paths: set[str] = set()
        bound_blobs: dict[str, bytes] = {}
        if isinstance(evidence, list):
            for index, entry in enumerate(evidence):
                epath = f"{rpath}.evidence[{index}]"
                if not isinstance(entry, dict):
                    _add(issues, "integrity", "evidence-entry-invalid", epath, "evidence entry must be a mapping")
                    continue
                rel_text = entry.get("path")
                relative = _check_repo_relative_file(rel_text)
                if relative is None:
                    _add(
                        issues, "integrity", "invalid-evidence-path", epath,
                        "evidence path must be a bounded repo-relative .md/.yaml/.json path",
                    )
                    continue
                if rel_text in seen_evidence_paths:
                    _add(
                        issues, "integrity", "duplicate-evidence-path", epath,
                        f"duplicate evidence path {rel_text!r}",
                    )
                    continue
                seen_evidence_paths.add(rel_text)
                if inspected is None:
                    continue
                try:
                    blob = store.read_blob(
                        inspected, str(rel_text), max_bytes=MAX_EVIDENCE_BYTES
                    )
                except _GitFailure as exc:
                    _add(issues, "integrity", exc.code, epath, (
                        f"revision-bound evidence {rel_text} at {inspected}: {exc}"
                    ))
                    continue
                bound_blobs[str(rel_text)] = blob
                blob_sha256 = "sha256:" + hashlib.sha256(blob).hexdigest()
                if entry.get("sha256") != blob_sha256:
                    _add(
                        issues, "integrity", "evidence-bytes-mismatch", epath,
                        f"evidence bytes differ for {rel_text}: recorded "
                        f"{entry.get('sha256')!r} does not match the revision-bound "
                        f"blob {blob_sha256}",
                    )
                if entry.get("byte_length") != len(blob):
                    _add(
                        issues, "integrity", "evidence-bytes-mismatch", epath,
                        f"evidence byte length differs for {rel_text}: recorded "
                        f"{entry.get('byte_length')!r} vs revision-bound {len(blob)}",
                    )
            for required in REQUIRED_EVIDENCE_PATHS:
                if required not in seen_evidence_paths:
                    _add(
                        issues, "integrity", "evidence-binding-missing", rpath,
                        f"required evidence binding is missing: {required}",
                    )
        else:
            _add(issues, "integrity", "evidence-entry-invalid", f"{rpath}.evidence", "evidence must be a list")

        # --- revision-bound epoch register --------------------------------
        epoch: _EpochRegister | None = None
        if inspected is not None and REGISTER_V2_REL in bound_blobs:
            register_bytes = bound_blobs[REGISTER_V2_REL]
            if len(register_bytes) > MAX_REGISTER_BLOB_BYTES:
                _add(
                    issues, "integrity", "evidence-oversized", f"{rpath}.register",
                    f"epoch register blob exceeds {MAX_REGISTER_BLOB_BYTES} bytes",
                )
            else:
                schema_bytes = bound_blobs.get(REGISTER_V2_SCHEMA_REL)
                if schema_bytes is None and REGISTER_V2_SCHEMA_REL in seen_evidence_paths:
                    # The schema blob read failed above; the failure is
                    # already recorded against its evidence entry.
                    pass
                elif schema_bytes is None:
                    _add(
                        issues, "integrity", "register-schema-unavailable",
                        f"{rpath}.register",
                        "the epoch register schema blob is not bound by this record",
                    )
                elif len(schema_bytes) > MAX_REGISTER_SCHEMA_BLOB_BYTES:
                    _add(
                        issues, "integrity", "register-schema-unavailable",
                        f"{rpath}.register",
                        "the epoch register schema blob exceeds its size cap",
                    )
                elif (
                    "sha256:" + hashlib.sha256(schema_bytes).hexdigest()
                    != V2_CANONICAL_SCHEMA_SHA256
                ):
                    _add(
                        issues, "integrity", "register-schema-mismatch",
                        f"{rpath}.register",
                        "the epoch register schema blob is not the canonical "
                        "register v2 schema bytes; substitute schemas are refused",
                    )
                else:
                    epoch = _validate_epoch_register(
                        register_bytes,
                        schema_bytes,
                        rpath=rpath,
                        issues=issues,
                        recorded=recorded,
                        expected_entity_roster=(
                            genesis_entity_roster if position > 0 else None
                        ),
                    )
                    if position == 0 and epoch is not None:
                        # The genesis record object is independently digest-pinned,
                        # and its exact revision-bound register bytes are evidence-
                        # bound. That immutable epoch is therefore the historical
                        # runtime roster anchor for every appended v1 record.
                        genesis_entity_roster = frozenset(epoch.expected)
        elif inspected is not None:
            _add(
                issues, "integrity", "register-epoch-unavailable", f"{rpath}.register",
                "the epoch register blob is not bound by this record, so the "
                "record cannot be reconciled against its own population",
            )

        # --- heading anchors from revision-bound Markdown ------------------
        anchors: dict[str, set[str]] = {}
        if inspected is not None:
            for rel_text in sorted(seen_evidence_paths):
                if not rel_text.endswith(".md"):
                    continue
                blob = bound_blobs.get(rel_text)
                if blob is None:
                    continue
                cache_key = (inspected, rel_text)
                cached = anchor_cache.get(cache_key)
                if isinstance(cached, str):
                    _add(
                        issues, "integrity", "evidence-decode-failed",
                        f"{rpath}.evidence",
                        f"evidence document {rel_text} cannot be read: {cached}",
                    )
                    continue
                if cached is None:
                    try:
                        parsed = _evidence_heading_anchors(
                            blob.decode("utf-8", errors="strict")
                        )
                    except (UnicodeDecodeError, ReviewLoadError, ValueError) as exc:
                        anchor_cache[cache_key] = str(exc)
                        _add(
                            issues, "integrity", "evidence-decode-failed",
                            f"{rpath}.evidence",
                            f"evidence document {rel_text} cannot be read: {exc}",
                        )
                        continue
                    anchor_cache[cache_key] = parsed
                    cached = parsed
                anchors[rel_text] = cached

        # --- observations reconciled to the record's own epoch ------------
        observations = record.get("observations", [])
        if not isinstance(observations, list):
            _add(issues, "integrity", "observation-invalid", f"{rpath}.observations", "observations must be a list")
            observations = []
        seen_pairs: set[tuple[str, str]] = set()
        expected_pairs: set[tuple[str, str]] = set()
        if epoch is not None:
            expected_pairs = {
                (entity, trigger)
                for entity, info in epoch.expected.items()
                for trigger in info["triggers"]
            }
        for index, obs in enumerate(observations):
            opath = f"{rpath}.observations[{index}]"
            if not isinstance(obs, dict):
                _add(issues, "integrity", "observation-invalid", opath, "observation must be a mapping")
                continue
            entity = obs.get("entity")
            trigger = obs.get("trigger")
            pair = (entity, trigger) if isinstance(entity, str) and isinstance(trigger, str) else None
            if pair is not None:
                if pair in seen_pairs:
                    _add(
                        issues, "integrity", "duplicate-pair", opath,
                        f"duplicate entity/trigger pair {entity!r} {trigger!r}",
                    )
                seen_pairs.add(pair)
                observed_pairs_union.add(pair)
                if isinstance(entity, str):
                    observed_entities_union.add(entity)
            basis = obs.get("basis")
            outcome = obs.get("outcome")
            if basis not in BASIS_VALUES:
                _add(issues, "integrity", "invalid-basis", opath, f"basis {basis!r} is not a recognized observation basis")
            if outcome not in OUTCOME_VALUES:
                _add(issues, "integrity", "invalid-outcome", opath, f"outcome {outcome!r} is not a recognized observation outcome")
            if (
                isinstance(basis, str)
                and isinstance(outcome, str)
                and basis in BASIS_VALUES
                and outcome in OUTCOME_VALUES
                and (basis == "unknown") != (outcome == "unknown")
            ):
                _add(
                    issues, "integrity", "outcome-basis-mismatch", opath,
                    "basis 'unknown' requires outcome 'unknown' and a substantive "
                    "basis requires outcome 'reviewed'; a positive outcome on an "
                    "unknown basis is unsupported",
                )
            if outcome == "unknown":
                unknown_outcome_count += 1
            checked_via = obs.get("checked_via")
            if checked_via not in CHECKED_VIA_VALUES:
                _add(
                    issues, "integrity", "trigger-check-method-unknown", opath,
                    f"checked_via {checked_via!r} is not a recognized check method",
                )
            if epoch is not None:
                info = epoch.expected.get(entity) if isinstance(entity, str) else None
                if info is None:
                    if isinstance(entity, str):
                        _add(
                            issues, "integrity", "unknown-entity", opath,
                            f"unknown entity {entity!r}: not in this record's "
                            "revision-bound register population",
                        )
                else:
                    if trigger not in info["triggers"]:
                        _add(
                            issues, "integrity", "unknown-trigger", opath,
                            f"unknown trigger {trigger!r} for {entity!r}",
                        )
                    else:
                        recorded_check = info["checks"].get(trigger, {})
                        if checked_via != recorded_check.get("checked_via"):
                            _add(
                                issues, "integrity", "observation-mismatch", opath,
                                f"checked_via {checked_via!r} does not match the "
                                f"epoch register record for {entity} {trigger}",
                            )
                        if obs.get("evidence_ref") != recorded_check.get("evidence_ref"):
                            _add(
                                issues, "integrity", "observation-mismatch", opath,
                                f"evidence_ref does not match the epoch register "
                                f"record for {entity} {trigger}",
                            )
            observed_on = _parse_date(obs.get("observed_on"), path=f"{opath}.observed_on", issues=issues)
            if observed_on is not None and observed_on > as_of:
                _add(
                    issues, "integrity", "observed-in-future", opath,
                    f"observation date {observed_on.isoformat()} is later than as-of "
                    f"{as_of.isoformat()}",
                )
            if (
                observed_on is not None
                and reviewed is not None
                and observed_on != reviewed
            ):
                _add(
                    issues, "integrity", "observed-date-mismatch", opath,
                    "observed_on must equal the record reviewed_on for this import",
                )
            if (
                basis == "historical-declaration"
                and epoch is not None
                and isinstance(entity, str)
                and observed_on is not None
            ):
                epoch_info = epoch.expected.get(entity)
                if epoch_info is not None:
                    epoch_reviewed_raw = epoch_info.get("reviewed_on")
                    if isinstance(epoch_reviewed_raw, str):
                        try:
                            epoch_reviewed = date.fromisoformat(epoch_reviewed_raw)
                        except (TypeError, ValueError):
                            epoch_reviewed = None
                        if epoch_reviewed is not None and observed_on != epoch_reviewed:
                            _add(
                                issues, "integrity", "historical-observed-mismatch", opath,
                                f"historical-declaration observed_on "
                                f"{observed_on.isoformat()} must equal that entity's "
                                f"epoch reviewed_on {epoch_reviewed.isoformat()}",
                            )
            evidence_ref = obs.get("evidence_ref")
            if not isinstance(evidence_ref, str) or evidence_ref.count("#") != 1:
                _add(
                    issues, "integrity", "invalid-evidence-ref", opath,
                    "evidence reference must be repo-relative Markdown path#anchor",
                )
                continue
            if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in evidence_ref):
                _add(
                    issues, "integrity", "invalid-evidence-ref", opath,
                    "evidence reference contains a control, format, or surrogate character",
                )
                continue
            rel_text, anchor = evidence_ref.split("#", 1)
            relative = _check_repo_relative_file(rel_text, allowed_suffixes=(".md",))
            if relative is None or _ANCHOR_RE.fullmatch(anchor) is None:
                _add(
                    issues, "integrity", "invalid-evidence-ref", opath,
                    "evidence reference must be a bounded repo-relative Markdown path#anchor",
                )
                continue
            if rel_text not in seen_evidence_paths:
                _add(
                    issues, "integrity", "evidence-ref-unbound", opath,
                    f"evidence reference {rel_text!r} is not bound by this "
                    "record's revision-bound evidence",
                )
                continue
            available = anchors.get(rel_text)
            if available is None:
                _add(
                    issues, "integrity", "evidence-decode-failed", opath,
                    f"evidence document {rel_text} has no readable revision-bound anchors",
                )
                continue
            if anchor not in available:
                _add(
                    issues, "integrity", "evidence-anchor-missing", opath,
                    f"heading anchor {anchor!r} does not exist in the "
                    f"revision-bound {rel_text}",
                )

        if epoch is not None:
            missing_pairs = expected_pairs - seen_pairs
            if missing_pairs:
                by_entity: dict[str, list[str]] = {}
                for entity, trigger in sorted(missing_pairs):
                    by_entity.setdefault(entity, []).append(trigger)
                for entity in sorted(by_entity):
                    if entity not in {pair[0] for pair in seen_pairs}:
                        _add(
                            issues, "integrity", "missing-entity", rpath,
                            f"authoritative entity {entity!r} has no observations "
                            f"(missing triggers {sorted(by_entity[entity])!r})",
                        )
                    else:
                        _add(
                            issues, "integrity", "missing-trigger", rpath,
                            f"entity {entity!r} is missing triggers {sorted(by_entity[entity])!r}",
                        )
                sample = sorted(missing_pairs)[:6]
                _add(
                    issues, "coverage", "coverage-incomplete", rpath,
                    f"record covers {len(seen_pairs)} of {len(expected_pairs)} "
                    f"authoritative pairs; sample missing={sample!r}",
                )

        for check in record.get("record_checks", []) if isinstance(record.get("record_checks"), list) else []:
            if isinstance(check, dict):
                executed_checks.append(
                    {
                        "record": record.get("record_id"),
                        "check": check.get("check"),
                        "result": check.get("result"),
                        "detail": check.get("detail"),
                    }
                )
        for item in record.get("unknown_outcomes", []) if isinstance(record.get("unknown_outcomes"), list) else []:
            if isinstance(item, str) and item not in unknown_outcomes:
                unknown_outcomes.append(item)
        for item in record.get("limitations", []) if isinstance(record.get("limitations"), list) else []:
            if isinstance(item, str) and item not in limitations:
                limitations.append(item)
        views.append(
            _RecordView(
                position=position,
                record=record,
                reviewed=reviewed,
                recorded=recorded,
                inspected=inspected,
                observations=[o for o in observations if isinstance(o, dict)],
                evidence_paths=set(seen_evidence_paths),
                anchors=dict(anchors),
                seen_pairs=set(seen_pairs),
                epoch=epoch,
            )
        )

    if unknown_outcome_count:
        _add(
            issues, "coverage", "coverage-unknown-outcome", "records",
            f"{unknown_outcome_count} observations report unknown outcomes; "
            "full coverage requires a substantive basis for every pair",
        )

    integrity_ok = not any(issue.category == "integrity" for issue in issues)
    coverage_ok = integrity_ok and not any(issue.category == "coverage" for issue in issues)

    for position, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        asserts = record.get("asserts", {})
        if not isinstance(asserts, dict):
            continue
        rpath = f"records[{position}].asserts"
        if asserts.get("integrity_ok") is True and not integrity_ok:
            _add(
                issues, "integrity", "unsupported-positive-outcome", rpath,
                "the record asserts integrity while recomputed integrity fails",
            )
        if asserts.get("coverage_ok") is True and not coverage_ok:
            _add(
                issues, "integrity", "unsupported-positive-outcome", rpath,
                "the record asserts full coverage while recomputed coverage fails",
            )
        for check in record.get("record_checks", []) if isinstance(record.get("record_checks"), list) else []:
            if isinstance(check, dict) and check.get("result") == "pass" and not integrity_ok:
                _add(
                    issues, "integrity", "unsupported-positive-outcome", rpath,
                    f"record check {check.get('check')!r} reports pass while "
                    "recomputed integrity fails",
                )
                break
    integrity_ok = not any(issue.category == "integrity" for issue in issues)
    coverage_ok = integrity_ok and not any(issue.category == "coverage" for issue in issues)

    # Recurrence (v1): no independently verifiable executed-result
    # protocol exists, so no history establishes a completed cycle. An empty
    # commit with byte-identical evidence plus relabeled executed-check
    # observations, advanced dates, and copied pass declarations is still a
    # replay, not operation. A future version enables recurrence only by
    # defining and binding a closed executed-result artifact whose dated
    # results reconcile one-to-one to all governed pairs. The initial import
    # establishes integrity and coverage, never recurrence.
    recurring_operation_ok = False
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        asserts = record.get("asserts", {})
        if isinstance(asserts, dict) and asserts.get("recurring_operation_ok") is True:
            if not recurring_operation_ok:
                _add(
                    issues, "integrity", "unsupported-positive-outcome",
                    f"records[{position}].asserts",
                    "the record asserts a completed recurring operation while no "
                    "completed cycle is established",
                )
    if not recurring_operation_ok:
        if len(records) < 2:
            detail = (
                "a single import cannot establish a completed cycle: integrity and "
                "full coverage are established, but schema/history v1 defines no "
                "independently verifiable executed-result protocol; a future "
                "version must define and bind a closed executed-result artifact "
                "whose dated results reconcile one-to-one to all governed pairs"
            )
        else:
            detail = (
                "no completed cycle is established: schema/history v1 defines no "
                "independently verifiable executed-result protocol, so a "
                "different/descendant/unrelated commit with all 1,095 relabeled "
                "observations, advanced dates, and copied pass declarations is "
                "still a replay; a future version must define and bind a closed "
                "executed-result artifact whose dated results reconcile one-to-one "
                "to all governed pairs"
            )
        _add(issues, "recurrence", "recurrence-not-established", "records", detail)
    integrity_ok = not any(issue.category == "integrity" for issue in issues)
    coverage_ok = integrity_ok and not any(issue.category == "coverage" for issue in issues)
    if any(issue.category in {"integrity", "coverage"} for issue in issues):
        recurring_operation_ok = False

    # Report expected counts and register metadata from the latest validated
    # epoch. Each v1 epoch must carry the same exact governed roster/trigger
    # policy, while its revision and due dates can advance with history.
    anchor_epoch: _EpochRegister | None = None
    for view in reversed(views):
        if view is not None and view.epoch is not None:
            anchor_epoch = view.epoch
            break
    if anchor_epoch is not None:
        pairs_expected = sum(len(info["triggers"]) for info in anchor_epoch.expected.values())
        register_revision_value = anchor_epoch.document.get("register_revision")
        register_revision = (
            register_revision_value if isinstance(register_revision_value, int) else None
        )
        register_sha256_value: str | None = anchor_epoch.sha256
    else:
        pairs_expected = 0
        register_revision = None
        register_sha256_value = None

    # Coverage/count reporting describes the latest record, never the union
    # of earlier complete observations: a latest-record gap must stay visible
    # even when an earlier record was complete.
    latest_pairs: set[tuple[str, str]] = set()
    for view in reversed(views):
        if view is not None:
            latest_pairs = set(view.seen_pairs)
            break
    latest_entities = {entity for entity, _trigger in latest_pairs}
    observed_sources = sorted({e for e in latest_entities if e.startswith("source:")})
    observed_modules = sorted({e for e in latest_entities if e.startswith("module:")})
    observed_runtimes = sorted({e for e in latest_entities if e.startswith("runtime:")})

    executed_checks_sorted = tuple(
        sorted(
            executed_checks,
            key=lambda c: (str(c.get("record")), str(c.get("check"))),
        )
    )
    report = ReviewReport(
        requirement=requirement,
        as_of=as_of,
        history_path=history_path,
        history_sha256=history_sha256,
        register_revision=register_revision,
        register_sha256=register_sha256_value,
        review_schema_sha256=review_schema_sha256,
        integrity_ok=integrity_ok,
        coverage_ok=coverage_ok,
        recurring_operation_ok=recurring_operation_ok,
        entities_expected=len(anchor_epoch.expected) if anchor_epoch else 0,
        entities_observed=len(latest_entities),
        sources_expected=anchor_epoch.class_counts["source"] if anchor_epoch else 0,
        sources_observed=len(observed_sources),
        modules_expected=anchor_epoch.class_counts["module"] if anchor_epoch else 0,
        modules_observed=len(observed_modules),
        runtimes_expected=anchor_epoch.class_counts["runtime"] if anchor_epoch else 0,
        runtimes_observed=len(observed_runtimes),
        pairs_expected=pairs_expected,
        pairs_observed=len(latest_pairs),
        record_count=len(records),
        next_due_source=anchor_epoch.dues["source"] if anchor_epoch else None,
        next_due_runtime=anchor_epoch.dues["runtime"] if anchor_epoch else None,
        next_due_module=anchor_epoch.dues["module"] if anchor_epoch else None,
        queue_next_review_on=anchor_epoch.queue_next if anchor_epoch else None,
        executed_checks=executed_checks_sorted,
        unknown_outcomes=tuple(sorted(unknown_outcomes)),
        limitations=tuple(sorted(limitations)),
        issues=tuple(sorted(set(issues))),
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
    parser = argparse.ArgumentParser(
        description="Attributed review-history verifier (revision-bound)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="verify a review history file")
    check.add_argument("--history", type=Path, required=True)
    check.add_argument("--as-of", type=_iso_date, required=True)
    check.add_argument("--require", choices=REQUIREMENTS, required=True)
    check.add_argument("--format", choices=("json",), default="json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fail-closed review-history check: 0 satisfied, 1 gaps, 2 invalid."""

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.require not in REQUIREMENTS:
            raise ValueError(f"unknown requirement: {args.require}")
        # No --register or --review-schema override exists: the history is
        # reconciled against each record's own revision-bound register, and
        # the schema is always the pinned canonical bytes.
        document, history_sha256, review_schema_sha256 = load_history(args.history)
        report = verify_history(
            document,
            as_of=args.as_of,
            history_path=str(args.history),
            history_sha256=history_sha256,
            review_schema_sha256=review_schema_sha256,
            requirement=args.require,
        )
    except (ReviewLoadError, ValueError) as exc:
        payload = {
            "schema": ERROR_SCHEMA_ID,
            "ok": False,
            "error": str(exc),
        }
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2
    except Exception as exc:
        payload = {
            "schema": ERROR_SCHEMA_ID,
            "ok": False,
            "error": (
                "review verification failed closed: " f"{type(exc).__name__}: {exc}"
            ),
        }
        print(json.dumps(payload, allow_nan=False, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), allow_nan=False, indent=2, sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
