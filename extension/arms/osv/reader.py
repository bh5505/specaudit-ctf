"""Offline snapshot layer for the osv arm.

Reads a versioned, caller-supplied local JSON snapshot of CTF-owned,
OSV-shaped records keyed by full package coordinate (``ecosystem:name``).
This module is deliberately isolated from :mod:`api` (the live client):
the snapshot path must stay deterministic and network-free.

Snapshot container (documented in this package's README)::

    {
      "snapshot_schema": "specaudit-ctf.osv-snapshot/1",
      "snapshot_time": "2026-10-23T00:00:00Z",
      "packages": {
        "PyPI:demo-package": [ {OSV-shaped record}, ... ],
        ...
      }
    }

Every record requires OSV ``id`` + ``modified`` plus the ``affected`` data
that ties it to the coordinate it is filed under; other OSV fields are
optional but structurally validated. Mixed record ``schema_version`` values,
duplicate ids, malformed affected data, oversized records, unknown container
versions, and unsupported coordinates are hard rejections — never best-effort
parses.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ...arms.strict_data import StrictDataError, bounded_tree_refusal, strict_json_loads
from .policy import (
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_RECORD_BYTES,
    MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_RECORDS,
    MAX_TEXT,
    SNAPSHOT_SCHEMA,
)

_RANGE_TYPES = frozenset({"SEMVER", "ECOSYSTEM", "GIT"})
_EVENT_KEYS = frozenset({"introduced", "fixed", "last_affected", "limit"})
_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "id",
        "modified",
        "aliases",
        "related",
        "upstream",
        "summary",
        "details",
        "published",
        "withdrawn",
        "severity",
        "references",
        "affected",
        "database_specific",
    }
)
_AFFECTED_KEYS = frozenset({"package", "ranges", "versions", "ecosystem_specific", "database_specific"})
_PACKAGE_KEYS = frozenset({"ecosystem", "name", "purl"})
_REFERENCE_KEYS = frozenset({"type", "url"})
_SEVERITY_KEYS = frozenset({"type", "score", "source"})


class SnapshotError(ValueError):
    """The snapshot is unreadable, unbounded, or outside the closed schema."""


class Snapshot:
    """A validated, indexed snapshot: coordinate keys, id index, identity."""

    def __init__(
        self,
        *,
        snapshot_time: str,
        packages: dict[str, list[dict[str, Any]]],
        by_id: dict[str, dict[str, Any]],
        source: dict[str, Any],
    ) -> None:
        self.snapshot_time = snapshot_time
        self.packages = packages
        self.by_id = by_id
        self.source = source


def load_snapshot_file(path: Path) -> Snapshot:
    """Read a snapshot file once, bounded, and validate it in memory."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_SNAPSHOT_BYTES + 1)
    except OSError as exc:
        raise SnapshotError("args.snapshot could not be read") from exc
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotError(
            f"args.snapshot exceeds the {MAX_SNAPSHOT_BYTES} byte read cap"
        )
    snapshot = load_snapshot_bytes(raw)
    snapshot.source["path"] = str(path)
    return snapshot


def load_snapshot_bytes(raw: bytes) -> Snapshot:
    """Parse and validate exact snapshot bytes without any I/O."""
    if type(raw) is not bytes:
        raise SnapshotError("snapshot bytes must be immutable bytes")
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotError(
            f"args.snapshot exceeds the {MAX_SNAPSHOT_BYTES} byte read cap"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnapshotError("snapshot is not valid UTF-8") from exc
    try:
        document = strict_json_loads(
            text,
            max_nodes=MAX_DOCUMENT_NODES,
            max_depth=MAX_DOCUMENT_DEPTH,
        )
    except StrictDataError as exc:
        raise SnapshotError(f"snapshot is not strict JSON: {exc}") from exc
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SnapshotError("snapshot is not valid JSON") from exc

    if not isinstance(document, dict):
        raise SnapshotError("snapshot must be a JSON object")
    version = document.get("snapshot_schema")
    if version != SNAPSHOT_SCHEMA:
        raise SnapshotError(
            f"unknown source schema version: expected {SNAPSHOT_SCHEMA!r}, "
            f"got {version!r}"
        )
    snapshot_time = _text(document.get("snapshot_time"), "snapshot_time")
    packages_raw = document.get("packages")
    if not isinstance(packages_raw, dict) or not packages_raw:
        raise SnapshotError("snapshot must carry a non-empty packages mapping")

    packages: dict[str, list[dict[str, Any]]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    record_count = 0
    seen_schema_versions: set[str] = set()
    for coordinate, records_raw in packages_raw.items():
        _validate_coordinate_key(coordinate)
        if not isinstance(records_raw, list) or not records_raw:
            raise SnapshotError(
                f"coordinate {coordinate!r} must map to a non-empty records list"
            )
        records: list[dict[str, Any]] = []
        for position, raw_record in enumerate(records_raw):
            record_count += 1
            if record_count > MAX_SNAPSHOT_RECORDS:
                raise SnapshotError(
                    f"snapshot exceeds the {MAX_SNAPSHOT_RECORDS} record cap"
                )
            record = _validate_record(raw_record, f"{coordinate}[{position}]")
            if record["id"] in by_id:
                raise SnapshotError(f"duplicate OSV id in snapshot: {record['id']}")
            # Mixed container/record schema versions are a rejection, not a
            # parse: a snapshot cannot claim one format and carry another.
            record_version = record.get("schema_version")
            if isinstance(record_version, str):
                seen_schema_versions.add(record_version)
            if not _record_covers_coordinate(record, coordinate):
                raise SnapshotError(
                    f"record {record['id']} does not list the coordinate it is "
                    f"filed under ({coordinate!r})"
                )
            by_id[record["id"]] = record
            records.append(record)
        packages[coordinate] = records

    if len(seen_schema_versions) > 1:
        raise SnapshotError(
            "mixed record schema_version values in one snapshot: "
            + ", ".join(sorted(seen_schema_versions))
        )
    source = {
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
    return Snapshot(
        snapshot_time=snapshot_time,
        packages=packages,
        by_id=by_id,
        source=source,
    )


def lookup_by_id(snapshot: Snapshot, osv_id: str) -> dict[str, Any] | None:
    """Exact, case-sensitive OSV id lookup."""
    return snapshot.by_id.get(osv_id)


def lookup_by_coordinate(
    snapshot: Snapshot,
    ecosystem: str,
    name: str,
    version: str | None = None,
) -> list[dict[str, Any]]:
    """Records filed under the exact coordinate key.

    Without a version, every record for the coordinate is returned. With a
    version, only records carrying explicit version evidence for it (a
    versions list hit or a range hit) are returned — a package-level
    ``affected`` entry without version data never claims a version match.
    """
    records = snapshot.packages.get(f"{ecosystem}:{name}", [])
    if version is None:
        return list(records)
    return [
        record
        for record in records
        if any(
            _affected_covers_version(affected, ecosystem, name, version)
            for affected in record["affected"]
        )
    ]


def staleness_note(snapshot_time: str, upstream_modified: str) -> str | None:
    """Pure helper: is a live ``modified`` value newer than a snapshot?

    Returns a limitation string when the upstream record changed after the
    snapshot was taken, else None. Timestamps are compared as ISO-8601
    instants when parseable, falling back to exact string comparison.
    """
    parsed_snapshot = _parse_timestamp(snapshot_time)
    parsed_upstream = _parse_timestamp(upstream_modified)
    if parsed_snapshot is not None and parsed_upstream is not None:
        return (
            "upstream record was modified after the snapshot was taken "
            f"({upstream_modified} > {snapshot_time})"
        ) if parsed_upstream > parsed_snapshot else None
    newer = upstream_modified > snapshot_time
    return (
        f"upstream record was modified after the snapshot was taken "
        f"({upstream_modified} > {snapshot_time})"
    ) if newer else None


# --- validation helpers ------------------------------------------------------


def _validate_record(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SnapshotError(f"record {label} must be a mapping")
    serialized = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(serialized) > MAX_RECORD_BYTES:
        raise SnapshotError(
            f"record {label} exceeds the {MAX_RECORD_BYTES} byte record cap"
        )
    unknown = sorted(set(raw) - _RECORD_KEYS)
    if unknown:
        raise SnapshotError(f"record {label} has unsupported fields: {', '.join(unknown)}")
    record_id = _text(raw.get("id"), f"{label}.id")
    _text(raw.get("modified"), f"{label}.modified")
    for key in ("aliases", "related", "upstream"):
        if key in raw:
            _string_list(raw[key], f"{label}.{key}")
    for key in ("summary", "details", "published", "withdrawn"):
        if key in raw:
            _text(raw[key], f"{label}.{key}")
    if "severity" in raw:
        _validate_severity(raw["severity"], f"{label}.severity")
    if "references" in raw:
        _validate_references(raw["references"], f"{label}.references")
    # affected is mandatory here even though OSV itself makes it optional:
    # the container files records under a coordinate and affected is the
    # only evidence tying a record to the coordinate it is filed under.
    if "affected" not in raw:
        raise SnapshotError(f"{label} is missing affected data")
    _validate_affected(raw["affected"], f"{label}.affected")
    for key in ("database_specific",):
        if key in raw and not isinstance(raw[key], dict):
            raise SnapshotError(f"{label}.{key} must be an object")
    _walk_text(raw, label)
    return raw


def _validate_affected(raw: Any, label: str) -> None:
    if not isinstance(raw, list):
        raise SnapshotError(f"{label} must be a list")
    for index, item in enumerate(raw):
        item_label = f"{label}[{index}]"
        if not isinstance(item, dict):
            raise SnapshotError(f"{item_label} must be a mapping")
        unknown = sorted(set(item) - _AFFECTED_KEYS)
        if unknown:
            raise SnapshotError(
                f"{item_label} has unsupported fields: {', '.join(unknown)}"
            )
        package = item.get("package")
        if not isinstance(package, dict):
            raise SnapshotError(f"{item_label}.package must be a mapping")
        package_unknown = sorted(set(package) - _PACKAGE_KEYS)
        if package_unknown:
            raise SnapshotError(
                f"{item_label}.package has unsupported fields: {', '.join(package_unknown)}"
            )
        ecosystem = _text(package.get("ecosystem"), f"{item_label}.package.ecosystem")
        name = _text(package.get("name"), f"{item_label}.package.name")
        if ":" in ecosystem:
            raise SnapshotError(
                f"{item_label}.package.ecosystem must not contain a coordinate separator"
            )
        _coordinate_text(name, f"{item_label}.package.name")
        if "purl" in package:
            purl = _text(package["purl"], f"{item_label}.package.purl")
            if not purl.startswith("pkg:"):
                raise SnapshotError(f"{item_label}.package.purl must start with pkg:")
        if "ranges" in item:
            _validate_ranges(item["ranges"], f"{item_label}.ranges")
        if "versions" in item:
            _string_list(item["versions"], f"{item_label}.versions")
        for key in ("ecosystem_specific", "database_specific"):
            if key in item and not isinstance(item[key], dict):
                raise SnapshotError(f"{item_label}.{key} must be an object")


def _validate_ranges(raw: Any, label: str) -> None:
    if not isinstance(raw, list):
        raise SnapshotError(f"{label} must be a list")
    for index, entry in enumerate(raw):
        entry_label = f"{label}[{index}]"
        if not isinstance(entry, dict):
            raise SnapshotError(f"{entry_label} must be a mapping")
        unknown = sorted(set(entry) - {"type", "events", "repo"})
        if unknown:
            raise SnapshotError(
                f"{entry_label} has unsupported fields: {', '.join(unknown)}"
            )
        range_type = entry.get("type")
        if range_type not in _RANGE_TYPES:
            raise SnapshotError(
                f"{entry_label}.type must be one of {sorted(_RANGE_TYPES)}"
            )
        if range_type == "GIT" and not isinstance(entry.get("repo"), str):
            raise SnapshotError(f"{entry_label}.repo is required for GIT ranges")
        if "repo" in entry and not isinstance(entry["repo"], str):
            raise SnapshotError(f"{entry_label}.repo must be a string")
        events = entry.get("events")
        if not isinstance(events, list) or not events:
            raise SnapshotError(f"{entry_label}.events must be a non-empty list")
        for event_index, event in enumerate(events):
            event_label = f"{entry_label}.events[{event_index}]"
            if not isinstance(event, dict):
                raise SnapshotError(f"{event_label} must be a mapping")
            keys = set(event)
            if len(keys) != 1 or keys - _EVENT_KEYS:
                raise SnapshotError(
                    f"{event_label} must carry exactly one of "
                    f"{sorted(_EVENT_KEYS)}"
                )
            _text(next(iter(event.values())), f"{event_label} value")


def _validate_references(raw: Any, label: str) -> None:
    if not isinstance(raw, list):
        raise SnapshotError(f"{label} must be a list")
    for index, item in enumerate(raw):
        item_label = f"{label}[{index}]"
        if not isinstance(item, dict):
            raise SnapshotError(f"{item_label} must be a mapping")
        unknown = sorted(set(item) - _REFERENCE_KEYS)
        if unknown:
            raise SnapshotError(
                f"{item_label} has unsupported fields: {', '.join(unknown)}"
            )
        _text(item.get("type"), f"{item_label}.type")
        _text(item.get("url"), f"{item_label}.url")


def _validate_severity(raw: Any, label: str) -> None:
    if not isinstance(raw, list):
        raise SnapshotError(f"{label} must be a list")
    for index, item in enumerate(raw):
        item_label = f"{label}[{index}]"
        if not isinstance(item, dict):
            raise SnapshotError(f"{item_label} must be a mapping")
        unknown = sorted(set(item) - _SEVERITY_KEYS)
        if unknown:
            raise SnapshotError(
                f"{item_label} has unsupported fields: {', '.join(unknown)}"
            )
        _text(item.get("type"), f"{item_label}.type")
        _text(item.get("score"), f"{item_label}.score")


def _walk_text(value: Any, label: str) -> None:
    """Bound every string in a record: length cap, no control characters."""
    if isinstance(value, str):
        _text(value, label)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_text(item, f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _walk_text(item, f"{label}.{key}")


def _validate_coordinate_key(coordinate: Any) -> tuple[str, str]:
    if not isinstance(coordinate, str) or ":" not in coordinate:
        raise SnapshotError(
            f"coordinate key {coordinate!r} must be '<ecosystem>:<name>'"
        )
    ecosystem, _, name = coordinate.partition(":")
    _coordinate_text(ecosystem, "coordinate ecosystem")
    _coordinate_text(name, "coordinate name")
    if ":" in name:
        # A second separator makes the '<ecosystem>:<name>' key ambiguous;
        # such a coordinate is unsupported rather than best-effort split.
        raise SnapshotError(f"coordinate name {name!r} must not contain ':'")
    return ecosystem, name


def _record_covers_coordinate(record: dict[str, Any], coordinate: str) -> bool:
    for affected in record["affected"]:
        package = affected.get("package", {})
        if f"{package.get('ecosystem')}:{package.get('name')}" == coordinate:
            return True
    return False


def _affected_covers_version(
    affected: dict[str, Any], ecosystem: str, name: str, version: str
) -> bool:
    package = affected.get("package", {})
    if package.get("ecosystem") != ecosystem or package.get("name") != name:
        return False
    versions = affected.get("versions", [])
    if isinstance(versions, list) and version in versions:
        return True
    ranges = affected.get("ranges", [])
    return any(_range_covers_version(entry, version) for entry in ranges)


def _range_covers_version(entry: dict[str, Any], version: str) -> bool:
    if entry.get("type") == "GIT":
        return False
    parsed = _numeric_version(version)
    if parsed is None:
        return False
    introduced = None
    fixed = None
    last_affected = None
    for event in entry.get("events", []):
        key, value = next(iter(event.items()))
        if key == "introduced":
            introduced = None if value == "0" else (_numeric_version(value) or introduced)
        elif key == "fixed":
            fixed = _numeric_version(value)
        elif key == "last_affected":
            last_affected = _numeric_version(value)
    if introduced is not None and parsed < introduced:
        return False
    if fixed is not None and parsed >= fixed:
        return False
    if last_affected is not None and parsed > last_affected:
        return False
    return introduced is not None or fixed is not None or last_affected is not None


def _numeric_version(value: str) -> tuple[int, ...] | None:
    parts = value.split(".")
    if all(part.isdigit() for part in parts):
        return tuple(int(part) for part in parts)
    return None


def _parse_timestamp(value: str) -> Any:
    from datetime import datetime, timezone

    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _string_list(raw: Any, label: str) -> None:
    if not isinstance(raw, list):
        raise SnapshotError(f"{label} must be a list")
    for index, item in enumerate(raw):
        _text(item, f"{label}[{index}]")


def _coordinate_text(value: Any, label: str) -> str:
    text = _text(value, label)
    if any(ch.isspace() for ch in text):
        raise SnapshotError(f"{label} must not contain whitespace")
    return text


def _text(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise SnapshotError(f"{label} must be a non-empty string")
    if len(raw) > MAX_TEXT:
        raise SnapshotError(f"{label} exceeds the {MAX_TEXT} character text cap")
    if any(ord(ch) < 0x20 and ch not in "\t\n\r" for ch in raw):
        raise SnapshotError(f"{label} contains control characters")
    return raw
