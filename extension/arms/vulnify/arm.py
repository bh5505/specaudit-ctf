"""Curated vulnify arm: bounded local vulnerability reads."""

from __future__ import annotations

import hashlib
import io
import json
import math
from pathlib import Path
from typing import Any, Mapping

import yaml
from yaml.events import AliasEvent

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..mcp_client import redact
from ..strict_data import (
    StrictDataError,
    StrictMappingMixin,
    bounded_tree_refusal,
    strict_json_loads,
)
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_FEED_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RECORDS,
    args_refusal,
    feed_refusal,
    limit_refusal,
)

_RECORD_KEYS = frozenset(
    {
        "cve_id",
        "name",
        "severity",
        "description",
        "source",
        "published",
        "modified",
        "status",
        "cvss",
        "aliases",
        "references",
        "affected",
    }
)
_MAX_TEXT = 16_384


class VulnifyArm:
    """First-party in-process reader over a caller-supplied frozen feed."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return _fail(
                spec,
                action,
                f"action {action!r} is not on the allowlist "
                "(offline reads over a local vulnerability feed only; "
                "there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, feed_refused = feed_refusal(payload.get("feed"))
        if feed_refused:
            return _fail(spec, action, feed_refused)
        if path is None:
            return _fail(spec, action, "feed path validation failed")
        try:
            records, source, provenance = _load_feed(path)
        except FeedError as exc:
            return _fail(spec, action, str(exc))
        except Exception:
            return _fail(spec, action, "feed could not be parsed safely")
        if action == "lookup":
            return self._lookup(spec, payload, records, source, provenance)
        return self._list_vulns(spec, payload, records, source, provenance)

    def _lookup(
        self,
        spec: ArmSpec,
        payload: dict,
        records: list[dict[str, Any]],
        source: dict[str, Any],
        provenance: dict[str, Any],
    ) -> Result:
        cve_id = _opt_str(payload.get("cve_id"))
        name = _opt_str(payload.get("name"))

        # A supplied CVE id is authoritative. The secondary name never wins
        # merely because its record occurs earlier in the feed.
        if cve_id is not None:
            match = next((row for row in records if row.get("cve_id") == cve_id), None)
            wanted = cve_id
        else:
            matches = [row for row in records if row.get("name") == name]
            if len(matches) > 1:
                return _fail(
                    spec,
                    "lookup",
                    "multiple vulnerabilities match args.name; use args.cve_id",
                )
            match = matches[0] if matches else None
            wanted = name
        if match is None:
            return _fail(
                spec,
                "lookup",
                f"vulnerability {wanted!r} not found in this feed",
            )

        return _ok(
            spec,
            "lookup",
            {
                "vulnerability": match,
                "source": source,
                "provenance": provenance,
            },
        )

    def _list_vulns(
        self,
        spec: ArmSpec,
        payload: dict,
        records: list[dict[str, Any]],
        source: dict[str, Any],
        provenance: dict[str, Any],
    ) -> Result:
        limit, refusal = limit_refusal(payload.get("limit"))
        if refusal or limit is None:
            return _fail(spec, "list_vulns", refusal or "invalid limit")
        rows = [
            {
                "cve_id": record.get("cve_id", ""),
                "name": record.get("name", ""),
                "severity": record.get("severity", ""),
            }
            for record in records[:limit]
        ]
        return _ok(
            spec,
            "list_vulns",
            {
                "vulnerabilities": rows,
                "total": len(records),
                "returned": len(rows),
                "capped": len(rows) < len(records),
                "source": source,
                "provenance": provenance,
            },
        )

    def _list_tools(
        self, spec: ArmSpec, action: str, payload: dict
    ) -> Result:
        if payload:
            return _fail(spec, action, "list_tools takes no caller arguments")
        return _ok(
            spec,
            action,
            {
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": {key: sorted(values) for key, values in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
        )


class FeedError(ValueError):
    """The supplied snapshot is not a bounded, valid vulnerability feed."""


def _load_feed(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Read once, parse according to suffix, and bind results to the bytes."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FEED_BYTES + 1)
    except OSError as exc:
        raise FeedError("args.feed could not be read") from exc
    if len(raw) > MAX_FEED_BYTES:
        raise FeedError(f"args.feed exceeds the {MAX_FEED_BYTES} byte read cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FeedError("args.feed is not valid UTF-8") from exc
    if not text.strip():
        raise FeedError("args.feed is empty")

    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        records = _parse_jsonl(text)
    else:
        try:
            if suffix == ".json":
                data = strict_json_loads(text)
            else:
                data = yaml.load(text, Loader=_BoundedSafeLoader)
        except StrictDataError as exc:
            raise FeedError(str(exc)) from exc
        except (json.JSONDecodeError, RecursionError, yaml.YAMLError, ValueError) as exc:
            label = "JSON" if suffix == ".json" else "YAML"
            raise FeedError(f"args.feed is not valid {label}") from exc
        refusal = _tree_refusal(data)
        if refusal:
            raise FeedError(f"args.feed {refusal}")
        records = _extract_records(data)

    records = _validate_records(records)
    canonical = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    provenance = {
        "snapshot_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "normalization": {
            "records_sha256": f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        },
    }
    return records, _source(raw), provenance


def _parse_jsonl(text: str) -> list[Any]:
    records: list[Any] = []
    for line_number, line in enumerate(io.StringIO(text), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if len(records) >= MAX_RECORDS:
            raise FeedError(f"args.feed exceeds the {MAX_RECORDS} record cap")
        try:
            record = strict_json_loads(stripped)
        except StrictDataError as exc:
            raise FeedError(f"args.feed line {line_number}: {exc}") from exc
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise FeedError(f"args.feed line {line_number} is not valid JSON") from exc
        refusal = _tree_refusal(record)
        if refusal:
            raise FeedError(f"args.feed line {line_number} {refusal}")
        records.append(record)
    if not records:
        raise FeedError("args.feed contained no records")
    return records


def _extract_records(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        keys = [key for key in ("vulnerabilities", "records") if key in data]
        if len(keys) == 1 and isinstance(data[keys[0]], list):
            return data[keys[0]]
    raise FeedError(
        "args.feed must be a list or a mapping with one vulnerabilities/records list"
    )


def _validate_records(data: list[Any]) -> list[dict[str, Any]]:
    if len(data) > MAX_RECORDS:
        raise FeedError(f"args.feed exceeds the {MAX_RECORDS} record cap")
    records: list[dict[str, Any]] = []
    seen_cves: set[str] = set()
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise FeedError(f"args.feed record {index} must be a mapping")
        extra = sorted(set(item) - _RECORD_KEYS)
        if extra:
            raise FeedError(f"args.feed record {index} has unknown fields")
        cve_id = item.get("cve_id")
        name = item.get("name")
        if cve_id is not None and (
            not isinstance(cve_id, str) or not cve_id.strip()
        ):
            raise FeedError(
                f"args.feed record {index} field 'cve_id' must be a non-empty string"
            )
        if name is not None and (not isinstance(name, str) or not name.strip()):
            raise FeedError(
                f"args.feed record {index} field 'name' must be a non-empty string"
            )
        if cve_id is None and name is None:
            raise FeedError(f"args.feed record {index} requires cve_id or name")
        if isinstance(cve_id, str):
            _bounded_text(cve_id, f"args.feed record {index}.cve_id")
        if isinstance(name, str):
            _bounded_text(name, f"args.feed record {index}.name")
        for key in (
            "severity",
            "description",
            "source",
            "published",
            "modified",
            "status",
        ):
            if key in item and item[key] is not None:
                _bounded_text(item[key], f"args.feed record {index}.{key}")
        if "cvss" in item and item["cvss"] is not None:
            cvss = item["cvss"]
            if (
                not isinstance(cvss, (int, float))
                or isinstance(cvss, bool)
                or (isinstance(cvss, float) and not math.isfinite(cvss))
                or not 0 <= cvss <= 10
            ):
                raise FeedError(
                    f"args.feed record {index}.cvss must be null or a finite number from 0 to 10"
                )
        for key in ("aliases", "references", "affected"):
            if key in item:
                values = item[key]
                if not isinstance(values, list):
                    raise FeedError(
                        f"args.feed record {index}.{key} must be a list"
                    )
                for item_index, value in enumerate(values):
                    _bounded_text(
                        value,
                        f"args.feed record {index}.{key}[{item_index}]",
                    )
        normalized = dict(item)
        if isinstance(cve_id, str):
            normalized_cve = cve_id.strip()
            if normalized_cve in seen_cves:
                raise FeedError(
                    f"args.feed contains duplicate cve_id {normalized_cve!r}"
                )
            seen_cves.add(normalized_cve)
            normalized["cve_id"] = normalized_cve
        if isinstance(name, str):
            normalized["name"] = name.strip()
        records.append(normalized)
    return records


class _BoundedSafeLoader(StrictMappingMixin, yaml.SafeLoader):
    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._node_count = 0
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError("YAML aliases and anchors are not allowed")
        self._node_count += 1
        if self._node_count > MAX_DOCUMENT_NODES:
            raise yaml.YAMLError("YAML document exceeds the node cap")
        self._depth += 1
        if self._depth > MAX_DOCUMENT_DEPTH:
            self._depth -= 1
            raise yaml.YAMLError("YAML document exceeds the nesting-depth cap")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def _tree_refusal(data: Any) -> str | None:
    return bounded_tree_refusal(
        data,
        max_nodes=MAX_DOCUMENT_NODES,
        max_depth=MAX_DOCUMENT_DEPTH,
        max_text_chars=MAX_OUTPUT_CHARS,
    )


def _source(raw: bytes) -> dict[str, Any]:
    return {
        "kind": "operator-file",
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()


def _bounded_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) > _MAX_TEXT:
        raise FeedError(f"{label} must be a bounded string")
    if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
        raise FeedError(f"{label} contains control characters")
    return value


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        rendered = json.dumps(
            output, sort_keys=True, ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError):
        return _fail(spec, action, "result could not be encoded safely")
    if len(rendered) > MAX_OUTPUT_CHARS:
        return _fail(
            spec,
            action,
            f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; narrow the lookup",
        )
    return Result(ok=True, arm_id=spec.id, action=action, output=output, error=None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(
        ok=False,
        arm_id=spec.id,
        action=action,
        output=None,
        error=redact(str(error))[:MAX_OUTPUT_CHARS],
    )
