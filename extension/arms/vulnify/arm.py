"""Merged vulnify arm: bounded local vulnerability reads.

True merge of two implementations (main's as the base, feature-branch
functionality preserved):

  * **Feed interface (main)** — ``args.feed`` (json/jsonl/yaml), single
    ``cve_id``/``name`` lookup, ``list_vulns``. Wired into the opt-in
    trusted-observation layer via :func:`parse_feed_bytes` and
    :func:`render_producer_output_bytes`.
  * **Snapshot/batch interface (feature branch)** — ``args.bundle_path``
    (frozen local JSON snapshot keyed by canonical CVE id) with an
    ``args.cve_ids`` list; Finding-E curated-technique fallback (via
    :mod:`reader`) and a ``vulnify.lookup-receipt.v1`` custody receipt to
    stderr.

``lookup`` dispatches on the caller arg: ``cve_ids`` present → batch layer;
otherwise → feed layer.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import re
import sys
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
from . import reader
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_BUNDLE_BYTES,
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_FEED_BYTES,
    MAX_OUTPUT_CHARS,
    MAX_RECORDS,
    args_refusal,
    bundle_refusal,
    demo_bundle_path,
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
    """First-party in-process reader over a caller-supplied frozen feed/snapshot."""

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
                "(offline reads over a local vulnerability feed or snapshot only; "
                "there is no dispatch tier)",
            )
        # Feature-branch batch interface: args.cve_ids (list) over a
        # args.bundle_path frozen snapshot. Dispatches to the snapshot reader,
        # Finding-E curated fallback, and custody receipt.
        if action == "lookup" and "cve_ids" in payload:
            return self._lookup_batch(spec, action, payload)
        # Main's feed interface: args.feed with cve_id/name (lookup) or list_vulns.
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

    def _lookup_batch(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        """Feature-branch batch lookup: args.cve_ids over a frozen snapshot."""
        args_hash = _normalized_args_hash(payload)
        bundle_sha: str | None = None
        queries: list[dict[str, Any]] = []
        refusal = args_refusal(action, payload)
        raw_ids = payload.get("cve_ids")
        if refusal or not isinstance(raw_ids, list):
            reason = "cve_ids_not_a_list" if not isinstance(raw_ids, list) else "input_refusal"
            if isinstance(raw_ids, list):
                queries = [_query_receipt(value, "failed", reason) for value in raw_ids]
            return _failure(spec, action, args_hash, bundle_sha, queries, reason, refusal or reason)

        path, path_refusal = bundle_refusal(payload.get("bundle_path"))
        if path_refusal or path is None:
            reason = "bundle_too_large" if path_refusal and "read cap" in path_refusal else "bundle_missing"
            queries = [_query_receipt(value, "failed", reason) for value in raw_ids]
            return _failure(spec, action, args_hash, bundle_sha, queries, reason, path_refusal or reason)

        try:
            snapshot = _read_bundle_snapshot(path)
            bundle_sha = hashlib.sha256(snapshot).hexdigest()
            index = reader.load_bundle_bytes(snapshot)
        except (reader.BundleError, OSError) as exc:
            reason = "bundle_invalid_json"
            queries = [_query_receipt(value, "failed", reason) for value in raw_ids]
            return _failure(spec, action, args_hash, bundle_sha, queries, reason, f"{reason}: {redact(str(exc))}")

        results: list[dict[str, Any]] = []
        for raw_id in raw_ids:
            normalized = _normalize_cve(raw_id)
            if normalized is None:
                row = {
                    "cve_id": None,
                    "query_sha256": _value_hash(raw_id),
                    "status": "unmatched",
                    "reason": "malformed_id",
                    "record": None,
                    "snapshot_sha256": bundle_sha,
                }
            else:
                record = reader.lookup(index, normalized, bundle_sha)
                row = {
                    "cve_id": normalized,
                    "status": "matched" if record is not None else "unmatched",
                    "reason": None if record is not None else "unknown_cve",
                    "record": record,
                    "snapshot_sha256": bundle_sha,
                }
            results.append(row)
            queries.append({key: row[key] for key in ("cve_id", "status", "reason")})
            if "query_sha256" in row:
                queries[-1]["query_sha256"] = row["query_sha256"]

        output = {"reason": None, "snapshot_sha256": bundle_sha, "results": results, "count_matched": sum(row["status"] == "matched" for row in results)}
        if len(_canonical_json(output)) > MAX_OUTPUT_CHARS:
            reason = "output_too_large"
            return _failure(spec, action, args_hash, bundle_sha, queries, reason, "lookup output exceeds output cap")
        _write_receipt(args_hash, bundle_sha, queries, output, True, None)
        return Result(True, spec.id, action, output, None)

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
                "demo_bundle": str(demo_bundle_path()),
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
    return parse_feed_bytes(raw, format=_feed_format(path.suffix))


def parse_feed_bytes(
    raw: bytes, *, format: str
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Parse bounded feed bytes without performing I/O.

    The arm and the opt-in trusted-observation verifier share this function so
    the verifier replays the exact normalization contract over validator-held
    bytes instead of trusting producer-reported provenance.
    """
    if type(raw) is not bytes:
        raise FeedError("args.feed bytes must be immutable bytes")
    if type(format) is not str:
        raise FeedError("args.feed format is not supported")
    if len(raw) > MAX_FEED_BYTES:
        raise FeedError(f"args.feed exceeds the {MAX_FEED_BYTES} byte read cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FeedError("args.feed is not valid UTF-8") from exc
    if not text.strip():
        raise FeedError("args.feed is empty")

    if format not in {"json", "jsonl", "yaml"}:
        raise FeedError("args.feed format is not supported")
    if format == "jsonl":
        records = _parse_jsonl(text)
    else:
        try:
            if format == "json":
                data = strict_json_loads(text)
            else:
                data = yaml.load(text, Loader=_BoundedSafeLoader)
        except StrictDataError as exc:
            raise FeedError(str(exc)) from exc
        except (json.JSONDecodeError, RecursionError, yaml.YAMLError, ValueError) as exc:
            label = "JSON" if format == "json" else "YAML"
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


def _feed_format(suffix: str) -> str:
    normalized = suffix.lower()
    if normalized == ".json":
        return "json"
    if normalized == ".jsonl":
        return "jsonl"
    if normalized in {".yaml", ".yml"}:
        return "yaml"
    raise FeedError("args.feed format is not supported")


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


def render_producer_output_bytes(output: Any) -> bytes:
    """Render the exact UTF-8 form used by vulnify's pre-encoder size gate."""
    return json.dumps(
        output, sort_keys=True, ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        rendered = render_producer_output_bytes(output)
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


# --- Feature-branch snapshot/batch helpers ---------------------------------


_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)


def _normalize_cve(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip().upper()
    return value if _CVE_RE.fullmatch(value) else None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _value_hash(value: Any) -> str:
    try:
        encoded = _canonical_json(value)
    except (TypeError, ValueError):
        encoded = f"<{type(value).__name__}>"
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _normalized_args_hash(payload: dict[str, Any]) -> str:
    ids = payload.get("cve_ids")
    normalized_ids: Any = (
        [(_normalize_cve(value) or {"sha256": _value_hash(value)}) for value in ids]
        if isinstance(ids, list)
        else {"type": type(ids).__name__}
    )
    path = payload.get("bundle_path")
    return _value_hash({
        "bundle_path": str(Path(path).expanduser()) if isinstance(path, str) else {"type": type(path).__name__},
        "cve_ids": normalized_ids,
        "arg_keys": sorted(payload),
    })


def _read_bundle_snapshot(path: Path) -> bytes:
    with path.open("rb") as handle:
        snapshot = handle.read(MAX_BUNDLE_BYTES + 1)
    if len(snapshot) > MAX_BUNDLE_BYTES:
        raise reader.BundleError(f"bundle exceeds the {MAX_BUNDLE_BYTES} byte read cap")
    return snapshot


def _query_receipt(raw: Any, status: str, reason: str) -> dict[str, Any]:
    normalized = _normalize_cve(raw)
    row = {"cve_id": normalized, "status": status, "reason": reason}
    if normalized is None:
        row["query_sha256"] = _value_hash(raw)
    return row


def _failure(spec: ArmSpec, action: str, args_hash: str, bundle_sha: str | None, queries: list[dict[str, Any]], reason: str, error: str) -> Result:
    output = {"reason": reason, "snapshot_sha256": bundle_sha, "results": [], "count_matched": 0}
    _write_receipt(args_hash, bundle_sha, queries, output, False, reason)
    return Result(False, spec.id, action, output, error)


def _write_receipt(args_hash: str, bundle_sha: str | None, queries: list[dict[str, Any]], output: dict[str, Any], ok: bool, reason: str | None) -> None:
    receipt = {
        "schema": "vulnify.lookup-receipt.v1",
        "arm": ARM_ID,
        "action": "lookup",
        "normalized_args_sha256": args_hash,
        "bundle_sha256": bundle_sha,
        "queries": queries,
        "count_matched": sum(row.get("status") == "matched" for row in queries),
        "status": "complete" if ok else "failed",
        "reason": reason,
        "output_sha256": hashlib.sha256(_canonical_json(output).encode("utf-8")).hexdigest(),
    }
    print(_canonical_json(receipt), file=sys.stderr, flush=True)
