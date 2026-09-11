"""Fail-closed reader/index for frozen local vulnerability snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Finding E: when the frozen snapshot carries no technique anchors for a CVE
# (bundle prose has zero CVE references), fall back to the operator-curated
# expert map. Tagged `source: curated_expert_map` to stay distinct from any
# snapshot/bundle-derived or alert-asserted provenance.
_CURATED_PATH = Path(__file__).with_name("data") / "curated_cve_technique_map.json"
_curated_cache: dict[str, dict[str, Any]] | None = None


def _curated_index() -> dict[str, dict[str, Any]]:
    global _curated_cache
    if _curated_cache is None:
        try:
            _curated_cache = json.loads(_CURATED_PATH.read_text(encoding="utf-8"))["entries"]
        except FileNotFoundError:
            _curated_cache = {}
    return _curated_cache


def curated_technique_mappings(cve_id: str) -> list[dict[str, Any]] | None:
    """Expert-curated technique mappings for a CVE, or None when unknown."""
    entry = _curated_index().get(cve_id.upper())
    if entry is None:
        return None
    return [{"technique": entry["technique"], "tactic": entry.get("tactic"),
             "kind": entry.get("kind"), "confidence": entry.get("confidence"),
             "source": "curated_expert_map"}]


class BundleError(ValueError):
    """The snapshot is not readable or does not match the bounded schema."""


class _Pairs(list):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> _Pairs:
    return _Pairs(pairs)


def load_bundle_bytes(raw: bytes) -> dict[str, dict[str, Any]]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BundleError(f"bundle is not valid UTF-8: {exc}") from exc
    try:
        parsed = json.loads(text, object_pairs_hook=_pairs)
    except json.JSONDecodeError as exc:
        raise BundleError(f"bundle is not valid JSON: {exc}") from exc
    return _index(parsed)


def _plain(value: Any, label: str) -> Any:
    if isinstance(value, _Pairs):
        output: dict[str, Any] = {}
        for key, child in value:
            if not isinstance(key, str) or key in output:
                raise BundleError(f"{label} contains a duplicate or non-string key")
            output[key] = _plain(child, f"{label}.{key}")
        return output
    if isinstance(value, list):
        return [_plain(child, label) for child in value]
    return value


def _index(parsed: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(parsed, _Pairs):
        raise BundleError("bundle must be an object keyed by canonical CVE id")
    index: dict[str, dict[str, Any]] = {}
    for cve_id, raw_record in parsed:
        if not isinstance(cve_id, str) or cve_id in index:
            raise BundleError("bundle contains a duplicate or non-string CVE key")
        if not _canonical_cve(cve_id):
            raise BundleError(f"bundle key is not a canonical CVE id: {cve_id!r}")
        record = _plain(raw_record, cve_id)
        if not isinstance(record, dict):
            raise BundleError(f"record {cve_id} must be an object")
        unknown = sorted(set(record) - {"description", "descriptions", "references", "technique_mappings"})
        if unknown:
            raise BundleError(f"record {cve_id} has unsupported fields: {', '.join(unknown)}")
        if "description" in record and "descriptions" in record:
            raise BundleError(f"record {cve_id} must not carry both description forms")
        if "description" in record and not isinstance(record["description"], str):
            raise BundleError(f"record {cve_id}.description must be a string")
        if "descriptions" in record and not _valid_descriptions(record["descriptions"]):
            raise BundleError(f"record {cve_id}.descriptions must be a list of strings or language/value objects")
        if not isinstance(record.get("references"), list) or not all(
            isinstance(item, (str, dict)) for item in record["references"]
        ):
            raise BundleError(f"record {cve_id}.references must be a list of strings or objects")
        mappings = record.get("technique_mappings")
        if mappings is not None and (not isinstance(mappings, list) or not all(isinstance(item, (str, dict)) for item in mappings)):
            raise BundleError(f"record {cve_id}.technique_mappings must be a list of strings or objects")
        index[cve_id] = record
    return index


def _valid_descriptions(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, str)
        or (
            isinstance(item, dict)
            and set(item) <= {"lang", "value"}
            and isinstance(item.get("value"), str)
            and ("lang" not in item or isinstance(item["lang"], str))
        )
        for item in value
    )


def _canonical_cve(value: str) -> bool:
    parts = value.split("-")
    return (
        len(parts) == 3
        and parts[0] == "CVE"
        and len(parts[1]) == 4
        and parts[1].isascii()
        and parts[1].isdigit()
        and len(parts[2]) >= 4
        and parts[2].isascii()
        and parts[2].isdigit()
    )


def lookup(index: dict[str, dict[str, Any]], cve_id: str, snapshot_sha256: str) -> dict[str, Any] | None:
    record = index.get(cve_id)
    if record is None:
        return None
    raw_descriptions = record.get("descriptions")
    if raw_descriptions is None and "description" in record:
        raw_descriptions = [record["description"]]
    mappings = record.get("technique_mappings")
    if not mappings:
        mappings = curated_technique_mappings(cve_id)
    return {
        "cve_id": cve_id,
        "descriptions": raw_descriptions,
        "references": record["references"],
        "technique_mappings": mappings,
        "snapshot_sha256": snapshot_sha256,
    }
