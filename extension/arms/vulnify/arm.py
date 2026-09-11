"""Vulnify arm: bounded exact CVE lookups over a local frozen snapshot."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..mcp_client import redact
from . import reader
from .policy import (
    ALLOWED_ACTIONS,
    ARG_KEYS,
    ARMING,
    ARM_ID,
    CAVEATS,
    LIST_ACTIONS,
    MAX_BUNDLE_BYTES,
    MAX_OUTPUT_CHARS,
    args_refusal,
    bundle_refusal,
    demo_bundle_path,
)
from .reader import BundleError


class VulnifyArm:
    """First-party, stdlib-only local snapshot reader."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(self, spec: ArmSpec, action: str, args: Mapping[str, Any]) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return Result(False, spec.id, action, None, f"action {action!r} is not on the allowlist (offline exact local lookups only)")
        return self._lookup(spec, action, payload)

    def _lookup(self, spec: ArmSpec, action: str, payload: dict[str, Any]) -> Result:
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
        except (BundleError, OSError) as exc:
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

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict[str, Any]) -> Result:
        if payload:
            return Result(False, spec.id, action, None, "list_tools takes no caller arguments")
        return Result(True, spec.id, action, {
            "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
            "dispatch_actions": [],
            "demo_bundle": str(demo_bundle_path()),
            "arg_keys": {key: sorted(values) for key, values in ARG_KEYS.items()},
            "caveats": list(CAVEATS),
            "arming": ARMING,
        }, None)


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
        raise BundleError(f"bundle exceeds the {MAX_BUNDLE_BYTES} byte read cap")
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
