"""A bounded RAGE v0.1 *slice* for offline evidence interpretation.

No collector, zip/blob reader, general RAGE validator, or trusted observation.
An input hash binds bytes supplied by a caller; it does not authenticate origin.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 256_000
MAX_RECORDS = 128
MAX_PATHS = 32
MAX_EXPANSIONS = 512
HASH = re.compile(r"[0-9a-f]{64}\Z")
RECEIPT_HASH = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
FIELDS = {
    "manifest": {"kind", "spec_version", "taxonomy_version", "media_type", "created_at", "snapshot_at", "scope", "producer", "counts"},
    "node": {"kind", "node_id", "node_type", "provider", "name", "observed_at"},
    "edge": {"kind", "edge_id", "source", "target", "type", "state", "nature", "facts", "evidence"},
    "fact": {"kind", "fact_id", "source", "target", "edge_hint", "evidence", "captured_at", "provider", "content_hash"},
    "evidence": {"kind", "evidence_id", "content_hash", "source", "status", "captured_at", "scope"},
}


class InvalidGraph(ValueError):
    pass


def _unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise InvalidGraph("duplicate JSON key")
        out[key] = value
    return out


def _keys(value, expected, required):
    if not isinstance(value, dict) or set(value) - expected or not required <= set(value):
        raise InvalidGraph("unrecognized or missing fields")


def _string(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise InvalidGraph("invalid string")
    return value


def _timestamp(value):
    _string(value)
    if not value.endswith("Z"):
        raise InvalidGraph("timestamp must be UTC")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidGraph("invalid timestamp") from exc


def _refs(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value or len(value) > 16:
        raise InvalidGraph("empty or invalid provenance references")
    refs = [_string(v) for v in value]
    if len(set(refs)) != len(refs):
        raise InvalidGraph("duplicate provenance reference")
    return refs


def _node_id(value):
    _string(value)
    pieces = value.split("|")
    if len(pieces) != 4 or not re.fullmatch(r"[a-z][a-z0-9_-]*", pieces[0]):
        raise InvalidGraph("invalid RAGE node_id")
    if any(not p or re.search(r"%(?!25|7C)", p, re.I) for p in pieces):
        raise InvalidGraph("invalid RAGE node_id component")
    return value


def _decode(raw: bytes, expected_sha256: str):
    if len(raw) > MAX_BYTES or not HASH.fullmatch(expected_sha256):
        raise InvalidGraph("size limit or expected digest invalid")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_sha256:
        raise InvalidGraph("source bytes do not match expected digest")
    try:
        lines = raw.decode("utf-8").splitlines()
        if not 2 <= len(lines) <= MAX_RECORDS or any(not s.strip() for s in lines):
            raise InvalidGraph("record count or blank line invalid")
        records = [json.loads(line, object_pairs_hook=_unique_pairs) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidGraph("invalid UTF-8 NDJSON") from exc
    return records, digest


def read_graph(raw: bytes, expected_sha256: str):
    """Validate a redacted subset; reject all unhandled kinds/fields and locators."""
    records, digest = _decode(raw, expected_sha256)
    grouped = defaultdict(list)
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not isinstance(record.get("kind"), str) or record["kind"] not in FIELDS:
            raise InvalidGraph("unsupported record kind")
        kind = record["kind"]
        if (index == 0) != (kind == "manifest"):
            raise InvalidGraph("manifest must be first and unique")
        required = {
            "manifest": {"kind", "spec_version", "created_at", "scope", "producer"},
            "node": {"kind", "node_id", "node_type"},
            "edge": {"kind", "edge_id", "source", "target", "type", "state", "nature", "facts"},
            "fact": {"kind", "fact_id", "source", "target", "edge_hint", "evidence", "captured_at"},
            "evidence": {"kind", "evidence_id", "content_hash", "source", "status", "captured_at", "scope"},
        }[kind]
        _keys(record, FIELDS[kind], required)
        grouped[kind].append(record)
    manifest = records[0]
    if manifest["spec_version"] != "0.1" or manifest.get("media_type", "application/vnd.rage.graph+ndjson") != "application/vnd.rage.graph+ndjson":
        raise InvalidGraph("unsupported RAGE version or media type")
    _timestamp(manifest["created_at"])
    if "snapshot_at" in manifest:
        _timestamp(manifest["snapshot_at"])
    if manifest.get("taxonomy_version", "0.1") != "0.1":
        raise InvalidGraph("unsupported taxonomy version")
    _string(manifest["producer"])
    _keys(manifest["scope"], {"providers", "foothold"}, {"providers", "foothold"})
    if manifest["scope"]["providers"] != ["aws"]:
        raise InvalidGraph("only one synthetic AWS realm is admitted")
    foothold = _node_id(manifest["scope"]["foothold"])
    if foothold.split("|")[0] != manifest["scope"]["providers"][0]:
        raise InvalidGraph("foothold provider mismatch")
    indexed = {}
    for kind, idfield in (("node", "node_id"), ("edge", "edge_id"), ("fact", "fact_id"), ("evidence", "evidence_id")):
        seen = set()
        for rec in grouped[kind]:
            key = _string(rec[idfield])
            if key in seen:
                raise InvalidGraph("duplicate " + kind + " identifier")
            seen.add(key)
        indexed[kind] = {rec[idfield]: rec for rec in grouped[kind]}
    nodes, facts, evidence = indexed["node"], indexed["fact"], indexed["evidence"]
    if foothold not in nodes or not grouped["edge"]:
        raise InvalidGraph("missing foothold or edges")
    if "counts" in manifest:
        _keys(manifest["counts"], {"nodes", "edges", "facts", "evidence", "findings", "surfaces", "paths"},
              {"nodes", "edges", "facts", "evidence"})
        for plural, kind in (("nodes", "node"), ("edges", "edge"), ("facts", "fact"), ("evidence", "evidence")):
            value = manifest["counts"][plural]
            if type(value) is not int or value != len(grouped[kind]):
                raise InvalidGraph("manifest count mismatch")
        if any(manifest["counts"].get(k, 0) != 0 for k in ("findings", "surfaces", "paths")):
            raise InvalidGraph("unreviewed record kinds counted")
    for node in nodes.values():
        _node_id(node["node_id"])
        _string(node["node_type"])
        if "provider" in node and node["provider"] != "aws":
            raise InvalidGraph("node provider mismatch")
        if "name" in node:
            _string(node["name"])
        if "observed_at" in node:
            _timestamp(node["observed_at"])
        if node["node_id"].split("|")[0:2] != foothold.split("|")[0:2]:
            raise InvalidGraph("out-of-realm node")
    for rec in evidence.values():
        if not RECEIPT_HASH.fullmatch(_string(rec["content_hash"])):
            raise InvalidGraph("invalid receipt digest")
        if rec["status"] not in ("ok", "denied"):
            raise InvalidGraph("unknown collection outcome")
        _string(rec["source"])
        _timestamp(rec["captured_at"])
        if rec["scope"] != manifest["scope"]:
            raise InvalidGraph("receipt scope mismatch")
    for rec in facts.values():
        _timestamp(rec["captured_at"])
        for field in ("source", "target"):
            _node_id(rec[field])
            if rec[field] not in nodes:
                raise InvalidGraph("fact node reference missing")
        _string(rec["edge_hint"])
        if "provider" in rec and rec["provider"] != "aws":
            raise InvalidGraph("fact provider mismatch")
        if "content_hash" in rec and not RECEIPT_HASH.fullmatch(_string(rec["content_hash"])):
            raise InvalidGraph("invalid fact digest")
        if any(ref not in evidence for ref in _refs(rec["evidence"])):
            raise InvalidGraph("fact receipt missing")
    for edge in grouped["edge"]:
        _node_id(edge["source"])
        _node_id(edge["target"])
        if edge["source"] not in nodes or edge["target"] not in nodes:
            raise InvalidGraph("edge node reference missing")
        _string(edge["type"])
        if edge["state"] not in ("ACTIVE", "BLOCKED", "UNKNOWN", "CONDITIONAL", "POTENTIAL") or edge["nature"] not in ("explicit", "derived"):
            raise InvalidGraph("unrecognized edge semantics")
        for ref in _refs(edge["facts"]):
            fact = facts.get(ref)
            if not fact or (fact["source"], fact["target"], fact["edge_hint"]) != (edge["source"], edge["target"], edge["type"]):
                raise InvalidGraph("edge fact mismatch")
        fact_receipts = {eid for fid in _refs(edge["facts"]) for eid in _refs(facts[fid]["evidence"])}
        if edge["nature"] == "derived" and "evidence" not in edge:
            raise InvalidGraph("derived edge lacks evidence")
        if "evidence" in edge and set(_refs(edge["evidence"])) != fact_receipts:
            raise InvalidGraph("edge receipt differs from supporting facts")
    return manifest, indexed, digest


# The permissive upstream schema allows arbitrary extensions. Projection is an
# *opt-in, closed* redaction decision, never a generic discard-unknown parser.
PROJECT_DROP = {
    "manifest": {"taxonomy_version", "snapshot_at"},
    "node": {"provider", "name", "observed_at", "scope"},
    "edge": {"scope", "provider", "confidence", "weight", "conditions", "permissions", "rule_id", "derived_from", "observed_at"},
    "fact": {"provider", "content_hash", "scope"},
    "evidence": set(),
    "surface": {"kind", "surface_id", "resource_id", "category", "emits_hint", "severity", "evidence"},
    "path": {"kind", "path_id", "source", "target", "edge_ids", "score"},
    "finding": {"kind", "resource_id", "severity", "emits_hint", "evidence"},
}
SEMANTIC_EDGE_FIELDS = {"scope", "conditions", "permissions", "derived_from", "rule_id"}


def _safe_omission(value):
    """Only compact scalar/list metadata; arbitrary maps and raw payloads fail."""
    if isinstance(value, str):
        _string(value)
    elif type(value) in (int, float):
        if not (-1_000_000 <= value <= 1_000_000):
            raise InvalidGraph("unbounded omitted number")
    elif isinstance(value, list) and len(value) <= 16:
        for part in value:
            _string(part)
    elif value == {}:
        pass
    else:
        raise InvalidGraph("unsafe omitted value")


def project(raw: bytes, expected_sha256: str):
    """Return sanitized NDJSON and omission ledger for a closed RAGE v0.1 slice."""
    records, digest = _decode(raw, expected_sha256)
    projected = []
    omitted = defaultdict(int)
    semantic_edges = set()
    omitted_free_bag = False
    auxiliary_path_edges = set()
    for rec in records:
        if not isinstance(rec, dict) or not isinstance(rec.get("kind"), str):
            raise InvalidGraph("invalid projected record")
        kind = rec["kind"]
        if kind not in PROJECT_DROP:
            raise InvalidGraph("unknown projected kind")
        if kind in ("surface", "path", "finding"):
            if set(rec) - PROJECT_DROP[kind] - {"detail", "attributes"}:
                raise InvalidGraph("unsafe auxiliary fields")
            for bag in set(rec) & {"detail", "attributes"}:
                if not isinstance(rec[bag], dict):
                    raise InvalidGraph("free-bag must be an object")
                omitted[kind + "." + bag] += 1
                omitted_free_bag = True
            if kind == "path":
                auxiliary_path_edges.update(_refs(rec.get("edge_ids")))
            for key, value in rec.items():
                if key in ("detail", "attributes"):
                    continue
                _safe_omission(value)
            omitted[kind + "_records"] += 1
            continue
        accepted = FIELDS[kind]
        extra = set(rec) - accepted - PROJECT_DROP[kind] - {"attributes", "detail"}
        if extra:
            raise InvalidGraph("unsafe or unknown projected fields")
        clean = {key: value for key, value in rec.items() if key in accepted}
        for key in set(rec) & PROJECT_DROP[kind]:
            if kind == "edge" and key == "conditions" and isinstance(rec[key], dict):
                # Producer condition objects have no admitted evaluator here.
                # The bounded JSON bytes are discarded without reading values.
                pass
            else:
                _safe_omission(rec[key])
            omitted[kind + "." + key] += 1
        # Free bags may contain raw secrets. Retain neither keys nor values;
        # their presence taints the whole graph because relevance is unknown.
        for bag in ("attributes", "detail"):
            if bag in rec:
                if not isinstance(rec[bag], dict):
                    raise InvalidGraph("free-bag must be an object")
                omitted[kind + "." + bag] += 1
                omitted_free_bag = True
        if kind == "edge" and set(rec) & SEMANTIC_EDGE_FIELDS:
            semantic_edges.add(_string(rec.get("edge_id")))
            if clean.get("state") != "BLOCKED":
                clean["state"] = "UNKNOWN"
        projected.append(clean)
    graph_edge_ids = {rec["edge_id"] for rec in projected if rec["kind"] == "edge" and isinstance(rec.get("edge_id"), str)}
    if not auxiliary_path_edges <= graph_edge_ids:
        raise InvalidGraph("auxiliary path references missing edge")
    if omitted_free_bag or auxiliary_path_edges:
        for rec in projected:
            if rec["kind"] == "edge" and rec["state"] != "BLOCKED" and (omitted_free_bag or rec["edge_id"] in auxiliary_path_edges):
                semantic_edges.add(rec["edge_id"])
                rec["state"] = "UNKNOWN"
    manifest = projected[0] if projected else None
    if not isinstance(manifest, dict) or manifest.get("kind") != "manifest":
        raise InvalidGraph("manifest missing")
    if "counts" in manifest:
        original_counts = manifest["counts"]
        _keys(original_counts, {"nodes", "edges", "facts", "evidence", "findings", "surfaces", "paths"},
              {"nodes", "edges", "facts", "evidence"})
        for plural in ("findings", "surfaces", "paths"):
            if original_counts.get(plural, 0) != omitted.get(plural[:-1] + "_records", 0):
                # findings -> finding, surfaces -> surface, paths -> path
                raise InvalidGraph("auxiliary manifest count mismatch")
        manifest["counts"] = {**original_counts, "findings": 0, "surfaces": 0, "paths": 0}
    sanitized = ("\n".join(json.dumps(rec, sort_keys=True, separators=(",", ":")) for rec in projected) + "\n").encode()
    read_graph(sanitized, hashlib.sha256(sanitized).hexdigest())
    return sanitized, {"source_sha256": digest, "projected_sha256": hashlib.sha256(sanitized).hexdigest(),
                       "omitted": dict(sorted(omitted.items())), "semantic_edges_downgraded": len(semantic_edges)}


def evaluate(raw: bytes, expected_sha256: str, source: str, target: str, *, project_mode: bool = False):
    projection = None
    if project_mode:
        raw, projection = project(raw, expected_sha256)
        expected_sha256 = projection["projected_sha256"]
    manifest, indexed, digest = read_graph(raw, expected_sha256)
    nodes, edges, facts, evidence = (indexed[k] for k in ("node", "edge", "fact", "evidence"))
    if source != manifest["scope"]["foothold"] or target not in nodes:
        raise InvalidGraph("requested path outside manifest scope")
    adjacency = defaultdict(list)
    for edge in edges.values():
        adjacency[edge["source"]].append(edge)
    paths = []
    expansions = 0

    def visit(node, chain, visited):
        nonlocal expansions
        expansions += 1
        if expansions > MAX_EXPANSIONS:
            raise InvalidGraph("path expansion limit exceeded")
        if len(paths) >= MAX_PATHS:
            raise InvalidGraph("path count limit exceeded")
        if node == target and chain:
            statuses = []
            provenance = []
            for edge in chain:
                receipt_ids = sorted({eid for fid in _refs(edge["facts"]) for eid in _refs(facts[fid]["evidence"])})
                receipts = [evidence[eid] for eid in receipt_ids]
                provenance.append({"edge_id": edge["edge_id"], "nature": edge["nature"], "state_declared": edge["state"],
                                   "fact_ids": _refs(edge["facts"]), "receipts": [
                                       {"evidence_id": r["evidence_id"], "content_hash_declared": r["content_hash"],
                                        "source_declared": r["source"], "status_declared": r["status"],
                                        "captured_at_declared": r["captured_at"]} for r in receipts]})
                if edge["state"] == "BLOCKED":
                    statuses.append("blocked")
                elif edge["state"] != "ACTIVE" or any(r["status"] != "ok" for r in receipts):
                    statuses.append("unknown")
                else:
                    statuses.append("configured")
            verdict = "blocked" if "blocked" in statuses else "unknown" if "unknown" in statuses else "configured_candidate"
            paths.append({"edge_ids": [e["edge_id"] for e in chain], "edge_assessments": statuses,
                          "provenance": provenance, "verdict": verdict})
            return
        for edge in sorted(adjacency[node], key=lambda e: e["edge_id"]):
            if edge["target"] not in visited:
                visit(edge["target"], chain + [edge], visited | {edge["target"]})

    visit(source, [], {source})
    result = {
        "schema": "specaudit.graph-evidence-review.v1",
        "input_sha256": digest,
        "producer_declared": manifest["producer"],
        "created_at_declared": manifest["created_at"],
        "scope_declared": manifest["scope"],
        "source": source, "target": target,
        "paths": paths,
        "limitations": ["Synthetic configuration graph only; no effective access, collection authenticity, or workload behavior established.",
                        "Receipt content_hash values are declarations; referenced raw response bytes were not retained or verified."],
    }
    if projection is not None:
        result["input_sha256"] = projection["source_sha256"]
        result["projection"] = projection
        result["limitations"].append("Projection omitted records/fields and downgraded semantic edges; review the omission ledger before use.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review a narrow, sanitized RAGE v0.1 NDJSON slice offline")
    parser.add_argument("file", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--project", action="store_true", help="opt-in closed sanitizing projection; reports all omissions")
    args = parser.parse_args(argv)
    try:
        if args.file.is_symlink() or not args.file.is_file() or args.file.stat().st_size > MAX_BYTES:
            raise InvalidGraph("input must be a bounded regular file")
        result = evaluate(args.file.read_bytes(), args.sha256, args.source, args.target, project_mode=args.project)
    except (InvalidGraph, OSError) as exc:
        print(json.dumps({"error": str(exc), "schema": "specaudit.graph-evidence-review.v1"}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0
