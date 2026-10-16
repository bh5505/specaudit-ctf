"""Validate a learner workpaper against a bounded, hashed evidence manifest.

This checker never decides whether a security finding is true. It has no
network or execution path and does not load an instructor answer key.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping


STATUSES = {"supported", "rejected", "unresolved"}
KINDS = {"observed", "declared", "inferred"}
MAX_RECORDS = 100
MAX_EVIDENCE_BYTES = 1_048_576


def _object(value, label, errors):
    if not isinstance(value, dict):
        errors.append(f"{label}: expected object")
        return {}
    return value


def _text(value, label, errors):
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label}: nonempty text required")


def _text_list(value, label, errors):
    if not isinstance(value, list) or not value:
        errors.append(f"{label}: nonempty list required")
    else:
        for i, item in enumerate(value):
            _text(item, f"{label}[{i}]", errors)


def validate(manifest, submission, evidence_root=None, *, evidence_bytes: Mapping[str, bytes] | None = None):
    """Return structural errors; semantic conclusions remain human-reviewed."""
    if (evidence_root is None) == (evidence_bytes is None):
        raise ValueError("select exactly one evidence source")
    errors = []
    manifest = _object(manifest, "manifest", errors)
    submission = _object(submission, "submission", errors)
    if manifest.get("schema") != "specaudit.review-evidence.v1":
        errors.append("manifest: unsupported schema")
    if submission.get("schema") != "specaudit.review-workpaper.v1":
        errors.append("submission: unsupported schema")
    for field in ("subject", "version", "period", "boundary", "criterion", "reviewer"):
        _text(submission.get(field), field, errors)
    for field in ("assets", "trust_boundaries", "attacker_goals", "untested", "limitations", "recommendation", "retest"):
        _text_list(submission.get(field), field, errors)
    evidence = {}
    records = manifest.get("evidence")
    if not isinstance(records, list) or not records:
        errors.append("manifest.evidence: nonempty list required")
        records = []
    if len(records) > MAX_RECORDS:
        errors.append(f"manifest.evidence: maximum {MAX_RECORDS} records")
        records = records[:MAX_RECORDS]
    root = evidence_root.resolve() if evidence_root is not None else None
    if evidence_bytes is not None:
        if not isinstance(evidence_bytes, Mapping) or len(evidence_bytes) > MAX_RECORDS or any(
            not isinstance(k, str) or not isinstance(v, bytes) for k, v in evidence_bytes.items()
        ):
            raise ValueError("invalid inline evidence mapping")
        named = {row.get("file") for row in records if isinstance(row, dict) and isinstance(row.get("file"), str)}
        if set(evidence_bytes) != named:
            errors.append("inline evidence must match manifest file names exactly")
    for i, item in enumerate(records):
        label = f"manifest.evidence[{i}]"
        item = _object(item, label, errors)
        key = item.get("id")
        _text(key, f"{label}.id", errors)
        if not isinstance(key, str) or key in evidence:
            errors.append(f"{label}: duplicate or invalid id")
            continue
        evidence[key] = item
        for field in ("producer", "version", "captured_at", "subject", "scope", "custody", "data_class", "transformations", "limitations"):
            _text(item.get(field), f"{label}.{field}", errors)
        if not isinstance(item.get("kind"), str) or item["kind"] not in KINDS:
            errors.append(f"{label}.kind: expected observed, declared or inferred")
        rel = item.get("file")
        if not isinstance(rel, str) or not rel or Path(rel).is_absolute():
            errors.append(f"{label}.file: relative file required")
            continue
        if evidence_bytes is not None:
            content = evidence_bytes.get(rel)
            if content is None:
                errors.append(f"{label}.file: absent from inline evidence")
                continue
        else:
            try:
                path = (root / rel).resolve()
            except (OSError, ValueError):
                errors.append(f"{label}.file: invalid path")
                continue
            if not path.is_relative_to(root) or not path.is_file():
                errors.append(f"{label}.file: missing or outside evidence root")
                continue
            # This bounds a mutable path read; custody requires an immutable packet.
            try:
                with path.open("rb") as stream:
                    content = stream.read(MAX_EVIDENCE_BYTES + 1)
            except OSError:
                errors.append(f"{label}.file: unreadable")
                continue
        if len(content) > MAX_EVIDENCE_BYTES:
            errors.append(f"{label}.file: exceeds {MAX_EVIDENCE_BYTES} bytes")
            continue
        expected = item.get("sha256")
        if not isinstance(expected, str) or len(expected) != 64 or hashlib.sha256(content).hexdigest() != expected:
            errors.append(f"{label}.sha256: invalid or content mismatch")
    claims = submission.get("claims")
    if not isinstance(claims, list) or not claims:
        errors.append("claims: nonempty list required")
        claims = []
    seen = set()
    for i, claim in enumerate(claims):
        label = f"claims[{i}]"
        claim = _object(claim, label, errors)
        key = claim.get("id")
        _text(key, f"{label}.id", errors)
        if not isinstance(key, str) or key in seen:
            errors.append(f"{label}: duplicate or invalid id")
        else:
            seen.add(key)
        for field in ("hypothesis", "boundary", "observation", "inference", "alternative", "validation", "residual_risk"):
            _text(claim.get(field), f"{label}.{field}", errors)
        if not isinstance(claim.get("status"), str) or claim["status"] not in STATUSES:
            errors.append(f"{label}.status: invalid")
        refs = claim.get("evidence_ids")
        if not isinstance(refs, list) or not refs:
            errors.append(f"{label}.evidence_ids: nonempty list required")
        elif len(refs) != len(set(str(ref) for ref in refs)):
            errors.append(f"{label}.evidence_ids: duplicate reference")
        else:
            for ref in refs:
                if not isinstance(ref, str) or ref not in evidence:
                    errors.append(f"{label}.evidence_ids: unknown reference {ref!r}")
        if claim.get("status") == "supported" and isinstance(refs, list) and not any(
            evidence.get(ref, {}).get("kind") == "observed" for ref in refs if isinstance(ref, str)
        ):
            errors.append(f"{label}: supported claim requires observed evidence")
    coverage = submission.get("coverage")
    if not isinstance(coverage, list) or not coverage:
        errors.append("coverage: nonempty list required")
    else:
        ids = set()
        for i, row in enumerate(coverage):
            label = f"coverage[{i}]"
            row = _object(row, label, errors)
            _text(row.get("surface"), f"{label}.surface", errors)
            _text(row.get("disposition"), f"{label}.disposition", errors)
            refs = row.get("claim_ids")
            if not isinstance(refs, list):
                errors.append(f"{label}.claim_ids: list required")
            else:
                for ref in refs:
                    if not isinstance(ref, str) or ref not in seen:
                        errors.append(f"{label}.claim_ids: unknown claim {ref!r}")
            surface = row.get("surface")
            if not isinstance(surface, str) or surface in ids:
                errors.append(f"{label}: duplicate surface")
            else:
                ids.add(surface)
    if submission.get("overall") not in ("bounded-conclusion", "inconclusive"):
        errors.append("overall: bounded-conclusion or inconclusive required; no all-clear state")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        errors = validate(json.loads(args.manifest.read_text()), json.loads(args.submission.read_text()), args.evidence_root)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"input error: {exc}\n")
    print(json.dumps({"structurally_valid": not errors, "human_review_required": True, "errors": errors}, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
