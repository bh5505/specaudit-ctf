"""Causal tests for DATA-01/DATA-02 frozen slices."""

from __future__ import annotations

import pytest

from frozen_slices import (
    validate_rule_slice,
    validate_vuln_slice,
)


def _digest():
    return "sha256:" + "a" * 64


def _vuln():
    return {
        "slice_id": "v1",
        "source_id": "vulnify",
        "source_revision": "rev1",
        "source_timestamp": "2026-01-01T00:00:00Z",
        "snapshot_digest": _digest(),
        "record_count": 5,
        "records_digest": _digest(),
        "read_only": True,
        "denied_egress_proof": "proof",
        "stale_semantics": "stale",
        "unknown_semantics": "unknown",
        "negative_controls": ["missing"],
        "hosted_fallback": False,
    }


def _rule():
    return {
        "slice_id": "r1",
        "source_id": "security-detections",
        "source_revision": "rev1",
        "source_timestamp": "2026-01-01T00:00:00Z",
        "snapshot_digest": _digest(),
        "record_count": 5,
        "records_digest": _digest(),
        "read_only": True,
        "no_generation": True,
        "no_index_mutation": True,
        "no_deployment": True,
        "no_hosted_fallback": True,
        "missing_telemetry_cases": ["missing-log"],
        "negative_controls": ["missing"],
    }


def test_vuln_valid():
    r = validate_vuln_slice(_vuln())
    assert r.valid is True
    assert r.reasons == ()


def test_vuln_hosted_fallback_rejected():
    d = _vuln()
    d["hosted_fallback"] = True
    r = validate_vuln_slice(d)
    assert r.valid is False
    assert any("hosted_fallback" in x for x in r.reasons)


def test_vuln_missing_timestamp_rejected():
    d = _vuln()
    d["source_timestamp"] = None
    r = validate_vuln_slice(d)
    assert r.valid is False


def test_vuln_not_mapping():
    r = validate_vuln_slice("x")
    assert r.valid is False


def test_rule_valid():
    r = validate_rule_slice(_rule())
    assert r.valid is True


def test_rule_generation_rejected():
    d = _rule()
    d["no_generation"] = False
    r = validate_rule_slice(d)
    assert r.valid is False


def test_rule_missing_telemetry_required():
    d = _rule()
    d["missing_telemetry_cases"] = []
    r = validate_rule_slice(d)
    assert r.valid is False


def test_rule_bad_digest():
    d = _rule()
    d["snapshot_digest"] = "not-a-digest"
    r = validate_rule_slice(d)
    assert r.valid is False


def test_extra_keys_rejected():
    d = _vuln()
    d["extra"] = 1
    r = validate_vuln_slice(d)
    assert r.valid is False
