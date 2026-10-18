"""Causal tests for TEL telecom assurance case validation."""

from __future__ import annotations

import pytest

from telecom_case import validate_telecom_case


def _good():
    return {
        "case_id": "tel-01",
        "tel_module": "TEL-01",
        "architecture": "arch",
        "trust_zones": ["zone-a"],
        "management_plane": "mp",
        "telemetry": "tel",
        "criteria": ["c1"],
        "threat_model": "tm",
        "procedure": "proc",
        "evidence": ["ev"],
        "limitations": ["lim"],
        "conclusion": "conc",
    }


def test_good_passes():
    r = validate_telecom_case(_good())
    assert r.valid is True


def test_missing_fails():
    d = _good()
    del d["telemetry"]
    r = validate_telecom_case(d)
    assert r.valid is False
    assert "telemetry" in r.missing


def test_bad_module_fails():
    d = _good()
    d["tel_module"] = "TEL-99"
    r = validate_telecom_case(d)
    assert r.valid is False


def test_empty_fails():
    d = _good()
    d["architecture"] = ""
    r = validate_telecom_case(d)
    assert r.valid is False


def test_extra_fails():
    d = _good()
    d["extra"] = 1
    r = validate_telecom_case(d)
    assert r.valid is False


def test_non_mapping_raises():
    with pytest.raises(Exception):
        validate_telecom_case("x")
