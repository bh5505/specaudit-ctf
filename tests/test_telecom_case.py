"""Causal tests for TEL telecom assurance case validation."""

from __future__ import annotations

import pytest

from telecom_case import validate_telecom_case


def _good():
    return {
        "case_id": "tel-01",
        "tel_module": "TEL-01",
        "architecture": "Synthetic management host and isolated simulated service.",
        "trust_zones": ["management-zone", "simulated-service-zone"],
        "management_plane": "Read-only captured management policy.",
        "telemetry": "Captured synthetic management access events.",
        "criteria": ["criteria/management-separation.md"],
        "threat_model": "A learner evaluates a supplied cross-zone access claim.",
        "procedure": ["Review topology", "Compare policy to captured events"],
        "evidence": ["captures/management-policy.json"],
        "limitations": ["Synthetic records cannot establish live service isolation."],
        "conclusion": "The supplied capture supports only the declared synthetic case.",
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


@pytest.mark.parametrize("field", [
    "case_id", "architecture", "trust_zones", "management_plane", "telemetry",
    "criteria", "threat_model", "procedure", "evidence", "limitations", "conclusion",
])
@pytest.mark.parametrize("value", [False, True, 1, [None], {"ref": None}])
def test_substantive_sections_reject_placeholders(field, value):
    d = _good()
    d[field] = value
    assert validate_telecom_case(d).valid is False


@pytest.mark.parametrize("field", ["trust_zones", "criteria", "evidence", "limitations"])
@pytest.mark.parametrize("value", [[""], [" "], [[]], [{"ref": "x"}]])
def test_reference_lists_reject_empty_or_wrong_typed_items(field, value):
    d = _good()
    d[field] = value
    assert validate_telecom_case(d).valid is False


@pytest.mark.parametrize("value", [" ", "x/y", "x" * 129])
def test_case_identity_is_stable_bounded_identifier(value):
    d = _good()
    d["case_id"] = value
    assert validate_telecom_case(d).valid is False


@pytest.mark.parametrize("value", [[], {}])
def test_unhashable_module_is_invalid_without_raising(value):
    d = _good()
    d["tel_module"] = value
    assert validate_telecom_case(d).valid is False


def test_structured_sections_may_carry_concrete_nested_content():
    d = _good()
    d["architecture"] = {"diagram_ref": "architecture.svg", "notes": ["synthetic topology"]}
    assert validate_telecom_case(d).valid is True


def test_narrative_cannot_carry_lone_unicode_surrogate():
    d = _good()
    d["architecture"] = "topology-\udfff"
    assert validate_telecom_case(d).valid is False


def test_mixed_type_extra_keys_report_invalid():
    d = _good()
    d.update({1: "invalid key", "extra": "unexpected"})
    assert validate_telecom_case(d).valid is False
