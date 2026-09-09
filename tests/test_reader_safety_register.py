"""Causal tests for the checkout-only PR97 reader-safety register.

Integrity means that the closed register still corresponds to the named
checkout surfaces.  It must never be confused with verification of an
operator environment, input custody, isolation, monitoring, or grading.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tomllib
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any, Iterator, Mapping

import pytest
import yaml

import safety
import safety.check as safety_check


ROOT = Path(__file__).resolve().parents[1]
FIXED_AS_OF = date(2026, 9, 9)
EXPECTED_ARM_IDS = {
    "ad-pathfinder",
    "agentseal",
    "claude-ad",
    "collinear",
    "detection-in-the-cloud",
    "gpohound",
    "leonidas",
    "m365pwned",
    "numasec",
    "pentestkit",
    "rubeus",
    "security-detections-mcp",
    "specterops-skills",
    "vulnify",
}
EXPECTED_READER_SOURCE_PATHS = {
    "extension/invoke_profiles.py",
    "extension/contract.py",
    "extension/dispatch.py",
    "extension/arms/strict_data.py",
    "extension/arms/mcp_client.py",
    *{
        f"extension/arms/{module}/{name}.py"
        for module in (
            "ad_pathfinder",
            "agentseal",
            "claude_ad",
            "collinear",
            "detection_in_the_cloud",
            "gpohound",
            "leonidas",
            "m365pwned",
            "numasec",
            "pentestkit",
            "rubeus",
            "security_detections_mcp",
            "specterops_skills",
            "vulnify",
        )
        for name in ("__init__", "arm", "policy")
    },
}
EXPECTED_HANDLER_REGISTRY = {
    "ad-pathfinder": "extension.arms.ad_pathfinder.arm.AdPathfinderArm",
    "agentseal": "extension.arms.agentseal.arm.AgentSealArm",
    "claude-ad": "extension.arms.claude_ad.arm.ClaudeAdArm",
    "collinear": "extension.arms.collinear.arm.CollinearArm",
    "detection-in-the-cloud": (
        "extension.arms.detection_in_the_cloud.arm.DetectionInTheCloudArm"
    ),
    "gpohound": "extension.arms.gpohound.arm.GpohoundArm",
    "leonidas": "extension.arms.leonidas.arm.LeonidasArm",
    "m365pwned": "extension.arms.m365pwned.arm.M365PwnedArm",
    "numasec": "extension.arms.numasec.arm.NumasecArm",
    "pentestkit": "extension.arms.pentestkit.arm.PentestkitArm",
    "rubeus": "extension.arms.rubeus.arm.RubeusArm",
    "security-detections-mcp": (
        "extension.arms.security_detections_mcp.arm.SecurityDetectionsMcpArm"
    ),
    "specterops-skills": (
        "extension.arms.specterops_skills.arm.SpecteropsSkillsArm"
    ),
    "vulnify": "extension.arms.vulnify.arm.VulnifyArm",
}


class _AlwaysEqualStr(str):
    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False

    __hash__ = str.__hash__


@pytest.fixture(scope="module")
def registry():
    return safety.load_register()


@pytest.fixture(scope="module")
def surfaces():
    return safety.snapshot_surfaces()


def _copy_document(registry: Any) -> dict[str, Any]:
    return copy.deepcopy(dict(registry.document))


def _actions(document: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    for arm in document["arms"]:
        yield from arm["data_actions"]


def _codes(report: Any) -> set[str]:
    return {issue.code for issue in report.issues}


def _semantic_sha256(value: Any) -> str:
    """Hash the already-normalized public surface document independently."""
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _byte_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _rehash_surfaces(surfaces: Any, document: Mapping[str, Any]):
    """Return a self-consistent snapshot whose semantics differ from checkout."""
    copied = copy.deepcopy(dict(document))
    section_sha256 = {
        section: _semantic_sha256(copied[section])
        for section in surfaces.section_sha256
    }
    return replace(
        surfaces,
        document=copied,
        section_sha256=section_sha256,
        document_sha256=_semantic_sha256(copied),
    )


def _validate(
    registry: Any,
    surfaces: Any,
    *,
    require: str = "integrity",
):
    return safety.validate_register(
        registry,
        surfaces,
        scope="pr97-readers",
        require=require,
        as_of=FIXED_AS_OF,
    )


def _write_register(tmp_path: Path, document: Mapping[str, Any]) -> Path:
    path = tmp_path / "register.v1.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _load_document(tmp_path: Path, document: Mapping[str, Any]):
    return safety.load_register(_write_register(tmp_path, document))


def _assert_omission_fails_closed(
    document: Mapping[str, Any],
    *,
    surfaces: Any,
    tmp_path: Path,
    expected_code: str,
) -> None:
    """Accept either closed-schema refusal or a specific integrity finding."""
    try:
        changed = _load_document(tmp_path, document)
    except safety.SafetyLoadError as exc:
        assert "schema" in str(exc).lower()
        return
    report = _validate(changed, surfaces)
    assert not report.ok
    assert not report.integrity_ok
    assert expected_code in _codes(report)


def test_baseline_binds_exact_reader_inventory(registry, surfaces) -> None:
    document = registry.document
    arms = document["arms"]
    actions = list(_actions(document))
    report = _validate(registry, surfaces)

    assert report.ok
    assert report.integrity_ok
    assert not report.ready_ok
    assert {arm["arm_id"] for arm in arms} == EXPECTED_ARM_IDS
    assert len(arms) == 14
    assert len(actions) == 38
    assert sum(action["input_kind"] == "file" for action in actions) == 35
    assert sum(action["input_kind"] == "directory" for action in actions) == 3
    assert len(document["hazards"]) == 12
    assert len(document["controls"]) == 11
    assert report.arm_count == 14
    assert report.discovery_action_count == 14
    assert report.data_action_count == 38
    assert report.hazard_count == 12
    assert report.control_count == 11
    assert report.as_dict()["counts"] == {
        "arms": 14,
        "discovery_actions": 14,
        "data_actions": 38,
        "hazards": 12,
        "controls": 11,
        "issues": len(report.issues),
    }
    assert len({arm["discovery_capability_id"] for arm in arms}) == 14
    assert len({action["capability_id"] for action in actions}) == 38
    assert document["scope"] == {
        **document["scope"],
        "id": "pr97-readers",
        "repository_complete": False,
        "safety_complete": False,
        "arm_count": 14,
        "discovery_action_count": 14,
        "data_action_count": 38,
    }


def test_ready_remains_explicitly_nonzero_and_permanently_unverified(
    registry, surfaces
) -> None:
    report = _validate(registry, surfaces, require="ready")
    codes = _codes(report)

    assert report.integrity_ok
    assert not report.ready_ok
    assert not report.ok
    assert "safety-verifier-unimplemented" in codes
    assert "required-control-unverified" in codes
    assert "repository-scope-partial" in codes
    assert "safety-scope-incomplete" in codes
    assert all(control["status"] == "unverified" for control in registry.document["controls"])
    assert all(not control["evidence_refs"] for control in registry.document["controls"])


def test_every_action_row_is_independently_anchored(
    registry, surfaces, tmp_path: Path
) -> None:
    baseline = _copy_document(registry)
    for arm_index, arm in enumerate(baseline["arms"]):
        for action_index, action in enumerate(arm["data_actions"]):
            document = copy.deepcopy(baseline)
            row = document["arms"][arm_index]["data_actions"][action_index]
            row["action"] = f"mutated_{action['action']}"
            row["capability_id"] = (
                f"{arm['arm_id']}.mutated_{action['action']}"
            )
            report = _validate(_load_document(tmp_path, document), surfaces)
            assert not report.integrity_ok, (
                arm["arm_id"],
                action["action"],
            )
            assert "action-roster-mismatch" in _codes(report), (
                arm["arm_id"],
                action["action"],
                _codes(report),
            )


def test_no_individual_action_can_be_omitted(
    registry, surfaces, tmp_path: Path
) -> None:
    baseline = _copy_document(registry)
    exercised: set[str] = set()
    for arm_index, arm in enumerate(baseline["arms"]):
        for action_index, action in enumerate(arm["data_actions"]):
            document = copy.deepcopy(baseline)
            del document["arms"][arm_index]["data_actions"][action_index]
            _assert_omission_fails_closed(
                document,
                surfaces=surfaces,
                tmp_path=tmp_path,
                expected_code="action-roster-mismatch",
            )
            exercised.add(action["capability_id"])
    assert len(exercised) == 38


def test_every_path_contract_is_independently_anchored(
    registry, surfaces, tmp_path: Path
) -> None:
    baseline = _copy_document(registry)
    for arm_index, arm in enumerate(baseline["arms"]):
        document = copy.deepcopy(baseline)
        mutated = document["arms"][arm_index]
        original = mutated["input_contract"]["path_argument"]
        replacement = "mutated_path"
        mutated["input_contract"]["path_argument"] = replacement
        for action in mutated["data_actions"]:
            action["path_argument"] = replacement
            action["input_keys"] = [
                replacement if key == original else key
                for key in action["input_keys"]
            ]
        report = _validate(_load_document(tmp_path, document), surfaces)
        assert not report.integrity_ok, arm["arm_id"]
        assert "input-contract-mismatch" in _codes(report), (
            arm["arm_id"],
            _codes(report),
        )


def test_no_action_can_omit_its_caller_path_binding(
    registry, surfaces, tmp_path: Path
) -> None:
    baseline = _copy_document(registry)
    exercised: set[str] = set()
    for arm_index, arm in enumerate(baseline["arms"]):
        path_argument = arm["input_contract"]["path_argument"]
        for action_index, action in enumerate(arm["data_actions"]):
            assert path_argument in action["input_keys"]
            document = copy.deepcopy(baseline)
            row = document["arms"][arm_index]["data_actions"][action_index]
            row["input_keys"].remove(path_argument)
            _assert_omission_fails_closed(
                document,
                surfaces=surfaces,
                tmp_path=tmp_path,
                expected_code="action-roster-mismatch",
            )
            exercised.add(action["capability_id"])
    assert len(exercised) == 38


def test_every_control_definition_is_independently_anchored(
    registry, surfaces, tmp_path: Path
) -> None:
    baseline = _copy_document(registry)
    for control_index, control in enumerate(baseline["controls"]):
        document = copy.deepcopy(baseline)
        document["controls"][control_index]["objective"] += " Mutated."
        report = _validate(_load_document(tmp_path, document), surfaces)
        assert not report.integrity_ok, control["id"]
        assert "control-definition-mismatch" in _codes(report), (
            control["id"],
            _codes(report),
        )


def test_no_individual_required_control_can_be_omitted(
    registry, surfaces, tmp_path: Path
) -> None:
    baseline = _copy_document(registry)
    exercised: set[str] = set()
    for control_index, control in enumerate(baseline["controls"]):
        document = copy.deepcopy(baseline)
        del document["controls"][control_index]
        _assert_omission_fails_closed(
            document,
            surfaces=surfaces,
            tmp_path=tmp_path,
            expected_code="control-definition-mismatch",
        )
        exercised.add(control["id"])
    assert len(exercised) == 11


@pytest.mark.parametrize(
    "anchor",
    ("coverage", "policies", "invoke_profiles", "governance", "reader_runtime"),
)
def test_each_surface_anchor_drift_fails_independently(
    registry, surfaces, tmp_path: Path, anchor: str
) -> None:
    document = _copy_document(registry)
    document["surface_anchors"][anchor] = "sha256:" + ("0" * 64)

    report = _validate(_load_document(tmp_path, document), surfaces)

    assert not report.integrity_ok
    assert not report.ok
    assert "surface-anchor-mismatch" in _codes(report)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        ("hazard", "hazard-definition-mismatch"),
        ("arm-hazard", "arm-hazard-mismatch"),
        ("arm-control", "arm-control-mismatch"),
        ("source", "source-mapping-mismatch"),
    ),
)
def test_register_semantic_drift_is_not_hidden_by_valid_shape(
    registry,
    surfaces,
    tmp_path: Path,
    mutation: str,
    expected_code: str,
) -> None:
    """Exercise schema-valid substitutions, not malformed-input shortcuts."""
    document = _copy_document(registry)
    arm = document["arms"][0]
    if mutation == "hazard":
        document["hazards"][0]["impact"] += " Mutated."
    elif mutation == "arm-hazard":
        arm["hazard_ids"] = list(reversed(arm["hazard_ids"]))
    elif mutation == "arm-control":
        arm["required_control_ids"] = list(reversed(arm["required_control_ids"]))
    else:
        arm["source_id"] = "R99"

    report = _validate(_load_document(tmp_path, document), surfaces)

    assert not report.integrity_ok
    assert expected_code in _codes(report)


@pytest.mark.parametrize(
    ("mutation", "section", "expected_code"),
    (
        ("coverage-notes", "coverage", "coverage-mismatch"),
        ("policy-caveat", "policies", "policy-mismatch"),
        ("policy-arming", "policies", "policy-mismatch"),
        ("policy-output-cap", "policies", "policy-mismatch"),
        ("policy-result-cap", "policies", "policy-mismatch"),
        ("policy-input-cap", "policies", "policy-mismatch"),
        ("profile-default-off", "invoke_profiles", "profile-mismatch"),
        ("profile-timeout", "invoke_profiles", "profile-mismatch"),
        ("governance-runtime-input", "governance", "governance-mismatch"),
        ("governance-source-revision", "governance", "governance-mismatch"),
    ),
)
def test_self_consistent_surface_semantic_drift_hits_frozen_baseline(
    registry,
    surfaces,
    mutation: str,
    section: str,
    expected_code: str,
) -> None:
    """Changing snapshot data and its own hashes must not bless live drift."""
    document = copy.deepcopy(dict(surfaces.document))
    if mutation == "coverage-notes":
        document["coverage"]["records"][0]["notes"] += " Mutated."
    elif mutation.startswith("policy-"):
        policy = document["policies"]["records"][sorted(
            document["policies"]["records"]
        )[0]]
        contract = policy["contract"]
        if mutation == "policy-caveat":
            policy["source_sha256"] = "sha256:" + ("1" * 64)
        elif mutation == "policy-arming":
            policy["source_sha256"] = "sha256:" + ("2" * 64)
        elif mutation == "policy-output-cap":
            contract["max_output_chars"] += 1
        elif mutation == "policy-result-cap":
            contract["max_results"] += 1
        else:
            contract["max_file_bytes"] += 1
    elif mutation.startswith("profile-"):
        profiles = document["invoke_profiles"]["records"]
        profile = profiles[sorted(profiles)[0]]
        if mutation == "profile-default-off":
            profile["default_off"] = not profile["default_off"]
        else:
            profile["timeout_ms"] += 1
    elif mutation == "governance-runtime-input":
        document["governance"]["runtime"][0]["input_keys"].append(
            "mutated_input"
        )
    else:
        document["governance"]["sources"][0]["selected_revision"] = (
            "mutated-revision"
        )

    changed = _rehash_surfaces(surfaces, document)
    report = _validate(registry, changed)
    codes = _codes(report)

    assert not report.ok
    assert not report.integrity_ok
    assert expected_code in codes
    assert "surface-provenance-mismatch" in codes
    assert "surface-anchor-mismatch" in codes
    assert "surface-snapshot-mutated" not in codes
    assert report.surface_sha256[section] == surfaces.section_sha256[section]
    assert report.surface_sha256[section] != changed.section_sha256[section]


@pytest.mark.parametrize(
    "mutation",
    ("verified-control", "evidence-ref", "verified-arm", "top-level-evidence"),
)
def test_schema_refuses_verified_or_evidence_claims(
    registry, tmp_path: Path, mutation: str
) -> None:
    document = _copy_document(registry)
    if mutation == "verified-control":
        document["controls"][0]["status"] = "verified"
    elif mutation == "evidence-ref":
        document["controls"][0]["evidence_refs"] = ["evidence://unsupported"]
    elif mutation == "verified-arm":
        document["arms"][0]["state"] = "verified"
    else:
        document["verification_evidence"] = {"verified": True}

    with pytest.raises(safety.SafetyLoadError, match="schema"):
        _load_document(tmp_path, document)


def test_loader_rejects_duplicate_keys_and_aliases(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        "schema: specaudit.ctf.safety.register.v1\n"
        "schema: specaudit.ctf.safety.register.v1\n",
        encoding="utf-8",
    )
    with pytest.raises(safety.SafetyLoadError, match="duplicate"):
        safety.load_register(duplicate)

    alias = tmp_path / "alias.yaml"
    alias.write_text("first: &shared value\nsecond: *shared\n", encoding="utf-8")
    with pytest.raises(safety.SafetyLoadError, match="alias|anchor"):
        safety.load_register(alias)


def test_loader_refuses_register_and_schema_symlinks(tmp_path: Path) -> None:
    register_link = tmp_path / "register-link.yaml"
    schema_link = tmp_path / "schema-link.json"
    os.symlink(safety_check.DEFAULT_REGISTER_PATH, register_link)
    os.symlink(safety_check.DEFAULT_SCHEMA_PATH, schema_link)

    with pytest.raises(safety.SafetyLoadError, match="symlink"):
        safety.load_register(register_link)
    with pytest.raises(safety.SafetyLoadError, match="symlink"):
        safety.load_register(
            safety_check.DEFAULT_REGISTER_PATH,
            schema_path=schema_link,
        )


def test_schema_coedit_cannot_authorize_verified_evidence(
    registry, tmp_path: Path
) -> None:
    document = _copy_document(registry)
    document["controls"][0]["status"] = "verified"
    register_path = _write_register(tmp_path, document)
    schema = json.loads(safety_check.DEFAULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    schema["definitions"]["control"]["properties"]["status"] = {
        "enum": ["unverified", "verified"]
    }
    schema_path = tmp_path / "coedited-schema.json"
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    with pytest.raises(safety.SafetyLoadError, match="canonical|digest|schema"):
        safety.load_register(register_path, schema_path=schema_path)


@pytest.mark.parametrize(
    "path",
    (
        ("arms", 0, "hazard_ids"),
        ("arms", 0, "input_contract", "allowed_suffixes"),
        ("arms", 0, "data_actions", 0, "input_keys"),
    ),
    ids=("hazard-ids", "suffixes", "input-keys"),
)
def test_correlated_registry_rehash_cannot_hide_tuple_substitution(
    registry, surfaces, path: tuple[str | int, ...]
) -> None:
    document = _copy_document(registry)
    target: Any = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = tuple(target[path[-1]])
    forged = replace(
        registry,
        document=document,
        document_sha256=_semantic_sha256(document),
    )

    report = _validate(forged, surfaces)

    assert not report.integrity_ok
    assert "register-provenance-mismatch" in _codes(report)
    assert "register-snapshot-mutated" not in _codes(report)


def test_correlated_registry_rehash_cannot_hide_extra_key(
    registry, surfaces
) -> None:
    document = _copy_document(registry)
    document["verification_evidence"] = {"verified": True}
    forged = replace(
        registry,
        document=document,
        document_sha256=_semantic_sha256(document),
    )

    report = _validate(forged, surfaces)

    assert not report.integrity_ok
    assert "register-provenance-mismatch" in _codes(report)
    assert "register-snapshot-mutated" not in _codes(report)


def test_forged_register_provenance_is_reloaded_from_disk(
    registry, surfaces
) -> None:
    forged_digest = "sha256:" + ("0" * 64)
    forged = replace(
        registry,
        register_sha256=forged_digest,
        schema_sha256=forged_digest,
        document_sha256=forged_digest,
    )

    report = _validate(forged, surfaces)

    assert not report.integrity_ok
    assert "register-provenance-mismatch" in _codes(report)
    assert report.register_sha256 == registry.register_sha256
    assert report.schema_sha256 == registry.schema_sha256


def test_digest_string_subclasses_cannot_forge_provenance(
    registry, surfaces
) -> None:
    forged_digest = _AlwaysEqualStr("sha256:" + ("0" * 64))
    forged_registry = replace(
        registry,
        register_sha256=forged_digest,
        schema_sha256=forged_digest,
        document_sha256=forged_digest,
    )
    register_report = _validate(forged_registry, surfaces)
    assert not register_report.integrity_ok
    assert "register-provenance-mismatch" in _codes(register_report)

    forged_surfaces = replace(
        surfaces,
        document_sha256=forged_digest,
        raw_sha256_digest=forged_digest,
    )
    surface_report = _validate(registry, forged_surfaces)
    assert not surface_report.integrity_ok
    assert "surface-shape-mismatch" in _codes(surface_report)


@pytest.mark.parametrize("argument", ("scope", "require"))
def test_public_selector_string_subclasses_are_refused(
    registry, surfaces, argument: str
) -> None:
    kwargs = {
        "scope": "pr97-readers",
        "require": "integrity",
        "as_of": FIXED_AS_OF,
    }
    kwargs[argument] = _AlwaysEqualStr("unsupported")

    with pytest.raises(ValueError, match=argument):
        safety.validate_register(registry, surfaces, **kwargs)


@pytest.mark.parametrize("mutation", ("tuple-sequence", "extra-section"))
def test_correlated_surface_rehash_cannot_hide_non_json_shape(
    registry, surfaces, mutation: str
) -> None:
    document = copy.deepcopy(dict(surfaces.document))
    if mutation == "tuple-sequence":
        capabilities = document["reader_runtime"]["profile_capability_ids"]
        document["reader_runtime"]["profile_capability_ids"] = tuple(capabilities)
    else:
        document["unexpected"] = {}
    forged = _rehash_surfaces(surfaces, document)

    report = _validate(registry, forged)

    assert not report.integrity_ok
    assert "surface-shape-mismatch" in _codes(report)
    assert "surface-snapshot-mutated" not in _codes(report)


def test_post_snapshot_mutation_is_detected(registry, surfaces) -> None:
    loaded = safety.load_register()
    loaded.document["scope"]["description"] += " Mutated."
    report = _validate(loaded, surfaces)
    assert not report.integrity_ok
    assert "register-snapshot-mutated" in _codes(report)

    live = safety.snapshot_surfaces()
    live.document["unexpected"] = True
    report = _validate(registry, live)
    assert not report.integrity_ok
    assert "surface-snapshot-mutated" in _codes(report)

    changed_digest = safety.snapshot_surfaces()
    changed_digest.section_sha256["coverage"] = "sha256:" + ("0" * 64)
    report = _validate(registry, changed_digest)
    assert not report.integrity_ok
    assert "surface-snapshot-mutated" in _codes(report)


def test_raw_provenance_hash_mutation_cannot_remain_integrity_clean(
    registry,
) -> None:
    live = safety.snapshot_surfaces()
    forged = "sha256:" + ("0" * 64)
    live.raw_sha256["coverage_catalog"] = forged

    report = _validate(registry, live)

    assert not report.ok
    assert not report.integrity_ok
    assert "surface-snapshot-mutated" in _codes(report)
    assert "surface-provenance-mismatch" in _codes(report)
    assert report.surface_raw_sha256["coverage_catalog"] != forged


@pytest.mark.parametrize("mutation", ("value", "omission", "extra-key"))
def test_correlated_raw_provenance_forgery_fails_closed(
    registry, surfaces, mutation: str
) -> None:
    raw_sha256 = copy.deepcopy(dict(surfaces.raw_sha256))
    if mutation == "value":
        raw_sha256["coverage_catalog"] = "sha256:" + ("0" * 64)
    elif mutation == "omission":
        del raw_sha256["coverage_catalog"]
    else:
        raw_sha256["invented"] = "sha256:" + ("f" * 64)
    forged = replace(
        surfaces,
        raw_sha256=raw_sha256,
        raw_sha256_digest=_semantic_sha256(raw_sha256),
    )

    report = _validate(registry, forged)

    assert not report.integrity_ok
    assert "surface-provenance-mismatch" in _codes(report)
    assert "surface-snapshot-mutated" not in _codes(report)


def test_coverage_projection_uses_the_loaded_schema_hash(
    surfaces, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (
        surfaces.document["coverage"]["canonical_schema_sha256"]
        == surfaces.raw_sha256["coverage_schema"]
    )
    original = safety_check._safe_snapshot

    def changed_schema_snapshot(path: Path, *, label: str, max_bytes: int):
        snapshot = original(path, label=label, max_bytes=max_bytes)
        if Path(path) == safety_check.DEFAULT_COVERAGE_SCHEMA_PATH:
            data = snapshot.data + b"\n"
            return replace(snapshot, data=data, sha256=_byte_sha256(data))
        return snapshot

    monkeypatch.setattr(safety_check, "_safe_snapshot", changed_schema_snapshot)
    with pytest.raises(safety.SafetyLoadError, match="coverage schema.*canonical"):
        safety.snapshot_surfaces()


def test_governance_projection_refuses_split_schema_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = safety_check._safe_snapshot

    def changed_schema_snapshot(path: Path, *, label: str, max_bytes: int):
        snapshot = original(path, label=label, max_bytes=max_bytes)
        if Path(path) == safety_check.DEFAULT_GOVERNANCE_SCHEMA_PATH:
            data = snapshot.data + b"\n"
            return replace(snapshot, data=data, sha256=_byte_sha256(data))
        return snapshot

    monkeypatch.setattr(safety_check, "_safe_snapshot", changed_schema_snapshot)
    with pytest.raises(safety.SafetyLoadError, match="governance schema changed"):
        safety.snapshot_surfaces()


def test_reader_runtime_projection_binds_exact_sources_and_profiles(
    registry, surfaces
) -> None:
    runtime = surfaces.document["reader_runtime"]
    sources = runtime["source_sha256"]
    capability_ids = {
        arm["discovery_capability_id"] for arm in registry.document["arms"]
    } | {action["capability_id"] for action in _actions(registry.document)}
    refused = {
        *(f"{arm_id}.__unlisted__" for arm_id in EXPECTED_ARM_IDS),
        "__unlisted__.list_tools",
    }

    assert type(runtime["source_boundary"]) is str
    assert runtime["source_boundary"]
    assert len(EXPECTED_READER_SOURCE_PATHS) == 47
    assert set(sources) == EXPECTED_READER_SOURCE_PATHS
    assert runtime["handler_registry"] == EXPECTED_HANDLER_REGISTRY
    assert len(capability_ids) == 52
    assert runtime["profile_capability_ids"] == sorted(capability_ids)
    assert runtime["positive_profile_lookups"] == {
        capability_id: capability_id for capability_id in sorted(capability_ids)
    }
    assert set(runtime["negative_profile_lookups"]) == refused
    assert set(runtime["authorities"].values()) == {
        "extension.contract._default_arms",
        "extension.dispatch.dispatch_invoke",
        "extension.invoke_profiles.INVOKE_PROFILES",
        "extension.invoke_profiles.INVOKE_CAPABILITY_IDS",
        "extension.invoke_profiles.invoke_profile",
    }
    for path in EXPECTED_READER_SOURCE_PATHS:
        assert surfaces.raw_sha256[f"reader_source:{path}"] == sources[path]


def test_reader_runtime_source_drift_changes_the_gated_projection(
    registry, surfaces, monkeypatch: pytest.MonkeyPatch
) -> None:
    relative_path = "extension/arms/gpohound/arm.py"
    source_path = ROOT / relative_path
    original = safety_check._safe_snapshot

    def changed_source_snapshot(path: Path, *, label: str, max_bytes: int):
        snapshot = original(path, label=label, max_bytes=max_bytes)
        if Path(path) == source_path:
            data = snapshot.data + b"\n# causal reader-runtime drift\n"
            return replace(snapshot, data=data, sha256=_byte_sha256(data))
        return snapshot

    monkeypatch.setattr(safety_check, "_safe_snapshot", changed_source_snapshot)
    changed = safety.snapshot_surfaces()

    assert (
        changed.document["reader_runtime"]["source_sha256"][relative_path]
        != surfaces.document["reader_runtime"]["source_sha256"][relative_path]
    )
    report = _validate(registry, changed)
    assert not report.integrity_ok
    assert "reader-runtime-mismatch" in _codes(report)


def test_each_expected_reader_source_digest_is_causally_enforced(
    registry, surfaces, monkeypatch: pytest.MonkeyPatch
) -> None:
    relative_path = "extension/arms/gpohound/arm.py"
    monkeypatch.setitem(
        safety_check.EXPECTED_READER_SOURCE_SHA256,
        relative_path,
        "sha256:" + ("0" * 64),
    )

    report = _validate(registry, surfaces)

    assert not report.integrity_ok
    assert "reader-runtime-mismatch" in _codes(report)


def test_reader_runtime_source_omission_cannot_survive_correlated_rehash(
    registry, surfaces
) -> None:
    relative_path = "extension/arms/vulnify/policy.py"
    document = copy.deepcopy(dict(surfaces.document))
    del document["reader_runtime"]["source_sha256"][relative_path]
    forged = _rehash_surfaces(surfaces, document)

    report = _validate(registry, forged)

    assert not report.integrity_ok
    assert "reader-runtime-mismatch" in _codes(report)
    assert "surface-snapshot-mutated" not in _codes(report)


@pytest.mark.parametrize(
    "mutation", ("membership", "positive-lookup", "negative-refusal")
)
def test_reader_runtime_profile_projection_drift_fails_closed(
    registry, surfaces, mutation: str
) -> None:
    document = copy.deepcopy(dict(surfaces.document))
    runtime = document["reader_runtime"]
    if mutation == "membership":
        del runtime["profile_capability_ids"][0]
    elif mutation == "positive-lookup":
        capability_id = sorted(runtime["positive_profile_lookups"])[0]
        runtime["positive_profile_lookups"][capability_id] = "vulnify.list_vulns"
    else:
        del runtime["negative_profile_lookups"][0]
    forged = _rehash_surfaces(surfaces, document)

    report = _validate(registry, forged)

    assert not report.integrity_ok
    assert "reader-runtime-mismatch" in _codes(report)
    assert "surface-snapshot-mutated" not in _codes(report)


def test_surface_projection_converts_system_exit_to_load_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exit_during_snapshot(*args: Any, **kwargs: Any):
        raise SystemExit(0)

    monkeypatch.setattr(safety_check, "_safe_snapshot", exit_during_snapshot)
    with pytest.raises(safety.SafetyLoadError, match="SystemExit"):
        safety.snapshot_surfaces()


def test_cli_converts_surface_system_exit_to_exit_2_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def exit_during_snapshot():
        raise SystemExit(0)

    monkeypatch.setattr(safety_check, "snapshot_surfaces", exit_during_snapshot)
    exit_code = safety_check.main(
        [
            "check",
            "--scope",
            "pr97-readers",
            "--require",
            "integrity",
            "--as-of",
            "2026-09-09",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    payload = json.loads(captured.err)
    assert payload["ok"] is False
    assert "SystemExit" in payload["error"]


@pytest.mark.parametrize(
    ("require", "expected_exit", "expected_ok"),
    (("integrity", 0, True), ("ready", 1, False)),
)
def test_cli_never_uses_silence_as_success_or_failure(
    require: str,
    expected_exit: int,
    expected_ok: bool,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "safety",
            "check",
            "--scope",
            "pr97-readers",
            "--require",
            require,
            "--as-of",
            "2026-09-09",
            "--format",
            "json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == expected_exit
    assert completed.stderr == ""
    assert completed.stdout.strip()
    payload = json.loads(completed.stdout)
    assert payload["ok"] is expected_ok
    assert payload["requirement"] == require


@pytest.mark.parametrize("arguments", (["--help"], ["check", "--help"]))
def test_cli_help_is_explicitly_outside_the_json_check_contract(
    arguments: list[str],
) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "safety", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout.startswith("usage:")
    assert completed.stderr == ""


def test_invalid_cli_is_nonzero_json_on_stderr(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("schema: wrong\n", encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "safety",
            "check",
            "--register",
            str(invalid),
            "--scope",
            "pr97-readers",
            "--require",
            "integrity",
            "--as-of",
            "2026-09-09",
            "--format",
            "json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr.strip()
    assert json.loads(completed.stderr)["ok"] is False


def test_safety_tooling_is_checkout_only_and_does_not_import_extension() -> None:
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, sys, safety; "
                "safety.snapshot_surfaces(); "
                "print(json.dumps(sorted(name for name in sys.modules "
                "if name == 'extension' or name.startswith('extension.'))))"
            ),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(probe.stdout) == []

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_find = pyproject["tool"]["setuptools"]["packages"]["find"]
    assert package_find["include"] == ["extension*"]
    assert not any("safety" in pattern for pattern in package_find["include"])

    runtime_lock = json.loads((ROOT / "runtime" / "lock.json").read_text(encoding="utf-8"))
    assert "safety/" not in json.dumps(runtime_lock, sort_keys=True)
