"""Causal tests for the additive GOV-01 foundation.

The tests intentionally mutate one invariant at a time.  A green baseline is
not sufficient: profile deletion, action narrowing, contract drift, stale
currentness, invalid relationships, and evidence-free promotion must each make
the checker fail for the expected reason.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import stat
import tomllib
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Any, Mapping

import pytest
import yaml

from extension import invoke_profiles as invoke_profiles_module
from extension.invoke_profiles import INVOKE_PROFILES
from extension.arms.vulnify import policy as vulnify_policy
import governance.check as governance_check
from governance.check import (
    DEFAULT_REGISTER_PATH,
    DEFAULT_SCHEMA_PATH,
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_LINES,
    MAX_STRING_BYTES,
    PR97_ACTION_ARGUMENTS,
    PR97_CAPABILITY_IDS,
    PR97_IMPLEMENTATION_REVISION,
    PR97_SOURCE_BY_ARM,
    RegisterLoadError,
    Registry,
    _contract_digest,
    _governance_subject_digest,
    _github_heading_anchors,
    _module_contract_digest,
    _profile_digest,
    _source_contract_digest,
    load_register,
    main,
    snapshot_invoke_profiles,
    validate_register,
)

ROOT = Path(__file__).resolve().parents[1]
FIXED_AS_OF = date(2026, 9, 8)


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_register()


@pytest.fixture(scope="module")
def inventory():
    return snapshot_invoke_profiles(INVOKE_PROFILES)


def _copy_document(registry: Registry) -> dict[str, Any]:
    return copy.deepcopy(dict(registry.document))


def _runtime(document: dict[str, Any], capability_id: str) -> dict[str, Any]:
    return next(
        row for row in document["runtime"] if row["capability_id"] == capability_id
    )


def _source(document: dict[str, Any], source_id: str) -> dict[str, Any]:
    return next(row for row in document["sources"] if row["id"] == source_id)


def _codes(report, *, path: str | None = None) -> set[str]:
    return {
        issue.code
        for issue in report.issues
        if path is None or issue.path == path or issue.path.startswith(path + ".")
    }


def _validate(document, inventory, *, as_of: date = FIXED_AS_OF, require="integrity"):
    return validate_register(
        document,
        inventory,
        as_of=as_of,
        scope="pr97-readers",
        require=require,
    )


def _write_register(tmp_path: Path, document: Mapping[str, Any]) -> Path:
    path = tmp_path / "register.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def test_foundation_binds_exact_inventory_and_pr97_scope(registry, inventory) -> None:
    report = _validate(registry, inventory)

    assert report.ok
    assert report.integrity_ok
    assert not report.current_ok
    assert not report.complete_ok
    assert report.inventory_count == 212
    assert report.governed_runtime_count == 52
    assert report.source_count == 14
    assert report.module_count == 1
    assert registry.document["runtime_inventory"]["expected_count"] == 212
    assert tuple(registry.document["runtime_inventory"]["capability_ids"]) == (
        inventory.capability_ids
    )
    assert registry.document["runtime_inventory"]["contract_sha256"] == (
        inventory.contract_sha256
    )


def test_pr97_roster_is_14_policy_reads_plus_38_data_actions(registry) -> None:
    runtime = registry.document["runtime"]
    runtime_ids = {row["capability_id"] for row in runtime}

    assert len(PR97_ACTION_ARGUMENTS) == 14
    assert sum("list_tools" in actions for actions in PR97_ACTION_ARGUMENTS.values()) == 14
    assert sum(len(actions) - 1 for actions in PR97_ACTION_ARGUMENTS.values()) == 38
    assert len(PR97_CAPABILITY_IDS) == 52
    assert runtime_ids == PR97_CAPABILITY_IDS
    assert sum(row["action"] == "list_tools" for row in runtime) == 14
    assert sum(row["action"] != "list_tools" for row in runtime) == 38


def test_pr97_action_inputs_are_exact_and_policy_reads_stay_distinct(registry) -> None:
    for row in registry.document["runtime"]:
        expected = PR97_ACTION_ARGUMENTS[row["arm_id"]][row["action"]]
        assert tuple(row["input_keys"]) == expected
        if row["action"] == "list_tools":
            assert row["contract_ref"] == "policy-read-v1"
            assert row["input_keys"] == []
        else:
            assert row["contract_ref"] == "caller-file-read-v1"


def test_source_mappings_are_exact_candidates_not_consumption(registry) -> None:
    assert {row["id"] for row in registry.document["sources"]} == set(
        PR97_SOURCE_BY_ARM.values()
    )
    assert all(row["status"] == "research" for row in registry.document["sources"])
    assert all(row["selected_revision"] is None for row in registry.document["sources"])
    assert all(not row["content_digests"] for row in registry.document["sources"])
    assert "consumes" not in {
        relationship["kind"] for relationship in registry.document["relationships"]
    }


def test_cyb05_mapping_is_honestly_design_ready_and_proposed(registry) -> None:
    assert len(registry.document["modules"]) == 1
    module = registry.document["modules"][0]
    assert module["id"] == "CYB-05"
    assert module["status"] == "design-ready"
    pairs = {
        (relationship["kind"], relationship["from"], tuple(relationship["to"]))
        for relationship in registry.document["relationships"]
    }
    assert ("proposed-source", "module:CYB-05", ("source:R01",)) in pairs
    assert (
        "proposed-use",
        "module:CYB-05",
        ("runtime:vulnify.lookup",),
    ) in pairs


def test_explicit_integrity_cli_pass_reports_partial_state(capsys) -> None:
    exit_code = main(
        [
            "check",
            "--scope",
            "pr97-readers",
            "--require",
            "integrity",
            "--as-of",
            "2026-09-08",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert payload["ok"] is True
    assert payload["requested_scope"] == "pr97-readers"
    assert payload["register_scope"] == "pr97-readers"
    assert payload["integrity_ok"] is True
    assert payload["current_ok"] is False
    assert payload["complete_ok"] is False
    assert payload["repository_complete"] is False
    assert any(issue["code"] == "repository-partial" for issue in payload["issues"])


def test_report_binds_exact_loaded_bytes_and_authoritative_inventory(
    registry, inventory
) -> None:
    report = _validate(registry, inventory)
    payload = report.as_dict()

    assert payload["register_revision"] == registry.document["register_revision"]
    assert payload["register_sha256"] == (
        "sha256:" + hashlib.sha256(DEFAULT_REGISTER_PATH.read_bytes()).hexdigest()
    )
    assert payload["schema_sha256"] == (
        "sha256:" + hashlib.sha256(DEFAULT_SCHEMA_PATH.read_bytes()).hexdigest()
    )
    assert payload["authoritative_inventory_contract_sha256"] == (
        inventory.contract_sha256
    )


def test_default_complete_cli_fails_closed(capsys) -> None:
    exit_code = main(["check", "--as-of", "2026-09-08", "--format", "json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 1
    assert captured.err == ""
    assert payload["requirement"] == "complete"
    assert payload["ok"] is False
    assert payload["repository_complete"] is False
    assert any(
        issue["code"] == "runtime-governance-partial" for issue in payload["issues"]
    )


def test_repository_complete_flag_cannot_certify_its_own_truth(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    document["scope"]["repository_complete"] = True
    for collection in ("modules", "sources", "runtime"):
        for row in document[collection]:
            row["currentness"]["reviewed_on"] = "2026-09-08"
            row["currentness"]["review_due_on"] = "2027-09-08"

    report = _validate(document, inventory, require="complete")

    assert not report.integrity_ok
    assert not report.complete_ok
    assert not report.ok
    assert report.repository_complete is False
    assert "unsupported-complete-claim" in _codes(report)


def test_full_requested_target_does_not_relabel_partial_register(
    registry, inventory
) -> None:
    report = validate_register(
        registry,
        inventory,
        as_of=FIXED_AS_OF,
        scope="full",
        require="complete",
    )

    assert report.integrity_ok
    assert not report.complete_ok
    assert not report.ok
    assert report.requested_scope == "full"
    assert report.register_scope == "pr97-readers"
    assert "runtime-governance-partial" in _codes(report)


def test_v1_refuses_stored_full_scope_even_for_raw_mapping(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    document["scope"]["id"] = "full"

    report = validate_register(
        document,
        inventory,
        as_of=FIXED_AS_OF,
        scope="pr97-readers",
        require="integrity",
    )

    assert not report.integrity_ok
    assert not report.ok
    assert report.requested_scope == "pr97-readers"
    assert report.register_scope == "full"
    assert "unsupported-register-scope" in _codes(report)


def test_schema_rejects_unknown_fields_with_exit_two(
    registry, tmp_path: Path, capsys
) -> None:
    document = _copy_document(registry)
    document["unexpected"] = True
    path = tmp_path / "register.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    exit_code = main(
        ["check", "--register", str(path), "--as-of", "2026-09-08"]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert json.loads(captured.err)["ok"] is False
    assert "Additional properties" in captured.err


def test_loader_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text(
        "schema: specaudit.ctf.governance.register.v1\n"
        "schema: specaudit.ctf.governance.register.v1\n",
        encoding="utf-8",
    )

    with pytest.raises(RegisterLoadError, match="duplicate YAML mapping key"):
        load_register(path)


def test_loader_rejects_yaml_aliases_and_anchors(tmp_path: Path) -> None:
    path = tmp_path / "alias.yaml"
    path.write_text("first: &shared value\nsecond: *shared\n", encoding="utf-8")

    with pytest.raises(RegisterLoadError, match="aliases and anchors"):
        load_register(path)


def test_loader_rejects_deep_yaml_without_recursion_traceback(tmp_path: Path) -> None:
    path = tmp_path / "deep.yaml"
    nested = "leaf: value\n"
    for _ in range(80):
        nested = "node:\n" + "".join(
            f"  {line}" for line in nested.splitlines(keepends=True)
        )
    path.write_text(nested, encoding="utf-8")

    with pytest.raises(RegisterLoadError, match="nesting-depth cap"):
        load_register(path)


def test_loader_rejects_collection_over_node_budget(tmp_path: Path) -> None:
    path = tmp_path / "many-nodes.yaml"
    path.write_text("items:\n" + "  - value\n" * 20_100, encoding="utf-8")

    with pytest.raises(RegisterLoadError, match="node cap"):
        load_register(path)


@pytest.mark.parametrize("constant", [".nan", ".inf", "-.inf"])
def test_loader_rejects_nonfinite_yaml_numbers(
    tmp_path: Path, constant: str
) -> None:
    path = tmp_path / "nonfinite.yaml"
    path.write_text(f"value: {constant}\n", encoding="utf-8")

    with pytest.raises(RegisterLoadError, match="non-finite number"):
        load_register(path)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_loader_rejects_nonfinite_json_schema_numbers(
    tmp_path: Path, constant: str
) -> None:
    schema = tmp_path / "schema.json"
    schema.write_text(f'{{"type": "object", "minimum": {constant}}}', encoding="utf-8")

    with pytest.raises(RegisterLoadError, match="non-finite number"):
        load_register(DEFAULT_REGISTER_PATH, schema_path=schema)


def test_loader_rejects_duplicate_json_schema_keys(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    schema.write_text('{"type": "object", "type": "array"}', encoding="utf-8")

    with pytest.raises(RegisterLoadError, match="duplicate JSON schema key"):
        load_register(DEFAULT_REGISTER_PATH, schema_path=schema)


@pytest.mark.parametrize(
    "external_ref",
    ["file:///tmp/should-not-be-read.json", "https://example.invalid/schema.json"],
)
def test_loader_refuses_external_schema_refs_offline(
    tmp_path: Path, external_ref: str
) -> None:
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({"$ref": external_ref}), encoding="utf-8")

    with pytest.raises(RegisterLoadError, match=r"non-local \$ref"):
        load_register(DEFAULT_REGISTER_PATH, schema_path=schema)


def test_unresolved_local_schema_ref_is_normalized_to_cli_exit_two(
    tmp_path: Path, capsys
) -> None:
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({"$ref": "#/definitions/missing"}), encoding="utf-8")

    exit_code = main(
        [
            "check",
            "--schema",
            str(schema),
            "--scope",
            "pr97-readers",
            "--require",
            "integrity",
            "--as-of",
            "2026-09-08",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert json.loads(captured.err)["ok"] is False
    assert "canonical v1 schema digest" in captured.err


def test_permissive_custom_schema_cannot_turn_malformed_input_into_traceback(
    tmp_path: Path, capsys
) -> None:
    register = tmp_path / "malformed.yaml"
    register.write_text("arbitrary: true\n", encoding="utf-8")
    schema = tmp_path / "permissive.json"
    schema.write_text("{}", encoding="utf-8")

    exit_code = main(
        [
            "check",
            "--register",
            str(register),
            "--schema",
            str(schema),
            "--as-of",
            "2026-09-08",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert json.loads(captured.err)["ok"] is False
    assert "canonical v1 schema digest" in captured.err


def test_custom_schema_cannot_redefine_the_closed_v1_gate(
    registry, tmp_path: Path, capsys
) -> None:
    document = _copy_document(registry)
    document["schema"] = "attacker.schema"
    document["schema_version"] = 999
    document["register_revision"] = "not-an-integer"
    document["extra_authority"] = {"self_certified": True}
    register = _write_register(tmp_path, document)
    schema = tmp_path / "permissive.json"
    schema.write_text("{}", encoding="utf-8")

    exit_code = main(
        [
            "check",
            "--register",
            str(register),
            "--schema",
            str(schema),
            "--scope",
            "pr97-readers",
            "--require",
            "integrity",
            "--as-of",
            "2026-09-08",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert json.loads(captured.err)["ok"] is False
    assert "canonical v1 schema digest" in captured.err


def test_raw_mapping_cannot_self_certify_v1_metadata(registry, inventory) -> None:
    document = _copy_document(registry)
    document["schema"] = "attacker.schema"
    document["schema_version"] = 999
    document["register_revision"] = "not-an-integer"
    document["extra_authority"] = {"self_certified": True}

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert not report.ok
    assert report.register_revision is None
    assert {
        "register-schema-id-mismatch",
        "register-schema-version-mismatch",
        "register-revision-invalid",
        "register-top-level-shape-mismatch",
    } <= _codes(report)


def test_raw_mapping_cannot_redefine_inventory_authority(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    document["runtime_inventory"]["authority"] = "attacker.self-certified"

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert _codes(report, path="runtime_inventory.authority") == {
        "inventory-authority-mismatch"
    }


def test_raw_mapping_cannot_redefine_runtime_presence(registry, inventory) -> None:
    document = _copy_document(registry)
    row = _runtime(document, "vulnify.lookup")
    row["presence"] = "self-certified"

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert _codes(report, path="runtime:vulnify.lookup.presence") == {
        "runtime-presence-mismatch"
    }


def test_raw_mapping_cannot_redefine_runtime_result_schema(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    row = _runtime(document, "vulnify.lookup")
    row["result_schema"] = "attacker.result.v1"

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert _codes(report, path="runtime:vulnify.lookup.result_schema") == {
        "runtime-result-schema-mismatch"
    }


@pytest.mark.parametrize(
    ("kind", "path"),
    [
        ("runtime", "runtime:vulnify.lookup.record_version"),
        ("source", "source:R01.record_version"),
        ("module", "module:CYB-05.record_version"),
    ],
)
def test_raw_mapping_cannot_self_declare_new_entity_record_version(
    registry, inventory, kind: str, path: str
) -> None:
    document = _copy_document(registry)
    if kind == "runtime":
        row = _runtime(document, "vulnify.lookup")
    elif kind == "source":
        row = _source(document, "R01")
    else:
        row = document["modules"][0]
    row["record_version"] = 2

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert _codes(report, path=path) == {"unsupported-record-version"}


@pytest.mark.parametrize("kind", ["runtime", "source", "module", "relationship"])
def test_schema_rejects_new_entity_record_version(
    registry, tmp_path: Path, kind: str
) -> None:
    document = _copy_document(registry)
    if kind == "runtime":
        row = _runtime(document, "vulnify.lookup")
    elif kind == "source":
        row = _source(document, "R01")
    elif kind == "module":
        row = document["modules"][0]
    else:
        row = document["relationships"][0]
    row["record_version"] = 2

    with pytest.raises(RegisterLoadError, match="1 was expected"):
        load_register(_write_register(tmp_path, document))


def test_loader_rejects_register_symlink(tmp_path: Path) -> None:
    path = tmp_path / "register-link.yaml"
    path.symlink_to(DEFAULT_REGISTER_PATH)

    with pytest.raises(RegisterLoadError, match="must not be a symlink"):
        load_register(path)


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_loader_refuses_nonregular_path_before_open(
    tmp_path: Path, monkeypatch, kind: str
) -> None:
    path = tmp_path / kind
    if kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    open_calls: list[object] = []

    def unexpected_open(*args, **kwargs):
        open_calls.append((args, kwargs))
        raise AssertionError("os.open must not be called for a non-regular path")

    monkeypatch.setattr(governance_check.os, "open", unexpected_open)

    with pytest.raises(RegisterLoadError, match="must be a regular file"):
        governance_check._read_file_snapshot(
            path,
            label="test input",
            max_bytes=1024,
        )
    assert open_calls == []


def test_loader_refuses_device_mode_before_open(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "simulated-device"
    device_stat = os.stat_result(
        (stat.S_IFCHR | 0o600, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
    open_calls: list[object] = []

    monkeypatch.setattr(governance_check.os, "lstat", lambda unused: device_stat)

    def unexpected_open(*args, **kwargs):
        open_calls.append((args, kwargs))
        raise AssertionError("os.open must not be called for a device")

    monkeypatch.setattr(governance_check.os, "open", unexpected_open)

    with pytest.raises(RegisterLoadError, match="must be a regular file"):
        governance_check._read_file_snapshot(
            path,
            label="test input",
            max_bytes=1024,
        )
    assert open_calls == []


def test_evidence_snapshot_refuses_input_above_parser_byte_cap(
    tmp_path: Path,
) -> None:
    path = tmp_path / "oversized-evidence.md"
    path.write_bytes(b"# heading\n" + b"x" * MAX_EVIDENCE_BYTES)

    with pytest.raises(RegisterLoadError, match="byte input cap"):
        governance_check._read_file_snapshot(
            path,
            label="evidence document",
            max_bytes=MAX_EVIDENCE_BYTES,
        )


@pytest.mark.parametrize(
    ("unsafe_owner", "message"),
    [
        ("owner\x01control", "control, format, or surrogate"),
        ("owner\u202ebidi", "control, format, or surrogate"),
        ("owner\u200bzero-width", "control, format, or surrogate"),
        ("x" * (MAX_STRING_BYTES + 1), "string exceeds"),
    ],
)
def test_loader_rejects_unsafe_or_oversized_scalar_text(
    registry, tmp_path: Path, unsafe_owner: str, message: str
) -> None:
    document = _copy_document(registry)
    document["modules"][0]["owner"] = unsafe_owner

    with pytest.raises(RegisterLoadError, match=message):
        load_register(_write_register(tmp_path, document))


@pytest.mark.parametrize("invalid_date", ["20260908", "2026-9-8", "2026-02-30"])
def test_schema_requires_strict_calendar_dates(
    registry, tmp_path: Path, invalid_date: str
) -> None:
    document = _copy_document(registry)
    currentness = _runtime(document, "vulnify.lookup")["currentness"]
    currentness["reviewed_on"] = invalid_date
    currentness["review_due_on"] = "2027-09-08"

    with pytest.raises(RegisterLoadError, match="register schema error"):
        load_register(_write_register(tmp_path, document))


def test_schema_format_checker_rejects_incomplete_https_uri(
    registry, tmp_path: Path
) -> None:
    document = _copy_document(registry)
    _source(document, "R01")["url"] = "https://"

    with pytest.raises(RegisterLoadError, match="register schema error"):
        load_register(_write_register(tmp_path, document))


def test_schema_rejects_whitespace_selected_revision(
    registry, tmp_path: Path
) -> None:
    document = _copy_document(registry)
    _source(document, "R01")["selected_revision"] = "   "

    with pytest.raises(RegisterLoadError, match="register schema error"):
        load_register(_write_register(tmp_path, document))


def test_schema_rejects_reserved_missing_source_id_as_replacement(
    registry, tmp_path: Path
) -> None:
    document = _copy_document(registry)
    _source(document, "R01")["replacement"] = "R10"

    with pytest.raises(RegisterLoadError, match="register schema error"):
        load_register(_write_register(tmp_path, document))


def test_deleting_authoritative_profile_cannot_pass(registry) -> None:
    profiles = dict(INVOKE_PROFILES)
    profiles.pop("vulnify.lookup")

    report = _validate(registry, snapshot_invoke_profiles(profiles))

    assert not report.integrity_ok
    assert "inventory-id-mismatch" in _codes(report)
    assert "missing-authoritative-profile" in _codes(
        report, path="runtime:vulnify.lookup"
    )


def test_inventory_only_profile_deletion_is_caught_by_global_snapshot(registry) -> None:
    profiles = dict(INVOKE_PROFILES)
    profiles.pop("nmap.list_tools")

    report = _validate(registry, snapshot_invoke_profiles(profiles))

    assert not report.integrity_ok
    assert "inventory-id-mismatch" in _codes(report)
    assert "inventory-contract-mismatch" in _codes(report)
    assert "missing-authoritative-profile" not in _codes(report)


def test_inventory_only_profile_drift_is_caught_by_global_snapshot(registry) -> None:
    profiles = dict(INVOKE_PROFILES)
    profiles["nmap.list_tools"] = replace(
        profiles["nmap.list_tools"], side_effects=()
    )

    report = _validate(registry, snapshot_invoke_profiles(profiles))

    assert not report.integrity_ok
    assert {
        issue.code for issue in report.issues if issue.category == "integrity"
    } == {"inventory-contract-mismatch"}
    assert "runtime-contract-mismatch" not in _codes(report)


def test_profile_contract_drift_cannot_pass(registry) -> None:
    profiles = dict(INVOKE_PROFILES)
    profiles["vulnify.lookup"] = replace(
        profiles["vulnify.lookup"], side_effects=()
    )

    report = _validate(registry, snapshot_invoke_profiles(profiles))

    assert not report.integrity_ok
    assert "inventory-contract-mismatch" in _codes(report)
    assert "runtime-contract-mismatch" in _codes(
        report, path="runtime:vulnify.lookup"
    )


def test_nonfinite_authoritative_profile_cannot_enter_snapshot_digest() -> None:
    profiles = dict(INVOKE_PROFILES)
    profiles["vulnify.lookup"] = replace(
        profiles["vulnify.lookup"], max_spend=float("nan")
    )

    with pytest.raises(ValueError, match="Out of range float values"):
        snapshot_invoke_profiles(profiles)


def test_future_authoritative_profile_field_cannot_be_silently_ignored(
    monkeypatch,
) -> None:
    @dataclass(frozen=True)
    class FutureInvokeProfile(invoke_profiles_module.InvokeProfile):
        future_authority: str = "network-write"

    monkeypatch.setattr(
        invoke_profiles_module,
        "InvokeProfile",
        FutureInvokeProfile,
    )

    with pytest.raises(ValueError, match="field roster differs"):
        snapshot_invoke_profiles(INVOKE_PROFILES)


def test_omitted_snapshot_field_cannot_be_silently_ignored(monkeypatch) -> None:
    monkeypatch.setattr(
        governance_check,
        "_PROFILE_FIELDS",
        governance_check._PROFILE_FIELDS[:-1],
    )

    with pytest.raises(ValueError, match="field roster differs"):
        snapshot_invoke_profiles(INVOKE_PROFILES)


def test_authoritative_profile_key_mismatch_is_explicit_even_after_refreeze(
    registry
) -> None:
    profiles = dict(INVOKE_PROFILES)
    profiles["vulnify.lookup"] = replace(
        profiles["vulnify.lookup"], capability_id="vulnify.list_vulns"
    )
    mismatched_inventory = snapshot_invoke_profiles(profiles)
    document = _copy_document(registry)
    document["runtime_inventory"]["contract_sha256"] = (
        mismatched_inventory.contract_sha256
    )

    report = _validate(document, mismatched_inventory)

    assert "authoritative-profile-key-mismatch" in _codes(
        report, path="inventory:vulnify.lookup"
    )


def test_coordinated_action_relabel_cannot_preserve_capability_identity(
    registry,
) -> None:
    profiles = dict(INVOKE_PROFILES)
    profiles["vulnify.lookup"] = replace(
        profiles["vulnify.lookup"], action="list_vulns"
    )
    relabeled_inventory = snapshot_invoke_profiles(profiles)
    document = _copy_document(registry)
    document["runtime_inventory"]["contract_sha256"] = (
        relabeled_inventory.contract_sha256
    )
    runtime = _runtime(document, "vulnify.lookup")
    runtime["action"] = "list_vulns"
    runtime["input_keys"] = ["feed", "limit"]

    report = _validate(document, relabeled_inventory)

    assert not report.integrity_ok
    assert "authoritative-profile-structural-id-mismatch" in _codes(
        report, path="inventory:vulnify.lookup"
    )
    assert "runtime-structural-id-mismatch" in _codes(
        report, path="runtime:vulnify.lookup"
    )


def test_inventory_only_structural_identity_is_independently_bound(registry) -> None:
    profiles = dict(INVOKE_PROFILES)
    profiles["nmap.list_tools"] = replace(
        profiles["nmap.list_tools"], action="scan"
    )
    relabeled_inventory = snapshot_invoke_profiles(profiles)
    document = _copy_document(registry)
    document["runtime_inventory"]["contract_sha256"] = (
        relabeled_inventory.contract_sha256
    )

    report = _validate(document, relabeled_inventory)

    assert "authoritative-profile-structural-id-mismatch" in _codes(
        report, path="inventory:nmap.list_tools"
    )
    assert "runtime-structural-id-mismatch" not in _codes(report)


def test_runtime_structural_identity_is_independently_bound(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    runtime = _runtime(document, "vulnify.lookup")
    runtime["action"] = "list_vulns"
    runtime["input_keys"] = ["feed", "limit"]

    report = _validate(document, inventory)

    assert "runtime-structural-id-mismatch" in _codes(
        report, path="runtime:vulnify.lookup"
    )
    assert "authoritative-profile-structural-id-mismatch" not in _codes(report)


def test_actual_policy_arg_keys_are_an_independent_action_anchor(
    registry, inventory, monkeypatch
) -> None:
    monkeypatch.setitem(
        vulnify_policy.ARG_KEYS,
        "lookup",
        frozenset({"feed", "cve_id"}),
    )

    report = _validate(registry, inventory)

    assert "policy-action-surface-mismatch" in _codes(
        report, path="policy:vulnify"
    )
    assert "runtime-policy-action-surface-mismatch" in _codes(
        report, path="runtime:vulnify.lookup"
    )


def test_actual_policy_allowed_actions_cannot_narrow_independently(
    registry, inventory, monkeypatch
) -> None:
    monkeypatch.setattr(
        vulnify_policy,
        "ALLOWED_ACTIONS",
        frozenset({"list_vulns"}),
    )

    report = _validate(registry, inventory)

    assert "policy-allowed-action-surface-mismatch" in _codes(
        report, path="policy:vulnify"
    )


@pytest.mark.parametrize(
    ("anchor_name", "key", "expected_code"),
    [
        (
            "PR97_SOURCE_IDENTITIES",
            "R01",
            "pr97-source-identity-anchor-mismatch",
        ),
        ("PR97_ACTION_ARGUMENTS", "vulnify", "pr97-action-anchor-mismatch"),
        ("PR97_POLICY_MODULES", "vulnify", "pr97-policy-anchor-mismatch"),
        (
            "PR97_CONTRACT_TEMPLATES",
            "caller-file-read-v1",
            "pr97-contract-anchor-mismatch",
        ),
    ],
)
def test_missing_independent_anchor_cannot_shrink_coverage(
    registry,
    inventory,
    monkeypatch,
    anchor_name: str,
    key: str,
    expected_code: str,
) -> None:
    monkeypatch.delitem(getattr(governance_check, anchor_name), key)

    report = _validate(registry, inventory)

    assert expected_code in _codes(report)


def test_v1_contract_input_binding_cannot_self_certify_consumption(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    contract = next(
        item
        for item in document["contract_templates"]
        if item["id"] == "caller-file-read-v1"
    )
    contract["input_binding"] = "governed-source-pin"

    report = _validate(document, inventory)

    assert "contract-template-mismatch" in _codes(
        report, path="contract_template:caller-file-read-v1"
    )


def test_v1_contract_template_roster_is_exact(registry, inventory) -> None:
    document = _copy_document(registry)
    extra = copy.deepcopy(document["contract_templates"][0])
    extra["id"] = "fabricated-read-v1"
    document["contract_templates"].append(extra)

    report = _validate(document, inventory)

    assert "contract-template-roster-mismatch" in _codes(report)


def test_runtime_cannot_drop_frozen_contract_limitation(registry, inventory) -> None:
    document = _copy_document(registry)
    _runtime(document, "vulnify.lookup")["known_limitations"].pop()

    report = _validate(document, inventory)

    assert "runtime-limitations-mismatch" in _codes(
        report, path="runtime:vulnify.lookup"
    )


def test_pr97_implementation_revision_is_independently_frozen(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    _runtime(document, "vulnify.lookup")["implementation_revision"] = "0" * 40

    report = _validate(document, inventory)

    assert "runtime-implementation-revision-mismatch" in _codes(
        report, path="runtime:vulnify.lookup"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [("name", "fabricated source"), ("url", "https://example.invalid/source")],
)
def test_pr97_source_identity_is_independently_frozen(
    registry, inventory, field: str, value: str
) -> None:
    document = _copy_document(registry)
    _source(document, "R01")[field] = value

    report = _validate(document, inventory)

    assert "source-identity-mismatch" in _codes(report, path="source:R01")


def test_pr97_source_and_module_status_baselines_are_frozen(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    _source(document, "R01")["status"] = "retired"
    document["modules"][0]["status"] = "research"

    report = _validate(document, inventory)

    assert "source-status-baseline-mismatch" in _codes(
        report, path="source:R01"
    )
    assert "module-status-baseline-mismatch" in _codes(
        report, path="module:CYB-05"
    )


def test_deleting_governed_runtime_record_cannot_redefine_scope(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    document["runtime"] = [
        row for row in document["runtime"] if row["capability_id"] != "vulnify.lookup"
    ]

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert "pr97-runtime-roster-mismatch" in _codes(report)
    assert "dangling-relationship" in _codes(report)


def test_adding_authoritative_runtime_record_cannot_widen_pr97_scope(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    extra = copy.deepcopy(_runtime(document, "vulnify.list_tools"))
    extra["capability_id"] = "nmap.list_tools"
    extra["arm_id"] = "nmap"
    document["runtime"].append(extra)

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert {
        issue.code for issue in report.issues if issue.category == "integrity"
    } == {"pr97-runtime-roster-mismatch"}


def test_narrowing_action_input_keys_cannot_pass(registry, inventory) -> None:
    document = _copy_document(registry)
    _runtime(document, "vulnify.lookup")["input_keys"].remove("name")

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert "runtime-action-surface-mismatch" in _codes(
        report, path="runtime:vulnify.lookup"
    )


def test_schema_refuses_wildcard_relationship_targets(registry, tmp_path: Path) -> None:
    document = _copy_document(registry)
    document["relationships"][0]["to"] = ["runtime:vulnify.*"]
    path = tmp_path / "wildcard.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(RegisterLoadError, match="register schema error"):
        load_register(path)


def test_semantic_validator_refuses_dangling_exact_relationship(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    document["relationships"][0]["to"] = ["runtime:vulnify.unknown"]

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert "dangling-relationship" in _codes(report)
    assert "research-mapping-mismatch" in _codes(report)


def test_maintained_tier_without_evidence_regression_or_versions_fails(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    _runtime(document, "vulnify.lookup")["support_tier"] = "maintained"

    report = _validate(document, inventory)

    assert not report.integrity_ok
    codes = _codes(report, path="runtime:vulnify.lookup")
    assert "runtime-tier-mismatch" in codes
    assert "promotion-evidence-missing" in codes
    assert "maintained-without-regression" in codes
    assert "maintained-without-supported-versions" in codes


def test_promotion_event_must_bind_current_profile_and_contract(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    row = _runtime(document, "vulnify.lookup")
    row["promotion_evidence"] = ["promotion-vulnify-lookup"]
    document["promotion_events"].append(
        {
            "id": "promotion-vulnify-lookup",
            "subject": "runtime:vulnify.lookup",
            "from_status": "research",
            "to_status": "maintained",
            "decided_on": "2026-09-08",
            "reviewer": "independent-reviewer",
            "implementation_revision": row["implementation_revision"],
            "subject_digest": "sha256:" + "0" * 64,
            "contract_digest": "sha256:" + "0" * 64,
            "regression_case": "tests/test_arm_batch7.py",
            "verification_result": "local-pass",
            "exercised_path": "python3 -m extension invoke vulnify lookup",
            "supported_versions": ["specaudit-ctf==0.1.0"],
            "source_revisions": [],
            "limitations_accepted": list(row["known_limitations"]),
        }
    )

    report = _validate(document, inventory)

    assert not report.integrity_ok
    codes = _codes(report, path="runtime:vulnify.lookup")
    assert "promotion-subject-digest-mismatch" in codes
    assert "promotion-contract-digest-mismatch" in codes


def test_runtime_promotion_must_accept_exact_known_limitations(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    profiles = dict(INVOKE_PROFILES)
    profiles["vulnify.lookup"] = replace(
        profiles["vulnify.lookup"], tier="maintained"
    )
    promoted_inventory = snapshot_invoke_profiles(profiles)
    document["runtime_inventory"]["contract_sha256"] = (
        promoted_inventory.contract_sha256
    )
    row = _runtime(document, "vulnify.lookup")
    contract = next(
        item
        for item in document["contract_templates"]
        if item["id"] == row["contract_ref"]
    )
    row["support_tier"] = "maintained"
    row["supported_versions"] = ["specaudit-ctf==0.1.0"]
    row["regression_cases"] = ["tests/test_arm_batch7.py"]
    row["promotion_evidence"] = ["promotion-vulnify-maintained"]
    document["promotion_events"].append(
        {
            "id": "promotion-vulnify-maintained",
            "subject": "runtime:vulnify.lookup",
            "from_status": "research",
            "to_status": "maintained",
            "decided_on": "2026-09-08",
            "reviewer": "independent-reviewer",
            "implementation_revision": row["implementation_revision"],
            "subject_digest": _profile_digest(
                promoted_inventory.records["vulnify.lookup"]
            ),
            "contract_digest": _contract_digest(contract),
            "regression_case": "tests/test_arm_batch7.py",
            "verification_result": "local-pass",
            "exercised_path": "python3 -m extension invoke vulnify lookup",
            "supported_versions": ["specaudit-ctf==0.1.0"],
            "source_revisions": [],
            "limitations_accepted": list(reversed(row["known_limitations"])),
        }
    )

    report = _validate(document, promoted_inventory)

    assert not report.integrity_ok
    assert {
        issue.code for issue in report.issues if issue.category == "integrity"
    } == {
        "promotion-limitations-mismatch",
        "promotion-verifier-unimplemented",
    }


@pytest.mark.parametrize("subject_kind", ["source", "module"])
def test_generic_promotion_must_accept_exact_record_limitations(
    registry, inventory, subject_kind: str
) -> None:
    document = _copy_document(registry)
    if subject_kind == "source":
        row = _source(document, "R01")
        subject = "source:R01"
        from_status = "proposed"
        contract_digest = _source_contract_digest(row)
    else:
        row = document["modules"][0]
        subject = "module:CYB-05"
        from_status = "proposed"
        contract_digest = _module_contract_digest(row)
    event_id = f"promotion-{subject_kind}-limitations"
    row["promotion_evidence"] = [event_id]
    document["promotion_events"].append(
        {
            "id": event_id,
            "subject": subject,
            "from_status": from_status,
            "to_status": row["status"],
            "decided_on": "2026-09-08",
            "reviewer": "independent-reviewer",
            "implementation_revision": "9c6819c4709397d1d91f68cbb4ae13901d6d85f1",
            "subject_digest": _governance_subject_digest(row),
            "contract_digest": contract_digest,
            "regression_case": "tests/test_governance_registers.py",
            "verification_result": "local-pass",
            "exercised_path": "python3 -m governance check",
            "supported_versions": ["governance-register-v1"],
            "source_revisions": [],
            "limitations_accepted": ["does-not-match-row-limitations"],
        }
    )

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert {
        issue.code for issue in report.issues if issue.category == "integrity"
    } == {
        "promotion-limitations-mismatch",
        "promotion-verifier-unimplemented",
    }


def test_self_consistent_fabricated_promotion_is_refused(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    profiles = dict(INVOKE_PROFILES)
    profiles["vulnify.lookup"] = replace(
        profiles["vulnify.lookup"], tier="maintained"
    )
    promoted_inventory = snapshot_invoke_profiles(profiles)
    document["runtime_inventory"]["contract_sha256"] = (
        promoted_inventory.contract_sha256
    )
    row = _runtime(document, "vulnify.lookup")
    contract = next(
        item
        for item in document["contract_templates"]
        if item["id"] == row["contract_ref"]
    )
    row["support_tier"] = "maintained"
    row["implementation_revision"] = PR97_IMPLEMENTATION_REVISION
    row["supported_versions"] = ["fabricated-version"]
    row["regression_cases"] = ["does/not/exist.py::test_fabricated"]
    row["promotion_evidence"] = ["promotion-fabricated"]
    document["promotion_events"].append(
        {
            "id": "promotion-fabricated",
            "subject": "runtime:vulnify.lookup",
            "from_status": "research",
            "to_status": "maintained",
            "decided_on": "2026-09-08",
            "reviewer": "arbitrary-reviewer",
            "implementation_revision": PR97_IMPLEMENTATION_REVISION,
            "subject_digest": _profile_digest(
                promoted_inventory.records["vulnify.lookup"]
            ),
            "contract_digest": _contract_digest(contract),
            "regression_case": "does/not/exist.py::test_fabricated",
            "verification_result": "trust-me-pass",
            "exercised_path": "never-run",
            "supported_versions": ["fabricated-version"],
            "source_revisions": [],
            "limitations_accepted": list(row["known_limitations"]),
        }
    )

    report = _validate(document, promoted_inventory)

    assert not report.integrity_ok
    assert {
        issue.code for issue in report.issues if issue.category == "integrity"
    } == {"promotion-verifier-unimplemented"}


def test_source_admission_without_pin_rights_or_evidence_fails(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    _source(document, "R01")["status"] = "admitted"

    report = _validate(document, inventory)

    assert not report.integrity_ok
    codes = _codes(report, path="source:R01")
    assert "source-pin-missing" in codes
    assert "source-rights-unreviewed" in codes
    assert "promotion-evidence-missing" in codes


def test_whitespace_source_revision_cannot_satisfy_pin_gate(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    source = _source(document, "R01")
    source["status"] = "selected"
    source["selected_revision"] = "   "
    source["content_digests"] = ["sha256:" + "0" * 64]
    source["rights"]["license_review"] = "reviewed"
    source["rights"]["data_rights_review"] = "reviewed"

    report = _validate(document, inventory)

    assert "source-pin-missing" in _codes(report, path="source:R01")


@pytest.mark.parametrize(
    ("replacement", "expected_code"),
    [
        ("R01", "source-replacement-self"),
        ("R10", "source-replacement-unknown"),
        ("R99", "source-replacement-unknown"),
        ("R02", "source-replacement-relationship-mismatch"),
    ],
)
def test_source_replacement_requires_known_nonself_exact_relationship(
    registry, inventory, replacement: str, expected_code: str
) -> None:
    document = _copy_document(registry)
    _source(document, "R01")["replacement"] = replacement

    report = _validate(document, inventory)

    assert expected_code in _codes(report, path="source:R01")


def test_consumption_requires_admitted_source_and_exact_input_binding(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    document["relationships"].append(
        {
            "id": "bad-consumption",
            "record_version": 1,
            "kind": "consumes",
            "from": "runtime:vulnify.lookup",
            "to": ["source:R01"],
            "evidence_refs": [],
            "limitations": ["test-mutation"],
        }
    )

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert "relationship-roster-mismatch" in _codes(report)
    assert "consumes-unadmitted-source" in _codes(report)
    assert "consumes-unbound-input" in _codes(report)


def test_v1_refuses_extra_unsupported_relationship(registry, inventory) -> None:
    document = _copy_document(registry)
    document["relationships"].append(
        {
            "id": "self-certified-dependency",
            "record_version": 1,
            "kind": "depends-on",
            "from": "module:CYB-05",
            "to": ["module:CYB-05"],
            "evidence_refs": ["PROGRAM.md#first-proposed-vertical-slice"],
            "limitations": ["test-mutation"],
        }
    )

    report = _validate(document, inventory)

    assert "relationship-roster-mismatch" in _codes(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "limitations",
            ["mapping-establishes-provenance-and-runtime-consumption"],
        ),
        ("record_version", 2),
    ],
)
def test_relationship_safety_caveat_and_version_are_exact(
    registry, inventory, field: str, value: object
) -> None:
    document = _copy_document(registry)
    relationship = next(
        item
        for item in document["relationships"]
        if item["id"] == "map-r01-vulnify"
    )
    relationship[field] = value

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert "relationship-baseline-mismatch" in _codes(
        report, path="relationship:map-r01-vulnify"
    )


@pytest.mark.parametrize(
    ("evidence_ref", "expected_code"),
    [
        ("../../outside-secret.md#invented-anchor", "invalid-evidence-ref"),
        (
            "PROGRAM.md#definitely-not-an-existing-heading",
            "evidence-anchor-missing",
        ),
    ],
)
def test_relationship_evidence_must_resolve_inside_repo_to_real_heading(
    registry, inventory, evidence_ref: str, expected_code: str
) -> None:
    document = _copy_document(registry)
    document["relationships"][0]["evidence_refs"] = [evidence_ref]

    report = _validate(document, inventory)

    assert expected_code in _codes(report)
    assert "relationship-baseline-mismatch" in _codes(report)


@pytest.mark.parametrize(
    "markdown",
    [
        "```markdown\n## Candidate register: 42 unique candidates\n```\n",
        "~~~\n<a id='candidate-register-42-unique-candidates'></a>\n~~~\n",
        "<!--\n## Candidate register: 42 unique candidates\n-->\n",
        "<!-- <a id='candidate-register-42-unique-candidates'></a> -->\n",
        "<!-- inert -->## Candidate register: 42 unique candidates\n",
        "<!--\n-->## Candidate register: 42 unique candidates\n",
    ],
)
def test_evidence_anchor_parser_ignores_inert_markdown(markdown: str) -> None:
    assert (
        "candidate-register-42-unique-candidates"
        not in _github_heading_anchors(markdown)
    )


@pytest.mark.parametrize(
    "markdown",
    [
        "Candidate register {#candidate-register-42-unique-candidates}\n",
        "`{#candidate-register-42-unique-candidates}`\n",
        "<a id='candidate-register-42-unique-candidates'></a>\n",
        "\t## Candidate register: 42 unique candidates\n",
        "    ## Candidate register: 42 unique candidates\n",
    ],
)
def test_evidence_anchor_parser_rejects_nonheading_anchor_syntax(
    markdown: str,
) -> None:
    assert (
        "candidate-register-42-unique-candidates"
        not in _github_heading_anchors(markdown)
    )


def test_evidence_anchor_slug_does_not_include_link_destination() -> None:
    markdown = "## [Candidate](register-42-unique-candidates)\n"

    assert (
        "candidate-register-42-unique-candidates"
        not in _github_heading_anchors(markdown)
    )
    assert "candidate" in _github_heading_anchors(markdown)


def test_evidence_anchor_slug_refuses_ambiguous_image_alt_text() -> None:
    markdown = "## ![Candidate &reg;ister: 42 unique candidates](image.png)\n"

    with pytest.raises(RegisterLoadError, match=r"U\+00AE"):
        _github_heading_anchors(markdown)


def test_evidence_anchor_slug_uses_plain_image_alt_text() -> None:
    markdown = "## ![Candidate](ignored-destination.png) register\n"

    assert _github_heading_anchors(markdown) == {"candidate-register"}


@pytest.mark.parametrize(
    "markdown",
    [
        "<pre>\n## Candidate register: 42 unique candidates\n</pre>\n",
        "<script>\n## Candidate register: 42 unique candidates\n</script>\n",
        "<div>\n## Candidate register: 42 unique candidates\n</div>\n",
    ],
)
def test_evidence_anchor_parser_ignores_raw_html_blocks(markdown: str) -> None:
    assert (
        "candidate-register-42-unique-candidates"
        not in _github_heading_anchors(markdown)
    )


@pytest.mark.parametrize(
    "markdown",
    [
        "<?processing instruction\n\n## Candidate register: 42 unique candidates\n?>\n",
        "<!DOCTYPE declaration\n\n## Candidate register: 42 unique candidates\n>\n",
        "<![CDATA[\n\n## Candidate register: 42 unique candidates\n]]>\n",
    ],
)
def test_evidence_anchor_parser_keeps_terminated_html_blocks_across_blanks(
    markdown: str,
) -> None:
    assert (
        "candidate-register-42-unique-candidates"
        not in _github_heading_anchors(markdown)
    )


def test_evidence_anchor_parser_resumes_after_fence_and_comment() -> None:
    markdown = (
        "```\n## Not rendered\n```\n"
        "<!-- ## Also not rendered -->\n"
        "<pre>\n## Still not rendered\n</pre>\n"
        "<?processing\n\n## Still not rendered either\n?>\n"
        "## Candidate register: 42 unique candidates\n"
    )

    assert "candidate-register-42-unique-candidates" in _github_heading_anchors(
        markdown
    )


def test_evidence_anchor_parser_resumes_after_same_line_comment_close() -> None:
    markdown = (
        "<!-- inert -->\n"
        "## Candidate register: 42 unique candidates\n"
    )

    assert "candidate-register-42-unique-candidates" in _github_heading_anchors(
        markdown
    )


def test_evidence_anchor_parser_accepts_three_leading_spaces() -> None:
    markdown = "   ## Candidate register: 42 unique candidates\n"

    assert "candidate-register-42-unique-candidates" in _github_heading_anchors(
        markdown
    )


def test_evidence_anchor_parser_removes_tab_without_making_a_hyphen() -> None:
    markdown = "## Candidate\tregister: 42 unique candidates\n"

    anchors = _github_heading_anchors(markdown)

    assert "candidate-register-42-unique-candidates" not in anchors
    assert "candidateregister-42-unique-candidates" in anchors


def test_evidence_anchor_parser_preserves_each_literal_space() -> None:
    markdown = "## Candidate  register: 42 unique candidates\n"

    anchors = _github_heading_anchors(markdown)

    assert "candidate-register-42-unique-candidates" not in anchors
    assert "candidate--register-42-unique-candidates" in anchors


def test_evidence_anchor_duplicate_count_includes_setext_headings() -> None:
    markdown = (
        "Candidate register: 42 unique candidates\n"
        "========================================\n"
        "## Candidate register: 42 unique candidates\n"
    )

    anchors = _github_heading_anchors(markdown)

    assert "candidate-register-42-unique-candidates" not in anchors
    assert "candidate-register-42-unique-candidates-1" in anchors


def test_evidence_anchor_collision_removes_markdown_line_breaks() -> None:
    markdown = (
        "Candidate-\n"
        "register: 42 unique candidates\n"
        "================================\n"
        "## Candidate register: 42 unique candidates\n"
    )

    anchors = _github_heading_anchors(markdown)

    assert "candidate-register-42-unique-candidates" not in anchors
    assert "candidate-register-42-unique-candidates-1" in anchors


def test_evidence_anchor_duplicate_allocator_avoids_suffix_collisions() -> None:
    markdown = "## A\n## A\n## A-1\n## A\n"

    assert _github_heading_anchors(markdown) == {
        "a",
        "a-1",
        "a-1-1",
        "a-2",
    }


@pytest.mark.parametrize("line_ending", ["\n", "\r\n", "\r"])
def test_evidence_anchor_parser_refuses_excessive_logical_lines(
    line_ending: str,
) -> None:
    markdown = ("## bounded" + line_ending) * (MAX_EVIDENCE_LINES + 1)

    with pytest.raises(RegisterLoadError, match="maximum logical line count"):
        _github_heading_anchors(markdown)


@pytest.mark.parametrize(
    "character",
    [
        "\N{COMBINING ACUTE ACCENT}",
        "\N{UNDERTIE}",
        "\N{GREEK CAPITAL LETTER THETA}",
        "\N{GRINNING FACE}",
        "\N{CIRCLED LATIN CAPITAL LETTER A}",
    ],
)
def test_evidence_anchor_slug_refuses_ambiguous_nonascii(
    character: str,
) -> None:
    markdown = f"## Candidate{character} register\n"

    with pytest.raises(RegisterLoadError, match="unsupported non-ASCII"):
        _github_heading_anchors(markdown)


def test_evidence_anchor_slug_removes_nonascii_dash_punctuation() -> None:
    markdown = (
        "## T03 \N{EM DASH} Risk-based vulnerability prioritization\n"
        "## T01\N{EN DASH}T08 release wave\n"
    )

    assert _github_heading_anchors(markdown) == {
        "t03--risk-based-vulnerability-prioritization",
        "t01t08-release-wave",
    }


def test_currentness_is_derived_from_fixed_as_of(registry, inventory) -> None:
    document = _copy_document(registry)
    currentness = _runtime(document, "vulnify.lookup")["currentness"]
    currentness["reviewed_on"] = "2026-03-08"
    currentness["review_due_on"] = "2026-09-08"

    on_due = _validate(document, inventory, as_of=date(2026, 9, 8))
    after_due = _validate(document, inventory, as_of=date(2026, 9, 9))

    target_path = "runtime:vulnify.lookup.currentness"
    assert "stale" not in _codes(on_due, path=target_path)
    assert "unreviewed" not in _codes(on_due, path=target_path)
    assert "drift-triggers-unverified" in _codes(on_due, path=target_path)
    assert not on_due.current_ok
    assert "stale" in _codes(after_due, path=target_path)


@pytest.mark.parametrize(
    ("collection", "record_id", "target_path"),
    [
        ("modules", "CYB-05", "module:CYB-05.currentness"),
        ("sources", "R01", "source:R01.currentness"),
        ("runtime", "vulnify.lookup", "runtime:vulnify.lookup.currentness"),
    ],
)
def test_each_register_has_a_causal_currentness_gate(
    registry,
    inventory,
    collection: str,
    record_id: str,
    target_path: str,
) -> None:
    baseline = _validate(registry, inventory)
    assert "unreviewed" in _codes(baseline, path=target_path)

    reviewed_document = _copy_document(registry)
    key = "capability_id" if collection == "runtime" else "id"
    reviewed_row = next(
        row for row in reviewed_document[collection] if row[key] == record_id
    )
    reviewed_row["currentness"]["reviewed_on"] = "2026-03-08"
    reviewed_row["currentness"]["review_due_on"] = "2026-09-08"
    reviewed = _validate(reviewed_document, inventory)
    assert "unreviewed" not in _codes(reviewed, path=target_path)
    assert "drift-triggers-unverified" in _codes(reviewed, path=target_path)

    future_document = _copy_document(registry)
    future_row = next(
        row for row in future_document[collection] if row[key] == record_id
    )
    future_row["currentness"]["reviewed_on"] = "2099-01-01"
    future_row["currentness"]["review_due_on"] = "2099-12-31"
    future = _validate(future_document, inventory)
    assert "review-in-future" in _codes(future, path=target_path)
    assert "drift-triggers-unverified" in _codes(future, path=target_path)


def test_future_dated_reviews_cannot_satisfy_current_requirement(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    for collection in ("modules", "sources", "runtime"):
        for row in document[collection]:
            row["currentness"]["reviewed_on"] = "2099-01-01"
            row["currentness"]["review_due_on"] = "2099-12-31"

    report = _validate(document, inventory, require="current")

    assert not report.integrity_ok
    assert not report.current_ok
    assert not report.ok
    assert "review-in-future" in _codes(report)


def test_future_promotion_decision_cannot_satisfy_historical_check(
    registry, inventory
) -> None:
    document = _copy_document(registry)
    row = _runtime(document, "vulnify.lookup")
    contract = next(
        item
        for item in document["contract_templates"]
        if item["id"] == row["contract_ref"]
    )
    row["supported_versions"] = ["specaudit-ctf==0.1.0"]
    row["regression_cases"] = ["tests/test_arm_batch7.py"]
    row["promotion_evidence"] = ["promotion-vulnify-research"]
    document["promotion_events"].append(
        {
            "id": "promotion-vulnify-research",
            "subject": "runtime:vulnify.lookup",
            "from_status": "proposed",
            "to_status": "research",
            "decided_on": "2099-01-01",
            "reviewer": "independent-reviewer",
            "implementation_revision": row["implementation_revision"],
            "subject_digest": _profile_digest(
                inventory.records["vulnify.lookup"]
            ),
            "contract_digest": _contract_digest(contract),
            "regression_case": "tests/test_arm_batch7.py",
            "verification_result": "local-pass",
            "exercised_path": "python3 -m extension invoke vulnify lookup",
            "supported_versions": ["specaudit-ctf==0.1.0"],
            "source_revisions": [],
            "limitations_accepted": list(row["known_limitations"]),
        }
    )

    report = _validate(document, inventory)

    assert not report.integrity_ok
    assert _codes(report) == {
        "promotion-decision-in-future",
        "promotion-verifier-unimplemented",
        "repository-partial",
        "unreviewed",
    }


def test_validation_never_cross_promotes_other_registers(registry, inventory) -> None:
    document = _copy_document(registry)
    source = _source(document, "R01")
    source["status"] = "selected"
    before_runtime = _runtime(document, "vulnify.lookup")["support_tier"]
    before_module = document["modules"][0]["status"]

    _validate(document, inventory)

    assert _runtime(document, "vulnify.lookup")["support_tier"] == before_runtime
    assert document["modules"][0]["status"] == before_module
    assert before_runtime == "research"
    assert before_module == "design-ready"


def test_checkout_configuration_and_static_imports_keep_governance_separate() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_find = pyproject["tool"]["setuptools"]["packages"]["find"]
    assert package_find["include"] == ["extension*"]

    for path in (ROOT / "extension").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name.split(".", 1)[0] != "governance" for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                assert not node.module or node.module.split(".", 1)[0] != "governance"

    runtime_lock = json.loads((ROOT / "runtime" / "lock.json").read_text(encoding="utf-8"))
    locked_paths = set(runtime_lock["producer_source_files"])
    for invocation in runtime_lock["invocations"].values():
        locked_paths.update(invocation["extension_paths"])
    assert not any(path == "governance" or path.startswith("governance/") for path in locked_paths)
    assert DEFAULT_REGISTER_PATH == ROOT / "governance" / "register.v1.yaml"
