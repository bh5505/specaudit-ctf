"""Curated attack-stix-data arm: offline exact lookups, fail-closed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from extension.contract import (
    ArmSpec,
    Catalog,
    CatalogEntry,
    Extension,
    NotInstalledError,
)
from extension.arms.attackstix import ALLOWED_ACTIONS, ARM_ID, AttackStixArm
from extension.arms.attackstix import reader
from extension.arms.attackstix.policy import (
    MAX_BUNDLE_BYTES,
    args_refusal,
    bundle_refusal,
    demo_bundle_path,
)
from extension.arms.attackstix.reader import BundleError

ROOT = Path(__file__).resolve().parents[1]
DEMO = demo_bundle_path()


def _spec(entry_id: str = ARM_ID) -> ArmSpec:
    return ArmSpec(
        id=entry_id,
        protocols=("cli",),
        curated=True,
        notes="test",
        tier="research",
        held_reason=None,
    )


def _ext() -> Extension:
    entry = CatalogEntry(
        id=ARM_ID,
        kind="arm",
        protocols=("cli",),
        curated=True,
        notes="test arm row",
        tier="research",
        held_reason=None,
    )
    arm = AttackStixArm()
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: arm})


def test_demo_bundle_ships_and_parses() -> None:
    assert DEMO.is_file()
    index = reader.load_bundle(DEMO)
    kinds = {subject.kind for subject in index["subjects"]}
    assert kinds == {"technique", "software", "group"}
    assert len(index["subjects"]) == 22  # 18 techniques + 2 tools + 2 groups
    assert index["relationships"], "demo bundle ships relationship objects"


def test_bundle_refusals(tmp_path: Path) -> None:
    missing, why = bundle_refusal(str(tmp_path / "nope.json"))
    assert missing is None and "not an existing file" in why
    url, why = bundle_refusal("https://example.com/attack.json")
    assert url is None and "local file, not a URL" in why
    bad_suffix = tmp_path / "bundle.txt"
    bad_suffix.write_text("{}", encoding="utf-8")
    _, why = bundle_refusal(str(bad_suffix))
    assert "STIX bundle file" in why
    empty, why = bundle_refusal("   ")
    assert empty is None and "requires a local STIX bundle" in why
    control = tmp_path / "ctrl.json"
    control.write_text("{}", encoding="utf-8")
    _, why = bundle_refusal(f"{control}\x00")
    assert "control characters" in why
    tiny_cap = tmp_path / "small.json"
    tiny_cap.write_text("{}", encoding="utf-8")
    _, why = bundle_refusal(str(tiny_cap), max_bytes=1)
    assert "read cap" in why


def test_bundle_refusal_accepts_demo(tmp_path: Path) -> None:
    path, why = bundle_refusal(str(DEMO), max_bytes=MAX_BUNDLE_BYTES)
    assert why is None and path == DEMO


def test_reader_failures_are_typed(tmp_path: Path) -> None:
    not_json = tmp_path / "bad.json"
    not_json.write_text("{nope", encoding="utf-8")
    with pytest.raises(BundleError, match="not valid JSON"):
        reader.load_bundle(not_json)
    not_utf8 = tmp_path / "bytes.json"
    not_utf8.write_bytes(b'{"type":"bundle","objects":["\xff\xfe"]}')
    with pytest.raises(BundleError, match="not valid UTF-8"):
        reader.load_bundle(not_utf8)
    not_bundle = tmp_path / "obj.json"
    not_bundle.write_text(json.dumps({"type": "attack-pattern"}), encoding="utf-8")
    with pytest.raises(BundleError, match="type 'bundle'"):
        reader.load_bundle(not_bundle)
    no_objects = tmp_path / "empty.json"
    no_objects.write_text(json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-00000000000f"}), encoding="utf-8")
    with pytest.raises(BundleError, match="objects list"):
        reader.load_bundle(no_objects)


def test_technique_lookup_by_id_and_name() -> None:
    index = reader.load_bundle(DEMO)
    by_id = reader.find_technique(index, attack_id="t1530")
    assert by_id is not None and by_id.attack_id == "T1530"
    assert by_id.name == "Data from Cloud Storage"
    by_name = reader.find_technique(index, name="Valid Accounts")
    assert by_name is not None and by_name.attack_id == "T1078"
    assert reader.find_technique(index, attack_id="T9999") is None
    assert reader.find_technique(index, name="No Such Technique") is None


def test_technique_projection_fields() -> None:
    index = reader.load_bundle(DEMO)
    subject = reader.find_technique(index, attack_id="T1098.001")
    assert subject is not None
    row = reader.project_technique(index, subject)
    assert row["attack_id"] == "T1098.001"
    assert row["is_subtechnique"] is True
    assert row["kill_chain_phases"] == ["persistence", "privilege-escalation"]
    parent = reader.find_technique(index, attack_id="T1098")
    assert parent is not None
    assert reader.project_technique(index, parent)["is_subtechnique"] is False


def test_software_and_group_lookups() -> None:
    index = reader.load_bundle(DEMO)
    pacu = reader.find_software(index, "pacu")
    assert pacu is not None and pacu.name == "Pacu"
    row = reader.project_software(index, pacu)
    assert row["kind"] == "tool"
    assert row["platforms"]
    group = reader.find_group(index, "Storm-0501")
    assert group is not None
    grow = reader.project_group(index, group)
    assert grow["aliases"]
    assert reader.find_software(index, "No Such Tool") is None


def test_relationships_are_edge_bounded_and_typed() -> None:
    index = reader.load_bundle(DEMO)
    pacu = reader.find_software(index, "Pacu")
    assert pacu is not None
    rows = reader.relationships_for(index, pacu)
    assert rows
    for row in rows:
        assert row["relationship_type"] in reader.ALLOWED_RELATIONSHIP_TYPES
        assert row["source"]["label"] == "Pacu"
    sub = reader.relationships_for(
        index, pacu, relationship_type="subtechnique-of"
    )
    assert sub == []
    target_ids = {row["target"]["stix_id"] for row in rows}
    assert target_ids


def test_arm_installed_is_handler_presence() -> None:
    arm = AttackStixArm()
    assert arm.installed(_spec(ARM_ID)) is True
    assert arm.installed(_spec("other-arm")) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec("other-arm"), "technique", {})


def test_arm_list_tools_shape() -> None:
    result = _ext().invoke(ARM_ID, "list_tools", {})
    assert result.ok is True
    assert set(result.output["read_actions"]) == ALLOWED_ACTIONS | {
        "list_tools",
        "tools/list",
    }
    assert result.output["dispatch_actions"] == []
    assert "offline read tier" in " ".join(result.output["caveats"])
    refused = _ext().invoke(ARM_ID, "list_tools", {"bundle": str(DEMO)})
    assert refused.ok is False and "no caller arguments" in refused.error


def test_arm_actions_against_demo_bundle() -> None:
    ext = _ext()
    hit = ext.invoke(ARM_ID, "technique", {"bundle": str(DEMO), "id": "T1552.005"})
    assert hit.ok is True
    assert hit.output["name"] == "Cloud Instance Metadata API"
    assert hit.output["attack_id"] == "T1552.005"
    parent = ext.invoke(ARM_ID, "technique", {"bundle": str(DEMO), "id": "T1552"})
    assert parent.ok is True
    assert parent.output["name"] == "Unsecured Credentials"
    assert parent.output["is_subtechnique"] is False
    rel = ext.invoke(
        ARM_ID,
        "relationships",
        {"bundle": str(DEMO), "id": "T1098.001", "type": "subtechnique-of"},
    )
    assert rel.ok is True and len(rel.output) == 1


def test_arm_evaluated_failures_never_raise() -> None:
    ext = _ext()
    miss = ext.invoke(ARM_ID, "technique", {"bundle": str(DEMO), "id": "T9999"})
    assert miss.ok is False and "not found in this bundle" in miss.error
    url = ext.invoke(
        ARM_ID, "technique", {"bundle": "http://x/y.json", "id": "T1078"}
    )
    assert url.ok is False and "local file, not a URL" in url.error
    unknown = ext.invoke(ARM_ID, "scan", {"bundle": str(DEMO)})
    assert unknown.ok is False and "not on the allowlist" in unknown.error
    observe = ext.invoke(ARM_ID, "observe", {"fixture_id": "x", "seed": 1})
    assert observe.ok is False and "not on the allowlist" in observe.error
    extra = ext.invoke(
        ARM_ID, "software", {"bundle": str(DEMO), "name": "Pacu", "force": True}
    )
    assert extra.ok is False and "unexpected: force" in extra.error
    ambiguous = ext.invoke(
        ARM_ID, "technique", {"bundle": str(DEMO), "id": "T1078", "name": "x"}
    )
    assert ambiguous.ok is False and "exactly one" in ambiguous.error
    bad_type = ext.invoke(
        ARM_ID, "relationships", {"bundle": str(DEMO), "name": "Pacu", "type": "employs"}
    )
    assert bad_type.ok is False and "args.type must be one of" in bad_type.error


def test_arm_corrupt_bundle_is_evaluated_failure(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    result = _ext().invoke(
        ARM_ID, "technique", {"bundle": str(bad), "id": "T1078"}
    )
    assert result.ok is False
    assert "not valid JSON" in result.error


def test_reader_fails_closed_on_idless_rows(tmp_path: Path) -> None:
    """Rows without a string id fail the load — never a partial index."""
    for objects in (
        [{"type": "relationship", "relationship_type": ["uses"], "source_ref": "a", "target_ref": "b"}],
        [{"type": "attack-pattern", "name": "No id"}],
        [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-00000000000a",
                "name": "Once",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T0001"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-00000000000a",
                "name": "Twice",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T0002"}
                ],
            },
        ],
    ):
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-00000000000e",
            "objects": objects,
        }
        path = tmp_path / f"{len(objects)}-obj.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        with pytest.raises(BundleError, match="string id|duplicate bundle object id"):
            reader.load_bundle(path)


def test_reader_tolerates_unhashable_keyed_values(tmp_path: Path) -> None:
    """Unhashable values in keyed fields skip rows, never raise TypeError."""
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-00000000000e",
        "objects": [
            {
                "type": "relationship",
                "id": "relationship--00000000-0000-4000-8000-000000000001",
                "relationship_type": ["uses"],
                "source_ref": "a",
                "target_ref": "b",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-00000000000a",
                "name": "Broken Refs",
                "external_references": [
                    {"source_name": ["mitre-attack"], "external_id": "T0000"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-00000000000b",
                "name": "Good Technique",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T0001"}
                ],
            },
        ],
    }
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    index = reader.load_bundle(path)
    # The unhashable-relationship row was skipped; the subject loaded
    # with no attack id extracted from its broken reference.
    assert index["relationships"] == []
    broken = reader.find_technique(index, name="Broken Refs")
    assert broken is not None and broken.attack_id is None
    good = reader.find_technique(index, attack_id="T0001")
    assert good is not None and good.name == "Good Technique"


def test_tools_list_alias_works() -> None:
    result = _ext().invoke(ARM_ID, "tools/list", {})
    assert result.ok is True
    assert "technique" in result.output["read_actions"]


def test_output_cap_refuses_rather_than_truncates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import extension.arms.attackstix.arm as arm_module

    monkeypatch.setattr(arm_module, "MAX_OUTPUT_CHARS", 10)
    result = _ext().invoke(
        ARM_ID, "technique", {"bundle": str(DEMO), "id": "T1078"}
    )
    assert result.ok is False
    assert "output cap" in result.error


def test_arm_invoke_refuses_blank_ids_and_names() -> None:
    ext = _ext()
    blank = ext.invoke(ARM_ID, "technique", {"bundle": str(DEMO), "id": "   "})
    assert blank.ok is False and "exactly one" in blank.error
    blank_pair = ext.invoke(
        ARM_ID, "software", {"bundle": str(DEMO), "name": "  "}
    )
    assert blank_pair.ok is False and "args.name" in blank_pair.error


def test_extras_are_sorted_and_deterministic() -> None:
    from score.grading import grade

    def row(key: str) -> dict[str, str]:
        return {
            "finding_key": key,
            "control": "c",
            "severity": "high",
            "rationale": "r",
            "traces_to": "t",
        }

    found = {
        "track": "t",
        "total": 3,
        "findings": [row("z-extra"), row("a-extra"), row("m-extra")],
    }
    expected = {"track": "t", "total": 0, "findings": []}
    document = grade(found, expected)
    assert document["extras"] == ["a-extra", "m-extra", "z-extra"]


def _receipt(capsys: pytest.CaptureFixture[str]) -> dict:
    lines = [line for line in capsys.readouterr().err.splitlines() if line.strip()]
    assert len(lines) == 1
    return json.loads(lines[0])


def test_cvelookup_demo_hit_miss_and_malformed_leave_receipt(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _ext().invoke(
        ARM_ID,
        "cvelookup",
        {"cve_ids": ["cve-2099-0001", "CVE-2099-9999", "not-a-cve"]},
    )
    assert result.ok is True
    hit, miss, malformed = result.output["results"]
    assert hit["cve_id"] == "CVE-2099-0001"
    assert hit["status"] == "matched" and hit["count_matched"] == 2
    assert {row["type"] for row in hit["matched_objects"]} == {"attack-pattern", "tool"}
    assert all(row["cve_id"] == "CVE-2099-0001" for row in hit["matched_objects"])
    assert all(row["description"] for row in hit["matched_objects"])
    assert all(row["external_references"] for row in hit["matched_objects"])
    assert all("x_mitre_version" in row for row in hit["matched_objects"])
    assert miss["reason"] == "unknown_cve" and miss["matched_objects"] == []
    assert malformed["reason"] == "malformed_id"
    assert malformed["cve_id"] is None and "query_sha256" in malformed

    receipt = _receipt(capsys)
    assert receipt["arm"] == ARM_ID and receipt["action"] == "cvelookup"
    assert receipt["bundle_sha256"] == hashlib.sha256(DEMO.read_bytes()).hexdigest()
    assert receipt["count_matched"] == 2
    assert len(receipt["normalized_args_sha256"]) == 64
    assert len(receipt["output_sha256"]) == 64
    assert [row["reason"] for row in receipt["queries"]] == [
        None,
        "unknown_cve",
        "malformed_id",
    ]
    assert "not-a-cve" not in json.dumps(receipt)


@pytest.mark.parametrize(
    "payload,setup,reason",
    [
        ({"bundle_path": "missing.json", "cve_ids": ["CVE-2099-0001"]}, None, "bundle_missing"),
        ({"bundle_path": "bad.json", "cve_ids": ["CVE-2099-0001"]}, "invalid", "bundle_invalid_json"),
        ({"cve_ids": "CVE-2099-0001"}, None, "cve_ids_not_a_list"),
    ],
)
def test_cvelookup_invocation_failures_leave_receipts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    payload: dict,
    setup: str | None,
    reason: str,
) -> None:
    invocation = dict(payload)
    if "bundle_path" in invocation:
        path = tmp_path / invocation["bundle_path"]
        if setup == "invalid":
            path.write_text("{not-json", encoding="utf-8")
        invocation["bundle_path"] = str(path)
    result = _ext().invoke(ARM_ID, "cvelookup", invocation)
    assert result.ok is False
    assert result.output["reason"] == reason
    receipt = _receipt(capsys)
    assert receipt["status"] == "failed" and receipt["reason"] == reason
    assert len(receipt["output_sha256"]) == 64
    if reason == "bundle_invalid_json":
        assert len(receipt["bundle_sha256"]) == 64
    else:
        assert receipt["bundle_sha256"] is None


def test_cvelookup_lone_surrogate_still_leaves_receipt(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _ext().invoke(
        ARM_ID,
        "cvelookup",
        {"cve_ids": ["\ud800", "CVE-٢٠٢٤-1234", "CVE-2024-١٢٣٤"]},
    )
    assert result.ok is True
    assert [row["reason"] for row in result.output["results"]] == [
        "malformed_id",
        "malformed_id",
        "malformed_id",
    ]
    receipt = _receipt(capsys)
    assert all(row["reason"] == "malformed_id" for row in receipt["queries"])
    assert all(len(row["query_sha256"]) == 64 for row in receipt["queries"])


def test_cvelookup_is_registered() -> None:
    from extension.invoke_profiles import invoke_profile

    profile = invoke_profile(ARM_ID, "cvelookup")
    assert profile is not None
    assert profile.side_effects == ("local-read",)
    assert "cvelookup" in _ext().invoke(ARM_ID, "list_tools", {}).output["read_actions"]


def test_args_refusal_contract() -> None:
    assert args_refusal("technique", {}) is not None
    assert args_refusal("technique", {"bundle": "b"}) is not None
    assert args_refusal("technique", {"bundle": "b", "id": "T1"}) is None
    assert args_refusal("software", {"bundle": "b"}) is not None
    assert args_refusal("software", {"bundle": "b", "name": "Pacu"}) is None
    assert args_refusal("cvelookup", {"cve_ids": []}) is None
    assert args_refusal("cvelookup", {}) is not None
