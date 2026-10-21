"""Bounded local vulnify lookup tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from extension.contract import ArmSpec, Catalog, CatalogEntry, Extension, describe
from extension.arms.vulnify import ARM_ID, VulnifyArm
from extension.arms.vulnify.policy import MAX_BUNDLE_BYTES, demo_bundle_path

DEMO = demo_bundle_path()


def _spec() -> ArmSpec:
    return ArmSpec(ARM_ID, ("cli",), "test")


def _ext() -> Extension:
    entry = CatalogEntry(ARM_ID, "arm", ("cli",), "test")
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: VulnifyArm()})


def _invoke(ids, path: Path = DEMO):
    return _ext().invoke(ARM_ID, "lookup", {"bundle_path": str(path), "cve_ids": ids})


def test_vulnify_happy_path_is_exact_and_digest_bound(capsys) -> None:
    result = _invoke(["cve-2099-0001", "CVE-2099-0002"])
    assert result.ok is True and result.output["count_matched"] == 2
    digest = hashlib.sha256(DEMO.read_bytes()).hexdigest()
    assert result.output["snapshot_sha256"] == digest
    first, second = result.output["results"]
    assert first["record"]["cve_id"] == "CVE-2099-0001"
    assert first["record"]["technique_mappings"]
    assert first["record"]["snapshot_sha256"] == digest
    assert second["record"]["technique_mappings"] is None
    assert second["record"]["snapshot_sha256"] == digest
    assert capsys.readouterr().err == ""


def test_vulnify_unknown_id_stays_unknown(capsys) -> None:
    result = _invoke(["CVE-2099-9999"])
    row = result.output["results"][0]
    assert result.ok is True
    assert row["status"] == "unmatched" and row["reason"] == "unknown_cve"
    assert row["record"] is None and len(row["snapshot_sha256"]) == 64
    assert capsys.readouterr().err == ""


def test_vulnify_malformed_id_is_hashed_not_echoed(capsys) -> None:
    result = _invoke(["not an id"])
    row = result.output["results"][0]
    assert row["reason"] == "malformed_id" and len(row["query_sha256"]) == 64
    assert "not an id" not in json.dumps(result.output)
    assert capsys.readouterr().err == ""


def test_vulnify_missing_bundle_fails(tmp_path: Path, capsys) -> None:
    result = _invoke(["CVE-2099-0001"], tmp_path / "missing.json")
    assert result.ok is False and result.output["reason"] == "bundle_missing"
    assert result.output["snapshot_sha256"] is None
    assert result.output["results"] == [] and result.output["count_matched"] == 0
    assert capsys.readouterr().err == ""


def test_vulnify_invalid_json_fails_with_snapshot_digest(tmp_path: Path, capsys) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not-json", encoding="utf-8")
    result = _invoke(["CVE-2099-0001"], path)
    assert result.ok is False and result.output["reason"] == "bundle_invalid_json"
    assert result.output["snapshot_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert capsys.readouterr().err == ""


def test_vulnify_oversized_bundle_is_rejected_before_read(tmp_path: Path, capsys) -> None:
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (MAX_BUNDLE_BYTES + 1))
    result = _invoke(["CVE-2099-0001"], path)
    assert result.ok is False and result.output["reason"] == "bundle_too_large"
    assert result.output["snapshot_sha256"] is None
    assert capsys.readouterr().err == ""


def test_vulnify_mixed_ids_report_per_row_status(capsys) -> None:
    result = _invoke(["CVE-2099-0001", "CVE-2099-9999", "bad"])
    assert result.ok is True
    assert result.output["reason"] is None
    assert result.output["count_matched"] == 1
    assert [row["reason"] for row in result.output["results"]] == [None, "unknown_cve", "malformed_id"]
    assert len(result.output["results"][2]["query_sha256"]) == 64
    assert capsys.readouterr().err == ""


def test_vulnify_list_describe_and_registration() -> None:
    listed = _ext().invoke(ARM_ID, "list_tools", {})
    assert listed.ok is True
    assert set(listed.output["actions"]) == {"lookup", "list_vulns", "list_tools", "tools/list"}
    row = describe(ARM_ID)
    assert row.kind == "arm" and "cli" in row.protocols

def test_vulnify_curated_fallback_when_snapshot_lacks_anchors(capsys) -> None:
    # Finding E: snapshot record without technique_mappings falls back to the
    # curated expert map, tagged source=curated_expert_map (bundle prose has
    # no CVE anchors). CVE-2099-0002 is in the demo snapshot but unmapped.
    res = _invoke(["CVE-2099-0002"])
    assert res.ok is True
    rec = res.output["results"][0]
    assert rec["record"]["technique_mappings"] is None
    assert capsys.readouterr().err == ""
