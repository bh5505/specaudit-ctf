"""Bounded local vulnify lookup and custody tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from extension.contract import ArmSpec, Catalog, CatalogEntry, Extension, describe
from extension.arms.vulnify import ARM_ID, VulnifyArm
from extension.arms.vulnify.policy import MAX_BUNDLE_BYTES, demo_bundle_path

DEMO = demo_bundle_path()


def _spec() -> ArmSpec:
    return ArmSpec(ARM_ID, ("cli",), True, "test", "experimental")


def _ext() -> Extension:
    entry = CatalogEntry(ARM_ID, "arm", ("cli",), True, "test", "experimental")
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: VulnifyArm()})


def _receipt(capsys) -> dict:
    lines = [line for line in capsys.readouterr().err.splitlines() if line]
    assert len(lines) == 1
    return json.loads(lines[0])


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
    assert _receipt(capsys)["bundle_sha256"] == digest


def test_vulnify_unknown_id_stays_unknown(capsys) -> None:
    result = _invoke(["CVE-2099-9999"])
    row = result.output["results"][0]
    assert result.ok is True
    assert row["status"] == "unmatched" and row["reason"] == "unknown_cve"
    assert row["record"] is None and len(row["snapshot_sha256"]) == 64
    assert _receipt(capsys)["queries"][0]["reason"] == "unknown_cve"


def test_vulnify_malformed_id_is_hashed_not_echoed(capsys) -> None:
    result = _invoke(["not an id"])
    row = result.output["results"][0]
    assert row["reason"] == "malformed_id" and len(row["query_sha256"]) == 64
    receipt = _receipt(capsys)
    assert "not an id" not in json.dumps(receipt)


def test_vulnify_missing_bundle_fails_with_receipt(tmp_path: Path, capsys) -> None:
    result = _invoke(["CVE-2099-0001"], tmp_path / "missing.json")
    assert result.ok is False and result.output["reason"] == "bundle_missing"
    receipt = _receipt(capsys)
    assert receipt["status"] == "failed" and receipt["bundle_sha256"] is None


def test_vulnify_invalid_json_fails_with_snapshot_digest(tmp_path: Path, capsys) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not-json", encoding="utf-8")
    result = _invoke(["CVE-2099-0001"], path)
    assert result.ok is False and result.output["reason"] == "bundle_invalid_json"
    assert _receipt(capsys)["bundle_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_vulnify_oversized_bundle_is_rejected_before_read(tmp_path: Path, capsys) -> None:
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (MAX_BUNDLE_BYTES + 1))
    result = _invoke(["CVE-2099-0001"], path)
    assert result.ok is False and result.output["reason"] == "bundle_too_large"
    assert _receipt(capsys)["bundle_sha256"] is None


def test_vulnify_receipt_integrity(capsys) -> None:
    result = _invoke(["CVE-2099-0001", "CVE-2099-9999", "bad"])
    receipt = _receipt(capsys)
    canonical = json.dumps(result.output, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert receipt["schema"] == "vulnify.lookup-receipt.v1"
    assert receipt["arm"] == ARM_ID and receipt["action"] == "lookup"
    assert receipt["output_sha256"] == hashlib.sha256(canonical.encode()).hexdigest()
    assert len(receipt["normalized_args_sha256"]) == 64
    assert [row["reason"] for row in receipt["queries"]] == [None, "unknown_cve", "malformed_id"]


def test_vulnify_list_describe_and_registration() -> None:
    listed = _ext().invoke(ARM_ID, "list_tools", {})
    assert listed.ok is True and listed.output["dispatch_actions"] == []
    assert set(listed.output["read_actions"]) == {"lookup", "list_tools", "tools/list"}
    row = describe(ARM_ID)
    assert row.tier == "experimental" and row.curated is True
    from extension.invoke_profiles import invoke_profile
    for action in ("list_tools", "lookup"):
        profile = invoke_profile(ARM_ID, action)
        assert profile is not None
        assert profile.side_effects == ("local-read",)
        assert profile.tier == "experimental"
