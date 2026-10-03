import hashlib
import json
from pathlib import Path

import pytest

from graph_evidence.importer import InvalidGraph, evaluate, main


FIXTURE = Path(__file__).resolve().parents[1] / "graph_evidence/fixtures/synthetic-aws.rage.ndjson"
PROJECT_FIXTURE = FIXTURE.with_name("synthetic-aws-projection.rage.ndjson")
SOURCE = "aws|000000000000|aws:iam:role|trainee"
TARGET = "aws|000000000000|aws:s3:bucket|practice-data"


def raw_and_hash(records=None):
    raw = FIXTURE.read_bytes() if records is None else ("\n".join(json.dumps(r) for r in records) + "\n").encode()
    return raw, hashlib.sha256(raw).hexdigest()


def records():
    return [json.loads(line) for line in FIXTURE.read_text().splitlines()]


def test_configured_blocked_unknown_are_separate():
    raw, digest = raw_and_hash()
    result = evaluate(raw, digest, SOURCE, TARGET)
    assert result["input_sha256"] == "c09cc7d617c082dbf42b27bca63007a9d84d0290894499e10e67208b7445f496"
    assert {p["verdict"] for p in result["paths"]} == {"configured_candidate", "blocked", "unknown"}
    assert all(len(p["edge_ids"]) == 2 for p in result["paths"])
    assert "no effective access" in result["limitations"][0]


def test_digest_and_duplicate_receipt_refused():
    raw, digest = raw_and_hash()
    with pytest.raises(InvalidGraph, match="digest"):
        evaluate(raw, "0" * 64, SOURCE, TARGET)
    data = records()
    data.append(dict(next(r for r in data if r["kind"] == "evidence")))
    raw, digest = raw_and_hash(data)
    with pytest.raises(InvalidGraph, match="duplicate evidence"):
        evaluate(raw, digest, SOURCE, TARGET)


@pytest.mark.parametrize("change", [
    lambda rows: rows[0].update(spec_version="0.2"),
    lambda rows: next(r for r in rows if r["kind"] == "evidence").update(pointer="blobs/forged"),
    lambda rows: next(r for r in rows if r["kind"] == "edge").update(secret="plaintext"),
    lambda rows: next(r for r in rows if r["kind"] == "edge").update(facts=["forged"]),
    lambda rows: next(r for r in rows if r["kind"] == "evidence").update(status="mystery"),
    lambda rows: rows[0].update(scope={"providers": ["aws"], "foothold": "aws|another|role|x"}),
])
def test_drift_forged_locator_and_missing_provenance_fail_closed(change):
    data = records()
    change(data)
    raw, digest = raw_and_hash(data)
    with pytest.raises(InvalidGraph):
        evaluate(raw, digest, SOURCE, TARGET)


def test_duplicate_json_key_and_cli_failure(capsys, tmp_path):
    data = FIXTURE.read_text().replace('"kind":"manifest"', '"kind":"manifest","kind":"manifest"', 1).encode()
    digest = hashlib.sha256(data).hexdigest()
    path = tmp_path / "bad.rage.ndjson"
    path.write_bytes(data)
    assert main([str(path), "--sha256", digest, "--source", SOURCE, "--target", TARGET]) == 2
    assert "duplicate JSON key" in capsys.readouterr().err


def test_source_shaped_safe_metadata_is_checked_not_echoed():
    data = records()
    data[0].update(taxonomy_version="0.1", snapshot_at="2026-09-01T00:00:00Z",
                   counts={"nodes": 5, "edges": 6, "facts": 6, "evidence": 6,
                           "findings": 0, "surfaces": 0, "paths": 0})
    node = next(r for r in data if r["kind"] == "node")
    node.update(provider="aws", name="synthetic role", observed_at="2026-09-01T00:00:00Z")
    fact = next(r for r in data if r["kind"] == "fact")
    fact.update(provider="aws", content_hash="sha256:" + "a" * 64)
    receipt = next(r for r in data if r["kind"] == "evidence")
    receipt["content_hash"] = "sha256:" + receipt["content_hash"]
    raw, digest = raw_and_hash(data)
    result = evaluate(raw, digest, SOURCE, TARGET)
    assert len(result["paths"]) == 3
    assert "synthetic role" not in json.dumps(result)
    data[0]["counts"]["findings"] = 1
    raw, digest = raw_and_hash(data)
    with pytest.raises(InvalidGraph, match="unreviewed"):
        evaluate(raw, digest, SOURCE, TARGET)


@pytest.mark.parametrize("field,value", [("kind", []), ("source", []), ("target", {})])
def test_malformed_fields_are_typed_invalid(field, value):
    data = records()
    next(r for r in data if r["kind"] == "edge")[field] = value
    raw, digest = raw_and_hash(data)
    with pytest.raises(InvalidGraph):
        evaluate(raw, digest, SOURCE, TARGET)


def test_path_expansion_is_bounded_even_without_a_reachable_target(monkeypatch):
    import graph_evidence.importer as importer

    monkeypatch.setattr(importer, "MAX_EXPANSIONS", 2)
    data = records()
    unreachable = "aws|000000000000|aws:s3:bucket|unreachable"
    data.append({"kind": "node", "node_id": unreachable, "node_type": "ObjectStorage"})
    raw, digest = raw_and_hash(data)
    with pytest.raises(InvalidGraph, match="expansion limit"):
        evaluate(raw, digest, SOURCE, unreachable)


def test_cli_success(capsys):
    _, digest = raw_and_hash()
    assert main([str(FIXTURE), "--sha256", digest, "--source", SOURCE, "--target", TARGET]) == 0
    assert len(json.loads(capsys.readouterr().out)["paths"]) == 3


def projected_source_records():
    data = records()
    data[0]["counts"] = {"nodes": 5, "edges": 6, "facts": 6, "evidence": 6,
                          "findings": 1, "surfaces": 1, "paths": 1}
    first_edge = next(r for r in data if r["kind"] == "edge" and r["edge_id"] == "edge-2")
    first_edge.update(permissions=["s3:GetObject"], conditions=["session-policy-unverified"], weight=2.0)
    next(r for r in data if r["kind"] == "node")["attributes"] = {}
    data.extend([
        {"kind": "surface", "surface_id": "sf-1", "resource_id": TARGET, "category": "synthetic",
         "emits_hint": "CanReadData", "severity": "low", "evidence": ["receipt-2"]},
        {"kind": "path", "path_id": "path-1", "source": SOURCE, "target": TARGET,
         "edge_ids": ["edge-1", "edge-2"], "score": 2.0},
        {"kind": "finding", "resource_id": TARGET, "severity": "low", "emits_hint": "CanReadData",
         "evidence": ["receipt-2"]},
    ])
    return data


def test_opt_in_projection_omission_ledger_and_unknown_permission():
    data = projected_source_records()
    raw, digest = raw_and_hash(data)
    with pytest.raises(InvalidGraph):
        evaluate(raw, digest, SOURCE, TARGET)
    result = evaluate(raw, digest, SOURCE, TARGET, project_mode=True)
    assert result["input_sha256"] == digest
    assert result["projection"]["omitted"]["path_records"] == 1
    assert result["projection"]["omitted"]["surface_records"] == 1
    assert result["projection"]["omitted"]["finding_records"] == 1
    assert result["projection"]["omitted"]["edge.permissions"] == 1
    assert result["projection"]["semantic_edges_downgraded"] == 5
    assert [p for p in result["paths"] if p["edge_ids"] == ["edge-1", "edge-2"]][0]["verdict"] == "unknown"


def test_packaged_source_shaped_projection_fixture(capsys):
    assert [json.loads(line) for line in PROJECT_FIXTURE.read_text().splitlines()] == projected_source_records()
    digest = hashlib.sha256(PROJECT_FIXTURE.read_bytes()).hexdigest()
    assert digest == "5362a030dd5ddaa688f3d80f941b6962d7e82461b6557ed6c471f441bf1323ef"
    assert main([str(PROJECT_FIXTURE), "--sha256", digest, "--source", SOURCE,
                 "--target", TARGET, "--project"]) == 0
    assert json.loads(capsys.readouterr().out)["projection"]["semantic_edges_downgraded"] == 5


@pytest.mark.parametrize("kind,field,value", [
    ("node", "attributes", ["malformed bag"]),
    ("evidence", "pointer", "blobs/forged"),
    ("finding", "value_ref", "secret-value"),
    ("path", "narrative", "possibly sensitive"),
    ("edge", "x-new-permission", ["wildcard"]),
])
def test_projection_refuses_secret_bags_locators_and_drift(kind, field, value):
    data = projected_source_records()
    next(r for r in data if r["kind"] == kind)[field] = value
    raw, digest = raw_and_hash(data)
    with pytest.raises(InvalidGraph):
        evaluate(raw, digest, SOURCE, TARGET, project_mode=True)


def test_projection_drops_secret_bags_and_condition_maps_without_echo():
    sentinel = "SYNTHETIC-SECRET-NEVER-ECHO"
    data = projected_source_records()
    edge = next(r for r in data if r.get("edge_id") == "edge-2")
    edge["attributes"] = {"raw_token": sentinel}
    edge["conditions"] = {"session_context": sentinel}
    path = next(r for r in data if r["kind"] == "path")
    path["detail"] = {"raw_observation": sentinel}
    raw, digest = raw_and_hash(data)
    output = evaluate(raw, digest, SOURCE, TARGET, project_mode=True)
    assert sentinel not in json.dumps(output)
    assert output["projection"]["omitted"]["edge.attributes"] == 1
    assert output["projection"]["omitted"]["path.detail"] == 1
    assert output["projection"]["omitted"]["edge.conditions"] == 1
    assert all(p["verdict"] != "configured_candidate" for p in output["paths"])
