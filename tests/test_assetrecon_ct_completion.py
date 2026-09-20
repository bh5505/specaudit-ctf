"""Causal CT completion: empty pages are negative evidence; malformed names are limited.

Hermetic: worker fetch is stubbed; fixtures are local JSON. No provider contact.
"""
from __future__ import annotations

import json

import pytest

from extension.arms.assetrecon import AssetReconArm
from extension.arms.assetrecon import arm, worker
from extension.arms.assetrecon.model import Refusal
from extension.arms.assetrecon.sources import ADAPTERS, MALFORMED_CT_NAME_LIMITATION
from extension.contract import ArmSpec

SPEC = ArmSpec("asset-recon", ("cli",), True, "Hermetic fixture", "research")
HASH = "0" * 64
FP = "a" * 64
MALFORMED = "invalid_name.example.test"
VALID = "api.example.test"
OUT_OF_SCOPE = "unrelated.example"


def invoke(action, payload):
    return AssetReconArm().invoke(SPEC, action, payload)


def consume(source, data):
    parsed = ADAPTERS[source].parse(data)
    observations = list(parsed)
    return observations, list(parsed.limitations)


def test_crtsh_empty_response_is_negative_evidence(monkeypatch):
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: ([], HASH))
    result = worker.collect("crtsh", "domain", "public.com", "subdomains")
    assert result["ok"] is True
    assert result["data"] == []
    assert result["digest"] == HASH
    assert "CT index results are a snapshot; provider has no completeness guarantee" in result["limitations"]
    assert "CT rows not binding query filtered" not in result["limitations"]


def test_certspotter_empty_response_is_negative_evidence(monkeypatch):
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: ([], HASH))
    result = worker.collect("certspotter", "domain", "public.com")
    assert result["ok"] is True
    assert result["data"] == []
    assert result["digest"] == HASH
    assert result["cursor"] is None
    assert result["limitations"]


def test_crtsh_nonempty_all_unbound_response_is_refused(monkeypatch):
    rows = [{"name_value": OUT_OF_SCOPE}, {"name_value": MALFORMED}]
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: (rows, HASH))
    with pytest.raises(Refusal, match="^CT record does not bind query$"):
        worker.collect("crtsh", "domain", "public.com", "subdomains")


def test_certspotter_nonempty_all_unbound_response_is_refused(monkeypatch):
    rows = [{"id": "1", "dns_names": [OUT_OF_SCOPE], "cert_sha256": FP}]
    monkeypatch.setattr(worker, "fetch", lambda *a, **k: (rows, HASH))
    with pytest.raises(Refusal, match="issuance does not bind query"):
        worker.collect("certspotter", "domain", "public.com")


def test_crtsh_parser_empty_list_is_not_malformed():
    observations, limitations = consume("crtsh", [])
    assert observations == []
    assert limitations == []


def test_certspotter_parser_empty_list_is_not_malformed():
    observations, limitations = consume("certspotter", [])
    assert observations == []
    assert limitations == []


def test_crtsh_all_malformed_reports_limitation_without_evidence():
    observations, limitations = consume("crtsh", [{"name_value": MALFORMED + "\nbad\x00name", "id": 1}])
    assert observations == []
    assert limitations == [MALFORMED_CT_NAME_LIMITATION]
    assert MALFORMED not in MALFORMED_CT_NAME_LIMITATION
    assert "\x00" not in MALFORMED_CT_NAME_LIMITATION


def test_certspotter_all_malformed_reports_limitation_without_evidence():
    observations, limitations = consume("certspotter", [{
        "id": "1", "dns_names": [MALFORMED, "bad\x00name"], "cert_sha256": FP,
    }])
    assert observations == []
    assert limitations == [MALFORMED_CT_NAME_LIMITATION]


def test_crtsh_mixed_valid_and_malformed_keeps_valid_and_limits():
    observations, limitations = consume("crtsh", [{
        "name_value": VALID + "\n" + MALFORMED, "id": 1,
    }])
    assert [(obs.relation, obs.right) for obs in observations] == [("query_match", VALID)]
    assert limitations == [MALFORMED_CT_NAME_LIMITATION]
    assert all(MALFORMED not in value for obs in observations for value in (obs.left, obs.right))


def test_certspotter_mixed_valid_and_malformed_keeps_valid_and_limits():
    observations, limitations = consume("certspotter", [{
        "id": "1", "dns_names": [VALID, MALFORMED], "cert_sha256": FP,
    }])
    assert [(obs.relation, obs.right) for obs in observations] == [("san", VALID)]
    assert limitations == [MALFORMED_CT_NAME_LIMITATION]
    assert all(MALFORMED not in value for obs in observations for value in (obs.left, obs.right))


def test_valid_out_of_scope_name_is_not_malformed():
    observations, limitations = consume("crtsh", [{"name_value": OUT_OF_SCOPE, "id": 1}])
    assert [(obs.relation, obs.right) for obs in observations] == [("query_match", OUT_OF_SCOPE)]
    assert limitations == []


def test_mixed_out_of_scope_and_malformed_keeps_valid_source_name():
    observations, limitations = consume("crtsh", [{
        "name_value": OUT_OF_SCOPE + "\n" + MALFORMED, "id": 1,
    }])
    assert any(obs.right == OUT_OF_SCOPE for obs in observations)
    assert all(MALFORMED not in value for obs in observations for value in (obs.left, obs.right))
    assert limitations == [MALFORMED_CT_NAME_LIMITATION]


def test_offline_mixed_fixture_keeps_valid_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(arm, "run_worker", lambda *_: pytest.fail("offline attempted live worker"))
    path = tmp_path / "ct.json"
    path.write_text(json.dumps([{
        "name_value": VALID + "\n" + MALFORMED,
        "id": 1,
        "sha256": FP,
    }]))
    result = invoke("parse", {
        "seeds": {"domains": ["example.test"]},
        "fixtures": [{"source": "crtsh", "path": str(path)}],
    })
    assert not result.ok
    assert result.output["status"] == "partial"
    assert MALFORMED_CT_NAME_LIMITATION in result.output["limitations"]
    dumped = json.dumps(result.output)
    assert VALID in dumped
    assert MALFORMED not in dumped
    assert "bad\x00" not in dumped


def test_offline_all_malformed_fixture_does_not_emit_invalid_names(tmp_path, monkeypatch):
    monkeypatch.setattr(arm, "run_worker", lambda *_: pytest.fail("offline attempted live worker"))
    path = tmp_path / "ct.json"
    path.write_text(json.dumps([{"name_value": MALFORMED, "id": 1, "sha256": FP}]))
    result = invoke("parse", {
        "seeds": {"domains": ["example.test"]},
        "fixtures": [{"source": "crtsh", "path": str(path)}],
    })
    assert not result.ok
    assert result.output["status"] == "partial"
    assert MALFORMED_CT_NAME_LIMITATION in result.output["limitations"]
    dumped = json.dumps(result.output)
    assert MALFORMED not in dumped
    assert result.output["nodes"]
    parsed = ADAPTERS["crtsh"].parse(json.loads(path.read_text()))
    list(parsed)
    assert parsed.limitations == [MALFORMED_CT_NAME_LIMITATION]


@pytest.mark.parametrize("source", ["crtsh", "certspotter"])
@pytest.mark.parametrize("mixed", [False, True])
def test_offline_ct_omissions_make_final_result_partial(source, mixed, tmp_path, monkeypatch):
    names = [MALFORMED] + ([VALID] if mixed else [])
    data = ([{"name_value": "\n".join(names), "sha256": FP}] if source == "crtsh"
            else [{"dns_names": names, "cert_sha256": FP}])
    path = tmp_path / "omissions.json"
    path.write_text(json.dumps(data))
    monkeypatch.setattr(arm, "run_worker", lambda *_: pytest.fail("offline contacted worker"))
    result = invoke("discover", {"seeds": {"domains": ["example.test"]},
                                "fixtures": [{"source": source, "path": str(path)}]})
    assert not result.ok
    assert result.output["status"] == "partial"
    assert MALFORMED_CT_NAME_LIMITATION in result.output["limitations"]
    assert bool(result.output["evidence"]) is mixed
    assert (VALID in json.dumps(result.output)) is mixed
    assert MALFORMED not in json.dumps(result.output)


@pytest.mark.parametrize("source,expected_calls", [("crtsh", 2), ("certspotter", 1)])
def test_empty_ct_collection_keeps_no_result_without_retries(monkeypatch, source, expected_calls):
    calls = []
    monkeypatch.setenv("ASSET_RECON_PROVIDERS", source)
    monkeypatch.setattr(worker, "fetch", lambda *a, **kw: ([], HASH))

    def collect(request, timeout):
        calls.append(request)
        return worker.collect(request["source"], request["kind"], request["value"], request.get("variant"))

    monkeypatch.setattr(arm, "run_worker", collect)
    result = invoke("ct", {"live": True, "providers": [source], "seeds": {"domains": ["public.com"]},
                           "limits": {"retries": 1, "min_interval_ms": 50}})
    assert len(calls) == expected_calls
    assert result.output["evidence"]
    assert any(e["observation"]["relation"] == "no_result" for e in result.output["evidence"])
    assert "provider request or parsing incomplete" not in result.output["limitations"]
