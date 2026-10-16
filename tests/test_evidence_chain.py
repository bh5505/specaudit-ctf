"""Evidence-chain construction, cross-layer rules and schema closedness."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import jsonschema
import pytest

from evidence_chain import (
    GRADING_LIMITATION, ChainError, build_chain, verify_chain,
)

AS_OF = date(2026, 10, 13)
RAW = [{"digest": "sha256:" + "a" * 64, "locator": "packet/evidence/main.tf",
        "custody_note": "operator-exported packet entry"}]
OBSERVATIONS = [{"digest": "sha256:" + "a" * 64, "evidence_class": "declared"}]
INFERENCE = {"digest": "sha256:" + "b" * 64, "author_role": "analyst",
             "statement_count": 2}
ADJUDICATION = {"digest": "sha256:" + "c" * 64, "reviewer": "operator",
                "original_score": "70", "adjusted_score": "65",
                "rationale": "fixture coverage is exact but evidence-truth is unverified",
                "decided_on": "2026-10-12"}
WORKPAPER = {"digest": "sha256:" + "d" * 64,
             "conclusion": "passed with inherited fixture-coverage limits"}


def _build(*, raw=None, observations=None, adjudication=None, **kwargs) -> dict:
    return build_chain(raw if raw is not None else RAW,
                       observations if observations is not None else OBSERVATIONS,
                       INFERENCE,
                       adjudication if adjudication is not None else ADJUDICATION,
                       WORKPAPER, **kwargs)


def test_build_happy_path_and_round_trip() -> None:
    chain = _build(machine_verdict={"source": "score.grading",
                                    "digest": "sha256:" + "e" * 64})
    assert set(chain) == {
        "schema", "schema_version", "raw", "observations", "inference",
        "adjudication", "workpaper", "machine_verdict", "human_verdict",
        "inherited_limitations"}
    assert chain["adjudication"]["inference_digest"] == INFERENCE["digest"]
    assert verify_chain(chain, as_of=AS_OF).ok
    assert verify_chain(json.loads(json.dumps(chain)), as_of=AS_OF).ok


def test_evidence_class_carried_through_unchanged() -> None:
    mixed = [
        {"digest": "sha256:" + "a" * 64, "evidence_class": "declared"},
        {"observation_id": "obs-1", "digest": "sha256:" + "a" * 64,
         "evidence_class": "observed"},
        {"digest": "sha256:" + "a" * 64, "evidence_class": "inferred"},
    ]
    chain = build_chain(RAW, mixed, INFERENCE, ADJUDICATION, WORKPAPER)
    assert [row["evidence_class"] for row in chain["observations"]] == [
        "declared", "observed", "inferred"]
    # An explicit attempt to upgrade a declared observation is refused outright.
    with pytest.raises(ChainError):
        _build(observations=[{**OBSERVATIONS[0], "evidence_class": "upgraded"}])


def test_missing_inference_reference_refused() -> None:
    chain = _build()
    broken = json.loads(json.dumps(chain))
    del broken["adjudication"]["inference_digest"]
    result = verify_chain(broken, as_of=AS_OF)
    assert not result.ok and "malformed" in result.reasons
    retargeted = json.loads(json.dumps(chain))
    retargeted["adjudication"]["inference_digest"] = "sha256:" + "9" * 64
    result = verify_chain(retargeted, as_of=AS_OF)
    assert not result.ok and "inference-reference-mismatch" in result.reasons


def test_original_score_always_retained() -> None:
    adjusted_null = _build(adjudication={**ADJUDICATION, "adjusted_score": None})
    assert adjusted_null["adjudication"]["original_score"] == "70"
    assert adjusted_null["adjudication"]["adjusted_score"] is None
    assert verify_chain(adjusted_null, as_of=AS_OF).ok
    with pytest.raises(ChainError):
        _build(adjudication={**ADJUDICATION, "original_score": None,
                             "adjusted_score": None})
    with pytest.raises(ChainError):
        _build(adjudication={**ADJUDICATION, "original_score": None})


def test_future_decided_on_refused() -> None:
    chain = _build()
    assert verify_chain(chain, as_of=AS_OF).ok
    future = json.loads(json.dumps(chain))
    future["adjudication"]["decided_on"] = "2026-10-14"
    result = verify_chain(future, as_of=AS_OF)
    assert not result.ok and result.reasons == ("future-decision",)


def test_verdicts_remain_siblings() -> None:
    machine = {"source": "score.grading", "digest": "sha256:" + "e" * 64}
    human = {"source": "rubric", "digest": "sha256:" + "f" * 64}
    chain = _build(machine_verdict=machine, human_verdict=human)
    assert chain["machine_verdict"] == machine and chain["human_verdict"] == human
    assert not any("final" in key or "override" in key for key in chain)
    assert verify_chain(chain, as_of=AS_OF).ok
    assert verify_chain(_build(), as_of=AS_OF).ok  # both-null siblings stay siblings
    overridden = json.loads(json.dumps(chain))
    overridden["final_verdict"] = {"source": "operator", "digest": "sha256:" + "1" * 64}
    result = verify_chain(overridden, as_of=AS_OF)
    assert not result.ok and "override-verdict-present" in result.reasons
    with pytest.raises(ChainError):
        _build(human_verdict={"source": "gut-feeling", "digest": "sha256:" + "f" * 64})


def test_schema_closedness_refuses_unknown_keys() -> None:
    chain = _build()
    mutations = [
        {"unheard_layer": {"digest": "sha256:" + "1" * 64}},
        {"workpaper": {**WORKPAPER, "extra": "field"}},
        {"observations": [{**OBSERVATIONS[0], "upgraded": True}]},
    ]
    for mutation in mutations:
        mutated = json.loads(json.dumps(chain))
        mutated.update(mutation)
        result = verify_chain(mutated, as_of=AS_OF)
        assert not result.ok and "malformed" in result.reasons


def test_inherited_limitation_propagation() -> None:
    graded = _build(machine_verdict={"source": "score.grading",
                                     "digest": "sha256:" + "e" * 64})
    assert graded["inherited_limitations"] == [GRADING_LIMITATION]
    assert verify_chain(graded, as_of=AS_OF).ok
    stripped = json.loads(json.dumps(graded))
    stripped["inherited_limitations"] = []
    result = verify_chain(stripped, as_of=AS_OF)
    assert not result.ok and "missing-inherited-limitation" in result.reasons
    # A machine verdict that is not from grading inherits nothing.
    other = _build(machine_verdict={"source": "human-transcript",
                                    "digest": "sha256:" + "e" * 64})
    assert other["inherited_limitations"] == []
    assert verify_chain(other, as_of=AS_OF).ok


def test_unanchored_observation_refused() -> None:
    floating = _build(observations=[{"digest": "sha256:" + "9" * 64,
                                     "evidence_class": "observed"}])
    result = verify_chain(floating, as_of=AS_OF)
    assert not result.ok and "unanchored-observation" in result.reasons


def test_shipped_schema_matches_the_contract(tmp_path: Path) -> None:
    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "evidence_chain" / "schema"
         / "evidence-chain.v1.schema.json").read_text())
    jsonschema.validate(_build(machine_verdict={
        "source": "score.grading", "digest": "sha256:" + "e" * 64}), schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"final_verdict": {"source": "x"}}, schema)
