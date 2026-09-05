"""Challenge grading: found-vs-expected with owned-evidence doctrine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from score.__main__ import main as score_main
from score.grading import GradingError, grade, load_findings_document, verdict

ROOT = Path(__file__).resolve().parents[1]


def _finding(key: str, severity: str = "high") -> dict[str, str]:
    return {
        "finding_key": key,
        "control": "least-privilege",
        "severity": severity,
        "rationale": "planted violation",
        "traces_to": "extension/range/tf_iam_open/input/main.tf",
    }


def _contract(*keys: str) -> dict[str, object]:
    return {
        "track": "telecom-aws-99-test",
        "total": len(keys),
        "findings": [_finding(key) for key in keys],
    }


def _found(*keys: str, severity: str = "high") -> dict[str, object]:
    return {
        "track": "telecom-aws-99-test",
        "total": len(keys),
        "findings": [_finding(key, severity=severity) for key in keys],
    }


# --- loader strictness ---------------------------------------------------


def test_loader_rejects_unknown_and_malformed(tmp_path: Path) -> None:
    bad = tmp_path / "doc.json"
    bad.write_text("{nope", encoding="utf-8")
    with pytest.raises(GradingError, match="not valid JSON"):
        load_findings_document(bad, what="doc")
    doc = tmp_path / "doc.json"
    doc.write_text(json.dumps({"track": "t", "total": 0, "findings": [], "extra": 1}), encoding="utf-8")
    with pytest.raises(GradingError, match="unknown keys"):
        load_findings_document(doc, what="doc")
    doc.write_text(json.dumps({"track": "t", "total": 2, "findings": [_finding("a")]}), encoding="utf-8")
    with pytest.raises(GradingError, match="does not match findings count"):
        load_findings_document(doc, what="doc")
    row = _finding("a")
    row["severity"] = "catastrophic"
    doc.write_text(json.dumps({"track": "t", "total": 1, "findings": [row]}), encoding="utf-8")
    with pytest.raises(GradingError, match="severity"):
        load_findings_document(doc, what="doc")
    row = _finding("a")
    row["finding_key"] = "  "
    doc.write_text(json.dumps({"track": "t", "total": 1, "findings": [row]}), encoding="utf-8")
    with pytest.raises(GradingError, match="non-empty string"):
        load_findings_document(doc, what="doc")
    duplicate = {"track": "t", "total": 2, "findings": [_finding("a"), _finding("a")]}
    doc.write_text(json.dumps(duplicate), encoding="utf-8")
    with pytest.raises(GradingError, match="duplicate finding_key"):
        load_findings_document(doc, what="doc")


# --- grading semantics ---------------------------------------------------


def test_exact_match_passes() -> None:
    document = grade(_found("a", "b"), _contract("a", "b"))
    assert document["passed"] is True
    assert document["score"] == 1.0
    assert document["hits"] == ["a", "b"]
    assert document["misses"] == []
    assert document["extras"] == []
    assert document["invalid"] == []
    assert verdict(document) == 0


def test_partial_coverage_never_passes() -> None:
    document = grade(_found("a"), _contract("a", "b"))
    assert document["passed"] is False
    assert document["score"] == 0.5
    assert document["misses"] == ["b"]
    assert verdict(document) == 1


def test_extras_fail_the_verdict() -> None:
    document = grade(_found("a", "b", "c"), _contract("a", "b"))
    assert document["passed"] is False
    assert document["extras"] == ["c"]
    assert document["score"] == 1.0  # score is coverage, not correctness


def test_missing_evidence_is_invalid_and_never_a_hit() -> None:
    found = _found("a")
    found["findings"][0]["traces_to"] = "  "
    document = grade(found, _contract("a"))
    assert document["passed"] is False
    assert document["hits"] == []
    assert len(document["invalid"]) == 1
    assert "unowned evidence" in document["invalid"][0]["reason"]
    assert document["misses"] == ["a"]  # the key was claimed, not shipped


def test_duplicate_keys_are_invalid() -> None:
    found = _found("a", "a")
    document = grade(found, _contract("a"))
    assert document["passed"] is False
    assert [row["reason"] for row in document["invalid"]] == ["duplicate finding_key"]
    assert document["hits"] == ["a"]


def test_severity_mismatch_is_a_soft_flag() -> None:
    found = _found("a", severity="medium")
    document = grade(found, _contract("a"))
    assert document["passed"] is True
    assert document["hits"] == ["a"]
    assert document["severity_mismatches"] == [
        {"finding_key": "a", "expected": "high", "found": "medium"}
    ]


def test_track_mismatch_and_empty_contract_fail() -> None:
    found = _found("a")
    found["track"] = "other-track"
    document = grade(found, _contract("a"))
    assert document["passed"] is False
    assert document["track_match"] is False
    empty: dict[str, object] = {"track": "telecom-aws-99-test", "total": 0, "findings": []}
    document = grade(_found(), empty)
    assert document["passed"] is False


# --- CLI mode ------------------------------------------------------------


def _write(tmp_path: Path, name: str, payload: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_cli_grade_modes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    found = _write(tmp_path, "found.json", _found("a", "b"))
    contract = _write(tmp_path, "contract.json", _contract("a", "b"))
    assert score_main(["--grade", str(found), "--expected", str(contract)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "specaudit.ctf.grade.v1"

    partial = _write(tmp_path, "partial.json", _found("a"))
    assert score_main(["--grade", str(partial), "--expected", str(contract)]) == 1

    broken = tmp_path / "broken.json"
    broken.write_text("{nope", encoding="utf-8")
    assert score_main(["--grade", str(broken), "--expected", str(contract)]) == 2


def test_cli_grade_flag_pairs_enforced(tmp_path: Path) -> None:
    contract = _write(tmp_path, "contract.json", _contract("a"))
    assert score_main(["--grade", str(contract)]) == 2
    assert score_main(["--expected", str(contract)]) == 2
    assert score_main(["--grade", str(contract), "--expected", str(contract), "envelope.json"]) == 2
    assert score_main([]) == 2


# --- shipped contracts ---------------------------------------------------


def test_shipped_challenge_contracts_are_valid() -> None:
    contracts = sorted((ROOT / "challenges").glob("*/artifacts/*expected*.json"))
    assert contracts, "challenge contracts must ship"
    for path in contracts:
        document = load_findings_document(path, what=path.name)
        assert document["total"] == len(document["findings"])
        for row in document["findings"]:
            for key in ("control", "rationale", "traces_to"):
                assert str(row[key]).strip(), (path, row["finding_key"], key)
            # Every expected finding traces into the synthetic fixture tree.
            assert "extension/range/" in row["traces_to"] or "tf_" in row["traces_to"], (
                path,
                row["finding_key"],
            )


def test_shipped_contracts_grade_as_themselves() -> None:
    """A contract graded against itself passes — the grader is sound."""
    from score.grading import grade_files

    contracts = sorted((ROOT / "challenges").glob("*/artifacts/*expected*.json"))
    assert contracts
    for path in contracts:
        document = grade_files(path, path)
        assert document["passed"] is True, path
        assert document["score"] == 1.0


def test_cli_grade_mode_rejects_rubric(tmp_path: Path) -> None:
    import yaml

    found = _write(tmp_path, "found.json", _found("a"))
    contract = _write(tmp_path, "contract.json", _contract("a"))
    rubric = tmp_path / "rubric.yaml"
    rubric.write_text(yaml.safe_dump({"name": "r"}), encoding="utf-8")
    assert (
        score_main(
            ["--grade", str(found), "--expected", str(contract), "--rubric", str(rubric)]
        )
        == 2
    )
