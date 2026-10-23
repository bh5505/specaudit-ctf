"""Challenge-local integrity for lab-contract-01-solidity-review.

Hermetic file checks: the expected-findings contract loads through the
grader's own loader, the shipped planted/instructor sources carry
exactly the constructs the contract traces to (an unguarded treasury
setter against an admin-guarded near miss), the grade matrix fails the
near miss and the evidence-less row, and the Foundry project pins the
witness toolchain without any dependency. No forge, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

from score.grading import grade, load_findings_document

ROOT = Path(__file__).resolve().parents[1]
CHALLENGE = ROOT / "challenges" / "lab-contract-01-solidity-review"
PLANTED_PATH = "challenges/lab-contract-01-solidity-review/planted/Treasury.sol"
TRACK = "lab-contract-01-solidity-review"
KEY = "treasury-setter-unauthorized"
NEAR_MISS_KEY = "contract-fee-collector-unauthorized"
ADMIN_GUARD = 'require(msg.sender == admin, "admin only")'


def _expected() -> dict:
    return load_findings_document(
        CHALLENGE / "artifacts" / "expected-findings.json", what="expected contract"
    )


def _planted() -> str:
    return (ROOT / PLANTED_PATH).read_text(encoding="utf-8")


def _function_body(source: str, name: str) -> str:
    """Brace-balanced body of `name`'s definition (fails loudly if absent)."""
    marker = f"function {name}("
    open_brace = source.index("{", source.index(marker))
    depth = 0
    for index in range(open_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace : index + 1]
    raise AssertionError(f"unbalanced braces around {name}")


def _found_submission(*rows: dict, track: str = TRACK) -> dict:
    return {"track": track, "total": len(rows), "findings": list(rows)}


def _owned_row() -> dict:
    """The expected row itself: exact key and fully owned evidence."""
    return dict(_expected()["findings"][0])


# --- the shipped contract ------------------------------------------------


def test_expected_contract_loads_through_the_grader() -> None:
    document = _expected()
    assert document["track"] == TRACK
    assert document["lane"] == "planted-code"
    assert document["fixtures"] == [PLANTED_PATH]
    assert document["total"] == 1
    row = document["findings"][0]
    assert row["finding_key"] == KEY
    assert row["severity"] == "high"
    assert row["control"].startswith("access control:")


def test_planted_setter_is_unguarded_and_payout_pays_treasury() -> None:
    set_treasury = _function_body(_planted(), "setTreasury")
    # The planted defect: the payout-destination setter carries no
    # administrator check at all.
    assert "require(" not in set_treasury
    assert "msg.sender" not in set_treasury
    assert "treasury = newTreasury" in set_treasury
    # The consequence construct: payout() pays whatever treasury names.
    payout = _function_body(_planted(), "payout")
    assert "treasury.call{value: amount}" in payout


def test_fixed_variant_guards_the_same_setter() -> None:
    source = (CHALLENGE / "instructor" / "TreasuryFixed.sol").read_text(
        encoding="utf-8"
    )
    assert ADMIN_GUARD in _function_body(source, "setTreasury")


def test_near_miss_setter_is_guarded_in_the_planted_file() -> None:
    # The deliberate false-positive trap: shaped like the defect, but
    # owned by the administrator check.
    assert ADMIN_GUARD in _function_body(_planted(), "setFeeCollector")


def test_trace_names_the_planted_file_and_both_constructs() -> None:
    traces_to = _expected()["findings"][0]["traces_to"]
    assert PLANTED_PATH in traces_to
    assert "setTreasury(address)" in traces_to
    assert "payout()" in traces_to


# --- the grade matrix ----------------------------------------------------


def test_complete_submission_with_owned_evidence_passes() -> None:
    document = grade(_found_submission(_owned_row()), _expected())
    assert document["passed"] is True
    assert document["hits"] == [KEY]
    assert document["misses"] == []
    assert document["extras"] == []
    assert document["invalid"] == []


def test_omitting_the_key_is_a_miss() -> None:
    document = grade(_found_submission(), _expected())
    assert document["passed"] is False
    assert document["misses"] == [KEY]


def test_the_near_miss_key_is_an_extra_and_fails() -> None:
    near_miss = {**_owned_row(), "finding_key": NEAR_MISS_KEY}
    document = grade(_found_submission(_owned_row(), near_miss), _expected())
    assert document["passed"] is False
    assert document["extras"] == [NEAR_MISS_KEY]


def test_empty_trace_is_invalid_and_never_passes() -> None:
    unowned = {**_owned_row(), "traces_to": "  "}
    document = grade(_found_submission(unowned), _expected())
    assert document["passed"] is False
    assert document["hits"] == []
    assert [row["finding_key"] for row in document["invalid"]] == [KEY]
    assert document["misses"] == [KEY]


def test_track_mismatch_does_not_pass() -> None:
    document = grade(
        _found_submission(_owned_row(), track="some-other-track"), _expected()
    )
    assert document["passed"] is False
    assert document["track_match"] is False


# --- the shipped witness project ------------------------------------------


def test_witness_builds_offline_by_declaration() -> None:
    source = (CHALLENGE / "test" / "TreasuryProperty.t.sol").read_text(
        encoding="utf-8"
    )
    # No forge-std (or any) dependency: the only imports are the two
    # shipped variants, and the inline Vm interface at the canonical
    # cheatcode address is what keeps the build offline.
    assert [line.strip() for line in source.splitlines() if line.strip().startswith("import")] == [
        'import {Treasury} from "../planted/Treasury.sol";',
        'import {TreasuryFixed} from "../instructor/TreasuryFixed.sol";',
    ]
    assert "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D" in source
    assert "function test_PlantedVariantViolatesInvariant" in source
    assert "function test_FixedVariantUpholdsInvariant" in source


def test_foundry_project_pins_the_witness_toolchain() -> None:
    config = (CHALLENGE / "foundry.toml").read_text(encoding="utf-8")
    assert 'solc = "0.8.28"' in config
    assert 'evm_version = "cancun"' in config
    assert "[remappings]" not in config


def test_challenge_deliverables_ship() -> None:
    for relative in (
        "README.md",
        "METHODOLOGY.md",
        "foundry.toml",
        "instructor/TreasuryFixed.sol",
        "instructor/EXPLANATION.md",
        "artifacts/expected-findings.json",
        "artifacts/coverage-ledger-example.json",
        "artifacts/property-witness.md",
    ):
        assert (CHALLENGE / relative).is_file(), relative
    assert (ROOT / PLANTED_PATH).is_file()
    ledger = json.loads(
        (CHALLENGE / "artifacts" / "coverage-ledger-example.json").read_text(
            encoding="utf-8"
        )
    )
    looked = {row["function"] for row in ledger["rows"] if row["looked"]}
    assert any("setTreasury" in name for name in looked)
    assert any("setFeeCollector" in name for name in looked)
