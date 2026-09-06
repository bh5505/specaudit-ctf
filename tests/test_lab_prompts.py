"""The canonical attempt prompts stay consistent with the contracts.

The matrix's fairness depends on these files: identical text per
challenge across heads, finding keys matching the graded contract, and
hint strings that are safe to copy into a JSON string value verbatim
(the 2026-09-06 smoke cell failed on exactly this: a head copied a
traces_to hint containing embedded double quotes into found.json and
the grader rightly refused the file).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "lab" / "prompts"
CHALLENGES = {
    "telecom-aws-01-reachability": "challenge-01-reachability.txt",
    "telecom-aws-02-iam-s3-misconfig": "challenge-02-iam-s3-misconfig.txt",
    "telecom-aws-03-iam-privesc": "challenge-03-iam-privesc.txt",
    "telecom-aws-04-network-exposure": "challenge-04-network-exposure.txt",
    "telecom-aws-05-logging-gaps": "challenge-05-logging-gaps.txt",
    "telecom-aws-06-chain-rehearsal": "challenge-06-chain-rehearsal.txt",
    "lab-knowledge-01-attack-mapping": "challenge-knowledge-01-attack-mapping.txt",
}


@pytest.mark.parametrize(("track", "name"), sorted(CHALLENGES.items()))
def test_prompt_matches_its_contract(track: str, name: str) -> None:
    prompt = (PROMPTS_DIR / name).read_text(encoding="utf-8")
    contract = json.loads(
        (
            Path(__file__).resolve().parent.parent
            / "challenges" / track / "artifacts" / "expected-findings.json"
        ).read_text(encoding="utf-8")
    )
    assert f'"{track}"' in prompt
    for finding in contract["findings"]:
        assert f'"{finding["finding_key"]}"' in prompt
        assert f'"{finding["severity"]}"' in prompt


@pytest.mark.parametrize("name", sorted(CHALLENGES.values()))
def test_prompt_hint_lines_carry_balanced_quotes(name: str) -> None:
    """Every hint line must be verbatim-safe inside a JSON string: no
    line may bait a head with an odd number of unescaped quotes."""
    for line in (PROMPTS_DIR / name).read_text(encoding="utf-8").splitlines():
        if "traces_to" in line or "control" in line or "finding_key" in line:
            assert line.count('"') % 2 == 0, f"unbalanced quotes bait JSON breakage: {line}"


def test_contract_finding_keys_are_quote_free() -> None:
    """finding_key is the mechanically matched string and the one a
    head must copy exactly; embedded double quotes there would bait
    the same JSON breakage the prompt pins guard against. Prose fields
    (rationale, traces_to) are head-rephrased, so prose quotes in the
    CONTRACT are not copy bait — the prompt-level pins own that line."""
    for track in CHALLENGES:
        contract = json.loads(
            (
                Path(__file__).resolve().parent.parent
                / "challenges" / track / "artifacts" / "expected-findings.json"
            ).read_text(encoding="utf-8")
        )
        for finding in contract["findings"]:
            assert '"' not in finding["finding_key"], (
                f"{track}/{finding['finding_key']} embeds a quote"
            )
