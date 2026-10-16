"""End-to-end tests for challenges/qualification/dry-run/validate.py.

Each test synthesizes a completed dry-run artifact set in a temp directory
(packet, verifiable attempt ledger, verifiable evidence chain, summary) and
runs the script as a subprocess exactly as an operator would. Happy path
exits 0; each sabotage exits 1 with the named reason; an invocation error
exits 2.
"""

from __future__ import annotations

from datetime import date, datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from attempt_ledger import append_row
from evidence_chain import build_chain

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATE = (REPO_ROOT / "challenges" / "qualification" / "dry-run"
            / "validate.py")
AS_OF = "2026-10-13"
AS_OF_DATE = date(2026, 10, 13)
RECORDED_AT = datetime(2026, 10, 13, 12, 0, 0)
CANARY = "INSTRUCTOR-CANARY-T03"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=False).encode("utf-8")


def build_dry_run(root: Path, *, with_negative_row: bool = True) -> None:
    """Synthesize one internally consistent completed dry-run directory."""
    packet = root / "packet" / "inputs"
    packet.mkdir(parents=True)
    brief = b"# dry-run learner brief\n"
    asset = b'{"asset_id": "asset-alpha", "cve_id": "CVE-2099-0001"}\n'
    (root / "packet" / "BRIEF.md").write_bytes(brief)
    (packet / "assets.json").write_bytes(asset)

    rows: tuple[dict, ...] = ()
    head: str | None = None
    rows, head = append_row(rows, {
        "attempt_id": "dryrun-0001-completion",
        "lane": "self-study",
        "subject": "t03-vertical-slice",
        "attempt_class": "completion",
        "outcome": "passed",
        "assistance": "none",
        "detail_digest": _digest(asset),
        "recorded_at": RECORDED_AT,
    })
    if with_negative_row:
        rows, head = append_row(rows, {
            "attempt_id": "dryrun-0002-key-acquisition",
            "lane": "self-study",
            "subject": "t03-vertical-slice",
            "attempt_class": "refusal",
            "outcome": "blocked",
            "assistance": "none",
            "detail_digest": _digest(brief),
            "recorded_at": RECORDED_AT,
        })
    lines = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        for row in rows)
    (root / "attempt-ledger.jsonl").write_text(lines, encoding="utf-8")

    chain = build_chain(
        [{"digest": _digest(asset), "locator": "packet/inputs/assets.json",
          "custody_note": "operator-staged learner packet entry"},
         {"digest": _digest(brief), "locator": "packet/BRIEF.md",
          "custody_note": "operator-staged learner packet entry"}],
        [{"digest": _digest(asset), "evidence_class": "observed"},
         {"digest": _digest(brief), "evidence_class": "declared"}],
        {"digest": _digest(b"prioritization statement"), "author_role": "analyst",
         "statement_count": 1},
        {"digest": _digest(b"adjudication body"), "reviewer": "operator",
         "original_score": "2-of-2-classes", "adjusted_score": "no-adjustment",
         "rationale": "machine consistency check only; human review unstaffed",
         "decided_on": AS_OF},
        {"digest": head, "conclusion": "dry run artifact set closed"},
    )
    (root / "evidence-chain.json").write_bytes(
        json.dumps(chain, indent=2, sort_keys=True).encode("utf-8") + b"\n")

    (root / "dry-run-summary.json").write_text(json.dumps({
        "schema": "specaudit.ctf.dry-run-summary.v1",
        "pilot": "t03-vertical-slice",
        "recorded_at": "2026-10-13T12:00:00",
        "operator": "operator role, unstaffed",
        "notes": "synthesized happy-path artifact set for validator tests",
    }, indent=2) + "\n", encoding="utf-8")


def run_validate(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATE), "--dir", str(root), "--as-of", AS_OF],
        capture_output=True, text=True, timeout=120)


def parsed(result: subprocess.CompletedProcess) -> dict:
    return json.loads(result.stdout)


def test_happy_dry_run_passes(tmp_path: Path) -> None:
    root = tmp_path / "run"
    build_dry_run(root)
    result = run_validate(root)
    assert result.returncode == 0, result.stdout + result.stderr
    report = parsed(result)
    assert report["ok"] is True and report["reasons"] == []


def test_missing_negative_row_refuses(tmp_path: Path) -> None:
    root = tmp_path / "run"
    build_dry_run(root, with_negative_row=False)
    result = run_validate(root)
    assert result.returncode == 1, result.stdout
    report = parsed(result)
    assert report["ok"] is False
    assert "ledger-missing-negative-class-row" in report["reasons"]
    # The completion row alone is not the failing check: the ledger chain
    # itself verifies.
    assert not any(reason.startswith("ledger-verify-failed")
                   for reason in report["reasons"])


def test_canary_leak_refuses(tmp_path: Path) -> None:
    root = tmp_path / "run"
    build_dry_run(root)
    leaked = root / "packet" / "inputs" / "leaked-key.md"
    leaked.write_text(f"Canary: `{CANARY}-REVIEW-01` must never ship.\n",
                      encoding="utf-8")
    result = run_validate(root)
    assert result.returncode == 1, result.stdout
    report = parsed(result)
    assert "canary-present:packet/inputs/leaked-key.md" in report["reasons"]


def test_broken_chain_refuses(tmp_path: Path) -> None:
    root = tmp_path / "run"
    build_dry_run(root)
    chain_path = root / "evidence-chain.json"
    chain = json.loads(chain_path.read_text(encoding="utf-8"))
    chain["adjudication"]["inference_digest"] = _digest(b"retargeted")
    chain_path.write_text(json.dumps(chain, indent=2, sort_keys=True),
                          encoding="utf-8")
    result = run_validate(root)
    assert result.returncode == 1, result.stdout
    report = parsed(result)
    assert ("chain-verify-failed:inference-reference-mismatch"
            in report["reasons"])


def test_missing_summary_refuses(tmp_path: Path) -> None:
    root = tmp_path / "run"
    build_dry_run(root)
    (root / "dry-run-summary.json").unlink()
    result = run_validate(root)
    assert result.returncode == 1
    assert "summary-missing" in parsed(result)["reasons"]


def test_invocation_errors_exit_two(tmp_path: Path) -> None:
    missing = run_validate(tmp_path / "does-not-exist")
    assert missing.returncode == 2
    bad_date = subprocess.run(
        [sys.executable, str(VALIDATE), "--dir", str(tmp_path),
         "--as-of", "not-a-date"], capture_output=True, text=True, timeout=60)
    assert bad_date.returncode == 2


def test_runbook_carries_the_mandated_validator_limit_line() -> None:
    runbook = (REPO_ROOT / "challenges" / "qualification" / "dry-run"
               / "runbook.md").read_text(encoding="utf-8")
    assert ("validate.py pass means the artifact set is internally "
            "consistent — it does not prove the runbook was followed, that a "
            "real learner path executed, or that no leak occurred outside "
            "the provided outputs.") in runbook


def test_runbook_requires_completion_and_negative_classes() -> None:
    runbook = (REPO_ROOT / "challenges" / "qualification" / "dry-run"
               / "runbook.md").read_text(encoding="utf-8")
    assert "at least one `completion` row and at least one negative" in runbook
    assert "Close, reset and retain" in runbook
