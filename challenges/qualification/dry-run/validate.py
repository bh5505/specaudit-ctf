#!/usr/bin/env python3
"""Machine-check one completed qualification dry-run artifact set.

Sys.path-bootstrapped checkout tool (precedent: tools/seif_ivanti_roundtrip.py):
run from anywhere as

    python challenges/qualification/dry-run/validate.py --dir DIR --as-of YYYY-MM-DD

Exit codes: 0 = every check passed; 1 = at least one named check failed
(JSON reasons on stdout); 2 = invocation error (bad --dir, bad --as-of,
--hmac-key-hex not 64 hex).

Checks, in order:
  1. learner packet present: packet/BRIEF.md and a nonempty packet/inputs/
     directory; no path component named "instructor" under packet/ (belt;
     the load-bearing separation check is the canary byte scan).
  2. attempt-ledger.jsonl verifies via attempt_ledger.verify_ledger and
     contains at least one completion row AND at least one negative-class
     row (the runbook requires the denominator to include failures or
     refusals, not completions only).
  3. evidence-chain.json verifies via evidence_chain.verify_chain against
     the caller-supplied --as-of date (this script never reads a clock).
  4. no INSTRUCTOR-CANARY bytes anywhere under --dir.
  5. dry-run-summary.json exists, parses, and carries the runbook's closed
     summary fields.

Honest limit (also stated in runbook.md): a pass means the artifact set is
internally consistent -- it does not prove the runbook was followed, that a
real learner path executed, or that no leak occurred outside the provided
outputs.
"""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from attempt_ledger import COMPLETION, ATTEMPT_CLASSES, verify_ledger  # noqa: E402
from evidence_chain import verify_chain  # noqa: E402

LEDGER_NAME = "attempt-ledger.jsonl"
CHAIN_NAME = "evidence-chain.json"
SUMMARY_NAME = "dry-run-summary.json"
SUMMARY_SCHEMA = "specaudit.ctf.dry-run-summary.v1"
SUMMARY_FIELDS = ("schema", "pilot", "recorded_at", "operator", "notes")
CANARY_MARK = b"INSTRUCTOR-CANARY"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_HEX_KEY = re.compile(r"[0-9a-f]{64}\Z")


def _iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            yield path


def validate(root: Path, *, as_of: date, hmac_key: bytes | None) -> list[str]:
    """Run every check; return the list of named reasons (empty = pass)."""
    reasons: list[str] = []

    def bad(reason: str) -> None:
        reasons.append(reason)

    # 1. Learner packet -----------------------------------------------------
    brief = root / "packet" / "BRIEF.md"
    if not brief.is_file():
        bad("missing-packet-brief")
    inputs = root / "packet" / "inputs"
    if not inputs.is_dir() or not any(inputs.iterdir()):
        bad("missing-packet-inputs")
    for path in _iter_files(root / "packet") if (root / "packet").is_dir() else []:
        if "instructor" in path.relative_to(root).parts:
            bad(f"packet-instructor-directory:{path.relative_to(root).as_posix()}")

    # 2. Attempt ledger -----------------------------------------------------
    ledger_path = root / LEDGER_NAME
    rows: list = []
    if not ledger_path.is_file():
        bad("ledger-missing")
    else:
        try:
            text = ledger_path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            bad(f"ledger-unreadable:{exc}")
        else:
            parse_error = None
            for number, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    parse_error = f"ledger-blank-line:{number}"
                    break
                try:
                    row = json.loads(line)
                except ValueError as exc:
                    parse_error = f"ledger-line-not-json:{number}"
                    break
                if not isinstance(row, dict):
                    parse_error = f"ledger-line-not-object:{number}"
                    break
                rows.append(row)
            if parse_error is not None:
                bad(parse_error)
            else:
                check = verify_ledger(rows, hmac_key=hmac_key)
                if not check.ok:
                    bad("ledger-verify-failed:" + ",".join(check.reasons))
                classes = {row.get("attempt_class") for row in rows}
                if COMPLETION not in classes:
                    bad("ledger-missing-completion-row")
                if not (classes & (ATTEMPT_CLASSES - {COMPLETION})):
                    bad("ledger-missing-negative-class-row")

    # 3. Evidence chain -----------------------------------------------------
    chain_path = root / CHAIN_NAME
    if not chain_path.is_file():
        bad("chain-missing")
    else:
        raw = chain_path.read_bytes()
        if len(raw) > MAX_ARTIFACT_BYTES:
            bad("chain-oversized")
        else:
            try:
                chain = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                bad(f"chain-unreadable:{exc}")
            else:
                result = verify_chain(chain, as_of=as_of)
                if not result.ok:
                    bad("chain-verify-failed:" + ",".join(result.reasons))

    # 4. Canary byte scan over the whole artifact set -----------------------
    for path in _iter_files(root):
        try:
            if path.stat().st_size > MAX_ARTIFACT_BYTES:
                bad(f"artifact-oversized:{path.relative_to(root).as_posix()}")
                continue
            if CANARY_MARK in path.read_bytes():
                bad(f"canary-present:{path.relative_to(root).as_posix()}")
        except OSError as exc:
            bad(f"artifact-unreadable:{path.relative_to(root).as_posix()}:{exc}")

    # 5. Dry-run summary ----------------------------------------------------
    summary_path = root / SUMMARY_NAME
    if not summary_path.is_file():
        bad("summary-missing")
    else:
        try:
            summary = json.loads(summary_path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            bad(f"summary-unreadable:{exc}")
        else:
            if not isinstance(summary, dict):
                bad("summary-not-object")
            else:
                for field in SUMMARY_FIELDS:
                    value = summary.get(field)
                    if (field == "schema" and value != SUMMARY_SCHEMA):
                        bad("summary-bad-schema")
                    elif field != "schema" and (
                            not isinstance(value, str) or not value.strip()):
                        bad(f"summary-missing-field:{field}")
    return reasons


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate one completed qualification dry-run artifact set.")
    parser.add_argument("--dir", type=Path, required=True,
                        help="completed dry-run directory")
    parser.add_argument("--as-of", required=True, metavar="YYYY-MM-DD",
                        help="verification date; the chain's decided_on may not "
                             "lie in the future relative to it")
    parser.add_argument("--hmac-key-hex", default=None,
                        help="64-hex HMAC key when the ledger was written keyed")
    args = parser.parse_args(argv)
    root = args.dir
    if not root.is_dir():
        print(f"validate.py: --dir is not a directory: {root}", file=sys.stderr)
        return 2
    try:
        as_of = date.fromisoformat(args.as_of)
    except ValueError:
        print(f"validate.py: --as-of is not an ISO date: {args.as_of}",
              file=sys.stderr)
        return 2
    hmac_key = None
    if args.hmac_key_hex is not None:
        key_text = args.hmac_key_hex.strip().lower()
        if not _HEX_KEY.fullmatch(key_text):
            print("validate.py: --hmac-key-hex must be 64 hex characters",
                  file=sys.stderr)
            return 2
        hmac_key = bytes.fromhex(key_text)
    reasons = validate(root, as_of=as_of, hmac_key=hmac_key)
    print(json.dumps({
        "ok": not reasons,
        "dir": str(root),
        "as_of": as_of.isoformat(),
        "reasons": reasons,
        "note": "internal consistency only; see runbook.md for the honest limit",
    }, indent=2))
    return 0 if not reasons else 1


if __name__ == "__main__":
    raise SystemExit(main())
