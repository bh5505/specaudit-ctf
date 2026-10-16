"""Offline CLI for the append-only attempt ledger.

The ledger file is JSON-lines: one canonical row object per line, in
chain order. ``record`` verifies the whole existing chain before
appending and fails closed (exit 1, no append) on any corruption; every
timestamp and detail digest is an explicit flag -- this CLI never reads
a clock, never touches a network, and never spawns a process. Exit
codes: 0 success, 1 typed refusal or verification failure, 2 usage
error.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import sys

from attempt_ledger.ledger import (
    ASSISTANCE, ATTEMPT_CLASSES, LANES, LedgerError, append_row, summarize,
    verify_ledger,
)

_HEX_KEY = re.compile(r"[0-9a-f]{64}\Z")


def _emit(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True, indent=2, allow_nan=False))


def _key_hex(value: str | None, parser: argparse.ArgumentParser) -> bytes | None:
    if value is None:
        return None
    text = value.strip().lower()
    if not _HEX_KEY.fullmatch(text):
        parser.error("--key-hex must be 64 hex characters")
    return bytes.fromhex(text)


def _naive_at(value: str, parser: argparse.ArgumentParser) -> datetime:
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        parser.error(f"--at is not an iso datetime: {value}")
    if moment.tzinfo is not None:
        parser.error("--at must be naive; this CLI never reads a clock")
    return moment


def _load_rows(path: Path) -> list[dict]:
    """Read the JSON-lines ledger; a missing file starts an empty chain."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise LedgerError("unreadable", f"ledger unreadable: {exc}") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise LedgerError("corrupt", f"ledger is not utf-8: {exc}") from exc
    if text and not text.endswith("\n"):
        raise LedgerError("corrupt", "ledger does not end with a newline")
    rows: list[dict] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise LedgerError("corrupt", f"ledger line {number} is blank")
        try:
            row = json.loads(line, parse_constant=_no_constant)
        except ValueError as exc:
            raise LedgerError("corrupt", f"ledger line {number} is not JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise LedgerError("corrupt", f"ledger line {number} is not an object")
        rows.append(row)
    return rows


def _no_constant(value: str) -> None:
    raise ValueError(f"non-JSON constant {value}")


def _append_line(path: Path, row: dict) -> None:
    """Append one canonical line; refuse to extend a partial trailing line."""
    if path.exists() and path.stat().st_size > 0:
        with path.open("rb") as stream:
            stream.seek(-1, os.SEEK_END)
            if stream.read(1) != b"\n":
                raise LedgerError("corrupt", "refusing to append after a partial line")
    line = json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False,
                      ensure_ascii=False) + "\n"
    with path.open("ab") as stream:
        stream.write(line.encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record", help="append one attempt row after full-chain verify")
    record.add_argument("--ledger", type=Path, required=True)
    record.add_argument("--attempt-id", required=True)
    record.add_argument("--lane", required=True, choices=sorted(LANES))
    record.add_argument("--subject", required=True)
    record.add_argument("--class", dest="attempt_class", required=True,
                        choices=sorted(ATTEMPT_CLASSES))
    record.add_argument("--outcome", default=None)
    record.add_argument("--assistance", required=True, choices=sorted(ASSISTANCE))
    record.add_argument("--detail-digest", required=True, help="sha256:<64 hex> of the "
                        "structured detail document held outside the ledger")
    record.add_argument("--at", required=True, help="naive iso recording time")
    record.add_argument("--key-hex", default=None, help="optional 64-hex HMAC key")
    verify = commands.add_parser("verify", help="verify the whole chain")
    verify.add_argument("--ledger", type=Path, required=True)
    verify.add_argument("--key-hex", default=None)
    verify.add_argument("--retained-head", default=None,
                        help="out-of-band head digest; enables truncation detection")
    summary = commands.add_parser("summarize", help="counts over every row")
    summary.add_argument("--ledger", type=Path, required=True)

    ns = parser.parse_args(argv)
    try:
        key = _key_hex(getattr(ns, "key_hex", None), parser)
        rows = _load_rows(ns.ledger)
        if ns.command == "record":
            check = verify_ledger(rows, hmac_key=key)
            if not check.ok:
                _emit({"ok": False, "stage": "verify-existing", "reasons": list(check.reasons)})
                return 1
            rows, head = append_row(
                rows, {
                    "attempt_id": ns.attempt_id, "lane": ns.lane, "subject": ns.subject,
                    "attempt_class": ns.attempt_class, "outcome": ns.outcome,
                    "assistance": ns.assistance, "detail_digest": ns.detail_digest,
                    "recorded_at": _naive_at(ns.at, parser),
                }, hmac_key=key)
            _append_line(ns.ledger, rows[-1])
            _emit({"ok": True, "ledger_seq": rows[-1]["ledger_seq"], "head_digest": head})
        elif ns.command == "verify":
            check = verify_ledger(rows, hmac_key=key, retained_head=ns.retained_head)
            _emit({"ok": check.ok, "reasons": list(check.reasons), "total": len(rows),
                   "head_digest": rows[-1]["row_digest"] if rows else None})
            return 0 if check.ok else 1
        else:
            _emit({"ok": True, **summarize(rows)})
    except (LedgerError, OSError) as exc:
        reason = getattr(exc, "reason", "error")
        _emit({"ok": False, "reason": reason, "error": str(exc)})
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
