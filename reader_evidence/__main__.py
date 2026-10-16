"""Offline CLI for trusted-side acquisition, observation binding, and slices.

Every timestamp is an explicit flag; this CLI never reads a clock, never
touches a network, and never spawns a process. JSON out. Exit codes: 0
success, 1 typed refusal, 2 usage error.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import date, datetime
import json
import os
from pathlib import Path
import re
import sys

from reader_evidence.acquisition import (
    AcquisitionError,
    AcquisitionRecord,
    acquire,
    acquire_directory,
    verify_unchanged,
)
from reader_evidence.custody import (
    CUSTODY_JOURNAL_SCHEMA,
    CustodyError,
    MAX_VERIFIED_BYTES,
    WRITABLE_CUSTODY_STATES,
    append_observation,
    verify_journal,
)
from reader_evidence.data_slices import (
    DataSliceError,
    check_freshness,
    detections_demo_slice,
    verify_slice_bytes,
    vulnify_demo_slice,
)
from reader_evidence.observations import bind_reader_observation

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_RECORD_FIELDS = {"logical_path", "resolved_path", "size_bytes", "sha256", "suffix",
                  "acquired_at"}


def _emit(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True, indent=2))


def _refusal(exc: Exception) -> int:
    reason = getattr(exc, "reason", "error")
    _emit({"ok": False, "reason": reason, "error": str(exc)})
    return 1


def _naive_at(value: str, parser: argparse.ArgumentParser) -> datetime:
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        parser.error(f"--at is not an iso datetime: {value}")
    if moment.tzinfo is not None:
        parser.error("--at must be naive; this CLI never reads a clock")
    return moment


def _record(raw: object, parser: argparse.ArgumentParser) -> AcquisitionRecord:
    if not isinstance(raw, dict) or set(raw) != _RECORD_FIELDS:
        parser.error("record JSON requires exactly the AcquisitionRecord fields")
    if not isinstance(raw["size_bytes"], int) or isinstance(raw["size_bytes"], bool):
        parser.error("record size_bytes must be an integer")
    if not isinstance(raw["sha256"], str) or not _DIGEST.fullmatch(raw["sha256"]):
        parser.error("record sha256 must be sha256:<64 lowercase hex>")
    try:
        acquired_at = datetime.fromisoformat(str(raw["acquired_at"]))
    except ValueError:
        parser.error("record acquired_at is not an iso datetime")
    if acquired_at.tzinfo is not None:
        parser.error("record acquired_at must be naive")
    return AcquisitionRecord(
        logical_path=str(raw["logical_path"]), resolved_path=str(raw["resolved_path"]),
        size_bytes=raw["size_bytes"], sha256=raw["sha256"], suffix=str(raw["suffix"]),
        acquired_at=acquired_at)


def _read_record_argument(value: str, parser: argparse.ArgumentParser) -> AcquisitionRecord:
    try:
        return _record(json.loads(value), parser)
    except json.JSONDecodeError:
        parser.error("--record-json is not valid JSON")


def _key_hex(value: str | None, parser: argparse.ArgumentParser) -> bytes | None:
    if value is None:
        return None
    text = value.strip().lower()
    if not _HEX64.fullmatch(text):
        parser.error("--key-hex must be 64 hex characters")
    return bytes.fromhex(text)


def _load_journal(path: Path) -> list[dict]:
    """Read the JSON-lines custody journal; a missing file starts an empty chain."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise CustodyError("unreadable", f"journal unreadable: {exc}") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise CustodyError("corrupt", f"journal is not utf-8: {exc}") from exc
    if text and not text.endswith("\n"):
        raise CustodyError("corrupt", "journal does not end with a newline")
    records: list[dict] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise CustodyError("corrupt", f"journal line {number} is blank")
        try:
            record = json.loads(line, parse_constant=_no_constant)
        except ValueError as exc:
            raise CustodyError("corrupt", f"journal line {number} is not JSON: {exc}") from exc
        if not isinstance(record, dict):
            raise CustodyError("corrupt", f"journal line {number} is not an object")
        records.append(record)
    return records


def _no_constant(value: str) -> None:
    raise ValueError(f"non-JSON constant {value}")


def _append_journal_line(path: Path, record: dict) -> None:
    """Append one canonical line; refuse to extend a partial trailing line."""
    if path.exists() and path.stat().st_size > 0:
        with path.open("rb") as stream:
            stream.seek(-1, os.SEEK_END)
            if stream.read(1) != b"\n":
                raise CustodyError("corrupt", "refusing to append after a partial line")
    line = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False,
                      ensure_ascii=False) + "\n"
    with path.open("ab") as stream:
        stream.write(line.encode("utf-8"))


def _read_verified_bytes(path: Path) -> bytes:
    """Read retained artifact bytes for a verified-custody append (bounded)."""
    try:
        if path.stat().st_size > MAX_VERIFIED_BYTES:
            raise CustodyError("oversized",
                               f"artifact exceeds the {MAX_VERIFIED_BYTES}-byte cap: {path}")
        return path.read_bytes()
    except OSError as exc:
        raise CustodyError("unreadable", f"artifact unreadable: {path} ({exc})") from exc


def _artifact_argument(value: str) -> tuple[str, Path]:
    observation_id, separator, path = value.partition("=")
    if not separator or not _DIGEST.fullmatch(observation_id) or not path.strip():
        raise CustodyError(
            "malformed", "--artifact expects <observation_id sha256 hex>=<path>")
    return observation_id, Path(path.strip())


def _document(payload: object) -> dict:
    document = asdict(payload)
    document["acquired_at"] = payload.acquired_at.isoformat()
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    acquire_cmd = commands.add_parser("acquire", help="acquire one bounded regular file")
    acquire_cmd.add_argument("--path", type=Path, required=True)
    acquire_cmd.add_argument("--root", type=Path, required=True)
    acquire_cmd.add_argument("--suffixes", default="json,yaml,yml,jsonl,md",
                             help="comma-separated approved suffixes")
    acquire_cmd.add_argument("--max-bytes", type=int, default=1_048_576)
    acquire_cmd.add_argument("--at", required=True, help="naive iso acquisition time")
    verify_cmd = commands.add_parser("verify", help="re-check a recorded acquisition")
    verify_cmd.add_argument("--record-json", required=True, help="AcquisitionRecord JSON")
    verify_cmd.add_argument("--path", type=Path, required=True, help="current locator")
    verify_cmd.add_argument("--root", type=Path, required=True)
    manifest_cmd = commands.add_parser("manifest", help="inventory a directory deterministically")
    manifest_cmd.add_argument("--path", type=Path, required=True)
    manifest_cmd.add_argument("--root", type=Path, required=True)
    manifest_cmd.add_argument("--max-entries", type=int, default=4_096)
    manifest_cmd.add_argument("--max-total-bytes", type=int, default=8_388_608)
    manifest_cmd.add_argument("--max-depth", type=int, default=16)
    manifest_cmd.add_argument("--at", required=True, help="naive iso acquisition time")
    bind_cmd = commands.add_parser("bind", help="mint a reader-observation.v1 document")
    bind_cmd.add_argument("--record-json", required=True, help="AcquisitionRecord JSON")
    bind_cmd.add_argument("--attempt-id", required=True)
    bind_cmd.add_argument("--arm", required=True)
    bind_cmd.add_argument("--action", required=True)
    bind_cmd.add_argument("--handler-rev", required=True)
    bind_cmd.add_argument("--result-digest", required=True, help="sha256:<64 hex>")
    bind_cmd.add_argument("--at", required=True, help="naive iso collection time")
    slice_cmd = commands.add_parser("verify-slice", help="digest-check and freshness-check a demo slice")
    slice_cmd.add_argument("--which", choices=("vulnify", "detections"), required=True)
    slice_cmd.add_argument("--path", type=Path, required=True)
    slice_cmd.add_argument("--as-of", required=True, help="naive iso date of consultation")
    custody_cmd = commands.add_parser(
        "custody", help="append/verify the durable custody journal (JSON-lines)")
    custody_sub = custody_cmd.add_subparsers(dest="custody_command", required=True)
    custody_append = custody_sub.add_parser(
        "append", help="append one custody record after full-journal verify")
    custody_append.add_argument("--journal", type=Path, required=True)
    custody_append.add_argument("--observation-json", required=True,
                                help="reader-observation.v1 document")
    custody_append.add_argument("--record-json", required=True,
                                help="AcquisitionRecord JSON the observation binds")
    custody_append.add_argument("--custody-state", required=True,
                                choices=sorted(WRITABLE_CUSTODY_STATES))
    custody_append.add_argument("--at", required=True, help="naive iso recording time")
    custody_append.add_argument("--key-hex", default=None, help="optional 64-hex HMAC key")
    custody_append.add_argument(
        "--verified-bytes", type=Path, default=None,
        help="retained artifact file; required for --custody-state verified-custody")
    custody_verify = custody_sub.add_parser("verify", help="verify the whole journal")
    custody_verify.add_argument("--journal", type=Path, required=True)
    custody_verify.add_argument("--key-hex", default=None)
    custody_verify.add_argument(
        "--retained-head", default=None,
        help="out-of-band head digest; enables truncation detection")
    custody_verify.add_argument(
        "--artifact", action="append", default=[],
        help="observation_id=PATH pairs of retained artifacts "
             "re-verified against verified-custody records")

    ns = parser.parse_args(argv)
    try:
        if ns.command == "acquire":
            record = acquire(ns.path, approved_root=ns.root,
                             allowed_suffixes=frozenset(ns.suffixes.split(",")),
                             max_bytes=ns.max_bytes, acquired_at=_naive_at(ns.at, parser))
            _emit({"ok": True, "record": _document(record)})
        elif ns.command == "verify":
            record = _read_record_argument(ns.record_json, parser)
            if Path(ns.path).resolve() != Path(record.resolved_path):
                raise AcquisitionError(
                    "root-escape",
                    f"recorded locator {record.resolved_path} is not the current path {ns.path}")
            verify_unchanged(record, approved_root=ns.root)
            _emit({"ok": True, "record": _document(record)})
        elif ns.command == "manifest":
            manifest = acquire_directory(
                ns.path, approved_root=ns.root, max_entries=ns.max_entries,
                max_total_bytes=ns.max_total_bytes, max_depth=ns.max_depth,
                acquired_at=_naive_at(ns.at, parser))
            _emit({"ok": True, "manifest": _document(manifest)})
        elif ns.command == "bind":
            record = _read_record_argument(ns.record_json, parser)
            observation = bind_reader_observation(
                record, attempt_id=ns.attempt_id, arm_id=ns.arm, action=ns.action,
                handler_revision=ns.handler_rev, execution_result_digest=ns.result_digest,
                collected_at=_naive_at(ns.at, parser))
            _emit({"ok": True, "observation": observation})
        elif ns.command == "verify-slice":
            demo = (vulnify_demo_slice() if ns.which == "vulnify" else detections_demo_slice())
            data = ns.path.read_bytes()
            verify_slice_bytes(demo, data)
            check_freshness(demo, as_of=date.fromisoformat(ns.as_of))
            _emit({"ok": True, "slice_id": demo.slice_id, "pinned_path": demo.pinned_path,
                   "review_due": demo.review_due})
        elif ns.command == "custody":
            return _custody_command(ns, parser)
    except (AcquisitionError, CustodyError, DataSliceError, OSError, ValueError) as exc:
        return _refusal(exc)
    return 0


def _custody_command(ns: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """The custody journal subcommand: append after verify, or verify.

    Fail closed: an existing journal that fails verification aborts the
    append before any byte is written. The journal file itself is the only
    state; seen observation ids are never stored anywhere else.
    """
    key = _key_hex(ns.key_hex, parser)
    records = _load_journal(ns.journal)
    if ns.custody_command == "append":
        check = verify_journal(records, hmac_key=key)
        if not check.ok:
            _emit({"ok": False, "stage": "verify-existing",
                   "reasons": list(check.reasons)})
            return 1
        try:
            observation = json.loads(ns.observation_json)
        except json.JSONDecodeError as exc:
            raise CustodyError("malformed",
                               f"--observation-json is not valid JSON: {exc}") from exc
        if not isinstance(observation, dict):
            raise CustodyError("malformed", "--observation-json must be a JSON object")
        acquisition = _read_record_argument(ns.record_json, parser)
        verified_bytes = None
        if ns.custody_state == "verified-custody":
            if ns.verified_bytes is None:
                parser.error(
                    "--verified-bytes is required for --custody-state verified-custody")
            verified_bytes = _read_verified_bytes(ns.verified_bytes)
        records, head = append_observation(
            records, observation, acquisition,
            custody_state=ns.custody_state, recorded_at=_naive_at(ns.at, parser),
            hmac_key=key, verified_bytes=verified_bytes)
        _append_journal_line(ns.journal, records[-1])
        _emit({"ok": True, "journal": CUSTODY_JOURNAL_SCHEMA,
               "seq": records[-1]["seq"], "head_digest": head})
        return 0
    artifacts = dict(_artifact_argument(value) for value in ns.artifact)
    retained = {
        observation_id: _read_verified_bytes(path)
        for observation_id, path in artifacts.items()
    }
    check = verify_journal(records, hmac_key=key, retained_head=ns.retained_head,
                           artifacts=retained)
    _emit({"ok": check.ok, "reasons": list(check.reasons), "total": len(records),
           "head_digest": records[-1]["record_digest"] if records else None})
    return 0 if check.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
