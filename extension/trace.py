"""Server-side attempt-trace capture for the agent-head exercise lane.

The stdio MCP server is our process, so it — never the agent — is the
evidence channel: when ``SPECAUDIT_CTF_MCP_TRACE`` names a file, every
``tools/call`` request/response pair is appended there as one ndjson
record (tool, redacted bounded arguments, bounded result summary with
``isError``). Records form a keyed digest chain (HMAC-SHA256 over the
canonical record JSON, chained through the previous record's HMAC) so
the grading side can verify the trace it grades is the trace the server
wrote. The chain is a tripwire against sloppy tampering, not Byzantine
robustness: anyone who can rewrite the file AND read the key can forge
a valid chain, so the key never lives in the attempt directory and the
verdict vocabulary stays "verified attempt trace", not "tamper-proof".

Sink rules (fail closed):

- The env unset means capture is off and behavior is byte-identical to
  the untraced server.
- The env set but the sink unusable (missing parent directory, unwritable
  path, key missing or not hex) is a startup refusal: the server writes
  one stderr line and exits nonzero instead of serving unrecorded.
- Only ``tools/call`` traffic is recorded; JSON-RPC envelope noise
  (initialize, ping, parse errors) is not tool evidence.
- A clean EOF appends a ``close`` record; a crashed or killed server
  leaves the chain without one, and ``verify_trace`` treats every
  missing-close trace as a failed attempt, never a gradable one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .arms.mcp_client import redact

ENV_TRACE = "SPECAUDIT_CTF_MCP_TRACE"
ENV_KEY = "SPECAUDIT_CTF_MCP_TRACE_KEY"
ENV_ATTEMPT = "SPECAUDIT_CTF_MCP_TRACE_ATTEMPT"

GENESIS_PREFIX = "specaudit-ctf-trace-v1:"
MAX_FIELD_CHARS = 4096
_ATTEMPT_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _scrub(obj: Any, scrub: Any) -> Any:
    """Scrub every string in a JSON-shaped payload (same semantics as
    the arm-side object scrubber; kept local so this module does not
    lean on a sibling's private helper)."""
    if isinstance(obj, str):
        return scrub(obj)
    if isinstance(obj, list):
        return [_scrub(item, scrub) for item in obj]
    if isinstance(obj, dict):
        return {_scrub(str(key), scrub): _scrub(value, scrub) for key, value in obj.items()}
    return obj


class TraceUnavailable(Exception):
    """The trace env is set but the sink cannot be used (fail closed)."""


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _chain_hmac(key: bytes, prev_hmac: str, payload: Mapping[str, Any]) -> str:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(prev_hmac.encode("ascii"))
    mac.update(_canonical(payload))
    return mac.hexdigest()


def _cap_str(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    if len(text) > MAX_FIELD_CHARS:
        text = text[:MAX_FIELD_CHARS] + "…"
    return text


def _redacted(arguments: Mapping[str, Any]) -> dict[str, Any]:
    scrubbed = _scrub(dict(arguments), redact)
    capped = {
        str(key): _cap_str(value)[:MAX_FIELD_CHARS]
        for key, value in scrubbed.items()
    }
    return capped


def load_trace_key(raw: str | None) -> bytes:
    """Parse the trace key env value; refuse anything not 64 hex chars."""
    text = (raw or "").strip().lower()
    if not _ATTEMPT_HEX_RE.fullmatch(text):
        raise TraceUnavailable(
            f"{ENV_KEY} must be 64 lowercase hex characters "
            "(the grading side needs the same key to verify the chain)"
        )
    return bytes.fromhex(text)


def mint_key() -> str:
    """Fresh 64-hex trace key for an attempt this process spawns."""
    return os.urandom(32).hex()


def range_fixture_ids() -> tuple[str, ...]:
    """Shipped fixture roster: what one successful run_range covers.

    The range lifecycle always runs every shipped fixture, so the roster
    comes from the packaged manifest, not from any envelope body (the
    execution-result envelope carries capability coverage, not fixture
    rows). The sealed runtime bundle has no range module; there the
    roster is empty and a run_range record simply proves nothing.
    """
    try:
        from .range.runner import default_range_root

        manifest = json.loads(
            (default_range_root() / "manifest.json").read_text(encoding="utf-8")
        )
    except Exception:  # noqa: BLE001 - sealed runtimes have no range
        return ()
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list):
        return ()
    return tuple(item for item in fixtures if isinstance(item, str))


class TraceSink:
    """Append-only ndjson recorder bound to one attempt trace file."""

    def __init__(self, path: Path, key: bytes, attempt_id: str | None = None) -> None:
        self._path = path
        self._key = key
        self._attempt_id = attempt_id
        self._seq = 0
        self._prev = GENESIS_PREFIX
        self._calls = 0
        self._closed = False

    def start(self) -> None:
        """Validate the sink is usable BEFORE the server serves."""
        parent = self._path.parent
        if not parent.is_dir():
            raise TraceUnavailable(f"trace parent directory is missing: {parent}")
        if self._path.exists() and not self._path.is_file():
            raise TraceUnavailable(f"trace path is not a file: {self._path}")
        try:
            with self._path.open("a", encoding="utf-8"):
                pass
        except OSError as exc:
            raise TraceUnavailable(f"trace file is not writable: {exc}") from exc

    def observe(self, request: Mapping[str, Any], response: Mapping[str, Any] | None) -> None:
        """Record one tools/call request/response pair (honestly bounded)."""
        if self._closed:
            return
        params = request.get("params")
        if not isinstance(params, Mapping):
            return
        tool = params.get("name")
        if not isinstance(tool, str):
            return
        arguments = params.get("arguments")
        arguments = arguments if isinstance(arguments, Mapping) else {}
        summary = _result_summary(tool, arguments, response)
        self._append(
            {
                "type": "call",
                "tool": tool,
                "args": _redacted(arguments),
                "result": summary,
            }
        )
        self._calls += 1

    def close(self) -> None:
        """Append the close record on a clean server shutdown."""
        if self._closed:
            return
        self._append({"type": "close", "calls": self._calls})
        self._closed = True

    def _append(self, body: Mapping[str, Any]) -> None:
        self._seq += 1
        record: dict[str, Any] = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "prev": self._prev,
        }
        if self._attempt_id is not None:
            record["attempt_id"] = self._attempt_id
        record.update(body)
        record["hmac"] = _chain_hmac(self._key, self._prev, record)
        self._prev = record["hmac"]
        line = json.dumps(record, sort_keys=True, ensure_ascii=False)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def _result_summary(
    tool: str, arguments: Mapping[str, Any], response: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Bounded, redacted result facts; never the full envelope body."""
    summary: dict[str, Any] = {
        "isError": None,
        "envelope_status": None,
        "capability_id": None,
        "fixture_ids": [],
        "error": None,
    }
    if response is None:
        return summary
    if not isinstance(response, Mapping):
        summary["error"] = "non-mapping response"
        return summary
    if response.get("error") is not None:
        err = response.get("error")
        message = err.get("message") if isinstance(err, Mapping) else str(err)
        summary["error"] = _cap_str(message)
        return summary
    result = response.get("result")
    if not isinstance(result, Mapping):
        summary["error"] = "missing tool result"
        return summary
    summary["isError"] = result.get("isError") is True
    envelope = result.get("structuredContent")
    if isinstance(envelope, Mapping):
        summary["envelope_status"] = _cap_str(envelope.get("status"))
        summary["capability_id"] = _cap_str(envelope.get("capability_id"))
        limitations = envelope.get("limitations")
        if isinstance(limitations, list) and limitations:
            summary["error"] = _cap_str(limitations[0])
    if tool == "run_range" and summary["isError"] is False:
        # One successful run_range covers the shipped fixture roster.
        summary["fixture_ids"] = list(range_fixture_ids())
    return summary


def maybe_sink() -> TraceSink | None:
    """Build the sink when the trace env is set; refuse if unusable."""
    raw = os.environ.get(ENV_TRACE, "").strip()
    if not raw:
        return None
    key = load_trace_key(os.environ.get(ENV_KEY))
    attempt = os.environ.get(ENV_ATTEMPT, "").strip().lower() or None
    if attempt is not None and not _ATTEMPT_HEX_RE.fullmatch(attempt):
        raise TraceUnavailable(
            f"{ENV_ATTEMPT} must be 64 lowercase hex characters when set"
        )
    sink = TraceSink(Path(raw), key, attempt_id=attempt)
    sink.start()
    return sink


class TraceVerification:
    """Outcome of re-walking a trace file against its keyed chain."""

    def __init__(self, ok: bool, reasons: list[str]) -> None:
        self.ok = ok
        self.reasons = reasons
        self.records: list[dict[str, Any]] = []
        self.tool_calls = 0
        self.attempt_id: str | None = None
        self.close_ok = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain_ok": self.ok,
            "close_ok": self.close_ok,
            "records": len(self.records),
            "tool_calls": self.tool_calls,
            "attempt_id": self.attempt_id,
            "reasons": self.reasons,
        }


def verify_trace(path: Path, key: bytes) -> TraceVerification:
    """Recompute the whole chain; any defect fails the trace.

    Failures: unreadable/partial trailing line, HMAC mismatch, seq
    discontinuity, missing close record (crash or truncation), or a
    genesis that is not this harness'.
    """
    verification = TraceVerification(ok=False, reasons=[])
    try:
        raw = path.read_bytes()
    except OSError as exc:
        verification.reasons.append(f"trace unreadable: {exc}")
        return verification
    if not raw:
        verification.reasons.append("trace is empty")
        return verification
    if not raw.endswith(b"\n"):
        verification.reasons.append("trace ends with a partial line")
    lines = raw.decode("utf-8", errors="replace").splitlines()
    prev = GENESIS_PREFIX
    seen_attempt: str | None = None
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            verification.reasons.append(f"record {index + 1} is not valid JSON")
            return verification
        if not isinstance(record, Mapping):
            verification.reasons.append(f"record {index + 1} is not an object")
            return verification
        claimed = record.get("hmac")
        body = {k: v for k, v in record.items() if k != "hmac"}
        expected = _chain_hmac(key, prev, body)
        if not isinstance(claimed, str) or not hmac.compare_digest(claimed, expected):
            verification.reasons.append(f"record {index + 1} fails the digest chain")
            return verification
        if record.get("prev") != prev:
            verification.reasons.append(f"record {index + 1} breaks the chain order")
            return verification
        if record.get("seq") != index + 1:
            verification.reasons.append(f"record {index + 1} has a seq discontinuity")
            return verification
        prev = claimed
        verification.records.append(dict(record))
        if record.get("type") == "call":
            verification.tool_calls += 1
        if record.get("type") == "close":
            verification.close_ok = True
        attempt = record.get("attempt_id")
        if attempt is not None:
            if not isinstance(attempt, str) or not _ATTEMPT_HEX_RE.fullmatch(attempt):
                verification.reasons.append(
                    f"record {index + 1} carries a malformed attempt id"
                )
                return verification
            if seen_attempt is None:
                seen_attempt = attempt
            elif attempt != seen_attempt:
                verification.reasons.append(
                    f"record {index + 1} switches attempt id mid-trace"
                )
                return verification
    verification.attempt_id = seen_attempt
    genesis = verification.records[0].get("prev") if verification.records else None
    if genesis != GENESIS_PREFIX:
        verification.reasons.append("trace does not start from the harness genesis")
    if not verification.close_ok:
        verification.reasons.append("trace has no close record (crashed or truncated)")
    verification.ok = not verification.reasons
    return verification


def refusal_line(reason: str) -> None:
    """The one stderr line a refused server writes before exiting."""
    print(f"mcp_server: trace sink unusable: {reason}", file=sys.stderr, flush=True)
