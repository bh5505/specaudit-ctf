"""OSV advisory arm: offline snapshot reads + bounded live queries.

Two clearly separated layers under one interface:

  * ``read_snapshot`` / ``get_advisory`` — offline, deterministic reads over a
    caller-supplied local snapshot (:mod:`reader`; never touches :mod:`api`);
  * ``query_package`` / ``query_commit`` — bounded read-only live queries
    against the fixed official host (:mod:`api`).

Envelope status model shared by both layers:
``complete`` → ``ok=true`` (CLI exit 0, MCP ``isError=false``);
``partial`` / ``unknown`` / ``error`` → ``ok=false`` with a bounded, non-empty
evidence list and a reason (CLI exit 1, MCP ``isError=true``). An empty
records list is meaningful only with ``complete``.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..mcp_client import redact
from . import api, reader
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    CAVEATS,
    INPUT_HINT,
    LIST_ACTIONS,
    LIVE_TIMEOUT_SECONDS,
    MAX_LIVE_RECORDS,
    MAX_OUTPUT_CHARS,
    MAX_PAGES,
    MAX_RESPONSE_BYTES,
    OSV_API_HOST,
    OSV_QUERY_PATH,
    SNAPSHOT_LIMITATIONS,
    SNAPSHOT_SCHEMA,
    args_refusal,
    demo_snapshot_path,
    snapshot_refusal,
)


class OsvArm:
    """Advisory-context source: frozen snapshots plus a bounded live client."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def __init__(self, transport: api.Transport | None = None) -> None:
        # Constructor injection keeps tests socket-free: the default live
        # transport is only built when a live action runs without one.
        self._transport = transport

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(
        self,
        spec: ArmSpec,
        action: str,
        args: Mapping[str, Any],
        transport: api.Transport | None = None,
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)

        if action in ("read_snapshot", "get_advisory"):
            return self._snapshot_action(spec, action, payload)
        if action in ("query_package", "query_commit"):
            return self._live_action(spec, action, payload, transport)
        return _fail(
            spec,
            action,
            f"action {action!r} is not on the allowlist "
            "(offline snapshot reads and bounded live OSV queries only)",
        )

    # --- snapshot layer (offline, deterministic) -----------------------------

    def _snapshot_action(
        self, spec: ArmSpec, action: str, payload: dict
    ) -> Result:
        path, refusal = snapshot_refusal(payload.get("snapshot"))
        if refusal or path is None:
            return _fail(spec, action, refusal or "snapshot path validation failed")
        try:
            snapshot = reader.load_snapshot_file(path)
        except reader.SnapshotError as exc:
            return _fail(spec, action, str(exc))
        except Exception:
            return _fail(spec, action, "snapshot could not be parsed safely")

        if action == "get_advisory":
            osv_id = payload["id"].strip()
            record = reader.lookup_by_id(snapshot, osv_id)
            limitations = list(SNAPSHOT_LIMITATIONS)
            records: list[dict[str, Any]] = []
            if record is None:
                limitations.append(
                    f"no advisory with id {redact(osv_id)[:128]!r} in this snapshot"
                )
            else:
                records = [record]
            return _ok(
                spec,
                action,
                {
                    "status": "complete",
                    "query": {
                        "kind": "advisory",
                        "id": osv_id,
                        "snapshot_schema": SNAPSHOT_SCHEMA,
                        "snapshot_time": snapshot.snapshot_time,
                    },
                    "records": records,
                    "source": _snapshot_source(snapshot),
                    "limitations": limitations,
                    "reason": None,
                    "evidence": [],
                },
            )

        records = [
            record
            for coordinate in sorted(snapshot.packages)
            for record in snapshot.packages[coordinate]
        ]
        records.sort(key=lambda record: record["id"])
        return _ok(
            spec,
            action,
            {
                "status": "complete",
                "query": {
                    "kind": "snapshot",
                    "snapshot_schema": SNAPSHOT_SCHEMA,
                    "snapshot_time": snapshot.snapshot_time,
                    "package_count": len(snapshot.packages),
                    "record_count": len(records),
                },
                "records": records,
                "source": _snapshot_source(snapshot),
                "limitations": list(SNAPSHOT_LIMITATIONS),
                "reason": None,
                "evidence": [],
            },
        )

    # --- live layer (bounded, fixed host) ------------------------------------

    def _live_action(
        self,
        spec: ArmSpec,
        action: str,
        payload: dict,
        transport: api.Transport | None,
    ) -> Result:
        body = _request_body(action, payload)
        envelope = api.run_query(
            body,
            transport=transport if transport is not None else self._transport,
            timeout=LIVE_TIMEOUT_SECONDS,
        )
        status = envelope["status"]
        if status == "complete":
            return _ok(spec, action, envelope)
        return Result(
            ok=False,
            arm_id=spec.id,
            action=action,
            output=envelope,
            error=redact(str(envelope.get("reason") or status))[:MAX_OUTPUT_CHARS],
        )

    # --- interface listing ----------------------------------------------------

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        if payload:
            return _fail(spec, action, "list_tools takes no caller arguments")
        return _ok(
            spec,
            action,
            {
                "actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "arg_keys": {key: sorted(values) for key, values in ARG_KEYS.items()},
                "caps": {
                    "live_timeout_seconds": LIVE_TIMEOUT_SECONDS,
                    "max_pages": MAX_PAGES,
                    "max_records": MAX_LIVE_RECORDS,
                    "max_response_bytes": MAX_RESPONSE_BYTES,
                },
                "live_endpoint": {"host": OSV_API_HOST, "path": OSV_QUERY_PATH},
                "snapshot_schema": SNAPSHOT_SCHEMA,
                "demo_snapshot": str(demo_snapshot_path()),
                "caveats": list(CAVEATS),
                "input_hint": INPUT_HINT,
            },
        )


def _request_body(action: str, payload: dict) -> dict[str, Any]:
    """Build the exact OSV query body; the payload is pre-validated."""
    if action == "query_commit":
        return {"commit": payload["commit"].strip().lower()}
    if "purl" in payload:
        purl = payload["purl"].strip()
        if "version" in payload:
            return {"package": {"purl": purl}, "version": payload["version"].strip()}
        return {"package": {"purl": purl}}
    return {
        "package": {
            "ecosystem": payload["ecosystem"].strip(),
            "name": payload["name"].strip(),
        },
        "version": payload["version"].strip(),
    }


def _snapshot_source(snapshot: reader.Snapshot) -> dict[str, Any]:
    return {
        "path": snapshot.source["path"],
        "sha256": snapshot.source["sha256"],
        "bytes": snapshot.source["bytes"],
        "snapshot_time": snapshot.snapshot_time,
    }


def render_output_bytes(output: Any) -> bytes:
    """Render the exact UTF-8 form used by this arm's output size gate."""
    return json.dumps(
        output, sort_keys=True, ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        size = len(render_output_bytes(output))
    except (TypeError, ValueError, OverflowError) as exc:
        return _fail(spec, action, f"result could not be encoded: {exc}")
    if size > MAX_OUTPUT_CHARS:
        return _fail(
            spec,
            action,
            f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; "
            "narrow the query",
        )
    return Result(True, spec.id, action, output, None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(False, spec.id, action, None, redact(str(error))[:MAX_OUTPUT_CHARS])
