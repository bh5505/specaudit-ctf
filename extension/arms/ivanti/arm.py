"""Ivanti (RiskSense) VM API arm: governed assets + findings extraction.

The sponsor estate is Xpanse ASM + Ivanti VM; this arm is the durable, governed
way to pull host (assets), hostFinding (findings), vulnerability, and tag data
straight from the Ivanti VM platform API. It is a pure-stdlib HTTP REST client
(no requests/pandas/duckdb), so the sealed specaudit-ctf runtime can execute it
hermetically. Output is the flattened, JSON-safe shape the ``ext_telecom_asmvm``
pack consumes as its Ivanti bronze (assets/findings rows).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
from typing import Any, Mapping

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from ..mcp_client import redact
from .client import DEFAULT_SIZE, IvantiClient, IvantiError
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    DEFAULT_CONFIG_NAMES,
    ENDPOINTS,
    ENV_SCOPE,
    LIST_ACTIONS,
    IvantiConfigError,
    args_refusal,
    connection_config,
    parse_filters,
    resolve_config_path,
)

MAX_OUTPUT_CHARS = 512 * 1024


def _normalized_args_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class IvantiArm:
    """First-party, stdlib-only Ivanti VM REST extractor."""

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def __init__(self, config_path: str | None = None) -> None:
        # Allow injection for hermetic tests without touching env/INI.
        self._config_path = config_path

    def installed(self, spec: ArmSpec) -> bool:
        if spec.id != ARM_ID:
            return False
        # A live API arm is "installed" when it can be armed (config/env present).
        path = resolve_config_path(self._config_path)
        try:
            connection_config(path)
            return True
        except IvantiConfigError:
            return False

    def invoke(self, spec: ArmSpec, action: str, args: Mapping[str, Any]) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return Result(
                False, spec.id, action, None,
                f"action {action!r} is not on the allowlist (search/export/filters/fields)",
            )
        try:
            return self._dispatch(spec, action, payload)
        except IvantiConfigError as exc:
            return Result(False, spec.id, action, None, redact(str(exc)))
        except (IvantiError, ValueError, csv.Error, OSError) as exc:
            return Result(False, spec.id, action, None, redact(str(exc)))

    def _list_tools(self, spec: ArmSpec, action: str, payload: dict[str, Any]) -> Result:
        if payload:
            return Result(False, spec.id, action, None, "list_tools takes no arguments")
        return Result(True, spec.id, action, {
            "read_actions": sorted(ALLOWED_ACTIONS),
            "endpoints": sorted(ENDPOINTS),
            "arg_keys": sorted({
                "endp", "filters", "projection", "size", "pages",
                "save", "extract_host", "filename", "poll", "timeout",
                "config", "verify_ssl",
            }),
            "default_size": DEFAULT_SIZE,
            "armed": self._armed(),
            "arming": f"set IVANTI_CONFIG (or IVANTI_URL/IVANTI_API_VER/IVANTI_CLIENT_ID/IVANTI_API_KEY) to arm; optional {ENV_SCOPE} for IP/CIDR scope",
        }, None)

    def _armed(self) -> bool:
        try:
            connection_config(resolve_config_path(self._config_path))
            return True
        except IvantiConfigError:
            return False

    def _client(self, payload: dict[str, Any]) -> IvantiClient:
        explicit = payload.get("config") or self._config_path
        path = resolve_config_path(explicit)
        if path is None:
            path = explicit or DEFAULT_CONFIG_NAMES[0]
        conf = connection_config(path)
        verify_ssl = bool(payload.get("verify_ssl", True))
        return IvantiClient(conf["url"], conf["api_ver"], conf["client_id"],
                            conf["api_key"], verify_ssl=verify_ssl)

    def _dispatch(self, spec: ArmSpec, action: str, payload: dict[str, Any]) -> Result:
        refusal = args_refusal(payload)
        if refusal:
            return Result(False, spec.id, action, None, refusal)
        endp = payload["endp"]
        client = self._client(payload)

        if action == "filters":
            try:
                data = client.filters(endp)
            except IvantiError as exc:
                return Result(False, spec.id, action, None, redact(str(exc)))
            return Result(True, spec.id, action, {"endp": endp, "filters": data[:200]}, None)

        if action == "fields":
            try:
                data = client.fields(endp)
            except IvantiError as exc:
                return Result(False, spec.id, action, None, redact(str(exc)))
            return Result(True, spec.id, action, {"endp": endp, "fields": data[:500]}, None)

        if action == "search":
            return self._search(spec, action, payload, client, endp)

        if action == "export":
            return self._export(spec, action, payload, client, endp)

        return Result(False, spec.id, action, None, f"unknown action {action!r}")

    def _search(self, spec: ArmSpec, action: str, payload: dict[str, Any],
                client: IvantiClient, endp: str) -> Result:
        filters = parse_filters(payload.get("filters"))
        projection = payload.get("projection") or "basic"
        size = payload.get("size", DEFAULT_SIZE)
        pages = payload.get("pages")
        save = payload.get("save")
        extract_host = bool(payload.get("extract_host", False))
        args_hash = _normalized_args_hash(payload)
        try:
            flattened = client.search(endp, filters=filters, projection=projection,
                                      size=size, pages=pages, extract_host=extract_host)
        except IvantiError as exc:
            return Result(False, spec.id, action, None, redact(str(exc)))
        saved_path: str | None = None
        if save:
            saved_path = _write_csv(save, flattened, endp)
        output: dict[str, Any] = {
            "endp": endp,
            "projection": projection,
            "count": len(flattened),
            "saved_csv": saved_path,
            "records": flattened,
            "args_hash": args_hash,
        }
        _trim_records(output, MAX_OUTPUT_CHARS)
        return Result(True, spec.id, action, output, None)

    def _export(self, spec: ArmSpec, action: str, payload: dict[str, Any],
                client: IvantiClient, endp: str) -> Result:
        filters = parse_filters(payload.get("filters"))
        save = payload.get("save")
        filename = payload.get("filename") or "ivanti-export"
        poll = float(payload.get("poll", 6.0))
        timeout = float(payload.get("timeout", 3600.0))
        try:
            data = client.export(endp, filters=filters, filename=filename,
                                 save=save, poll=poll, timeout=timeout)
        except IvantiError as exc:
            return Result(False, spec.id, action, None, redact(str(exc)))
        return Result(True, spec.id, action, {
            "endp": endp,
            "saved_csv": save,
            "bytes": len(data),
        }, None)


def _write_csv(path: str, records: list[dict[str, Any]], endp: str) -> str:
    if not records:
        # keep an empty file with just the id column so the pack ingest is stable
        with open(path, "w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(["id"])
        return path
    columns: list[str] = []
    seen = set()
    for record in records:
        for key in record:
            if key not in seen:
                seen.add(key)
                columns.append(key)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for record in records:
            writer.writerow({key: _csv_cell(value) for key, value in record.items()})
    return path


def _csv_cell(value: Any) -> Any:
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return value


def _trim_records(output: dict[str, Any], limit: int) -> None:
    records = output.get("records")
    if not isinstance(records, list):
        return
    # cap embedded record count by serialized size to keep the MCP envelope small
    size = 0
    kept: list[dict[str, Any]] = []
    for record in records:
        serialized = len(json.dumps(record, default=str))
        if size + serialized > limit and kept:
            break
        kept.append(record)
        size += serialized
    output["count"] = len(records)
    output["records"] = kept
    output["truncated"] = len(kept) < len(records)
