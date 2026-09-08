"""Curated vulnify arm: bounded local vulnerability reads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..mcp_client import redact
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_OUTPUT_CHARS,
    MAX_RESULTS,
    args_refusal,
    feed_refusal,
    limit_refusal,
)


class VulnifyArm:
    """Specialized transport for catalog id vulnify.

    First-party in-process read arm: a stdlib vulnerability-feed reader
    with no subprocess and no endpoint.  ``installed`` reports handler
    presence only — the corpus is per-invoke caller data (args.feed),
    the same contract as every other file-consuming arm.
    """

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            return self._list_tools(spec, action, payload)
        if action not in ALLOWED_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(offline reads over a local vulnerability feed only; "
                "there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        path, feed_refused = feed_refusal(payload.get("feed"))
        if feed_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=feed_refused,
            )
        try:
            records = _load_feed(path)
        except Exception as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if isinstance(records, str):
            # refusal string from _load_feed
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=records,
            )
        if action == "lookup":
            return self._lookup(spec, payload, records)
        return self._list_vulns(spec, payload, records)

    # ------------------------------------------------------------------
    # action handlers
    # ------------------------------------------------------------------

    def _lookup(
        self,
        spec: ArmSpec,
        payload: dict,
        records: list[dict],
    ) -> Result:
        cve_id = _opt_str(payload.get("cve_id"))
        name = _opt_str(payload.get("name"))
        for rec in records:
            if cve_id and rec.get("cve_id") == cve_id:
                return _ok_result(spec, "lookup", rec)
            if name and rec.get("name") == name:
                return _ok_result(spec, "lookup", rec)
        wanted = cve_id or name
        return Result(
            ok=False,
            arm_id=spec.id,
            action="lookup",
            output=None,
            error=f"vulnerability {wanted!r} not found in this feed",
        )

    def _list_vulns(
        self,
        spec: ArmSpec,
        payload: dict,
        records: list[dict],
    ) -> Result:
        limit, lrefusal = limit_refusal(payload.get("limit"))
        if lrefusal:
            return Result(
                ok=False,
                arm_id=spec.id,
                action="list_vulns",
                output=None,
                error=lrefusal,
            )
        summary = [
            {
                "cve_id": rec.get("cve_id", ""),
                "name": rec.get("name", ""),
                "severity": rec.get("severity", ""),
            }
            for rec in records[:limit]
        ]
        return _ok_result(spec, "list_vulns", summary)

    def _list_tools(
        self, spec: ArmSpec, action: str, payload: dict
    ) -> Result:
        if payload:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="list_tools takes no caller arguments",
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": {key: sorted(vals) for key, vals in ARG_KEYS.items()},
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )


# ------------------------------------------------------------------
# feed loader
# ------------------------------------------------------------------

def _load_feed(path: Path) -> list[dict] | str:
    """Load a local vulnerability feed.

    Handles JSON arrays and JSONL (one JSON object per line).
    Returns a list of dicts on success, or a refusal string on error.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"args.feed could not be read: {exc}"
    text = raw.strip()
    if not text:
        return "args.feed is empty"

    # Try JSON array first.
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return f"args.feed is not valid JSON: {exc}"
        if not isinstance(data, list):
            return "args.feed top-level value must be a JSON array or JSONL"
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                return f"args.feed record {i} is not a JSON object"
        return data

    # Fall back to JSONL: one JSON object per line.
    records: list[dict] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return f"args.feed line {lineno} is not valid JSON: {exc}"
        if not isinstance(obj, dict):
            return f"args.feed line {lineno} is not a JSON object"
        records.append(obj)
    if not records:
        return "args.feed contained no parseable records"
    return records


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()


def _ok_result(spec: ArmSpec, action: str, output: Any) -> Result:
    text = json.dumps(output, sort_keys=True)
    if len(text) > MAX_OUTPUT_CHARS:
        return Result(
            ok=False,
            arm_id=spec.id,
            action=action,
            output=None,
            error=(
                f"result exceeds the {MAX_OUTPUT_CHARS} character output "
                "cap; narrow the lookup"
            ),
        )
    return Result(
        ok=True,
        arm_id=spec.id,
        action=action,
        output=output,
        error=None,
    )
