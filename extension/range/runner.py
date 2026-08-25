"""Read synthetic range fixtures and emit exposure / path / impact."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..arms.burp.sse import redact
from ..contract import (
    CATALOG_KIND_ARM,
    Extension,
    NotHeldError,
    NotInstalledError,
    default_extension,
)

SCHEMA_ID = "range.lifecycle.v2"
DEFAULT_SEED = 123
FIXTURE_S3_PUBLIC = "tf_s3_public_access"
FIXTURE_IAM_OPEN = "tf_iam_open"
ARM_ACTION = "observe"
STATUS_COMPLETE = "complete"
STATUS_DEGRADED = "degraded"
STATUS_FAILED = "failed"
_ARM_STATUS_OK = "ok"
_ARM_STATUS_LIMITED = frozenset({"skipped", "error"})
_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
}


class RangeError(Exception):
    """Fail-closed range fixture or runner error."""


def default_range_root() -> Path:
    return Path(__file__).resolve().parent


def run_range(
    range_root: Path | None = None,
    *,
    seed: int | None = None,
    extension: Extension | None = None,
    arm_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Evaluate fixtures and optionally invoke curated arms.

    Arms:
      - ``NotInstalledError`` (including missing ``BURP_MCP_ENDPOINT``) is
        recorded as ``status="skipped"`` with ``reason="not installed"``.
      - ``NotHeldError`` is ``status="error"``. Catalog hold reasons are
        kept unless catalog notes would leak secret-shaped text.
      - Any other ``Exception`` (including ``UnknownIdError`` for an
        unknown arm id, transport failures) becomes ``status="error"`` with
        a redacted ``error`` string.
      - Only arm ``status="ok"`` is success; missing/unknown is ``failed``,
        never ``complete``. Skip/error never yields ``complete``. Omitted
        ``arm_ids`` (``None``) auto-discovers curated arms as optional:
        skip/error is ``degraded``. Explicit empty ``arm_ids=()`` is
        required-empty: no arms, so lifecycle match may be ``complete``.
        Explicit non-empty ``arm_ids`` are required: skip/error is
        ``failed``. A lifecycle mismatch is ``failed``. Compatibility
        ``ok`` is true iff ``status`` is ``complete``.

    Seed precedence: ``seed`` arg overrides ``manifest.json:seed`` which
    overrides ``DEFAULT_SEED`` (123). Manifest and CLI seeds are validated
    as signed 32-bit integers.
    """
    root = range_root if range_root is not None else default_range_root()
    manifest = _load_manifest(root)
    if seed is not None:
        if isinstance(seed, bool):
            raise RangeError("seed must be an integer")
        if isinstance(seed, float):
            raise RangeError("seed must be an integer")
        try:
            document_seed = int(seed)
        except (ValueError, TypeError) as exc:
            raise RangeError("seed must be an integer") from exc
        # Also validate that string seeds that happen to be numeric don't
        # silently pass if caller passed a float-like or other non-int.
        # Strictly, only int seeds are allowed; string numeric is tolerated
        # via int() for backwards compatibility, but bool/float are rejected.
        if not (-(2**31) <= document_seed < 2**31):
            raise RangeError("seed out of range")
    elif "seed" in manifest:
        try:
            document_seed = int(manifest["seed"])  # type: ignore[arg-type]
        except (ValueError, TypeError) as exc:
            raise RangeError("seed must be an integer") from exc
        if not (-(2**31) <= document_seed < 2**31):
            raise RangeError("seed out of range")
    else:
        document_seed = DEFAULT_SEED
    ext = extension if extension is not None else default_extension()
    # Capture required-vs-optional before resolving ids so arm_ids=() stays
    # required-empty (complete on match) and None stays auto-discover optional.
    required = arm_ids is not None
    resolved_arms = _resolve_arm_ids(ext, arm_ids)
    rows = [
        _run_fixture(
            root, fixture_id, document_seed, ext, resolved_arms, required=required
        )
        for fixture_id in manifest["fixtures"]
    ]
    status = _document_status(rows)
    return {
        "schema": SCHEMA_ID,
        "seed": document_seed,
        "live_aws": False,
        "status": status,
        "ok": status == STATUS_COMPLETE,
        "coverage": _merge_coverage(rows),
        "fixtures": rows,
    }


def _load_manifest(root: Path) -> dict[str, Any]:
    data = _load_json(root / "manifest.json")
    if "live_aws" in data and not isinstance(data["live_aws"], bool):
        raise RangeError("manifest live_aws must be a boolean")
    if data.get("live_aws"):
        raise RangeError("range fixtures must be synthetic")
    if "version" in data:
        if not isinstance(data["version"], int) or isinstance(data["version"], bool):
            raise RangeError("manifest version must be an integer")
        if data["version"] != 1:
            raise RangeError("manifest version must be 1")
    if "seed" in data:
        seed_val = data["seed"]
        # bool is subclass of int — reject booleans explicitly.
        if isinstance(seed_val, bool) or not isinstance(seed_val, int):
            raise RangeError("manifest seed must be an integer")
        if not (-(2**31) <= seed_val < 2**31):
            raise RangeError("manifest seed out of range")
    fixtures = data.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise RangeError("manifest fixtures must be a non-empty list")
    if not all(isinstance(item, str) and item for item in fixtures):
        raise RangeError("manifest fixture ids must be non-empty strings")
    if len(set(fixtures)) != len(fixtures):
        raise RangeError("manifest fixtures must be unique")
    data["fixtures"] = list(fixtures)
    return data


def _run_fixture(
    root: Path,
    fixture_id: str,
    seed: int,
    ext: Extension,
    arm_ids: Sequence[str],
    *,
    required: bool,
) -> dict[str, Any]:
    fixture_dir = root / fixture_id
    if not fixture_dir.is_dir():
        raise RangeError(f"unknown fixture: {fixture_id}")
    assets = _load_kind(fixture_dir / "input" / "assets.json", "asset-config")
    connectivity = _load_kind(
        fixture_dir / "input" / "connectivity.json", "connectivity"
    )
    sast = _load_kind(fixture_dir / "input" / "sast.json", "sast")
    expected = _load_json(fixture_dir / "expected.json")
    derived = derive_lifecycle(assets, connectivity, sast)
    matched = derived == {
        "exposure": expected.get("exposure"),
        "path": expected.get("path"),
        "impact": expected.get("impact"),
    }
    arms = _invoke_arms(ext, arm_ids, fixture_id, seed)
    status = _fixture_status(matched=matched, arms=arms, required=required)
    return {
        "id": fixture_id,
        "status": status,
        "ok": status == STATUS_COMPLETE,
        "matched_expected": matched,
        "coverage": _coverage_from_arms(arms),
        "exposure": derived["exposure"],
        "path": derived["path"],
        "impact": derived["impact"],
        "arms": arms,
    }


def derive_lifecycle(
    assets: Mapping[str, Any],
    connectivity: Mapping[str, Any],
    sast: Mapping[str, Any],
) -> dict[str, Any]:
    asset_rows = assets.get("assets")
    if not isinstance(asset_rows, list) or not asset_rows:
        raise RangeError("assets must be a non-empty list")
    if len(asset_rows) != 1:
        raise RangeError("exactly one asset row is required")
    if not isinstance(asset_rows[0], dict):
        raise RangeError("asset row must be an object")
    asset = asset_rows[0]
    asset_id = str(asset.get("id") or "")
    if not asset_id:
        raise RangeError("asset id is required")
    kind = _exposure_kind(asset)
    findings = sast.get("findings")
    if not isinstance(findings, list):
        raise RangeError("sast findings must be a list")
    severity = _severity_for(asset_id, findings)
    path = _path_to(asset_id, connectivity)
    impact_kind = _impact_kind(kind)
    return {
        "exposure": {
            "id": f"demo-exp-{asset_id}",
            "kind": kind,
            "asset_id": asset_id,
            "asset_name": str(asset.get("name") or asset_id),
            "severity": severity,
            "summary": _exposure_summary(asset, kind),
        },
        "path": path,
        "impact": {
            "id": f"demo-imp-{asset_id}",
            "kind": impact_kind,
            "asset_id": asset_id,
            "severity": severity,
            "summary": _impact_summary(asset, impact_kind),
        },
    }


def _exposure_kind(asset: Mapping[str, Any]) -> str:
    atype = str(asset.get("type") or "")
    if atype == "aws_s3_bucket":
        acl = str(asset.get("acl") or "").lower()
        blocked = bool(asset.get("public_access_block"))
        if acl.startswith("public") or not blocked:
            return "public_storage"
    if atype == "aws_iam_policy":
        if asset.get("action") == "*" and asset.get("resource") == "*":
            return "open_identity"
    raise RangeError(f"no exposure derived for asset {asset.get('id')}")


def _impact_kind(exposure_kind: str) -> str:
    if exposure_kind == "public_storage":
        return "data_disclosure"
    if exposure_kind == "open_identity":
        return "privilege_escalation"
    raise RangeError(f"no impact for exposure {exposure_kind}")


def _exposure_summary(asset: Mapping[str, Any], kind: str) -> str:
    asset_id = asset["id"]
    atype = asset["type"]
    if kind == "public_storage":
        return f"{atype} {asset_id} is reachable without auth"
    if kind == "open_identity":
        return f"{atype} {asset_id} grants Action=* on Resource=*"
    raise RangeError(f"no exposure summary for {kind}")


def _impact_summary(asset: Mapping[str, Any], kind: str) -> str:
    name = str(asset.get("name") or asset.get("id"))
    if kind == "data_disclosure":
        return f"Unauthenticated parties can read objects on {name}"
    if kind == "privilege_escalation":
        return f"A principal attached to {name} can act on every resource"
    raise RangeError(f"no impact summary for {kind}")


def _severity_for(asset_id: str, findings: Sequence[Any]) -> str:
    best = ""
    best_rank = -1
    for row in findings:
        if not isinstance(row, dict) or row.get("asset_id") != asset_id:
            continue
        severity = str(row.get("severity") or "none").lower()
        rank = _SEVERITY_RANK.get(severity, 0)
        if rank > best_rank:
            best = severity
            best_rank = rank
    return best if best else "high"


def _path_to(asset_id: str, connectivity: Mapping[str, Any]) -> list[dict[str, str]]:
    edges = connectivity.get("edges")
    if not isinstance(edges, list):
        raise RangeError("connectivity edges must be a list")
    path: list[dict[str, str]] = []
    for edge in edges:
        if not isinstance(edge, dict):
            raise RangeError("connectivity edge must be an object")
        if str(edge.get("to") or "") != asset_id:
            continue
        path.append(
            {
                "from": str(edge.get("from") or ""),
                "to": asset_id,
                "via": str(edge.get("via") or ""),
                "auth": str(edge.get("auth") or "none"),
            }
        )
    path.sort(key=lambda row: (row["from"], row["to"], row["via"], row["auth"]))
    if not path:
        raise RangeError(f"no connectivity path to {asset_id}")
    return path


def _resolve_arm_ids(
    ext: Extension, arm_ids: Sequence[str] | None
) -> list[str]:
    if arm_ids is not None:
        # Deduplicate preserving order (billing/rate-limit protection).
        return list(dict.fromkeys(arm_ids))
    return [
        entry.id
        for entry in ext.list_entries()
        if entry.kind == CATALOG_KIND_ARM and entry.curated
    ]


def _fixture_status(
    *,
    matched: bool,
    arms: Sequence[Mapping[str, Any]],
    required: bool,
) -> str:
    if not matched:
        return STATUS_FAILED
    limited = False
    for row in arms:
        status = row.get("status")
        if status == _ARM_STATUS_OK:
            continue
        if status in _ARM_STATUS_LIMITED:
            limited = True
            continue
        # Missing/unknown is not an allowlisted success; never complete.
        return STATUS_FAILED
    if not limited:
        return STATUS_COMPLETE
    return STATUS_FAILED if required else STATUS_DEGRADED


def _document_status(rows: Sequence[Mapping[str, Any]]) -> str:
    statuses = [row["status"] for row in rows]
    if any(status == STATUS_FAILED for status in statuses):
        return STATUS_FAILED
    if any(status == STATUS_DEGRADED for status in statuses):
        return STATUS_DEGRADED
    return STATUS_COMPLETE


def _coverage_from_arms(rows: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    attempted: list[str] = []
    complete: list[str] = []
    skipped: list[str] = []
    error: list[str] = []
    for row in rows:
        arm_id = str(row["arm_id"])
        attempted.append(arm_id)
        status = row.get("status")
        if status == "ok":
            complete.append(arm_id)
        elif status == "skipped":
            skipped.append(arm_id)
        else:
            error.append(arm_id)
    return {
        "attempted": attempted,
        "complete": complete,
        "skipped": skipped,
        "error": error,
    }


def _unique_ids(ids: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(ids))


def _merge_coverage(rows: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {
        "attempted": [],
        "complete": [],
        "skipped": [],
        "error": [],
    }
    for row in rows:
        coverage = row["coverage"]
        for key in merged:
            merged[key].extend(coverage[key])
    return {key: _unique_ids(vals) for key, vals in merged.items()}


def _held_range_error(ext: Extension, arm_id: str, exc: NotHeldError) -> str:
    # Catalog hold reasons are operator policy ("no token passthrough").
    # Keyword-redact only when notes would leak secret-shaped text.
    text = str(exc)
    notes = ext.describe(arm_id).notes
    if redact(notes) != notes:
        return redact(text)
    return text


def _invoke_arms(
    ext: Extension,
    arm_ids: Sequence[str],
    fixture_id: str,
    seed: int,
) -> list[dict[str, Any]]:
    args = {"fixture_id": fixture_id, "seed": seed}
    rows: list[dict[str, Any]] = []
    for arm_id in arm_ids:
        try:
            result = ext.invoke(arm_id, ARM_ACTION, args)
        except NotInstalledError:
            rows.append(
                {
                    "arm_id": arm_id,
                    "action": ARM_ACTION,
                    "status": "skipped",
                    "reason": "not installed",
                }
            )
            continue
        except NotHeldError as exc:
            rows.append(
                {
                    "arm_id": arm_id,
                    "action": ARM_ACTION,
                    "status": "error",
                    "output": None,
                    "error": _held_range_error(ext, arm_id, exc),
                }
            )
            continue
        except Exception as exc:  # noqa: BLE001 - record per-arm, stay fail-closed
            rows.append(
                {
                    "arm_id": arm_id,
                    "action": ARM_ACTION,
                    "status": "error",
                    "output": None,
                    "error": redact(str(exc)),
                }
            )
            continue
        rows.append(
            {
                "arm_id": arm_id,
                "action": ARM_ACTION,
                "status": "ok" if result.ok else "error",
                "output": result.output,
                "error": result.error,
            }
        )
    return rows


def _load_kind(path: Path, kind: str) -> dict[str, Any]:
    data = _load_json(path)
    if data.get("kind") != kind:
        raise RangeError(f"{path.name} kind must be {kind}")
    return data


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RangeError(f"missing fixture file: {path.name}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RangeError(f"invalid json in {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise RangeError(f"{path.name} must be an object")
    return data
