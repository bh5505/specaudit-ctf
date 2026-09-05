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

SCHEMA_ID = "range.lifecycle.v3"
DEFAULT_SEED = 123
FIXTURE_S3_PUBLIC = "tf_s3_public_access"
FIXTURE_IAM_OPEN = "tf_iam_open"
FIXTURE_IAM_ASSUME_ROLE = "tf_iam_assume_role"
FIXTURE_IAM_EXTERNAL_TRUST = "tf_iam_external_trust"
FIXTURE_SG_OPEN_INGRESS = "tf_sg_open_ingress"
FIXTURE_CLOUDTRAIL_DISABLED = "tf_cloudtrail_disabled"
FIXTURE_S3_NO_ACCESS_LOGGING = "tf_s3_no_access_logging"
FIXTURE_S3_POLICY_BLOCKED = "tf_s3_policy_blocked_trap"
FIXTURE_S3_UNENCRYPTED = "tf_s3_unencrypted"
FIXTURE_CHAIN_INGRESS_ROLE = "tf_chain_ingress_role"
ARM_ACTION = "observe"
STATUS_COMPLETE = "complete"
STATUS_DEGRADED = "degraded"
STATUS_FAILED = "failed"
# The expected.json mirror: derived documents carry exactly these keys
# and a fixture's expected document must carry exactly the same set.
DERIVED_KEYS = ("exposure", "path", "impact", "exposures", "chains")
# Ports where world-open ingress is a finding regardless of service:
# administrative shells and databases (donor planting vocabulary).
SENSITIVE_PORTS = frozenset({22, 3389, 3306, 5432, 1521})
_OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
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
    expected = _load_expected(fixture_dir / "expected.json")
    derived = derive_lifecycle(assets, connectivity, sast)
    matched = derived == expected
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
        "exposures": derived["exposures"],
        "chains": derived["chains"],
        "arms": arms,
    }


def derive_lifecycle(
    assets: Mapping[str, Any],
    connectivity: Mapping[str, Any],
    sast: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the v3 lifecycle document from fixture inputs.

    Assets may be single- or multi-row. Every row yields exactly one
    exposure: kind, severity (max planted sast finding, default high),
    the attempted connectivity path into the asset, and the impact for
    that kind. The primary exposure is the highest-severity row (ties
    break in asset order) and is projected to the flat ``exposure``,
    ``path``, and ``impact`` keys. ``chains`` pairs intra-fixture
    exposures with one deliberate rule this iteration: an
    ``open_ingress`` asset plus an ``assumable_role`` asset yields an
    ``internet_to_identity`` chain. Cross-fixture reasoning stays in the
    challenge layer. The derived document carries exactly
    :data:`DERIVED_KEYS` and is compared by equality against the
    fixture's ``expected.json`` mirror.
    """
    asset_rows = assets.get("assets")
    if not isinstance(asset_rows, list) or not asset_rows:
        raise RangeError("assets must be a non-empty list")
    findings = sast.get("findings")
    if not isinstance(findings, list):
        raise RangeError("sast findings must be a list")
    edges = connectivity.get("edges")
    if not isinstance(edges, list):
        raise RangeError("connectivity edges must be a list")
    exposures: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for asset in asset_rows:
        if not isinstance(asset, dict):
            raise RangeError("asset row must be an object")
        asset_id = str(asset.get("id") or "")
        if not asset_id:
            raise RangeError("asset id is required")
        if asset_id in seen_ids:
            raise RangeError(f"duplicate asset id: {asset_id}")
        seen_ids.add(asset_id)
        kind = _exposure_kind(asset)
        severity = _severity_for(asset_id, findings)
        exposures.append(
            {
                "id": f"demo-exp-{asset_id}",
                "kind": kind,
                "asset_id": asset_id,
                "asset_name": str(asset.get("name") or asset_id),
                "severity": severity,
                "summary": _exposure_summary(asset, kind),
                "path": _path_to(asset_id, connectivity),
                "impact": _impact_row(asset, kind, severity),
            }
        )
    primary = _primary_exposure(exposures)
    return {
        "exposure": {
            key: primary[key]
            for key in ("id", "kind", "asset_id", "asset_name", "severity", "summary")
        },
        "path": primary["path"],
        "impact": primary["impact"],
        "exposures": exposures,
        "chains": _chains(exposures),
    }


def _primary_exposure(
    exposures: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any]:
    best = exposures[0]
    for row in exposures[1:]:
        if _SEVERITY_RANK.get(str(row["severity"]), 0) > _SEVERITY_RANK.get(
            str(best["severity"]), 0
        ):
            best = row
    return best


def _impact_row(
    asset: Mapping[str, Any], kind: str, severity: str
) -> dict[str, Any]:
    impact_kind = _impact_kind(kind)
    return {
        "id": f"demo-imp-{asset['id']}",
        "kind": impact_kind,
        "asset_id": asset["id"],
        "severity": severity,
        "summary": _impact_summary(asset, impact_kind),
    }


def _chains(
    exposures: Sequence[Mapping[str, Any]],
) -> list[dict[str, str]]:
    ingress = [row for row in exposures if row["kind"] == "open_ingress"]
    roles = [row for row in exposures if row["kind"] == "assumable_role"]
    chains: list[dict[str, str]] = []
    for src in ingress:
        for dst in roles:
            chains.append(
                {
                    "kind": "internet_to_identity",
                    "ingress_asset": str(src["asset_id"]),
                    "role_asset": str(dst["asset_id"]),
                    "summary": (
                        f"Internet-reachable ingress on {src['asset_name']} "
                        f"chains into assumable role {dst['asset_name']}"
                    ),
                }
            )
    return chains


def _exposure_kind(asset: Mapping[str, Any]) -> str:
    atype = str(asset.get("type") or "")
    if atype == "aws_s3_bucket":
        blocked = bool(asset.get("public_access_block"))
        acl = str(asset.get("acl") or "").lower()
        if blocked and bool(asset.get("policy_allows_anonymous")):
            # AWS semantics: with Block Public Access enabled, a bucket
            # policy that would grant anonymous reads is neutralized.
            # The grant is a policy misconfiguration, not a live
            # exposure — the negative control for graders and auditors.
            return "blocked_public_policy"
        if acl.startswith("public") or not blocked:
            return "public_storage"
        if asset.get("encryption_enabled") is False:
            return "unencrypted_storage"
        if asset.get("access_logging") is False:
            return "logging_gap"
    if atype == "aws_iam_policy":
        if asset.get("action") == "*" and asset.get("resource") == "*":
            return "open_identity"
    if atype == "aws_iam_role":
        if bool(asset.get("external_trust")):
            return "open_trust"
        if asset.get("assumable"):
            return "assumable_role"
    if atype == "aws_security_group":
        if _is_open_ingress(asset):
            return "open_ingress"
    if atype == "aws_cloudtrail":
        if asset.get("enabled") is False:
            return "monitoring_gap"
    raise RangeError(f"no exposure derived for asset {asset.get('id')}")


def _is_open_ingress(asset: Mapping[str, Any]) -> bool:
    """World-open ingress counts when it touches a sensitive port.

    Public ingress on ordinary service ports (443 and friends) is
    normal posture; the planted finding is 0.0.0.0/0 or ::/0 reaching
    administrative shells and database engines.
    """
    if str(asset.get("direction") or "") != "ingress":
        return False
    if str(asset.get("cidr") or "") not in _OPEN_CIDRS:
        return False
    try:
        low = int(asset.get("from_port"))  # type: ignore[arg-type]
        high = int(asset.get("to_port"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if high < low:
        return False
    return any(low <= port <= high for port in SENSITIVE_PORTS)


def _impact_kind(exposure_kind: str) -> str:
    if exposure_kind == "public_storage":
        return "data_disclosure"
    if exposure_kind in ("open_identity", "assumable_role"):
        return "privilege_escalation"
    if exposure_kind == "open_trust":
        return "identity_compromise"
    if exposure_kind == "open_ingress":
        return "remote_service_exposure"
    if exposure_kind in ("monitoring_gap", "logging_gap"):
        return "detection_gap"
    if exposure_kind == "blocked_public_policy":
        return "blocked"
    if exposure_kind == "unencrypted_storage":
        return "data_at_rest_exposure"
    raise RangeError(f"no impact for exposure {exposure_kind}")


def _exposure_summary(asset: Mapping[str, Any], kind: str) -> str:
    asset_id = asset["id"]
    atype = asset["type"]
    if kind == "public_storage":
        return f"{atype} {asset_id} is reachable without auth"
    if kind == "open_identity":
        return f"{atype} {asset_id} grants Action=* on Resource=*"
    if kind == "open_trust":
        return (
            f"{atype} {asset_id} trusts an external principal "
            "without requiring MFA"
        )
    if kind == "assumable_role":
        return f"{atype} {asset_id} is assumable via sts:AssumeRole by broader principals"
    if kind == "open_ingress":
        return (
            f"{atype} {asset_id} admits {asset.get('cidr')} ingress "
            f"on port range {asset.get('from_port')}-{asset.get('to_port')}"
        )
    if kind == "monitoring_gap":
        return f"{atype} {asset_id} is disabled; control-plane events go unrecorded"
    if kind == "logging_gap":
        return f"{atype} {asset_id} does not record server access logs"
    if kind == "blocked_public_policy":
        return (
            f"{atype} {asset_id} grants anonymous reads by policy; "
            "block public access neutralizes it"
        )
    if kind == "unencrypted_storage":
        return f"{atype} {asset_id} stores objects without server-side encryption"
    raise RangeError(f"no exposure summary for {kind}")


def _impact_summary(asset: Mapping[str, Any], kind: str) -> str:
    name = str(asset.get("name") or asset.get("id"))
    if kind == "data_disclosure":
        return f"Unauthenticated parties can read objects on {name}"
    if kind == "privilege_escalation":
        if str(asset.get("type") or "") == "aws_iam_role":
            return f"A principal that can assume {name} acts with its permissions on every resource"
        return f"A principal attached to {name} can act on every resource"
    if kind == "identity_compromise":
        return f"An external principal can assume {name} without MFA"
    if kind == "remote_service_exposure":
        return f"Administrative or data services on {name} are reachable from any address"
    if kind == "detection_gap":
        return f"Activity involving {name} leaves no durable audit trail"
    if kind == "blocked":
        return f"The anonymous grant on {name} is neutralized; no live exposure"
    if kind == "data_at_rest_exposure":
        return f"Objects on {name} persist without encryption at rest"
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


def _load_expected(path: Path) -> dict[str, Any]:
    """Load the expected.json mirror.

    Fail-closed on key-set drift in either direction: an expected
    document missing a derived key (or carrying a stale one) is a
    fixture error, never a silent partial comparison.
    """
    data = _load_json(path)
    if set(data) != set(DERIVED_KEYS):
        raise RangeError(
            f"expected.json must mirror the derived document exactly "
            f"({', '.join(sorted(DERIVED_KEYS))})"
        )
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
