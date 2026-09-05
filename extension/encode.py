"""Thin execution-result.v1 encoder. envelopes.parse_execution_result owns status."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .contract import (
    NotAnArmError,
    NotCuratedError,
    NotHeldError,
    NotInstalledError,
    Result,
    UnmanifestedCapabilityError,
    UnknownIdError,
)
from .envelopes import (
    MANIFEST_SCHEMA_ID,
    RESULT_SCHEMA_ID,
    SCHEMA_VERSION,
    STATUS_COMPLETE,
    STATUS_DEGRADED,
    STATUS_FAILED,
    _ATTEMPT_ID_RE,
    _CAPABILITY_ID_RE,
    parse_capability_manifest,
    parse_execution_result,
)
from .invoke_profiles import (
    INVOKE_PROFILES,
    InvokeProfile,
    PACKAGE_NAME,
    PACKAGE_VERSION,
    invoke_profile,
)

RANGE_CAPABILITY_ID = "fixture.range-observe"
RANGE_TOOL = {"name": "fixture-range", "version": "1.0.0"}
# The deliberate capability grant for a range run: one URI per shipped
# fixture, kept in lockstep with extension/range/manifest.json by the
# drift-guard test (test_range_scope_matches_manifest). Static here —
# the sealed runtime excludes the range data tree, so this file cannot
# read the manifest at import time.
RANGE_SCOPE = (
    "file:///extension/range/tf_s3_public_access",
    "file:///extension/range/tf_iam_open",
    "file:///extension/range/tf_iam_assume_role",
    "file:///extension/range/tf_iam_external_trust",
    "file:///extension/range/tf_sg_open_ingress",
    "file:///extension/range/tf_cloudtrail_disabled",
    "file:///extension/range/tf_s3_no_access_logging",
    "file:///extension/range/tf_s3_policy_blocked_trap",
    "file:///extension/range/tf_s3_unencrypted",
    "file:///extension/range/tf_chain_ingress_role",
)
_RANGE_SCOPE_BY_FIXTURE = {
    uri.rsplit("/", 1)[-1]: uri for uri in RANGE_SCOPE
}
ROE_REF = "roe:synthetic-range"
_REFUSED_SCOPE = ("urn:specaudit-ctf:refused-before-dispatch",)
_REFUSED_RESERVED = {
    "timeout_ms": 30000,
    "max_output_bytes": 1048576,
    "max_tool_steps": 8,
    "max_spend": None,
}
# Match range-observe freeze reserved. Spent steps are this one capability.
_RANGE_RESERVED = {
    "timeout_ms": 60000,
    "max_output_bytes": 1048576,
    "max_tool_steps": 16,
    "max_spend": None,
}
# Static producer redaction; not inferred from a child-returned document.
_MANIFEST_REDACTION = {
    "fields": ("authorization", "cookie", "set-cookie"),
    "env": ("AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN"),
}
# Producer handoff bounds. Match reserved max_output_bytes on these profiles.
MAX_ARTIFACT_COUNT = 8
MAX_ARTIFACT_AGGREGATE_BYTES = 1_048_576
_ARTIFACT_FILE_MODE = 0o600


class AttemptContractError(Exception):
    """Fail-closed attempt/artifact transport contract error."""


class InvalidAttemptIdError(AttemptContractError):
    """Caller supplied an attempt id that cannot be echoed structurally."""


class ArtifactDirError(AttemptContractError):
    """Caller requested artifact handoff with an unusable directory."""


class ArtifactHandoffError(AttemptContractError):
    """Requested artifact bytes could not be written; envelope is not complete."""

    def __init__(self, message: str, *, envelope: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.envelope = dict(envelope)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_attempt_id(value: str | None) -> str | None:
    """Return a structurally valid attempt id, or None when omitted."""
    if value is None:
        return None
    if not isinstance(value, str) or not _ATTEMPT_ID_RE.match(value):
        raise InvalidAttemptIdError(
            "invalid attempt id (expected attempt-<64 lowercase hex>)"
        )
    return value


def mode_a_supported() -> bool:
    """Mode A needs Unix descriptor-relative directory writes."""
    return (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_CLOEXEC")
        and hasattr(os, "O_EXCL")
    )


class ArtifactSink:
    """Bound Unix directory fd for exclusive digest-named artifact writes.

    Writes use dir_fd/openat semantics so a path or ancestor swap after
    admission cannot redirect bytes into a replacement directory.
    """

    def __init__(self, dir_fd: int) -> None:
        if dir_fd < 0:
            raise ArtifactDirError("artifact directory is not usable")
        self._dir_fd = dir_fd
        self._count = 0
        self._bytes = 0

    @classmethod
    def open(cls, path: str) -> ArtifactSink:
        normalized, info = cls.validate_path(path)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            fd = os.open(normalized, flags)
        except OSError as exc:
            raise ArtifactDirError("artifact directory is not usable") from exc
        try:
            opened = os.fstat(fd)
            if not stat.S_ISDIR(opened.st_mode):
                raise ArtifactDirError("artifact directory must be a directory")
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ArtifactDirError("artifact directory changed during admission")
            names = [name for name in os.listdir(fd) if name not in (".", "..")]
            if names:
                raise ArtifactDirError("artifact directory must be empty")
        except ArtifactDirError:
            os.close(fd)
            raise
        except OSError as exc:
            os.close(fd)
            raise ArtifactDirError("artifact directory is not usable") from exc
        return cls(fd)


    @staticmethod
    def validate_path(path: str) -> tuple[str, os.stat_result]:
        # Platform-neutral admission contract for the artifact directory,
        # split from open() so non-Unix hosts reject a *bad path* with the
        # path error rather than the platform error: argument validation
        # precedes environment gating everywhere in this contract.
        if not isinstance(path, str) or not os.path.isabs(path):
            raise ArtifactDirError("artifact directory must be an absolute path")
        normalized = path.rstrip("/") or "/"
        try:
            info = os.lstat(normalized)
        except FileNotFoundError as exc:
            raise ArtifactDirError("artifact directory does not exist") from exc
        except OSError as exc:
            raise ArtifactDirError("artifact directory is not usable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ArtifactDirError("artifact directory must not be a symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise ArtifactDirError("artifact directory must be a directory")
        if [name for name in os.listdir(normalized) if name not in (".", "..")]:
            raise ArtifactDirError("artifact directory must be empty")
        return normalized, info

    def write(self, digest: str, blob: bytes) -> None:
        if self._dir_fd < 0:
            raise OSError("artifact directory is closed")
        if len(blob) > MAX_ARTIFACT_AGGREGATE_BYTES:
            raise OSError("artifact exceeds size cap")
        if self._bytes + len(blob) > MAX_ARTIFACT_AGGREGATE_BYTES:
            raise OSError("artifact aggregate exceeds size cap")
        if self._count + 1 > MAX_ARTIFACT_COUNT:
            raise OSError("artifact count exceeds cap")
        name = artifact_filename(digest)
        if os.sep in name or (os.altsep and os.altsep in name):
            raise OSError("artifact filename must be a relative basename")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(name, flags, _ARTIFACT_FILE_MODE, dir_fd=self._dir_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("artifact is not a regular file")
            if hasattr(os, "fchmod"):
                os.fchmod(fd, _ARTIFACT_FILE_MODE)
            view = memoryview(blob)
            offset = 0
            while offset < len(blob):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise OSError("artifact write made no progress")
                offset += written
            os.fsync(fd)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(name, dir_fd=self._dir_fd)
            except OSError:
                pass
            raise
        os.close(fd)
        try:
            os.fsync(self._dir_fd)
        except OSError:
            try:
                os.unlink(name, dir_fd=self._dir_fd)
            except OSError:
                pass
            raise
        self._count += 1
        self._bytes += len(blob)

    def close(self) -> None:
        fd = self._dir_fd
        self._dir_fd = -1
        if fd >= 0:
            os.close(fd)

    def __enter__(self) -> ArtifactSink:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def bind_artifact_dir(
    value: str | None, *, attempt_id: str | None
) -> ArtifactSink | None:
    """Admit and bind a validator-owned artifact directory. Not local-write authority.

    Opens the directory before tool dispatch. Mode A is Unix-only.
    """
    if value is None:
        return None
    if attempt_id is None:
        raise ArtifactDirError("--artifact-dir requires --attempt-id")
    if not mode_a_supported():
        ArtifactSink.validate_path(value)
        raise ArtifactDirError("Mode A artifact custody is Unix-only")
    return ArtifactSink.open(value)


def artifact_filename(digest: str) -> str:
    """Deterministic regular filename derived from a claimed sha256 digest."""
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise OSError("artifact digest is not a sha256 digest")
    hexdigest = digest[7:]
    if len(hexdigest) != 64 or any(ch not in "0123456789abcdef" for ch in hexdigest):
        raise OSError("artifact digest is not a sha256 digest")
    return f"sha256-{hexdigest}"


def encode_capability_manifest(profile: InvokeProfile) -> dict[str, Any]:
    """Encode one producer-authored capability.manifest.v1 from a registry profile.

    Authority is ``invoke_profiles.INVOKE_PROFILES``. A caller-constructed
    copy is refused so a child-self-declared document cannot mint admission.
    This function never dispatches.
    """
    authoritative = invoke_profile(profile.arm_id, profile.action)
    if authoritative is None or authoritative is not profile:
        raise ValueError("capability manifest requires an authoritative InvokeProfile")
    candidate = {
        "schema": MANIFEST_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "capability_id": profile.capability_id,
        "tier": profile.tier,
        "kind": "arm",
        "tool": {"name": profile.tool_name, "version": profile.tool_version},
        "protocols": ["cli-json"],
        "safety_class": profile.safety_class,
        "side_effects": list(profile.side_effects),
        "default_off": profile.default_off,
        "synthetic_only": profile.synthetic_only,
        "authorized_scope": list(profile.authorized_scope),
        "approval_ref": profile.approval_ref,
        "roe_ref": profile.roe_ref,
        "budget": {
            "timeout_ms": profile.timeout_ms,
            "max_output_bytes": profile.max_output_bytes,
            "max_tool_steps": profile.max_tool_steps,
            "max_spend": profile.max_spend,
        },
        "cleanup": {
            "required": profile.cleanup_required,
            "proof": "none" if not profile.cleanup_required else "artifact-digest",
        },
        "redaction": {
            "fields": list(_MANIFEST_REDACTION["fields"]),
            "env": list(_MANIFEST_REDACTION["env"]),
        },
    }
    parsed = parse_capability_manifest(candidate)
    if parsed.manifest is None:
        raise ValueError("internal capability-manifest encoder produced an invalid envelope")
    payload = parsed.manifest.to_dict()
    reparsed = parse_capability_manifest(payload)
    if reparsed.manifest is None:
        raise ValueError("capability-manifest parser did not agree with encoded document")
    return payload


def encode_capability_manifests() -> dict[str, dict[str, Any]]:
    """Encode the static manifest for every authoritative InvokeProfile."""
    return {
        capability_id: encode_capability_manifest(profile)
        for capability_id, profile in INVOKE_PROFILES.items()
    }


def encode_invoke_result(
    result: Result,
    *,
    profile: InvokeProfile,
    started_at: str,
    finished_at: str,
    attempt_id: str | None = None,
    artifact_dir: ArtifactSink | None = None,
) -> dict[str, Any]:
    """Encode one admitted result using its authoritative action profile."""
    cap = profile.capability_id
    blob = _canonical_bytes(result.output)
    owned = result.output not in (None, "")
    identity_matches = (
        result.arm_id == profile.arm_id and result.action == profile.action
    )
    artifacts = (
        [_artifact(blob, kind="policy-report")] if owned and identity_matches else []
    )
    if result.ok and identity_matches:
        claimed = STATUS_COMPLETE
        coverage = _coverage(attempted=(cap,), complete=(cap,), required=(cap,))
        limitations: tuple[str, ...] = ()
    elif not identity_matches:
        claimed = STATUS_FAILED
        coverage = _coverage(attempted=(cap,), failed=(cap,), required=(cap,))
        limitations = ("arm result identity did not match admitted capability",)
    else:
        claimed = STATUS_FAILED
        coverage = _coverage(attempted=(cap,), failed=(cap,), required=(cap,))
        limitations = ("required arm failed",)
    candidate = _envelope(
        capability_id=cap,
        tool={"name": profile.tool_name, "version": profile.tool_version},
        authorized=profile.authorized_scope,
        touched=profile.touched_scope,
        safety_class=profile.safety_class,
        side_effects=profile.side_effects,
        reserved=_profile_reserved(profile),
        started_at=started_at,
        finished_at=finished_at,
        status=claimed,
        transport_ok=True,
        artifacts=artifacts,
        coverage=coverage,
        limitations=limitations,
        output_bytes=len(blob),
        tool_steps=1,
        cleanup_required=profile.cleanup_required,
        approval_ref=profile.approval_ref,
        roe_ref=profile.roe_ref,
        attempt_id=attempt_id,
    )
    blobs = {item["digest"]: blob for item in artifacts}
    return _admit_with_artifacts(candidate, blobs=blobs, artifact_dir=artifact_dir)


def encode_invoke_failure(
    exc: BaseException,
    *,
    arm_id: str,
    action: str,
    profile: InvokeProfile | None,
    started_at: str,
    finished_at: str,
    attempt_id: str | None = None,
    artifact_dir: ArtifactSink | None = None,
) -> dict[str, Any]:
    """Encode a fail-closed invoke that never produced a transport Result."""
    cap = _capability_id(arm_id, action)
    if profile is not None:
        cap = profile.capability_id
    attempted: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    required: tuple[str, ...] = ()
    if isinstance(exc, (UnknownIdError, UnmanifestedCapabilityError)):
        limitations = ("unknown capability",)
    elif isinstance(exc, NotHeldError):
        unsupported = (cap,)
        limitations = ("held capability is never invocable",)
    elif isinstance(exc, NotAnArmError) and exc.kind == "methodology-only":
        unsupported = (cap,)
        limitations = ("methodology-only is never invocable",)
    elif isinstance(exc, NotInstalledError):
        attempted = (cap,)
        skipped = (cap,)
        required = (cap,)
        limitations = ("arm is not installed",)
    elif isinstance(exc, NotCuratedError):
        unsupported = (cap,)
        required = (cap,)
        limitations = ("arm is not curated",)
    elif isinstance(exc, NotAnArmError):
        unsupported = (cap,)
        required = (cap,)
        limitations = (f"{arm_id} is {exc.kind}, not an arm",)
    elif _is_invalid_args(exc):
        limitations = ("invalid JSON arguments",)
    else:
        attempted = (cap,)
        failed = (cap,)
        required = (cap,)
        limitations = ("invoke failed",)
    candidate = _envelope(
        capability_id=cap,
        tool=_failure_tool(profile),
        authorized=(profile.authorized_scope if profile else _REFUSED_SCOPE),
        touched=(),
        safety_class=(profile.safety_class if profile else "R0"),
        side_effects=("none",),
        reserved=(
            _profile_reserved(profile) if profile is not None else _REFUSED_RESERVED
        ),
        started_at=started_at,
        finished_at=finished_at,
        status=STATUS_FAILED,
        transport_ok=False,
        artifacts=[],
        coverage=_coverage(
            attempted=attempted,
            skipped=skipped,
            unsupported=unsupported,
            failed=failed,
            required=required,
        ),
        limitations=limitations,
        output_bytes=0,
        tool_steps=0,
        cleanup_required=(profile.cleanup_required if profile else False),
        approval_ref=(profile.approval_ref if profile else None),
        roe_ref=(profile.roe_ref if profile else None),
        attempt_id=attempt_id,
    )
    return _admit_with_artifacts(candidate, blobs={}, artifact_dir=artifact_dir)


def encode_range_document(
    document: Mapping[str, Any],
    *,
    started_at: str,
    finished_at: str,
    attempt_id: str | None = None,
    artifact_dir: ArtifactSink | None = None,
) -> dict[str, Any]:
    """Wrap range.lifecycle.v3 as coverage input. Inner ok is not outer status."""
    claimed = document.get("status")
    if claimed not in {STATUS_COMPLETE, STATUS_DEGRADED, STATUS_FAILED}:
        claimed = STATUS_FAILED
    inner = document.get("coverage") if isinstance(document.get("coverage"), dict) else {}
    attempted = _str_tuple(inner.get("attempted"))
    complete = _str_tuple(inner.get("complete"))
    skipped = _str_tuple(inner.get("skipped"))
    failed = _str_tuple(inner.get("error"))
    limitations: list[str] = []
    if skipped:
        limitations.append("optional arm is not installed")
    if failed:
        limitations.append("arm status=error")
    if claimed == STATUS_FAILED and not limitations:
        limitations.append("range lifecycle did not complete")
    blob = _canonical_bytes(dict(document))
    candidate = _envelope(
        capability_id=RANGE_CAPABILITY_ID,
        tool=RANGE_TOOL,
        authorized=RANGE_SCOPE,
        touched=_range_touched(document),
        safety_class="R0",
        side_effects=("local-read",),
        reserved=_RANGE_RESERVED,
        started_at=started_at,
        finished_at=finished_at,
        status=claimed,
        transport_ok=True,
        artifacts=[_artifact(blob, kind="range-report")],
        coverage=_coverage(
            attempted=attempted,
            complete=complete,
            skipped=skipped,
            failed=failed,
        ),
        limitations=tuple(limitations),
        output_bytes=len(blob),
        tool_steps=1,
        cleanup_required=False,
        approval_ref=None,
        roe_ref=ROE_REF,
        attempt_id=attempt_id,
    )
    blobs = {item["digest"]: blob for item in candidate["artifacts"]}
    return _admit_with_artifacts(candidate, blobs=blobs, artifact_dir=artifact_dir)


def encode_range_failure(
    exc: BaseException,
    *,
    started_at: str,
    finished_at: str,
    attempt_id: str | None = None,
    artifact_dir: ArtifactSink | None = None,
) -> dict[str, Any]:
    candidate = _envelope(
        capability_id=RANGE_CAPABILITY_ID,
        tool=RANGE_TOOL,
        authorized=RANGE_SCOPE,
        touched=(),
        safety_class="R0",
        side_effects=("none",),
        reserved=_RANGE_RESERVED,
        started_at=started_at,
        finished_at=finished_at,
        status=STATUS_FAILED,
        transport_ok=False,
        artifacts=[],
        coverage=_coverage(),
        limitations=("range run failed",),
        output_bytes=0,
        tool_steps=0,
        cleanup_required=False,
        approval_ref=None,
        roe_ref=ROE_REF,
        attempt_id=attempt_id,
    )
    return _admit_with_artifacts(candidate, blobs={}, artifact_dir=artifact_dir)


def _admit(candidate: Mapping[str, Any]) -> dict[str, Any]:
    parsed = parse_execution_result(candidate)
    if parsed.result is None:
        raise ValueError("internal execution-result encoder produced an invalid envelope")
    payload = parsed.result.to_dict()
    reparsed = parse_execution_result(payload)
    if reparsed.result is None or reparsed.status != payload["status"]:
        raise ValueError("execution-result parser did not agree with encoded status")
    return payload


def _admit_with_artifacts(
    candidate: Mapping[str, Any],
    *,
    blobs: Mapping[str, bytes],
    artifact_dir: ArtifactSink | None,
) -> dict[str, Any]:
    payload = _admit(candidate)
    if artifact_dir is None:
        return payload
    claimed = [
        item["digest"]
        for item in payload.get("artifacts") or []
        if isinstance(item, dict) and isinstance(item.get("digest"), str)
    ]
    if not claimed:
        return payload
    try:
        for digest in claimed:
            blob = blobs.get(digest)
            if blob is None:
                raise OSError("missing canonical bytes for claimed artifact digest")
            artifact_dir.write(digest, blob)
    except OSError as exc:
        failed = dict(payload)
        # Do not claim bytes this attempt did not deliver. Keep the original
        # status and transport_ok: transport_ok is invocation/response
        # transport, not custody. Parser fail-closes unowned-evidence when
        # the claim stays substantive without owned artifacts.
        failed["artifacts"] = []
        failed["limitations"] = list(
            dict.fromkeys(
                [*(failed.get("limitations") or []), "artifact handoff failed"]
            )
        )
        envelope = _admit(failed)
        raise ArtifactHandoffError("artifact handoff failed", envelope=envelope) from exc
    return payload


def _envelope(
    *,
    capability_id: str,
    tool: Mapping[str, str],
    authorized: Sequence[str],
    touched: Sequence[str],
    safety_class: str,
    side_effects: Sequence[str],
    reserved: Mapping[str, Any],
    started_at: str,
    finished_at: str,
    status: str,
    transport_ok: bool,
    artifacts: Sequence[Mapping[str, str]],
    coverage: Mapping[str, list[str]],
    limitations: Sequence[str],
    output_bytes: int,
    tool_steps: int,
    cleanup_required: bool,
    approval_ref: str | None,
    roe_ref: str | None,
    attempt_id: str | None = None,
) -> dict[str, Any]:
    finished = finished_at if finished_at >= started_at else started_at
    attempt = parse_attempt_id(attempt_id)
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "capability_id": capability_id,
        "tool": {"name": tool["name"], "version": tool["version"]},
    }
    if attempt is not None:
        payload["attempt_id"] = attempt
    payload.update(
        {
            "scope": {
                "authorized": list(authorized),
                "touched": list(dict.fromkeys(touched)),
            },
            "safety_class": safety_class,
            "side_effects": list(side_effects),
            "approval_ref": approval_ref,
            "roe_ref": roe_ref,
            "budget": {
                "reserved": {
                    "timeout_ms": reserved["timeout_ms"],
                    "max_output_bytes": reserved["max_output_bytes"],
                    "max_tool_steps": reserved["max_tool_steps"],
                    "max_spend": reserved["max_spend"],
                },
                "spent": {
                    "elapsed_ms": _elapsed_ms(started_at, finished),
                    "output_bytes": max(output_bytes, 0),
                    "tool_steps": max(tool_steps, 0),
                    "spend": 0,
                },
            },
            "started_at": started_at,
            "finished_at": finished,
            "status": status,
            "transport_ok": transport_ok,
            "artifacts": [dict(item) for item in artifacts],
            "coverage": dict(coverage),
            "cleanup": {
                "required": cleanup_required,
                "proof_digest": None,
                "residual": False,
            },
            "limitations": list(dict.fromkeys(item for item in limitations if item)),
        }
    )
    return payload


def _coverage(
    *,
    attempted: Sequence[str] = (),
    complete: Sequence[str] = (),
    skipped: Sequence[str] = (),
    unsupported: Sequence[str] = (),
    failed: Sequence[str] = (),
    required: Sequence[str] = (),
) -> dict[str, list[str]]:
    return {
        "attempted": _unique(attempted),
        "complete": _unique(complete),
        "skipped": _unique(skipped),
        "unsupported": _unique(unsupported),
        "failed": _unique(failed),
        "required": _unique(required),
    }


def _artifact(blob: bytes, *, kind: str) -> dict[str, str]:
    return {
        "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
        "kind": kind,
        "redaction": "credentials-stripped",
    }


def _capability_id(arm_id: str, action: str) -> str:
    candidate = f"{arm_id}.{action}"
    if _CAPABILITY_ID_RE.match(candidate):
        return candidate
    return "unknown.capability"


def _profile_reserved(profile: InvokeProfile) -> dict[str, Any]:
    return {
        "timeout_ms": profile.timeout_ms,
        "max_output_bytes": profile.max_output_bytes,
        "max_tool_steps": profile.max_tool_steps,
        "max_spend": profile.max_spend,
    }


def _failure_tool(profile: InvokeProfile | None) -> dict[str, str]:
    if profile is not None:
        return {"name": profile.tool_name, "version": profile.tool_version}
    return {"name": PACKAGE_NAME, "version": PACKAGE_VERSION}


def _range_touched(document: Mapping[str, Any]) -> tuple[str, ...]:
    fixtures = document.get("fixtures")
    if not isinstance(fixtures, list):
        return RANGE_SCOPE
    touched: list[str] = []
    for row in fixtures:
        if not isinstance(row, dict):
            continue
        uri = _RANGE_SCOPE_BY_FIXTURE.get(str(row.get("id") or ""))
        if uri:
            touched.append(uri)
    return tuple(dict.fromkeys(touched)) or RANGE_SCOPE


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _elapsed_ms(started_at: str, finished_at: str) -> int:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        start = datetime.strptime(started_at, fmt)
        finish = datetime.strptime(finished_at, fmt)
    except ValueError:
        return 0
    delta = int((finish - start).total_seconds() * 1000)
    return max(delta, 0)


def _is_invalid_args(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "invalid json" in text or "json arguments" in text


def _str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item)


def _unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(item for item in values if item))
