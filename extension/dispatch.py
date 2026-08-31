"""Transport-neutral invoke/range dispatch shared by CLI JSON and stdio MCP.

X4-PUB parity is by construction: both transports call these functions with
the same logical inputs, so ``python -m extension invoke ...`` and the MCP
``invoke`` tool emit byte-equivalent ``execution-result.v1`` envelopes
modulo wall-clock fields. The transports differ only in how they surface
:attr:`DispatchOutcome.exit_code` (process exit vs ``isError``) and in
argument shape checks that exist only on one transport (for example the
CLI's JSON-string parsing of ``args``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contract import (
    CATALOG_KIND_ARM,
    TIER_HELD,
    Extension,
    ExtensionError,
    NotCuratedError,
    NotHeldError,
    UnmanifestedCapabilityError,
)
from .encode import (
    ArtifactHandoffError,
    ArtifactSink,
    AttemptContractError,
    bind_artifact_dir,
    encode_invoke_failure,
    encode_invoke_result,
    encode_range_document,
    encode_range_failure,
    parse_attempt_id,
    utc_now,
)
from .invoke_profiles import invoke_profile

STATUS_COMPLETE = "complete"


@dataclass(frozen=True)
class DispatchOutcome:
    """One dispatch result shared by both transports.

    ``envelope`` is ``None`` only for pre-dispatch attempt/artifact contract
    errors, which never reach a tool execution on either transport: the CLI
    prints ``stderr_line`` and exits 2 without stdout; MCP maps
    ``contract_error`` to JSON-RPC ``-32602`` invalid params.
    """

    envelope: Mapping[str, Any] | None
    exit_code: int
    stderr_line: str | None
    contract_error: AttemptContractError | None = None


def dispatch_invoke(
    extension: Extension,
    *,
    arm_id: str,
    action: str,
    args: Mapping[str, Any] | None = None,
    args_error: ExtensionError | None = None,
    attempt_id: str | None = None,
    artifact_dir: str | None = None,
) -> DispatchOutcome:
    """Run one bounded invoke and encode its execution-result.v1 envelope.

    ``args_error`` carries the CLI's JSON-string parse failure so the shared
    failure encoder owns the "invalid JSON arguments" envelope; MCP callers
    never pass it (their arguments arrive pre-parsed).
    """
    sink: ArtifactSink | None = None
    try:
        try:
            parsed_attempt = parse_attempt_id(attempt_id)
            sink = bind_artifact_dir(artifact_dir, attempt_id=parsed_attempt)
        except AttemptContractError as exc:
            return DispatchOutcome(None, 2, str(exc), exc)
        started = utc_now()
        profile = None
        try:
            spec = extension.arm_spec(arm_id)
            if spec.tier == TIER_HELD:
                raise NotHeldError(spec.id, spec.held_reason)
            if not spec.curated:
                raise NotCuratedError(spec.id)
            profile = invoke_profile(arm_id, action)
            if profile is None:
                raise UnmanifestedCapabilityError(arm_id, action)
            if args_error is not None:
                raise args_error
            payload = dict(args) if args is not None else {}
            result = extension.invoke(arm_id, action, payload)
        except ExtensionError as exc:
            envelope = encode_invoke_failure(
                exc,
                arm_id=arm_id,
                action=action,
                profile=profile,
                started_at=started,
                finished_at=utc_now(),
                attempt_id=parsed_attempt,
                artifact_dir=sink,
            )
            return DispatchOutcome(envelope, 2, str(exc))
        try:
            envelope = encode_invoke_result(
                result,
                profile=profile,
                started_at=started,
                finished_at=utc_now(),
                attempt_id=parsed_attempt,
                artifact_dir=sink,
            )
        except ArtifactHandoffError as exc:
            return DispatchOutcome(exc.envelope, 2, str(exc))
        stderr_line = None
        if not result.ok and result.error:
            stderr_line = f"Invoke failed for {arm_id}.{action}: {result.error}"
        return DispatchOutcome(envelope, 0 if result.ok else 1, stderr_line)
    finally:
        if sink is not None:
            sink.close()


def dispatch_range(
    extension: Extension,
    *,
    seed: int | None = None,
    arm_ids: Sequence[str] | None = None,
    attempt_id: str | None = None,
    artifact_dir: str | None = None,
) -> DispatchOutcome:
    """Run the synthetic range and encode its execution-result.v1 envelope."""
    # Imported here, not at module top: the sealed CLI-JSON invocation never
    # touches the range runner, and the measured runtime bundle's producer
    # closure is exactly what that invocation imports (runtime/_tracer.py).
    from .range.runner import RangeError, run_range

    sink: ArtifactSink | None = None
    try:
        try:
            parsed_attempt = parse_attempt_id(attempt_id)
            sink = bind_artifact_dir(artifact_dir, attempt_id=parsed_attempt)
        except AttemptContractError as exc:
            return DispatchOutcome(None, 2, str(exc), exc)
        if arm_ids is not None:
            curated = {
                entry.id
                for entry in extension.list_entries()
                if entry.kind == CATALOG_KIND_ARM and entry.curated
            }
            for arm in arm_ids:
                if arm not in curated:
                    message = f"run_range arm_ids must be curated arms: {arm}"
                    envelope = encode_range_failure(
                        RangeError(message),
                        started_at=utc_now(),
                        finished_at=utc_now(),
                        attempt_id=parsed_attempt,
                    )
                    return DispatchOutcome(envelope, 2, message)
        started = utc_now()
        try:
            document = run_range(
                seed=seed, extension=extension, arm_ids=arm_ids
            )
        except RangeError as exc:
            envelope = encode_range_failure(
                exc,
                started_at=started,
                finished_at=utc_now(),
                attempt_id=parsed_attempt,
            )
            return DispatchOutcome(envelope, 2, str(exc))
        try:
            envelope = encode_range_document(
                document,
                started_at=started,
                finished_at=utc_now(),
                attempt_id=parsed_attempt,
                artifact_dir=sink,
            )
        except ArtifactHandoffError as exc:
            return DispatchOutcome(exc.envelope, 2, str(exc))
        status = envelope.get("status")
        return DispatchOutcome(envelope, 0 if status == STATUS_COMPLETE else 1, None)
    finally:
        if sink is not None:
            sink.close()
