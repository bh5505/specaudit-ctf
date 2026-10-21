"""Shared CLI and MCP dispatch for CTF arms and the synthetic range."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contract import CATALOG_KIND_ARM, Extension, ExtensionError, Result


@dataclass(frozen=True)
class DispatchOutcome:
    document: Mapping[str, Any]
    exit_code: int
    stderr_line: str | None = None


def _result_document(result: Result, arm_id: str, action: str) -> dict[str, Any]:
    if (
        not isinstance(result, Result)
        or type(result.ok) is not bool
        or result.arm_id != arm_id
        or result.action != action
        or (result.ok and result.error is not None)
        or (not result.ok and not isinstance(result.error, str))
    ):
        raise ValueError("arm returned an invalid result")
    return result.to_dict()


def dispatch_invoke(
    extension: Extension,
    *,
    arm_id: str,
    action: str,
    args: Mapping[str, Any] | None = None,
    args_error: Exception | None = None,
) -> DispatchOutcome:
    """Invoke the named handler and return its execution result directly."""
    if args_error is not None:
        return DispatchOutcome(Result(False, arm_id, action, error=str(args_error)).to_dict(), 2)
    try:
        result = extension.invoke(arm_id, action, args)
        document = _result_document(result, arm_id, action)
    except ExtensionError as exc:
        return DispatchOutcome(Result(False, arm_id, action, error=str(exc)).to_dict(), 2)
    except Exception:
        return DispatchOutcome(
            Result(False, arm_id, action, error="arm execution failed").to_dict(), 1,
            "arm execution failed",
        )
    return DispatchOutcome(document, 0 if result.ok else 1)


def dispatch_range(
    extension: Extension,
    *,
    seed: int | None = None,
    arm_ids: Sequence[str] | None = None,
) -> DispatchOutcome:
    """Run the shipped synthetic fixtures and return their report directly."""
    from .range.runner import RangeError, run_range

    if arm_ids is not None:
        for arm_id in arm_ids:
            try:
                entry = extension.describe(arm_id)
            except ExtensionError as exc:
                return DispatchOutcome({"status": "failed", "error": str(exc)}, 2)
            if entry.kind != CATALOG_KIND_ARM:
                return DispatchOutcome(
                    {"status": "failed", "error": f"{arm_id} is not an arm"}, 2
                )
    try:
        document = run_range(seed=seed, extension=extension, arm_ids=arm_ids)
    except RangeError as exc:
        return DispatchOutcome({"status": "failed", "error": str(exc)}, 2)
    except Exception:
        return DispatchOutcome({"status": "failed", "error": "range execution failed"}, 1)
    if not isinstance(document, dict):
        return DispatchOutcome({"status": "failed", "error": "invalid range result"}, 1)
    return DispatchOutcome(document, 0 if document.get("status") == "complete" else 1)
