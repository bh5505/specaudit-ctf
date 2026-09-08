"""Curated leonidas arm: declarative cloud attack corpus reads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

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
    corpus_refusal,
    limit_refusal,
)


class LeonidasArm:
    """Specialized transport for catalog id leonidas.

    First-party in-process read arm: a stdlib reader over a local
    Leonidas cloud attack corpus with no subprocess and no endpoint.
    ``installed`` reports handler presence only — the corpus is
    per-invoke caller data (args.corpus), the same contract as every
    other file-consuming arm.

    Executor bodies in the corpus are treated as inert text: they are
    returned verbatim but never executed.  No cloud credentials are
    present on the read path.
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
                error=(
                    f"action {action!r} is not on the allowlist "
                    "(offline reads over a local Leonidas corpus only; "
                    "there is no dispatch tier)"
                ),
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
        path, corpus_refused = corpus_refusal(payload.get("corpus"))
        if corpus_refused:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=corpus_refused,
            )
        assert path is not None  # noqa: S101 — guarded by corpus_refused
        try:
            techniques = _load_corpus(path)
        except _CorpusError as exc:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=redact(str(exc)),
            )
        if action == "technique":
            return self._technique(spec, payload, techniques)
        # action == "list_techniques"
        return self._list_techniques(spec, payload, techniques)

    # -- action handlers --------------------------------------------------

    def _technique(
        self, spec: ArmSpec, payload: dict, techniques: list[dict]
    ) -> Result:
        """Return the full definition for a single technique."""
        tid = _opt_str(payload.get("technique_id"))
        name = _opt_str(payload.get("name"))
        match = _find_technique(techniques, technique_id=tid, name=name)
        if match is None:
            identifier = tid or name
            return Result(
                ok=False,
                arm_id=spec.id,
                action="technique",
                output=None,
                error=f"technique {identifier!r} not found in this corpus",
            )
        text = json.dumps(match, sort_keys=True, default=str)
        if len(text) > MAX_OUTPUT_CHARS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action="technique",
                output=None,
                error=(
                    f"result exceeds the {MAX_OUTPUT_CHARS} character "
                    "output cap; narrow the lookup"
                ),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action="technique",
            output=match,
            error=None,
        )

    def _list_techniques(
        self, spec: ArmSpec, payload: dict, techniques: list[dict]
    ) -> Result:
        """Return a summary list of techniques (capped at limit)."""
        raw_limit = limit_refusal(payload.get("limit"))
        if isinstance(raw_limit, str):
            return Result(
                ok=False,
                arm_id=spec.id,
                action="list_techniques",
                output=None,
                error=raw_limit,
            )
        limit = raw_limit
        summaries: list[dict[str, Any]] = []
        for tech in techniques[:limit]:
            summaries.append(
                {
                    "technique_id": tech.get("technique_id", ""),
                    "name": tech.get("name", ""),
                    "platform": tech.get("platform", ""),
                    "severity": tech.get("severity", ""),
                }
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action="list_techniques",
            output={
                "count": len(summaries),
                "total": len(techniques),
                "techniques": summaries,
            },
            error=None,
        )

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
                "arg_keys": {
                    key: sorted(vals) for key, vals in ARG_KEYS.items()
                },
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )


# -- corpus loading -------------------------------------------------------


class _CorpusError(Exception):
    """Raised when the corpus file cannot be loaded."""


def _load_corpus(path: Path) -> list[dict]:
    """Load a Leonidas corpus from a local JSON or YAML file.

    Accepted shapes:
    - A JSON file containing a top-level array of technique dicts.
    - A YAML file with a ``techniques`` key whose value is a list.

    Returns the list of technique dicts, or raises ``_CorpusError``.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise _CorpusError(f"could not read corpus: {exc}") from exc

    suffix = path.suffix.lower()

    # --- JSON ---
    if suffix == ".json":
        try:
            data = json.loads(raw_bytes)
        except (json.JSONDecodeError, ValueError) as exc:
            raise _CorpusError(f"invalid JSON in corpus: {exc}") from exc
        if isinstance(data, list):
            return _validate_list(data)
        if isinstance(data, dict):
            techniques = data.get("techniques")
            if isinstance(techniques, list):
                return _validate_list(techniques)
        raise _CorpusError(
            "JSON corpus must be an array of techniques or a mapping "
            "with a 'techniques' key"
        )

    # --- YAML ---
    if suffix in (".yaml", ".yml"):
        if yaml is None:
            raise _CorpusError(
                "PyYAML is required to load YAML corpus files "
                "(pip install pyyaml)"
            )
        try:
            data = yaml.safe_load(raw_bytes)
        except yaml.YAMLError as exc:
            raise _CorpusError(f"invalid YAML in corpus: {exc}") from exc
        if isinstance(data, dict):
            techniques = data.get("techniques")
            if isinstance(techniques, list):
                return _validate_list(techniques)
        if isinstance(data, list):
            return _validate_list(data)
        raise _CorpusError(
            "YAML corpus must contain a 'techniques' list or be a "
            "top-level list"
        )

    # suffix guard (should be unreachable after policy validation)
    raise _CorpusError(
        f"unsupported corpus format: {suffix!r}; expected .json, .yaml, or .yml"
    )


def _validate_list(data: list) -> list[dict]:
    """Ensure every element in the corpus list is a dict."""
    out: list[dict] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise _CorpusError(
                f"corpus entry {idx} is not a mapping "
                f"(got {type(item).__name__})"
            )
        out.append(item)
    return out


# -- helpers --------------------------------------------------------------


def _find_technique(
    techniques: list[dict],
    *,
    technique_id: str | None = None,
    name: str | None = None,
) -> dict | None:
    """Exact-match search by technique_id or name (first match wins)."""
    for tech in techniques:
        if technique_id is not None:
            if str(tech.get("technique_id", "")).strip() == technique_id:
                return tech
        if name is not None:
            if str(tech.get("name", "")).strip().lower() == name.lower():
                return tech
    return None


def _opt_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()
