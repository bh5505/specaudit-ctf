"""Curated leonidas arm: declarative cloud attack corpus reads."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Mapping

import yaml
from yaml.events import AliasEvent

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..mcp_client import redact
from ..strict_data import (
    StrictDataError,
    StrictMappingMixin,
    bounded_tree_refusal,
    secret_shaped_key,
    strict_json_loads,
)
from .policy import (
    ALLOWED_ACTIONS,
    ARM_ID,
    ARG_KEYS,
    ARMING,
    CAVEATS,
    LIST_ACTIONS,
    MAX_CORPUS_BYTES,
    MAX_DOCUMENT_DEPTH,
    MAX_DOCUMENT_NODES,
    MAX_OUTPUT_CHARS,
    MAX_RECORDS,
    MAX_RESULTS,
    args_refusal,
    corpus_refusal,
    limit_refusal,
)


class LeonidasArm:
    """Specialized transport for catalog id leonidas.

    First-party in-process read arm: a bounded reader over a local
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
            return _fail(
                spec,
                action,
                f"action {action!r} is not on the allowlist "
                "(offline reads over a local Leonidas corpus only; "
                "there is no dispatch tier)",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return _fail(spec, action, refusal)
        path, corpus_refused = corpus_refusal(payload.get("corpus"))
        if corpus_refused:
            return _fail(spec, action, corpus_refused)
        if path is None:
            return _fail(spec, action, "corpus path validation failed")
        try:
            techniques, source = _load_corpus(path)
        except _CorpusError as exc:
            return _fail(spec, action, str(exc))
        except Exception:
            return _fail(spec, action, "corpus could not be parsed safely")
        if action == "technique":
            return self._technique(spec, payload, techniques, source)
        # action == "list_techniques"
        return self._list_techniques(spec, payload, techniques, source)

    # -- action handlers --------------------------------------------------

    def _technique(
        self,
        spec: ArmSpec,
        payload: dict,
        techniques: list[dict],
        source: dict[str, Any],
    ) -> Result:
        """Return the full definition for a single technique."""
        tid = _opt_str(payload.get("technique_id"))
        name = _opt_str(payload.get("name"))
        if tid is not None:
            match = _find_technique(techniques, technique_id=tid)
        else:
            matches = [
                technique
                for technique in techniques
                if str(technique.get("name", "")).strip().casefold()
                == (name or "").casefold()
            ]
            if len(matches) > 1:
                return _fail(
                    spec,
                    "technique",
                    "multiple techniques match args.name; use args.technique_id",
                )
            match = matches[0] if matches else None
        if match is None:
            identifier = tid or name
            return _fail(
                spec,
                "technique",
                f"technique {identifier!r} not found in this corpus",
            )
        return _ok(spec, "technique", {"technique": match, "source": source})

    def _list_techniques(
        self,
        spec: ArmSpec,
        payload: dict,
        techniques: list[dict],
        source: dict[str, Any],
    ) -> Result:
        """Return a summary list of techniques (capped at limit)."""
        raw_limit = limit_refusal(payload.get("limit"))
        if isinstance(raw_limit, str):
            return _fail(spec, "list_techniques", raw_limit)
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
        return _ok(
            spec,
            "list_techniques",
            {
                "count": len(summaries),
                "total": len(techniques),
                "returned": len(summaries),
                "capped": len(summaries) < len(techniques),
                "techniques": summaries,
                "source": source,
            },
        )

    def _list_tools(
        self, spec: ArmSpec, action: str, payload: dict
    ) -> Result:
        if payload:
            return _fail(spec, action, "list_tools takes no caller arguments")
        return _ok(
            spec,
            action,
            {
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": {
                    key: sorted(vals) for key, vals in ARG_KEYS.items()
                },
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
        )


# -- corpus loading -------------------------------------------------------


class _CorpusError(Exception):
    """Raised when the corpus file cannot be loaded."""


def _load_corpus(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load a Leonidas corpus from a local JSON or YAML file.

    Accepted shapes:
    - A JSON file containing a top-level array of technique dicts.
    - A YAML file with a ``techniques`` key whose value is a list.

    Returns the list of technique dicts, or raises ``_CorpusError``.
    """
    try:
        with path.open("rb") as handle:
            raw_bytes = handle.read(MAX_CORPUS_BYTES + 1)
    except OSError as exc:
        raise _CorpusError("could not read corpus") from exc
    if len(raw_bytes) > MAX_CORPUS_BYTES:
        raise _CorpusError(f"corpus exceeds the {MAX_CORPUS_BYTES} byte read cap")
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _CorpusError("corpus is not valid UTF-8") from exc

    suffix = path.suffix.lower()

    # --- JSON ---
    if suffix == ".json":
        try:
            data = strict_json_loads(raw)
        except StrictDataError as exc:
            raise _CorpusError(str(exc)) from exc
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise _CorpusError("invalid JSON in corpus") from exc

    # --- YAML ---
    elif suffix in (".yaml", ".yml"):
        try:
            data = yaml.load(raw, Loader=_BoundedSafeLoader)
        except StrictDataError as exc:
            raise _CorpusError(str(exc)) from exc
        except (yaml.YAMLError, RecursionError, ValueError) as exc:
            raise _CorpusError("invalid YAML in corpus") from exc

    else:
        raise _CorpusError("unsupported corpus format")

    refusal = _tree_refusal(data)
    if refusal:
        raise _CorpusError(f"corpus {refusal}")
    if _contains_secret_shaped_field(data):
        raise _CorpusError("corpus contains a secret-shaped field")
    if isinstance(data, list):
        techniques = data
    elif isinstance(data, dict) and isinstance(data.get("techniques"), list):
        techniques = data["techniques"]
    else:
        raise _CorpusError(
            "corpus must be an array or a mapping with a 'techniques' list"
        )
    return _validate_list(techniques), _source(raw_bytes)


def _validate_list(data: list) -> list[dict]:
    """Validate the fields used by lookup and summary actions."""
    if len(data) > MAX_RECORDS:
        raise _CorpusError(f"corpus exceeds the {MAX_RECORDS} technique cap")
    out: list[dict] = []
    seen: set[str] = set()
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise _CorpusError(
                f"corpus entry {idx} is not a mapping "
                f"(got {type(item).__name__})"
            )
        technique_id = item.get("technique_id")
        name = item.get("name")
        if not isinstance(technique_id, str) or not technique_id.strip():
            raise _CorpusError(
                f"corpus entry {idx} requires a non-empty string technique_id"
            )
        if not isinstance(name, str) or not name.strip():
            raise _CorpusError(f"corpus entry {idx} requires a non-empty string name")
        for key in ("platform", "severity", "executor"):
            if key in item and item[key] is not None and not isinstance(item[key], str):
                raise _CorpusError(
                    f"corpus entry {idx} field {key!r} must be a string or null"
                )
        normalized_id = technique_id.strip()
        if normalized_id in seen:
            raise _CorpusError(f"corpus contains duplicate technique_id {normalized_id!r}")
        seen.add(normalized_id)
        normalized = dict(item)
        normalized["technique_id"] = normalized_id
        normalized["name"] = name.strip()
        out.append(normalized)
    return out


class _BoundedSafeLoader(StrictMappingMixin, yaml.SafeLoader):
    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._node_count = 0
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError("YAML aliases and anchors are not allowed")
        self._node_count += 1
        if self._node_count > MAX_DOCUMENT_NODES:
            raise yaml.YAMLError("YAML document exceeds the node cap")
        self._depth += 1
        if self._depth > MAX_DOCUMENT_DEPTH:
            self._depth -= 1
            raise yaml.YAMLError("YAML document exceeds the nesting-depth cap")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def _tree_refusal(data: Any) -> str | None:
    return bounded_tree_refusal(
        data,
        max_nodes=MAX_DOCUMENT_NODES,
        max_depth=MAX_DOCUMENT_DEPTH,
        max_text_chars=MAX_OUTPUT_CHARS,
    )


def _contains_secret_shaped_field(data: Any) -> bool:
    stack = [data]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            if any(secret_shaped_key(key) for key in value):
                return True
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return False


def _source(raw: bytes) -> dict[str, Any]:
    return {
        "kind": "operator-file",
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


# -- helpers --------------------------------------------------------------


def _find_technique(
    techniques: list[dict],
    *,
    technique_id: str | None = None,
    name: str | None = None,
) -> dict | None:
    """Exact-match search used for identifier lookups."""
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


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    try:
        rendered = json.dumps(
            output, sort_keys=True, ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError):
        return _fail(spec, action, "result could not be encoded safely")
    if len(rendered) > MAX_OUTPUT_CHARS:
        return _fail(
            spec,
            action,
            f"result exceeds the {MAX_OUTPUT_CHARS} character output cap; narrow the lookup",
        )
    return Result(ok=True, arm_id=spec.id, action=action, output=output, error=None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(
        ok=False,
        arm_id=spec.id,
        action=action,
        output=None,
        error=redact(str(error))[:MAX_OUTPUT_CHARS],
    )
