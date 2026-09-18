"""Strict structured-data decoders shared by caller-file read arms.

The standard JSON and PyYAML decoders accept duplicate mapping keys and keep
the last value.  They also admit non-finite or underflowed numbers and escaped
lone surrogates that cannot be emitted as strict UTF-8.  Those behaviors are
unsafe for evidence-like inputs.  These helpers make ambiguity, lossy scalar
conversion, invalid Unicode scalar text, and excessive structure hard parse
failures before an arm applies its schema.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any


MAX_JSON_DOCUMENT_NODES = 50_000
MAX_JSON_DOCUMENT_DEPTH = 64
MAX_INTEGER_BITS = 4_096

_SECRET_TOKENS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "passcode",
        "passphrase",
        "secret",
        "token",
        "credential",
        "credentials",
        "hash",
    }
)
_SECRET_COMPOUNDS = frozenset(
    {
        "privatekey",
        "apikey",
        "accesskey",
        "dbpass",
        "userpass",
        "adminpass",
        "masterkey",
        "encryptionkey",
        "recoverykey",
        "signingkey",
        "clientkey",
    }
)
_SECRET_VALUE_SUFFIXES = frozenset(
    {
        "value",
        "text",
        "data",
        "bytes",
        "material",
        "contents",
        "content",
        "raw",
        "key",
        "id",
        "identifier",
    }
)
_NON_SECRET_SUFFIXES = frozenset(
    {
        "policy",
        "policyid",
        "length",
        "minlength",
        "maxlength",
        "age",
        "minage",
        "maxage",
        "minimumage",
        "maximumage",
        "history",
        "historysize",
        "historylength",
        "historycount",
        "complexity",
        "complexityenabled",
        "expiration",
        "expiry",
        "rotation",
        "rotationinterval",
        "rotationschedule",
        "algorithm",
        "type",
        "enabled",
        "required",
        "requirement",
        "requirements",
        "count",
        "lifetime",
        "provider",
        "guard",
        "guardenabled",
    }
)


class StrictDataError(ValueError):
    """A structured document is ambiguous or outside the strict grammar."""


def _strict_utf8_refusal(value: str) -> str | None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return "contains text that is not valid Unicode scalar data"
    return None


def bounded_tree_refusal(
    data: Any,
    *,
    max_nodes: int,
    max_depth: int,
    max_text_chars: int,
) -> str | None:
    """Return a safe refusal for an untrusted decoded value tree.

    The byte and composition caps on caller files do not cover direct Python
    arguments, and YAML can materialize integers whose decimal representation
    exceeds Python's guarded conversion limit.  Bound both scalar size and
    structure before callers compare, search, or JSON-encode the tree.
    """

    stack = [(data, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            return "exceeds the document node cap"
        if depth > max_depth:
            return "exceeds the document nesting-depth cap"
        if isinstance(value, dict):
            for key in value:
                if not isinstance(key, str):
                    return "contains a non-string mapping key"
                refusal = _strict_utf8_refusal(key)
                if refusal:
                    return refusal
                if len(key) > max_text_chars:
                    return "contains a mapping key exceeding the text cap"
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            refusal = _strict_utf8_refusal(value)
            if refusal:
                return refusal
            if len(value) > max_text_chars:
                return "contains a string exceeding the text cap"
        elif isinstance(value, bool) or value is None:
            continue
        elif isinstance(value, int):
            if value.bit_length() > MAX_INTEGER_BITS:
                return "contains an integer exceeding the magnitude cap"
        elif isinstance(value, float):
            if not math.isfinite(value):
                return "contains a non-finite number"
        else:
            return f"contains unsupported value type {type(value).__name__}"
    return None


def secret_shaped_key(value: str) -> bool:
    """Return whether a field name plausibly carries credential material.

    Common policy metadata such as password length, hash algorithm, and
    Credential Guard remains usable; opaque or value-bearing secret names fail
    closed.  The check handles separated, camel-case, and collapsed names.
    """

    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    tokens = [
        token.casefold()
        for token in re.split(r"[^A-Za-z0-9]+", separated)
        if token
    ]
    collapsed = "".join(tokens)
    for index, token in enumerate(tokens):
        if token not in _SECRET_TOKENS:
            continue
        suffix = "".join(tokens[index + 1 :])
        if not suffix:
            return True
        if any(suffix.startswith(item) for item in _SECRET_VALUE_SUFFIXES):
            return True
        if suffix not in _NON_SECRET_SUFFIXES:
            return True

    # ``pass`` is intentionally token-only: substring matching it would turn
    # ordinary fields such as ``compass`` and ``bypass`` into secret fields.
    collapsed_markers = (_SECRET_TOKENS - {"pass"}) | _SECRET_COMPOUNDS
    for marker in collapsed_markers:
        start = collapsed.find(marker)
        while start >= 0:
            suffix = collapsed[start + len(marker) :]
            if not suffix or any(
                suffix.startswith(item) for item in _SECRET_VALUE_SUFFIXES
            ):
                return True
            if suffix not in _NON_SECRET_SUFFIXES:
                return True
            start = collapsed.find(marker, start + 1)
    return False


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StrictDataError("duplicate mapping key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise StrictDataError("non-finite JSON numbers are not allowed")


def _float_underflows(value: str, parsed: float) -> bool:
    if parsed != 0.0:
        return False
    mantissa = re.split(r"[eE]", value, maxsplit=1)[0]
    return any(char in "123456789" for char in mantissa)


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise StrictDataError("non-finite JSON numbers are not allowed")
    if _float_underflows(value, parsed):
        raise StrictDataError("floating-point number underflows the supported range")
    return parsed


def _validate_yaml_float(value: str) -> None:
    """Refuse non-finite or underflowed values in PyYAML's float grammar."""

    normalized = value.replace("_", "").casefold()
    sign = -1.0 if normalized.startswith("-") else 1.0
    unsigned = normalized[1:] if normalized.startswith(("+", "-")) else normalized
    if unsigned in {".nan", ".inf"}:
        raise StrictDataError("non-finite YAML numbers are not allowed")
    if ":" in unsigned:
        digits = [float(part) for part in reversed(unsigned.split(":"))]
        base = 1.0
        parsed = 0.0
        for digit in digits:
            parsed += digit * base
            base *= 60.0
        parsed *= sign
    else:
        parsed = float(normalized)
    if not math.isfinite(parsed):
        raise StrictDataError("non-finite YAML numbers are not allowed")
    if _float_underflows(normalized, parsed):
        raise StrictDataError("floating-point number underflows the supported range")


def _preflight_json_structure(
    document: str,
    *,
    max_nodes: int = MAX_JSON_DOCUMENT_NODES,
    max_depth: int = MAX_JSON_DOCUMENT_DEPTH,
) -> None:
    """Bound JSON structure before the decoder materializes Python objects.

    The lexical pass counts the root, each object value, and each array element
    while ignoring object keys and string contents.  That matches the decoded
    value-tree node model without first allocating that tree.
    """

    in_string = False
    escaped = False
    stack: list[str] = []
    nodes = 1 if document.strip() else 0
    for offset, char in enumerate(document):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char in "[{":
            stack.append(char)
            if len(stack) > max_depth:
                raise StrictDataError("JSON document exceeds the nesting-depth cap")
            if char == "[":
                next_offset = offset + 1
                while (
                    next_offset < len(document)
                    and document[next_offset].isspace()
                ):
                    next_offset += 1
                if next_offset < len(document) and document[next_offset] != "]":
                    nodes += 1
        elif char in "]}":
            if stack:
                stack.pop()
        elif char == ":" and stack and stack[-1] == "{":
            nodes += 1
        elif char == "," and stack and stack[-1] == "[":
            nodes += 1
        if nodes > max_nodes:
            raise StrictDataError("JSON document exceeds the node cap")


def strict_json_loads(
    document: str,
    *,
    max_nodes: int = MAX_JSON_DOCUMENT_NODES,
    max_depth: int = MAX_JSON_DOCUMENT_DEPTH,
) -> Any:
    """Decode bounded JSON, refusing duplicates and non-finite numbers."""

    _preflight_json_structure(
        document, max_nodes=max_nodes, max_depth=max_depth
    )

    value = json.loads(
        document,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_json_constant,
        parse_float=_finite_json_float,
    )
    refusal = bounded_tree_refusal(
        value,
        max_nodes=max_nodes,
        max_depth=max_depth,
        # A decoded JSON string cannot contain more characters than the
        # source document; this keeps the post-decode pass focused on scalar
        # safety without imposing a new source-size policy.
        max_text_chars=max(1, len(document)),
    )
    if refusal:
        raise StrictDataError(refusal)
    return value


class StrictMappingMixin:
    """PyYAML loader mixin that refuses duplicate mapping keys.

    Place this mixin before ``yaml.SafeLoader`` in the loader's bases.
    """

    def construct_scalar(self, node: Any) -> Any:
        value = super().construct_scalar(node)
        if isinstance(value, str):
            refusal = _strict_utf8_refusal(value)
            if refusal:
                raise StrictDataError(refusal)
            if getattr(node, "tag", None) == "tag:yaml.org,2002:float":
                _validate_yaml_float(value)
        return value

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        # SafeConstructor normally flattens merge keys before constructing the
        # mapping.  Preserve that behavior, then reject collisions in the
        # resulting sequence rather than silently applying last-value-wins.
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError as exc:
                raise StrictDataError("mapping key is not hashable") from exc
            if key in mapping:
                raise StrictDataError("duplicate mapping key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


class BoundedYamlNodeMixin:
    """PyYAML composition guard for aliases, anchors, size, and depth.

    Subclasses must set ``strict_alias_event_type`` to the PyYAML
    ``AliasEvent`` class and place this mixin before ``yaml.SafeLoader``.
    Counting during composition prevents a large document from first becoming
    a large Python object and only then being rejected by schema validation.
    """

    strict_alias_event_type: Any = None
    max_document_nodes = 50_000
    max_document_depth = 64

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._strict_node_count = 0
        self._strict_depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        alias_type = self.strict_alias_event_type
        if (
            alias_type is not None
            and isinstance(event, alias_type)
        ) or getattr(event, "anchor", None) is not None:
            raise StrictDataError("YAML aliases and anchors are not allowed")

        self._strict_node_count += 1
        if self._strict_node_count > self.max_document_nodes:
            raise StrictDataError("YAML document exceeds the node cap")

        self._strict_depth += 1
        if self._strict_depth > self.max_document_depth:
            self._strict_depth -= 1
            raise StrictDataError("YAML document exceeds the nesting-depth cap")
        try:
            return super().compose_node(parent, index)
        finally:
            self._strict_depth -= 1
