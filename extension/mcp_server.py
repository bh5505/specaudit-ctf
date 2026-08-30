"""Stdio MCP server exposing list, describe, invoke, and run_range.

X4-PUB parity: ``invoke`` and ``run_range`` return the same
``execution-result.v1`` envelopes as the CLI JSON surface by sharing
``extension.dispatch``. Timestamps differ per run; every other field is
transport-independent. The frozen equivalence matrix lives at
``tests/goldens/transport-parity/matrix.json``.

Transport binding (MCP stdio per spec revision 2025-11-25):

- Framing is newline-delimited JSON only. Messages MUST NOT contain
  embedded newlines, and nothing but valid JSON-RPC messages is ever
  written to stdout. Legacy Content-Length input (never MCP stdio) is
  rejected as a parse error rather than silently accepted.
- The initialize handshake negotiates a supported protocol version:
  a supported request version is echoed; anything else answers with the
  latest supported version.
- Message size is capped at 1 MiB (implementation-defined; the spec is
  silent).

Error boundary
--------------
| Error class                       | MCP mapping              |
|-----------------------------------|--------------------------|
| Bad params shape (non-object      | JSON-RPC -32602          |
| arguments, missing/invalid        | ``_InvalidParams``       |
| action/seed/arm_ids/attempt       |                          |
| contract type, unknown tool)      |                          |
| Attempt/artifact contract error   | JSON-RPC -32602          |
| (invalid attempt id, unusable     | (pre-dispatch; never a   |
| artifact dir)                     | tool execution)          |
| Domain failure (unknown id, held, | ``isError: true`` tool   |
| not curated, not installed, not   | result whose content is  |
| an arm, unmanifested action,      | the failed               |
| range refusal)                    | execution-result.v1      |
|                                   | envelope                 |
| Evaluated non-success (arm        | ``isError: true`` tool   |
| result ok=False; range status     | result; the envelope     |
| degraded/failed)                  | carries the verdict      |
| Unknown method                    | JSON-RPC -32601          |
| Malformed/oversized/legacy-framed | JSON-RPC -32700          |
| message                           |                          |

``isError`` mirrors the CLI exit code (nonzero exit = ``isError: true``).
It is a transport signal, not a verdict: G-24 keeps verdict vocabulary in
the envelope's ``status``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO

from .contract import Extension, ExtensionError
from .dispatch import DispatchOutcome, dispatch_invoke, dispatch_range

TOOLS = ("list", "describe", "invoke", "run_range")
# Legacy-era initialize handshake, newest first. 2025-11-25 is the revision
# the campaign guardrails cite; the 2026+ per-request-metadata era is out of
# scope for X4.
_SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)
_LATEST_PROTOCOL_VERSION = _SUPPORTED_PROTOCOL_VERSIONS[0]
_SERVER_NAME = "specaudit-ctf"
_SERVER_VERSION = "1.0.0"
_MAX_BYTES = 1024 * 1024
_MISSING = object()
_RESULT_SCHEMA = json.loads(
    (Path(__file__).resolve().parent / "schema" / "execution-result.v1.schema.json")
    .read_text(encoding="utf-8")
)


class _ParseError(Exception):
    pass


_INVOKE_TOOL_DEF: dict[str, Any] = {
    "name": "invoke",
    "description": (
        "Invoke a curated installed arm that is not held. Only the bounded "
        "read-only X2-PUB action registry is admitted; the result is an "
        "execution-result.v1 envelope identical to `python -m extension "
        "invoke` output (timestamps differ per run). isError mirrors the "
        "CLI nonzero exit; the envelope status is the verdict."
    ),
    "annotations": {"readOnlyHint": True, "openWorldHint": False},
    "inputSchema": {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "action": {"type": "string"},
            "args": {
                "type": "object",
                "description": "Action arguments (default: {}).",
            },
            "attempt_id": {
                "type": "string",
                "description": (
                    "Optional validator-minted attempt-<64 lowercase hex> "
                    "echoed in the result envelope."
                ),
            },
            "artifact_dir": {
                "type": "string",
                "description": (
                    "Optional absolute empty Unix directory bound before "
                    "dispatch for digest-named artifacts (Mode A custody "
                    "handoff; requires attempt_id; Unix-only)."
                ),
            },
        },
        "required": ["id", "action"],
        "additionalProperties": False,
    },
    "outputSchema": _RESULT_SCHEMA,
}

_RUN_RANGE_TOOL_DEF: dict[str, Any] = {
    "name": "run_range",
    "description": (
        "Run the synthetic range fixtures and return an execution-result.v1 "
        "envelope wrapping the seed-stable range.lifecycle.v2 document, "
        "identical to `python -m extension.range` output (timestamps differ "
        "per run). No live cloud, no file writes over MCP (--out stays "
        "CLI-only). isError mirrors the CLI nonzero exit; degraded/failed "
        "verdicts live in the envelope status, never in transport success. "
        "Omit arm_ids to auto-discover curated arms (skip/error is "
        "degraded). Empty arm_ids is lifecycle-only and may be complete. "
        "Non-empty arm_ids are required (skip/error is failed)."
    ),
    "annotations": {"readOnlyHint": True, "openWorldHint": False},
    "inputSchema": {
        "type": "object",
        "properties": {
            "seed": {"type": "integer"},
            "arm_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Omitted: auto-discover curated arms (optional; "
                    "skip/error is degraded). Empty: no arms; complete "
                    "on lifecycle match. Non-empty: required; skip/error "
                    "is failed."
                ),
            },
            "attempt_id": {
                "type": "string",
                "description": (
                    "Optional validator-minted attempt-<64 lowercase hex> "
                    "echoed in the result envelope."
                ),
            },
            "artifact_dir": {
                "type": "string",
                "description": (
                    "Optional absolute empty Unix directory bound before "
                    "dispatch for digest-named artifacts (Mode A custody "
                    "handoff; requires attempt_id; Unix-only)."
                ),
            },
        },
        "additionalProperties": False,
    },
    "outputSchema": _RESULT_SCHEMA,
}

_TOOL_DEFS: tuple[dict[str, Any], ...] = (
    {
        "name": "list",
        "description": "List catalog entries.",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "describe",
        "description": "Describe one catalog entry by id.",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
            "additionalProperties": False,
        },
    },
    _INVOKE_TOOL_DEF,
    _RUN_RANGE_TOOL_DEF,
)


class _MethodNotFound(Exception):
    pass


class _InvalidParams(Exception):
    pass


class McpServer:
    """MCP server exposing catalog operations as tools.

    The server implements JSON-RPC 2.0 over stdio, exposing list,
    describe, invoke, and run_range operations as MCP tools.

    Attributes:
        extension: The Extension instance to use for catalog operations

    """

    def __init__(self, extension: Extension | None = None) -> None:
        """Initialize a new MCP server instance.

        Args:
            extension: Optional Extension instance, creates default if None

        """
        self.extension = extension if extension is not None else Extension()

    def handle(self, request: Mapping[str, Any] | Any) -> dict[str, Any] | None:
        """Handle a single JSON-RPC request.

        Args:
            request: The parsed JSON-RPC request object

        Returns:
            A JSON-RPC response dict, or None for notifications

        """
        if not isinstance(request, Mapping):
            return _rpc_error(None, -32600, "Invalid Request")
        req_id = request["id"] if "id" in request else _MISSING
        notify = req_id is _MISSING
        method = request.get("method")
        if not isinstance(method, str) or not method.strip():
            return None if notify else _rpc_error(request.get("id"), -32600, "Invalid Request")
        params = request.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            return None if notify else _rpc_error(req_id, -32602, "Invalid params")
        try:
            result = self._dispatch(method, params)
        except _MethodNotFound:
            return None if notify else _rpc_error(req_id, -32601, f"Method not found: {method}")
        except _InvalidParams as exc:
            return None if notify else _rpc_error(req_id, -32602, str(exc) or "Invalid params")
        except Exception as exc:  # noqa: BLE001 - JSON-RPC envelope
            return None if notify else _rpc_error(req_id, -32603, str(exc))
        if notify:
            return None
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def serve(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
        """Run the MCP server main loop.

        Args:
            stdin: Input stream (default: sys.stdin)
            stdout: Output stream (default: sys.stdout)

        Returns:
            Exit code (0 for clean shutdown, 1 for errors)

        """
        inn = stdin if stdin is not None else sys.stdin
        out = stdout if stdout is not None else sys.stdout
        while True:
            try:
                message = _read_message(inn)
            except EOFError:
                return 0
            except _ParseError as exc:
                if not _write_parse_error(out, exc):
                    return 1
                continue
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
                if not _write_parse_error(out, exc):
                    return 1
                continue
            except OSError:
                return 1
            if message is None:
                return 0
            response = self.handle(message)
            if response is not None:
                try:
                    _write_message(out, response)
                except OSError:
                    return 1

    def _dispatch(self, method: str, params: Mapping[str, Any]) -> Any:
        if method == "initialize":
            return _initialize(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [dict(item) for item in _TOOL_DEFS]}
        if method == "tools/call":
            return self._tools_call(params)
        if method.startswith("notifications/"):
            return None
        raise _MethodNotFound(method)

    def _tools_call(self, params: Mapping[str, Any]) -> dict[str, Any]:
        """Dispatch tools/call; see module docstring for error boundary."""
        name = params.get("name")
        if not isinstance(name, str) or not name.strip():
            raise _InvalidParams("tool name is required")
        if name not in TOOLS:
            raise _InvalidParams(f"unknown tool: {name}")
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise _InvalidParams("arguments must be an object")
        try:
            if name == "invoke":
                return self._invoke_tool(arguments)
            if name == "run_range":
                return self._run_range_tool(arguments)
            payload = self._run_tool(name, arguments)
        except ExtensionError as exc:
            return _tool_content(str(exc), is_error=True)
        return _tool_content(payload, is_error=False)

    def _run_tool(self, name: str, arguments: Mapping[str, Any]) -> Any:
        if name == "list":
            return [entry.to_dict() for entry in self.extension.list_entries()]
        if name == "describe":
            entry_id = _require_id(arguments)
            return self.extension.describe(entry_id).to_dict()
        raise _InvalidParams(f"unknown tool: {name}")

    def _invoke_tool(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Run one bounded invoke through the shared dispatch.

        Parity: the returned envelope is byte-equivalent to the CLI JSON
        output for the same logical request modulo started_at/finished_at/
        spent.elapsed_ms.
        """
        entry_id = _require_id(arguments)
        action = _require_action(arguments)
        # Do not coerce falsy non-mapping values to {}. Only None means
        # "absent, use default". Non-mapping falsy values (0, "", [], False)
        # must fail closed via the Mapping check below (-32602).
        args = arguments.get("args", {})
        if args is None:
            args = {}
        if not isinstance(args, Mapping):
            raise _InvalidParams("args must be a mapping")
        outcome = dispatch_invoke(
            self.extension,
            arm_id=entry_id,
            action=action,
            args=args,
            attempt_id=_optional_str(arguments, "attempt_id"),
            artifact_dir=_optional_str(arguments, "artifact_dir"),
        )
        return _outcome_content(outcome)

    def _run_range_tool(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Run the synthetic range through the shared dispatch.

        Shape errors (seed type, arm_ids shape, attempt/artifact contract)
        map to -32602 like other param-shape concerns; everything else is
        an evaluated result inside the execution-result.v1 envelope.
        Fixtures resolve from the package root only - no path arguments
        exist on this tool - and the response never writes files (`--out`
        stays CLI-only).
        """
        seed = arguments.get("seed")
        if seed is not None:
            if isinstance(seed, bool) or not isinstance(seed, int):
                raise _InvalidParams("seed must be an integer")
        arm_ids = arguments.get("arm_ids")
        if arm_ids is not None:
            if not isinstance(arm_ids, list) or not all(
                isinstance(item, str) and item.strip() for item in arm_ids
            ):
                raise _InvalidParams("arm_ids must be an array of non-empty strings")
        outcome = dispatch_range(
            self.extension,
            seed=seed,
            arm_ids=arm_ids,
            attempt_id=_optional_str(arguments, "attempt_id"),
            artifact_dir=_optional_str(arguments, "artifact_dir"),
        )
        return _outcome_content(outcome)


def _outcome_content(outcome: DispatchOutcome) -> dict[str, Any]:
    """Render one dispatch outcome as an MCP tool result.

    isError mirrors the CLI exit code (transport signal, not a verdict);
    the envelope inside the content carries the evaluated status.
    """
    if outcome.contract_error is not None:
        raise _InvalidParams(str(outcome.contract_error))
    assert outcome.envelope is not None  # only contract errors lack one
    return _tool_content(
        outcome.envelope,
        is_error=outcome.exit_code != 0,
        structured=outcome.envelope,
    )


def _require_id(arguments: Mapping[str, Any]) -> str:
    """Extract and validate the 'id' parameter from tool arguments.

    Domain errors map to isError=true responses (shape validated at _tools_call).
    Contrast with _require_action which raises _InvalidParams (-32602) because
    action is a tool-param shape concern, while id maps to catalog domain.

    Args:
        arguments: The tool arguments mapping

    Returns:
        The validated entry ID string

    Raises:
        ExtensionError: If id is missing or not a valid string

    """
    entry_id = arguments.get("id")
    if not isinstance(entry_id, str) or not entry_id.strip():
        raise ExtensionError("id is required")
    return entry_id


def _require_action(arguments: Mapping[str, Any]) -> str:
    """Extract and validate the 'action' parameter from tool arguments.

    Param-shape errors map to -32602 responses. Documented asymmetry with _require_id.

    Args:
        arguments: The tool arguments mapping

    Returns:
        The validated action string

    Raises:
        _InvalidParams: If action is missing or not a valid string

    """
    action = arguments.get("action")
    if not isinstance(action, str) or not action.strip():
        raise _InvalidParams("action is required")
    return action


def _optional_str(arguments: Mapping[str, Any], key: str) -> str | None:
    """Extract an optional string tool argument; wrong types are -32602."""
    value = arguments.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _InvalidParams(f"{key} must be a string")
    return value


def _initialize(params: Mapping[str, Any]) -> dict[str, Any]:
    """Handle the initialize handshake request.

    A supported requested version is echoed verbatim; anything else is
    answered with the latest supported version (spec: the server MUST
    respond with a version it supports).

    Args:
        params: The initialize request parameters

    Returns:
        Server capabilities and metadata

    """
    version = params.get("protocolVersion")
    if version not in _SUPPORTED_PROTOCOL_VERSIONS:
        version = _LATEST_PROTOCOL_VERSION
    return {
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": _SERVER_NAME, "version": _SERVER_VERSION},
    }


def _tool_content(
    payload: Any,
    *,
    is_error: bool,
    structured: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Wrap tool result in MCP content envelope.

    Args:
        payload: The result payload (string or JSON-serializable object)
        is_error: Whether this represents an error result
        structured: Optional structuredContent value (2025-06-18+; older
            clients ignore the additive field)

    Returns:
        A dict with content array and isError flag

    """
    if isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload, sort_keys=True)
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }
    if structured is not None:
        result["structuredContent"] = structured
    return result


def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    """Build a JSON-RPC error response.

    Args:
        req_id: The request ID (or _MISSING for notifications)
        code: The JSON-RPC error code
        message: The error message

    Returns:
        A JSON-RPC error response dict

    """
    return {
        "jsonrpc": "2.0",
        "id": None if req_id is _MISSING else req_id,
        "error": {"code": code, "message": message},
    }


def _read_message(stream: TextIO) -> Any:
    """Read one newline-delimited JSON message from a text stream.

    Stdio MCP framing is ndjson only. Legacy Content-Length input is a
    parse error, not an alternate framing. Blank lines are skipped.

    Raises:
        EOFError: If the stream ends
        _ParseError: If a line is not JSON or exceeds the size cap
    """
    while True:
        line = stream.readline()
        if line == "":
            raise EOFError
        stripped = line.strip()
        if not stripped:
            continue
        _reject_oversize(len(stripped.encode("utf-8")))
        return _loads(stripped)


def _loads(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise _ParseError(str(exc)) from exc


def _reject_oversize(size: int) -> None:
    if size > _MAX_BYTES:
        raise _ParseError(f"message exceeds {_MAX_BYTES} bytes")


def _write_parse_error(stream: TextIO, exc: BaseException) -> bool:
    """Write a parse error response to the stream.

    Args:
        stream: The output stream to write to
        exc: The exception that caused the parse error

    Returns:
        True if write succeeded, False on OSError

    """
    try:
        _write_message(stream, _rpc_error(None, -32700, f"Parse error: {exc}"))
    except OSError:
        return False
    return True


def _write_message(stream: TextIO, message: Mapping[str, Any]) -> None:
    """Write one JSON-RPC message as a single ndjson line.

    Nothing but complete JSON messages ever reaches stdout (spec: the
    server MUST NOT write anything that is not a valid MCP message).

    Args:
        stream: The output stream to write to
        message: The JSON-RPC message dict

    Raises:
        OSError: If the write operation fails

    """
    body = json.dumps(message, ensure_ascii=False)
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        # Binary write keeps "\n" from becoming "\r\n" on text-mode
        # Windows streams; ndjson lines must end in a bare newline.
        buffer.write(body.encode("utf-8") + b"\n")
        buffer.flush()
        return
    stream.write(body)
    stream.write("\n")
    stream.flush()


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for the MCP server.

    Args:
        argv: Optional command-line arguments (for testing). If None, uses sys.argv[1:]

    Returns:
        Exit code (0 for success, 1 for I/O errors, 2 for argument errors)

    """
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"-h", "--help"}:
        print("Usage: python -m extension.mcp_server", file=sys.stderr)
        return 0
    if args:
        print("Usage: python -m extension.mcp_server", file=sys.stderr)
        return 2
    return McpServer().serve()


if __name__ == "__main__":
    raise SystemExit(main())
