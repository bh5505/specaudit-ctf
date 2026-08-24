"""Stdio MCP server exposing list, describe, and invoke.

Tool contract error boundary
----------------------------
| Error class                      | MCP mapping              |
|----------------------------------|--------------------------|
| Bad params shape (non-object     | JSON-RPC -32602          |
| arguments, missing/invalid       | ``_InvalidParams``       |
| action/args type)                |                          |
| Domain failure (unknown id, not  | ``isError: true`` tool   |
| curated, not installed, not an   | result via               |
| arm, transport error surfaced    | ``ExtensionError``       |
| as Result.ok==False)             |                          |
|----------------------------------|--------------------------|
| Unknown tool / method not found  | JSON-RPC -32601          |
| Malformed JSON                   | JSON-RPC -32700          |

Shape errors are caller mistakes; domain errors are evaluated results
returned inside a successful JSON-RPC envelope with ``isError`` set.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Mapping, Sequence, TextIO

from .contract import CATALOG_KIND_ARM, Extension, ExtensionError
from .range.runner import RangeError, run_range

TOOLS = ("list", "describe", "invoke", "run_range")
_PROTOCOL_VERSION = "2024-11-05"
_SERVER_NAME = "specaudit-ctf"
_SERVER_VERSION = "1.0.0"
_MAX_BYTES = 1024 * 1024
_MISSING = object()


class _ParseError(Exception):
    def __init__(self, message: str, *, framing: str) -> None:
        super().__init__(message)
        self.framing = framing


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
    {
        "name": "invoke",
        "description": "Invoke a curated installed arm.",
        "annotations": {"readOnlyHint": False, "openWorldHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "action": {"type": "string"},
                "args": {"type": "object"},
            },
            "required": ["id", "action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_range",
        "description": (
            "Run the synthetic range fixtures and return the seed-stable "
            "lifecycle document. No live cloud, no file writes over MCP."
        ),
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "seed": {"type": "integer"},
                "arm_ids": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": False,
        },
    },
)


class _MethodNotFound(Exception):
    pass


class _InvalidParams(Exception):
    pass


class McpServer:
    """MCP server exposing catalog operations as tools.

    The server implements the JSON-RPC 2.0 protocol over stdio or HTTP,
    exposing list, describe, and invoke operations as MCP tools.

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
                message, framing = _read_message(inn)
            except EOFError:
                return 0
            except _ParseError as exc:
                if not _write_parse_error(out, exc, framing=exc.framing):
                    return 1
                continue
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
                if not _write_parse_error(out, exc, framing="ndjson"):
                    return 1
                continue
            except OSError:
                return 1
            if message is None:
                return 0
            response = self.handle(message)
            if response is not None:
                try:
                    _write_message(out, response, framing=framing)
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
        if name == "run_range":
            return self._run_range(arguments)
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
        return self.extension.invoke(entry_id, action, args).to_dict()

    def _run_range(self, arguments: Mapping[str, Any]) -> Any:
        """Run the synthetic range with MCP-side guards.

        Shape errors (seed type, arm_ids shape) map to -32602 like other
        param-shape concerns; non-curated arm ids are domain errors mapped
        to isError results. Fixtures resolve from the package root only -
        no path arguments exist on this tool - and the response never
        writes files (`--out` stays CLI-only).
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
            curated = {
                entry.id
                for entry in self.extension.list_entries()
                if entry.kind == CATALOG_KIND_ARM and entry.curated
            }
            for arm_id in arm_ids:
                if arm_id not in curated:
                    raise ExtensionError(
                        f"run_range arm_ids must be curated arms: {arm_id}"
                    )
        try:
            document = run_range(
                seed=seed, extension=self.extension, arm_ids=arm_ids
            )
        except RangeError as exc:
            # Runner domain errors (e.g. seed outside the signed 32-bit
            # window) surface as isError tool results, not -32603.
            raise ExtensionError(str(exc)) from exc
        if len(json.dumps(document, sort_keys=True).encode("utf-8")) > _MAX_BYTES:
            raise ExtensionError(f"range document exceeds {_MAX_BYTES} bytes")
        return document

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


def _initialize(params: Mapping[str, Any]) -> dict[str, Any]:
    """Handle the initialize handshake request.

    Args:
        params: The initialize request parameters

    Returns:
        Server capabilities and metadata

    """
    version = params.get("protocolVersion")
    if not isinstance(version, str) or not version.strip():
        version = _PROTOCOL_VERSION
    return {
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": _SERVER_NAME, "version": _SERVER_VERSION},
    }


def _tool_content(payload: Any, *, is_error: bool) -> dict[str, Any]:
    """Wrap tool result in MCP content envelope.

    Args:
        payload: The result payload (string or JSON-serializable object)
        is_error: Whether this represents an error result

    Returns:
        A dict with content array and isError flag

    """
    if isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload, sort_keys=True)
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


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


def _read_message(stream: TextIO) -> tuple[Any, str]:
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        return _read_message_bytes(buffer)
    return _read_message_text(stream)


def _read_message_text(stream: TextIO) -> tuple[Any, str]:
    """Read a JSON-RPC message from a text stream.

    Supports both ndjson (newline-delimited JSON) and Content-Length framing.

    Args:
        stream: The text stream to read from

    Returns:
        A tuple of (parsed_message, framing_type) or (None, framing) for EOF

    Raises:
        _ParseError: If the message is malformed or exceeds size limits

    """
    while True:
        try:
            line = stream.readline()
        except OSError as exc:
            raise _ParseError(str(exc), framing="ndjson") from exc
        if line == "":
            return None, "ndjson"
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            _reject_oversize(len(stripped.encode("utf-8")), "ndjson")
            return _loads(stripped, "ndjson"), "ndjson"
        headers = [line]
        while True:
            try:
                nxt = stream.readline()
            except OSError as exc:
                raise _ParseError(str(exc), framing="content-length") from exc
            if nxt == "":
                raise _ParseError("unexpected EOF in headers", framing="content-length")
            if nxt.strip() == "":
                break
            headers.append(nxt)
        length = _header_length(headers)
        try:
            body = stream.read(length)
        except OSError as exc:
            raise _ParseError(str(exc), framing="content-length") from exc
        return _loads(body, "content-length"), "content-length"


def _read_message_bytes(buffer: Any) -> tuple[Any, str]:
    while True:
        try:
            line = buffer.readline()
        except OSError as exc:
            raise _ParseError(str(exc), framing="ndjson") from exc
        if not line:
            return None, "ndjson"
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(b"{"):
            _reject_oversize(len(stripped), "ndjson")
            try:
                text = stripped.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _ParseError(str(exc), framing="ndjson") from exc
            return _loads(text, "ndjson"), "ndjson"
        headers = [line]
        while True:
            try:
                nxt = buffer.readline()
            except OSError as exc:
                raise _ParseError(str(exc), framing="content-length") from exc
            if not nxt:
                raise _ParseError("unexpected EOF in headers", framing="content-length")
            if nxt in (b"\r\n", b"\n"):
                break
            headers.append(nxt)
        length = _header_length(
            item.decode("ascii", errors="replace") for item in headers
        )
        try:
            body = buffer.read(length)
        except OSError as exc:
            raise _ParseError(str(exc), framing="content-length") from exc
        if len(body) < length:
            raise _ParseError("truncated body", framing="content-length")
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _ParseError(str(exc), framing="content-length") from exc
        return _loads(text, "content-length"), "content-length"


def _loads(text: str, framing: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise _ParseError(str(exc), framing=framing) from exc


def _reject_oversize(size: int, framing: str) -> None:
    if size > _MAX_BYTES:
        raise _ParseError(f"message exceeds {_MAX_BYTES} bytes", framing=framing)


def _header_length(headers: Any) -> int:
    """Extract Content-Length value from headers.

    Args:
        headers: Sequence of header lines (strings or bytes)

    Returns:
        The Content-Length value as an integer

    Raises:
        _ParseError: If Content-Length is missing, invalid, or out of range

    """
    for raw in headers:
        text = raw if isinstance(raw, str) else raw.decode("ascii", errors="replace")
        if text.lower().startswith("content-length:"):
            raw_len = text.split(":", 1)[1].strip()
            try:
                length = int(raw_len)
            except ValueError as exc:
                raise _ParseError(
                    f"invalid Content-Length: {raw_len}", framing="content-length"
                ) from exc
            if length < 0 or length > _MAX_BYTES:
                raise _ParseError(
                    f"Content-Length {length} exceeds {_MAX_BYTES} bytes",
                    framing="content-length",
                )
            return length
    raise _ParseError("missing Content-Length", framing="content-length")


def _write_parse_error(stream: TextIO, exc: BaseException, *, framing: str) -> bool:
    """Write a parse error response to the stream.

    Args:
        stream: The output stream to write to
        exc: The exception that caused the parse error
        framing: The framing type to use ("ndjson" or "content-length")

    Returns:
        True if write succeeded, False on OSError

    """
    try:
        _write_message(
            stream,
            _rpc_error(None, -32700, f"Parse error: {exc}"),
            framing=framing,
        )
    except OSError:
        return False
    return True


def _write_message(stream: TextIO, message: Mapping[str, Any], *, framing: str) -> None:
    """Write a JSON-RPC message to the stream.

    Args:
        stream: The output stream to write to
        message: The JSON-RPC message dict
        framing: The framing type to use ("ndjson" or "content-length")

    Raises:
        OSError: If the write operation fails

    """
    body = json.dumps(message, ensure_ascii=False)
    encoded = body.encode("utf-8")
    if framing == "content-length":
        header = f"Content-Length: {len(encoded)}\r\n\r\n"
        buffer = getattr(stream, "buffer", None)
        if buffer is not None:
            buffer.write(header.encode("ascii"))
            buffer.write(encoded)
            buffer.flush()
            return
        stream.write(header)
        stream.write(body)
        stream.flush()
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
