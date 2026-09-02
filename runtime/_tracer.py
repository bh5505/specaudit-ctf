"""Build-time helper: trace which modules the sealed invocations touch.

Not shipped in the runtime bundle. Always run as a **subprocess under the
staged, locked CPython 3.11 interpreter** with the staged, locked PyYAML
wheel on ``sys.path`` — never under the ambient dev interpreter. PyYAML
ships a compiled ``_yaml`` accelerator pinned to CPython's ABI; tracing
under a different interpreter (a newer/older CPython, a differently built
``yaml``) silently changes which files get imported (the accelerator
either loads or falls back to pure Python) and would make the trace lie
about what the real bundle needs.

Two sealed invocations are traced, each in its own fresh subprocess so
its ``sys.modules`` classification stays per-invocation truth:

- ``cli-json-invoke`` is the trusted one-shot CLI encode:

      python -m extension invoke agent-wiz list_tools {}

- ``stdio-mcp-server`` is the trusted stdio-MCP server entrypoint
  (X4-VAL's sealed argv ``-S -m extension.mcp_server``) driven through
  its real ndjson serve loop by a fixed read-only handshake: an
  ``initialize`` request, the ``notifications/initialized`` notice, and
  a ``tools/list`` request, then EOF. The server must answer both
  requests with valid JSON-RPC results — initialize echoing a supported
  protocol revision and tools/list naming exactly the four advertised
  tools — and exit 0 on EOF. Anything else is a tracer failure.

Every module left in ``sys.modules`` after an invocation is classified
into ``stdlib`` (top-level name is in ``sys.stdlib_module_names``),
``yaml`` (``yaml`` or ``_yaml``), ``extension`` (this producer package),
or ``unexpected`` (anything else — a third-party import sneaking into
the sealed runtime is a build failure, not a warning).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import runpy
import sys

CLI_TRACE_ARGV = ["invoke", "agent-wiz", "list_tools", "{}"]
_IGNORED_NAMES = frozenset({"__main__"})

# The fixed, read-only MCP handshake the tracer drives through the real
# serve() loop. Single-line ndjson, exactly like the Rust X4-VAL transport
# writes; EOF after tools/list ends the session cleanly.
MCP_TRACE_STDIN = (
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
    '{"protocolVersion":"2025-11-25","capabilities":{},'
    '"clientInfo":{"name":"ctf-runtime-tracer","version":"0"}}}\n'
    '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
    '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
)

#: The complete advertised tool surface; the traced tools/list response
#: must name exactly these and nothing else.
EXPECTED_MCP_TOOLS = ("describe", "invoke", "list", "run_range")

#: Supported protocol revisions, newest first (mirrors extension.mcp_server).
SUPPORTED_PROTOCOL_REVISIONS = ("2025-11-25", "2024-11-05", "2024-10-07")

INVOCATIONS = ("cli-json-invoke", "stdio-mcp-server")


def classify(name: str) -> str | None:
    """Bucket a dotted module name, or None to ignore it entirely."""
    if name in _IGNORED_NAMES:
        return None
    top = name.split(".", 1)[0]
    if top in ("yaml", "_yaml"):
        return "yaml"
    if top == "extension":
        return "extension"
    if top in sys.stdlib_module_names:
        return "stdlib"
    return "unexpected"


def _classify_final_modules() -> dict[str, list[dict[str, str]]]:
    """Classify the entire final ``sys.modules`` into trace buckets.

    Deliberately classifies the *entire* final ``sys.modules``, not a
    before/after diff: interpreter start-up itself already imports several
    modules any sealed invocation genuinely depends on (``encodings``,
    ``os``, ``io``, ``abc``, ``collections``, ``re``, ...) before our code
    runs a single line, so a "new since before" diff would silently drop
    them from the required-stdlib set. This is meant to run in a fresh
    subprocess with nothing extra pre-imported, so classifying everything
    present at the end is exactly "everything this invocation needs".

    Raises ``RuntimeError`` if the invocation imported anything outside
    the stdlib/yaml/extension buckets.
    """
    buckets: dict[str, list[dict[str, str]]] = {
        "stdlib": [],
        "yaml": [],
        "extension": [],
    }
    unexpected: list[str] = []
    for name, mod in sys.modules.items():
        file = getattr(mod, "__file__", None)
        if not file:
            # Builtin/frozen, or a synthetic in-memory pseudo-module a
            # compiled extension registers as a side effect of its own
            # initialization (e.g. yaml._yaml's bundled Cython runtime
            # registers "cython_runtime"/"_cython_<ver>" with no __file__).
            # Nothing to copy either way, and nothing to name-check: it is
            # already inside a file we are shipping regardless of its name.
            continue
        bucket = classify(name)
        if bucket is None:
            continue
        if bucket == "unexpected":
            unexpected.append(name)
            continue
        buckets[bucket].append({"name": name, "file": os.path.realpath(file)})
    if unexpected:
        raise RuntimeError(
            "sealed invocation imported unexpected non-stdlib/yaml/extension "
            f"modules: {sorted(unexpected)}"
        )
    for bucket in buckets.values():
        bucket.sort(key=lambda rec: rec["name"])
    return buckets


def _run_module_and_classify(module: str) -> dict[str, list[dict[str, str]]]:
    """Run one ``-m`` module to completion in this process, then classify.

    The SystemExit code the module's ``__main__`` raises is enforced: a
    non-zero exit is a tracer failure, never a partial trace.
    """
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        try:
            runpy.run_module(module, run_name="__main__", alter_sys=True)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        else:
            code = 0
    if code != 0:
        raise RuntimeError(
            f"traced invocation of {module} exited {code}: "
            f"{buf_err.getvalue()!r} / {buf_out.getvalue()!r}"
        )
    return _classify_final_modules()


def trace_cli_invoke() -> dict[str, list[dict[str, str]]]:
    """Trace ``python -m extension invoke agent-wiz list_tools {}``.

    Exercises Python's real ``-m extension`` runpy path, including its
    eager stdlib imports, rather than calling main() through a weaker
    in-process shortcut.
    """
    saved_argv = sys.argv
    sys.argv = ["-m", *CLI_TRACE_ARGV]
    try:
        return _run_module_and_classify("extension")
    finally:
        sys.argv = saved_argv


def _parse_ndjson_responses(text: str) -> list[dict]:
    responses: list[dict] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            message = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"non-JSON line on traced MCP stdout: {line!r}") from exc
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise RuntimeError(f"non-JSON-RPC line on traced MCP stdout: {line!r}")
        if "error" in message:
            raise RuntimeError(f"JSON-RPC error response from traced MCP server: {message}")
        responses.append(message)
    return responses


def validate_mcp_exchange(stdout_text: str) -> list[dict]:
    """Validate a full sealed MCP exchange: the fixed handshake's answers.

    Shared by the in-process trace and the subprocess smoke test so both
    enforce the identical contract: exactly two JSON-RPC result responses
    (ids 1 and 2), ``initialize`` echoing a supported protocol revision,
    and ``tools/list`` naming exactly the four advertised tools.
    """
    responses = _parse_ndjson_responses(stdout_text)
    if len(responses) != 2 or [r.get("id") for r in responses] != [1, 2]:
        raise RuntimeError(
            f"traced MCP server did not answer exactly the two requests: "
            f"{responses!r}"
        )
    initialize_result = responses[0].get("result")
    if not isinstance(initialize_result, dict):
        raise RuntimeError(f"traced MCP initialize has no result object: {responses[0]!r}")
    protocol = initialize_result.get("protocolVersion")
    if protocol not in SUPPORTED_PROTOCOL_REVISIONS:
        raise RuntimeError(
            f"traced MCP initialize echoed unsupported protocol revision: {protocol!r}"
        )
    tools_result = responses[1].get("result")
    names = (
        sorted(tool["name"] for tool in tools_result.get("tools", []))
        if isinstance(tools_result, dict)
        else None
    )
    if names != sorted(EXPECTED_MCP_TOOLS):
        raise RuntimeError(
            f"traced MCP tools/list does not name exactly {EXPECTED_MCP_TOOLS}: {names!r}"
        )
    return responses


def trace_stdio_mcp_server() -> dict[str, list[dict[str, str]]]:
    """Trace ``python -m extension.mcp_server`` through its real serve loop.

    ``sys.stdin`` is replaced with the fixed handshake script above; the
    server must answer ``initialize`` and ``tools/list`` and then exit 0
    on EOF. ``extension.mcp_server`` itself is absent from final
    ``sys.modules`` (runpy removes the ``__main__`` module), so the
    builder lists it as an explicit producer root — same as
    ``extension/__main__.py`` for the CLI invocation.
    """
    saved_stdin = sys.stdin
    saved_argv = sys.argv
    sys.stdin = io.StringIO(MCP_TRACE_STDIN)
    sys.argv = ["-m"]
    try:
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            try:
                runpy.run_module(
                    "extension.mcp_server", run_name="__main__", alter_sys=True
                )
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
            else:
                code = 0
    finally:
        sys.stdin = saved_stdin
        sys.argv = saved_argv
    if code != 0:
        raise RuntimeError(
            f"traced MCP server exited {code}: "
            f"{buf_err.getvalue()!r} / {buf_out.getvalue()!r}"
        )
    validate_mcp_exchange(buf_out.getvalue())
    return _classify_final_modules()


TRACE_FUNCTIONS = {
    "cli-json-invoke": trace_cli_invoke,
    "stdio-mcp-server": trace_stdio_mcp_server,
}


def _main() -> int:
    """Usage: python3.11 _tracer.py <repo_root> <yaml_site> <out_json_path> <invocation>

    Run under the staged, locked interpreter with ``repo_root`` (for
    ``extension``) and ``yaml_site_dir`` (the extracted, locked PyYAML
    wheel) on ``sys.path``. Exactly one invocation is traced per process
    so its sys.modules classification stays per-invocation truth.
    """
    repo_root, yaml_site, out_path, invocation = (
        sys.argv[1],
        sys.argv[2],
        sys.argv[3],
        sys.argv[4],
    )
    if invocation not in TRACE_FUNCTIONS:
        raise SystemExit(f"unknown traced invocation: {invocation!r}")
    sys.path.insert(0, yaml_site)
    sys.path.insert(0, repo_root)
    buckets = TRACE_FUNCTIONS[invocation]()
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(buckets, handle, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
