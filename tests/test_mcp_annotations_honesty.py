"""Mechanism-based honesty guard for MCP read-only annotations."""

from __future__ import annotations

import ast
from collections import deque
from functools import lru_cache
from pathlib import Path
import re

from extension import mcp_server


_REPO_ROOT = Path(__file__).resolve().parents[1]
_EXTENSION_ROOT = _REPO_ROOT / "extension"
_MCP_SOURCE = (_EXTENSION_ROOT / "mcp_server.py").read_text(encoding="utf-8")
_EFFECT_HANDLERS = {
    "_invoke_tool": ("extension.dispatch", "dispatch_invoke"),
    "_run_range_tool": ("extension.dispatch", "dispatch_range"),
}
_READ_TOOLS = {
    "list": ("_run_tool", "extension.contract"),
    "describe": ("_run_tool", "extension.contract"),
}
_HONESTY_PHRASES = {
    "invoke": (
        "Dispatches real arm actions (network egress / subprocess) bounded by the "
        "per-arm *_DISPATCH_SCOPE env gates; results are envelopes."
    ),
    "run_range": (
        "Executes local synthetic range fixtures in subprocesses; no live cloud, "
        "no file writes over MCP."
    ),
}


def _module_name(path: Path) -> str:
    relative = path.relative_to(_REPO_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


@lru_cache(maxsize=1)
def _import_graph() -> tuple[dict[str, frozenset[str]], dict[str, bool]]:
    """Parse the repo-local extension import graph once for this test run."""
    paths = sorted(_EXTENSION_ROOT.rglob("*.py"))
    modules = {_module_name(path): path for path in paths}
    graph: dict[str, frozenset[str]] = {}
    markers: dict[str, bool] = {}

    for module, path in modules.items():
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        imports: set[str] = set()
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]
        for node in ast.walk(tree):
            candidates: list[str] = []
            if isinstance(node, ast.Import):
                candidates.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    parent_parts = package.split(".") if package else []
                    keep = len(parent_parts) - (node.level - 1)
                    prefix = ".".join(parent_parts[:keep])
                    base = ".".join(part for part in (prefix, node.module or "") if part)
                else:
                    base = node.module or ""
                if base:
                    candidates.append(base)
                    candidates.extend(f"{base}.{alias.name}" for alias in node.names)
            imports.update(candidate for candidate in candidates if candidate in modules)
        graph[module] = frozenset(imports)
        markers[module] = bool(
            "subprocess" in text
            or "socket" in text
            or re.search(r"_DISPATCH_SCOPE", text)
            or "extension.dispatch" in imports
        )
    return graph, markers


def _reachable_marker(root: str, max_depth: int = 4) -> tuple[bool, frozenset[str]]:
    graph, markers = _import_graph()
    assert root in graph, f"MCP annotation root is not a first-party module: {root}"
    queue = deque([(root, 0)])
    seen: set[str] = set()
    marker_hits: set[str] = set()
    while queue:
        module, depth = queue.popleft()
        if module in seen:
            continue
        seen.add(module)
        if markers[module]:
            marker_hits.add(module)
        if depth < max_depth:
            queue.extend((dependency, depth + 1) for dependency in graph[module])
    return bool(marker_hits), frozenset(marker_hits)


def _method_source(name: str) -> str:
    tree = ast.parse(_MCP_SOURCE)
    server = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "McpServer"
    )
    method = next(
        node
        for node in server.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    )
    lines = _MCP_SOURCE.splitlines()
    return "\n".join(lines[method.lineno - 1 : method.end_lineno])


def _tool_handlers() -> dict[str, str]:
    """Discover descriptor-name to server-handler routing from source text."""
    call_router = _method_source("_tools_call")
    handlers = dict(
        re.findall(
            r'if name == "([^"]+)":\s+return self\.([a-z_]+)\(',
            call_router,
        )
    )
    assert "payload = self._run_tool(name, arguments)" in call_router
    run_tool = _method_source("_run_tool")
    for name in re.findall(r'if name == "([^"]+)":', run_tool):
        handlers[name] = "_run_tool"

    named_defs = dict(
        re.findall(
            r"_([A-Z_]+)_TOOL_DEF[^=]*=\s*\{\s*\"name\":\s*\"([^\"]+)\"",
            _MCP_SOURCE,
        )
    )
    assert set(named_defs.values()) == {"invoke", "run_range"}
    return handlers


def test_mcp_annotations_follow_reachable_side_effect_mechanisms() -> None:
    handlers = _tool_handlers()
    descriptors = {tool["name"]: tool for tool in mcp_server._TOOL_DEFS}
    assert not (set(handlers) - set(descriptors)), (
        "Source-discovered handlers lack descriptors: "
        f"{sorted(set(handlers) - set(descriptors))}"
    )

    for name, descriptor in descriptors.items():
        handler = handlers.get(name)
        declared = descriptor["annotations"]["readOnlyHint"]
        if handler is None:
            raise AssertionError(
                f"{name}: computed class=unclassified (no source-discovered handler), "
                f"declared readOnlyHint={declared}"
            )
        if handler in _EFFECT_HANDLERS:
            root, dispatch_identifier = _EFFECT_HANDLERS[handler]
            handler_source = _method_source(handler)
            assert dispatch_identifier in handler_source, (
                f"{name} handler {handler} no longer calls {dispatch_identifier}"
            )
            marker_hit, marker_modules = _reachable_marker(root)
            computed_class = "side-effecting" if marker_hit else "read-only"
            assert marker_hit, f"{name} lost all side-effect markers from {root}"
            assert declared is False, (
                f"{name}: computed class={computed_class}, "
                f"declared readOnlyHint={declared}, markers={sorted(marker_modules)}"
            )
            assert _HONESTY_PHRASES[name] in descriptor["description"]
        elif name in _READ_TOOLS and handler == _READ_TOOLS[name][0]:
            root = _READ_TOOLS[name][1]
            _reachable_marker(root)  # Keep the inventory root in the same graph tripwire.
            computed_class = "read-only inventory"
            assert declared is True, (
                f"{name}: computed class={computed_class}, "
                f"declared readOnlyHint={declared}"
            )
        else:
            raise AssertionError(
                f"{name}: computed class=unclassified for handler {handler}, "
                f"declared readOnlyHint={declared}"
            )
