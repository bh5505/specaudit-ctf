"""Build-time helper: trace which modules the sealed invocation touches.

Not shipped in the runtime bundle. Always run as a **subprocess under the
staged, locked CPython 3.11 interpreter** with the staged, locked PyYAML
wheel on ``sys.path`` — never under the ambient dev interpreter. PyYAML
ships a compiled ``_yaml`` accelerator pinned to CPython's ABI; tracing
under a different interpreter (a newer/older CPython, a differently built
``yaml``) silently changes which files get imported (the accelerator
either loads or falls back to pure Python) and would make the trace lie
about what the real bundle needs.

The traced invocation is exactly the trusted, sealed argv:

    python -m extension invoke agent-wiz list_tools {}

Every module left in ``sys.modules`` after that call is classified into
``stdlib`` (top-level name is in ``sys.stdlib_module_names``), ``yaml``
(``yaml`` or ``_yaml``), ``extension`` (this producer package), or
``unexpected`` (anything else — a third-party import sneaking into the
sealed runtime is a build failure, not a warning).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import runpy
import sys

TRACE_ARGV = ["invoke", "agent-wiz", "list_tools", "{}"]
_IGNORED_NAMES = frozenset({"__main__"})


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


def trace_file_paths() -> dict[str, list[dict[str, str]]]:
    """Run the sealed invocation and return one record per module needed to
    reach that point, grouped into ``stdlib``/``yaml``/``extension``.

    Deliberately classifies the *entire* final ``sys.modules``, not a
    before/after diff: interpreter start-up itself already imports several
    modules this invocation genuinely depends on (``encodings``, ``os``,
    ``io``, ``abc``, ``collections``, ``re``, ...) before our code runs a
    single line, so a "new since before" diff would silently drop them from
    the required-stdlib set. This function is meant to run in a fresh
    subprocess with nothing extra pre-imported, so classifying everything
    present at the end is exactly "everything this invocation needs".

    Raises ``RuntimeError`` if the invocation did not exit 0, or if it
    imported anything outside those three buckets.
    """
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        saved_argv = sys.argv
        sys.argv = ["-m", *TRACE_ARGV]
        try:
            try:
                # Exercise Python's real `-m extension` runpy path, including
                # its eager stdlib imports, rather than calling main() through
                # a weaker in-process shortcut.
                runpy.run_module("extension", run_name="__main__", alter_sys=True)
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
            else:
                code = 0
        finally:
            sys.argv = saved_argv
    if code != 0:
        raise RuntimeError(
            f"traced invocation exited {code}: {buf_err.getvalue()!r} / "
            f"{buf_out.getvalue()!r}"
        )
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


def _main() -> int:
    """Usage: python3.11 _tracer.py <repo_root> <yaml_site_dir> <out_json_path>

    Run under the staged, locked interpreter with ``repo_root`` (for
    ``extension``) and ``yaml_site_dir`` (the extracted, locked PyYAML
    wheel) on ``sys.path``.
    """
    repo_root, yaml_site, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    sys.path.insert(0, yaml_site)
    sys.path.insert(0, repo_root)
    buckets = trace_file_paths()
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(buckets, handle, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
