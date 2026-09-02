"""Stdlib-only, deterministic builder for the agent-wiz.list_tools runtime.

Produces one self-contained, relocatable Linux x86-64 GNU/glibc Python
runtime tree containing: the real ``python3.11`` launcher, exactly the
standard-library modules the two sealed invocations

    python -S -m extension invoke agent-wiz list_tools {}
    python -S -m extension.mcp_server            (X4-VAL stdio MCP)

actually import, the PyYAML ``yaml``/``_yaml`` package they import, this
producer's own source for those invocations, and licenses. Every included
file is discovered by *tracing the real invocations* under the locked
CPython build (see ``_tracer.py``), never by guesswork — the build fails
closed if a trace imports anything unexpected. The locked file closure is
the union of both invocations; ``lock.json`` also records each
invocation's own module names so per-invocation drift stays visible.

No third-party dependency: only the standard library, and never invokes
``pip``. Network is used solely to fetch the two locked inputs (into
``runtime/.cache/``, gitignored); once cached, every other subcommand is
offline.

Subcommands (``python3 -m runtime.build <cmd>``):

  fetch        Download+verify the locked CPython tarball and PyYAML wheel.
               ``--offline`` fails closed instead of touching the network
               when the cache is missing or invalid.
  lock-check   Recompute producer-source hashes (and, with ``--full``, the
               exact traced module/file/content closure) and compare to
               lock.json. Fails closed on drift. Fast/offline by default.
  lock-write   Regenerate the producer source and traced file/content locks
               from verified cached inputs. Run only as part of an explicit,
               reviewed dependency/source update.
  build        Offline lock-check --full -> assemble -> verify -> pack ->
               re-extract -> re-verify (must match) -> Mode-A smoke. Run
               ``fetch`` first. Prints the bundle manifest and timings.
  verify PATH  Recompute launcher/tree digests for an already built bundle.
  smoke PATH   Spawn the sealed argv against an already built bundle with
               a fully cleared environment (only PYTHONHOME,
               PYTHONNOUSERSITE, PYTHONDONTWRITEBYTECODE).
  selfcheck    Assemble the bundle twice, independently, and confirm both
               launcher and tree digests are byte-identical.
  all          Explicit online fetch followed by offline build + selfcheck.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runtime import _tracer, tree_hash  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = Path(__file__).resolve().parent
CACHE_DIR = RUNTIME_DIR / ".cache"
LOCK_PATH = RUNTIME_DIR / "lock.json"
TRACER_PATH = RUNTIME_DIR / "_tracer.py"
CAPABILITY_MANIFEST_PATH = (
    REPO_ROOT / "tests" / "goldens" / "capability-manifest" / "agent-wiz.list_tools.json"
)
LICENSE_OUTPUTS = (
    "licenses/specaudit-ctf-LICENSE.txt",
    "licenses/cpython-LICENSE.txt",
    "licenses/pyyaml-LICENSE.txt",
    "licenses/pyyaml-METADATA.txt",
)
CAPABILITY_ID = "agent-wiz.list_tools"
SUPPORTED_PLATFORM = ("Linux", "x86_64")
LAUNCHER_RELPATH = "bin/python3.11"
# Each sealed invocation is traced in its own fresh subprocess (see
# _tracer.py) and the locked closure is the union of their imports.
TRACE_INVOCATIONS = ("cli-json-invoke", "stdio-mcp-server")
INVOKE_ARGV = ("agent-wiz", "list_tools", "{}")
REQUIRED_BUNDLE_FILES = ("extension/__init__.py", "yaml/__init__.py")
# runpy removes the temporary `__main__`-bound entrypoints after `-m`
# exits, so the trace cannot observe either in final sys.modules. The CLI
# entrypoint, the stdio-MCP server entrypoint, and coverage.yaml are
# explicit non-module/source-data roots of the sealed invocations.
EXTRA_PRODUCER_FILES = (
    "extension/__main__.py",
    "extension/mcp_server.py",
    "extension/coverage.yaml",
)
_ATTEMPT_ID = "attempt-" + ("0" * 64)


class BuildError(Exception):
    """A fail-closed builder refusal. Never recoverable by retrying as-is."""


def log(message: str) -> None:
    print(f"[runtime.build] {message}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# lock.json
# --------------------------------------------------------------------------


def _load_lock() -> dict:
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


def _load_lock_snapshot() -> tuple[dict, str]:
    raw = LOCK_PATH.read_bytes()
    return json.loads(raw), f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _write_lock(data: dict) -> None:
    LOCK_PATH.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _sha256_file_hex(path: Path) -> str:
    return tree_hash.hash_file(path).split(":", 1)[1]


# --------------------------------------------------------------------------
# fetch
# --------------------------------------------------------------------------


def _verify_cached(path: Path, size: int, sha256_hex: str) -> bool:
    if not path.is_file():
        return False
    if path.stat().st_size != size:
        return False
    return _sha256_file_hex(path) == sha256_hex


def _fetch_one(entry: dict, dest: Path, *, offline: bool) -> None:
    if _verify_cached(dest, entry["size"], entry["sha256"]):
        log(f"cached and verified: {dest.name}")
        return
    if offline:
        raise BuildError(
            f"{dest.name} is missing or fails verification in the cache, "
            "and --offline was set: refusing to reach the network"
        )
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    log(f"fetching {entry['url']}")
    request = urllib.request.Request(
        entry["url"], headers={"User-Agent": "specaudit-ctf-runtime-builder"}
    )
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
        with tmp.open("wb") as out:
            shutil.copyfileobj(response, out)
    if not _verify_cached(tmp, entry["size"], entry["sha256"]):
        actual_size = tmp.stat().st_size if tmp.is_file() else -1
        tmp.unlink(missing_ok=True)
        raise BuildError(
            f"downloaded {dest.name} failed verification "
            f"(expected size={entry['size']} sha256={entry['sha256']}, "
            f"got size={actual_size}); refusing to admit it into the cache"
        )
    tmp.replace(dest)
    log(f"fetched and verified: {dest.name}")


def fetch(*, offline: bool = False) -> None:
    lock = _load_lock()
    _fetch_one(lock["cpython"], CACHE_DIR / "cpython.tar.gz", offline=offline)
    _fetch_one(lock["pyyaml"], CACHE_DIR / "pyyaml.whl", offline=offline)


def _verify_locked_cache(lock: dict) -> None:
    _fetch_one(lock["cpython"], CACHE_DIR / "cpython.tar.gz", offline=True)
    _fetch_one(lock["pyyaml"], CACHE_DIR / "pyyaml.whl", offline=True)


# --------------------------------------------------------------------------
# staging (extraction of the two locked, hash-verified inputs)
# --------------------------------------------------------------------------


def _safe_extract_tar(tar: tarfile.TarFile, dest: Path) -> None:
    dest = dest.resolve()
    try:
        tar.extractall(dest, filter="data")  # PEP 706, Python >= 3.12
        return
    except TypeError:
        pass  # older interpreter: fall through to manual traversal guard
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if target != dest and dest not in target.parents:
            raise BuildError(f"refusing to extract outside destination: {member.name}")
    tar.extractall(dest)  # noqa: S202 - traversal already checked above


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    dest = dest.resolve()
    for info in zf.infolist():
        target = (dest / info.filename).resolve()
        if target != dest and dest not in target.parents:
            raise BuildError(f"refusing to extract outside destination: {info.filename}")
    zf.extractall(dest)  # noqa: S202 - traversal already checked above


@contextlib.contextmanager
def staged_inputs():
    """Yield fresh, invocation-private extractions of both locked inputs.

    Only the verified archive/wheel bytes are shared. Persistent marker-based
    extracted trees are intentionally forbidden: one interrupted or parallel
    build must never poison another build's trusted source view.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".stage-", dir=CACHE_DIR) as tmp:
        base = Path(tmp)
        staged_cpython = base / "cpython"
        staged_yaml = base / "yaml"
        staged_cpython.mkdir()
        staged_yaml.mkdir()
        with tarfile.open(CACHE_DIR / "cpython.tar.gz") as tar:
            _safe_extract_tar(tar, staged_cpython)
        with zipfile.ZipFile(CACHE_DIR / "pyyaml.whl") as zf:
            _safe_extract_zip(zf, staged_yaml)
        yield staged_cpython, staged_yaml


def _launcher_path(staged_cpython: Path) -> Path:
    return staged_cpython / "python" / "bin" / "python3.11"


def _stdlib_root(staged_cpython: Path) -> Path:
    return staged_cpython / "python" / "lib" / "python3.11"


def _require_real_launcher(path: Path) -> None:
    if os.path.islink(path):
        raise BuildError(f"staged launcher is a symlink, refusing it: {path}")
    if not path.is_file():
        raise BuildError(f"staged launcher is missing: {path}")
    with path.open("rb") as handle:
        head = handle.read(20)
    if head[:2] == b"#!":
        raise BuildError(
            f"staged launcher starts with a shebang; only a real ELF "
            f"python3.11 is a permitted launcher: {path}"
        )
    # ELF64, little-endian, EM_X86_64. The v1 lock is intentionally not a
    # cross-platform promise and must not silently admit a different asset.
    if (
        len(head) < 20
        or head[:4] != b"\x7fELF"
        or head[4] != 2
        or head[5] != 1
        or head[18:20] != b"\x3e\x00"
    ):
        raise BuildError(f"launcher is not a Linux x86-64 ELF executable: {path}")


# --------------------------------------------------------------------------
# trace (subprocess, under the staged/locked interpreter — see _tracer.py)
# --------------------------------------------------------------------------


def run_tracer(
    staged_cpython: Path, staged_yaml: Path, invocation: str
) -> dict:
    """Run exactly one sealed invocation's trace in a fresh subprocess."""
    if invocation not in TRACE_INVOCATIONS:
        raise BuildError(f"unknown sealed invocation: {invocation!r}")
    launcher = _launcher_path(staged_cpython)
    _require_real_launcher(launcher)
    with tempfile.TemporaryDirectory(prefix="ctf-runtime-trace-") as tmp:
        out_path = Path(tmp) / "trace.json"
        # Match the validator's env_clear boundary. PYTHONHOME points only at
        # the hash-verified staged CPython input; repo/yaml paths are explicit
        # tracer arguments inserted ahead of that stdlib by _tracer.py.
        env = {
            "PYTHONHOME": str(staged_cpython / "python"),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        proc = subprocess.run(
            [
                str(launcher),
                "-S",
                str(TRACER_PATH),
                str(REPO_ROOT),
                str(staged_yaml),
                str(out_path),
                invocation,
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise BuildError(
                f"{invocation} tracer subprocess exited {proc.returncode}: "
                f"{proc.stderr.strip()}"
            )
        return json.loads(out_path.read_text(encoding="utf-8"))


def run_tracers(staged_cpython: Path, staged_yaml: Path) -> dict[str, dict]:
    """Trace every sealed invocation; returns one bucket set per profile."""
    return {
        invocation: run_tracer(staged_cpython, staged_yaml, invocation)
        for invocation in TRACE_INVOCATIONS
    }


def merge_traces(traces: dict[str, dict]) -> dict[str, list[dict[str, str]]]:
    """Union every invocation's per-module records into one closure.

    The bundle must serve *both* sealed invocations, so its file set is the
    union; a module imported by only one profile is still required. Records
    are de-duplicated by (name, file) and re-sorted for deterministic
    locking. One module name resolving to two different files across
    invocations (or within one) is a hard error: the bundle could not
    ship both and still have a truthful module identity.
    """
    merged: dict[str, dict[tuple[str, str], dict[str, str]]] = {}
    for invocation, buckets in traces.items():
        for bucket, records in buckets.items():
            by_key = merged.setdefault(bucket, {})
            names: dict[str, str] = {
                rec["name"]: rec["file"] for rec in by_key.values()
            }
            for record in records:
                key = (record["name"], record["file"])
                by_key.setdefault(key, record)
                previous_file = names.setdefault(record["name"], record["file"])
                if previous_file != record["file"]:
                    raise BuildError(
                        f"traced module {record['name']!r} resolves to two files "
                        f"({previous_file!r} and {record['file']!r}); cannot merge "
                        f"invocation {invocation!r} into one bundle closure"
                    )
    return {
        bucket: sorted(records.values(), key=lambda rec: (rec["name"], rec["file"]))
        for bucket, records in sorted(merged.items())
    }


def _traced_producer_relpaths(traced: dict) -> list[str]:
    relpaths = {
        os.path.relpath(rec["file"], REPO_ROOT) for rec in traced["extension"]
    }
    relpaths.update(EXTRA_PRODUCER_FILES)
    return sorted(relpaths)


def _relative_file(path: str | Path, root: Path) -> str:
    """Return a safe POSIX relative path for a regular source file."""
    root = root.resolve()
    candidate = Path(path).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise BuildError(f"traced file escaped its locked source root: {candidate}") from exc
    if not candidate.is_file() or candidate.is_symlink():
        raise BuildError(f"traced source is not a regular non-symlink file: {candidate}")
    return _safe_relpath(relative.as_posix())


def _safe_relpath(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise BuildError(f"unsafe bundle-relative path: {value!r}")
    parts = value.split("/")
    if (
        any(part in ("", ".", "..") for part in parts)
        or "\\" in value
        or "\0" in value
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)
    ):
        raise BuildError(f"unsafe bundle-relative path: {value!r}")
    return value


def _module_records(records: list[dict[str, str]], root: Path) -> list[dict[str, str]]:
    """Normalize and content-lock every module file touched by the trace."""
    normalized = [
        {
            "name": record["name"],
            "path": _relative_file(record["file"], root),
            "sha256": _sha256_file_hex(Path(record["file"])),
        }
        for record in records
    ]
    return sorted(normalized, key=lambda item: (item["name"], item["path"]))


def _unique_relpaths(records: list[dict[str, str]], root: Path) -> list[str]:
    """Map trace records to a deterministic, de-duplicated source file set."""
    return sorted({_relative_file(record["file"], root) for record in records})


def _expected_bundle_files(lock: dict) -> set[str]:
    expected = {LAUNCHER_RELPATH, *LICENSE_OUTPUTS}
    expected.update(_safe_relpath(path) for path in lock["producer_source_files"])
    expected.update(
        _safe_relpath(f"lib/python3.11/{record['path']}")
        for record in lock["included_stdlib_files"]
    )
    expected.update(
        _safe_relpath(record["path"]) for record in lock["included_yaml_files"]
    )
    return expected


def _expected_bundle_hashes(lock: dict) -> dict[str, str]:
    expected: dict[str, str] = {LAUNCHER_RELPATH: lock["cpython"]["launcher_sha256"]}

    def add(path: str, digest: str) -> None:
        path = _safe_relpath(path)
        previous = expected.setdefault(path, digest)
        if previous != digest:
            raise BuildError(f"lock assigns conflicting bytes to bundle path: {path}")

    for path, digest in lock["producer_source_files"].items():
        add(path, digest)
    for record in lock["included_stdlib_files"]:
        add(f"lib/python3.11/{record['path']}", record["sha256"])
    for record in lock["included_yaml_files"]:
        add(record["path"], record["sha256"])
    for path, record in lock["license_files"].items():
        add(path, record["sha256"])
    if set(expected) != _expected_bundle_files(lock):
        raise BuildError("lock file/hash inventories disagree")
    return expected


def _verify_locked_output_bytes(out_dir: Path, lock: dict) -> None:
    for relpath, expected_hex in sorted(_expected_bundle_hashes(lock).items()):
        path = out_dir / relpath
        if path.is_symlink() or not path.is_file():
            raise BuildError(f"locked output file is missing/non-regular: {relpath}")
        actual_hex = _sha256_file_hex(path)
        if actual_hex != expected_hex:
            raise BuildError(
                f"locked output content drift: {relpath} "
                f"(locked {expected_hex[:12]}…, copied {actual_hex[:12]}…)"
            )


def _license_records(staged_cpython: Path, staged_yaml: Path) -> dict[str, dict[str, str]]:
    dist_info_candidates = sorted(staged_yaml.glob("*.dist-info"))
    if len(dist_info_candidates) != 1:
        raise BuildError(
            f"expected exactly one PyYAML dist-info directory, found: "
            f"{dist_info_candidates}"
        )
    dist_info = dist_info_candidates[0]
    sources = {
        "licenses/specaudit-ctf-LICENSE.txt": ("LICENSE", REPO_ROOT / "LICENSE"),
        "licenses/cpython-LICENSE.txt": (
            "cpython:python/lib/python3.11/LICENSE.txt",
            _stdlib_root(staged_cpython) / "LICENSE.txt",
        ),
        "licenses/pyyaml-LICENSE.txt": (
            "pyyaml:.dist-info/licenses/LICENSE",
            dist_info / "licenses" / "LICENSE",
        ),
        "licenses/pyyaml-METADATA.txt": (
            "pyyaml:.dist-info/METADATA",
            dist_info / "METADATA",
        ),
    }
    return {
        output: {
            "source": label,
            "sha256": _sha256_file_hex(source),
        }
        for output, (label, source) in sorted(sources.items())
    }


# --------------------------------------------------------------------------
# lock-check / lock-write
# --------------------------------------------------------------------------


def _producer_source_problems(lock: dict) -> list[str]:
    producer_files: dict[str, str] = lock["producer_source_files"]
    problems: list[str] = []
    for relpath, expected_hex in sorted(producer_files.items()):
        path = REPO_ROOT / relpath
        if path.is_symlink() or not path.is_file():
            problems.append(f"missing producer source file: {relpath}")
            continue
        actual_hex = _sha256_file_hex(path)
        if actual_hex != expected_hex:
            problems.append(
                f"producer source content drift: {relpath} "
                f"(locked {expected_hex[:12]}…, current {actual_hex[:12]}…)"
            )
    return problems


def _invocation_records(buckets: dict) -> dict[str, list[str]]:
    """Per-invocation summary recorded in lock.json for drift visibility."""
    return {
        "stdlib_module_names": sorted(rec["name"] for rec in buckets["stdlib"]),
        "yaml_module_names": sorted(rec["name"] for rec in buckets["yaml"]),
        "extension_paths": sorted(
            os.path.relpath(rec["file"], REPO_ROOT) for rec in buckets["extension"]
        ),
    }


def _validate_locked_sources(
    lock: dict, staged_cpython: Path, staged_yaml: Path, traces: dict[str, dict]
) -> tuple[int, int, int]:
    traced = merge_traces(traces)
    producer_files: dict[str, str] = lock["producer_source_files"]
    problems = _producer_source_problems(lock)
    traced_relpaths = _traced_producer_relpaths(traced)
    locked_relpaths = sorted(producer_files)
    if traced_relpaths != locked_relpaths:
        added = sorted(set(traced_relpaths) - set(locked_relpaths))
        removed = sorted(set(locked_relpaths) - set(traced_relpaths))
        problems.append(
            "producer source FILE SET drift (run `lock-write` after review): "
            f"added={added} removed={removed}"
        )

    locked_invocations = lock.get("invocations")
    if not isinstance(locked_invocations, dict) or sorted(
        locked_invocations
    ) != sorted(TRACE_INVOCATIONS):
        problems.append(
            "sealed-invocation provenance drift: lock.json does not record exactly "
            f"{TRACE_INVOCATIONS} (run `lock-write` after review)"
        )
    else:
        for invocation, buckets in sorted(traces.items()):
            if _invocation_records(buckets) != locked_invocations[invocation]:
                problems.append(
                    f"sealed invocation {invocation!r} module-set drift: the trace "
                    "no longer matches lock.json's per-invocation record "
                    "(run `lock-write` after review)"
                )

    traced_stdlib = sorted(rec["name"] for rec in traced["stdlib"])
    if traced_stdlib != lock["included_stdlib_module_names"]:
        problems.append(
            "stdlib module-name set drift: traced imports a different set of "
            "stdlib modules than lock.json records (run `lock-write` after review)"
        )
    traced_yaml = sorted(rec["name"] for rec in traced["yaml"])
    if traced_yaml != lock["included_yaml_module_names"]:
        problems.append(
            "yaml module-name set drift: traced imports a different set of "
            "yaml modules than lock.json records (run `lock-write` after review)"
        )
    traced_stdlib_files = _module_records(
        traced["stdlib"], _stdlib_root(staged_cpython)
    )
    if traced_stdlib_files != lock.get("included_stdlib_files"):
        problems.append(
            "stdlib FILE closure/content drift: trace no longer matches the "
            "locked copied file set (run `lock-write` after review)"
        )
    traced_yaml_files = _module_records(traced["yaml"], staged_yaml)
    if traced_yaml_files != lock.get("included_yaml_files"):
        problems.append(
            "yaml FILE closure/content drift: trace no longer matches the "
            "locked copied file set (run `lock-write` after review)"
        )
    launcher_hex = _sha256_file_hex(_launcher_path(staged_cpython))
    if launcher_hex != lock["cpython"].get("launcher_sha256"):
        problems.append("launcher content does not match its locked extracted digest")
    if _license_records(staged_cpython, staged_yaml) != lock.get("license_files"):
        problems.append("license/metadata inputs no longer match their locked bytes")
    manifest_hex = _sha256_file_hex(CAPABILITY_MANIFEST_PATH)
    manifest_lock = lock.get("capability_manifest", {})
    if (
        manifest_lock.get("path")
        != "tests/goldens/capability-manifest/agent-wiz.list_tools.json"
        or manifest_lock.get("sha256") != manifest_hex
    ):
        problems.append("capability-manifest bytes no longer match their lock")
    if problems:
        raise BuildError("locked source validation failed:\n  " + "\n  ".join(problems))
    return len(producer_files), len(traced_stdlib), len(traced_yaml)


def lock_check(*, full: bool = False) -> None:
    lock, _lock_sha256 = _load_lock_snapshot()
    producer_files: dict[str, str] = lock["producer_source_files"]
    problems = _producer_source_problems(lock)
    if not full:
        if problems:
            raise BuildError("lock-check (fast) failed:\n  " + "\n  ".join(problems))
        log(f"lock-check (fast): {len(producer_files)} producer source files match lock.json")
        return

    # Full checking may be expensive, but it is still offline. Network use is
    # confined to the explicit `fetch` command.
    _verify_locked_cache(lock)
    with staged_inputs() as (staged_cpython, staged_yaml):
        traces = run_tracers(staged_cpython, staged_yaml)
        counts = _validate_locked_sources(lock, staged_cpython, staged_yaml, traces)
        # Detect a cache replacement during extraction/trace, after source
        # bytes have been selected but before reporting success.
        _verify_locked_cache(lock)
    log(
        f"lock-check (full): {counts[0]} producer files, "
        f"{counts[1]} stdlib modules, {counts[2]} yaml modules "
        f"across {len(TRACE_INVOCATIONS)} sealed invocations "
        "all match lock.json"
    )


def lock_write() -> None:
    # An explicit lock update still consumes only already verified inputs.
    # Fetching/updating those inputs is a separate reviewed action.
    fetch(offline=True)
    with staged_inputs() as (staged_cpython, staged_yaml):
        traces = run_tracers(staged_cpython, staged_yaml)
        traced = merge_traces(traces)

        producer_files = {
            os.path.relpath(rec["file"], REPO_ROOT): _sha256_file_hex(Path(rec["file"]))
            for rec in traced["extension"]
        }
        for relpath in EXTRA_PRODUCER_FILES:
            producer_files[relpath] = _sha256_file_hex(REPO_ROOT / relpath)

        lock = _load_lock()
        lock["producer_source_files"] = dict(sorted(producer_files.items()))
        lock["invocations"] = {
            invocation: _invocation_records(buckets)
            for invocation, buckets in sorted(traces.items())
        }
        lock["included_stdlib_module_names"] = sorted(
            rec["name"] for rec in traced["stdlib"]
        )
        lock["included_yaml_module_names"] = sorted(
            rec["name"] for rec in traced["yaml"]
        )
        lock["included_stdlib_files"] = _module_records(
            traced["stdlib"], _stdlib_root(staged_cpython)
        )
        lock["included_yaml_files"] = _module_records(traced["yaml"], staged_yaml)
        lock["cpython"]["launcher_sha256"] = _sha256_file_hex(
            _launcher_path(staged_cpython)
        )
        lock["license_files"] = _license_records(staged_cpython, staged_yaml)
    lock["capability_manifest"] = {
        "path": "tests/goldens/capability-manifest/agent-wiz.list_tools.json",
        "sha256": _sha256_file_hex(CAPABILITY_MANIFEST_PATH),
    }
    _write_lock(lock)
    log(
        f"lock.json updated: {len(producer_files)} producer files, "
        f"{len(lock['included_stdlib_module_names'])} stdlib modules, "
        f"{len(lock['included_yaml_module_names'])} yaml modules across "
        f"{len(traces)} sealed invocations"
    )


# --------------------------------------------------------------------------
# assemble (build the trimmed, normalized bundle tree)
# --------------------------------------------------------------------------


def _copy_regular_file(src: Path, dst: Path, *, mode: int) -> None:
    if os.path.islink(src):
        raise BuildError(f"refusing to copy a symlink into the bundle: {src}")
    if not src.is_file():
        raise BuildError(f"expected a regular file, found none: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    os.chmod(dst, mode)


def _remove_existing_tree(path: Path) -> None:
    """Remove one prior builder-owned tree without following planted links."""
    if not path.exists() and not path.is_symlink():
        return
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BuildError(f"refusing to replace a linked/non-directory output: {path}")
    # A prior successful build is intentionally 0555/0444. Restore write
    # permission only on real directories so an unprivileged owner can replace
    # that exact output on the next run. Files need no write bit to be unlinked.
    for dirpath, dirnames, filenames in os.walk(path, topdown=True, followlinks=False):
        directory = Path(dirpath)
        for name in [*dirnames, *filenames]:
            child = directory / name
            child_info = os.lstat(child)
            if stat.S_ISLNK(child_info.st_mode):
                raise BuildError(f"refusing to remove output containing a symlink: {child}")
            if name in dirnames and not stat.S_ISDIR(child_info.st_mode):
                raise BuildError(f"output traversal changed type: {child}")
            if name in filenames and not stat.S_ISREG(child_info.st_mode):
                raise BuildError(f"refusing to remove non-regular output: {child}")
        os.chmod(directory, 0o700)
    shutil.rmtree(path)


def _seal_directory_modes(root: Path) -> None:
    # Bottom-up: children lose their write bit before their parent does.
    for dirpath, _dirnames, _filenames in os.walk(root, topdown=False):
        os.chmod(dirpath, 0o555)


def _write_licenses(out_dir: Path, staged_cpython: Path, staged_yaml: Path) -> None:
    licenses_dir = out_dir / "licenses"
    _copy_regular_file(
        REPO_ROOT / "LICENSE", licenses_dir / "specaudit-ctf-LICENSE.txt", mode=0o444
    )
    _copy_regular_file(
        _stdlib_root(staged_cpython) / "LICENSE.txt",
        licenses_dir / "cpython-LICENSE.txt",
        mode=0o444,
    )
    dist_info_candidates = sorted(staged_yaml.glob("*.dist-info"))
    if len(dist_info_candidates) != 1:
        raise BuildError(
            f"expected exactly one PyYAML dist-info directory, found: "
            f"{dist_info_candidates}"
        )
    dist_info = dist_info_candidates[0]
    _copy_regular_file(
        dist_info / "licenses" / "LICENSE",
        licenses_dir / "pyyaml-LICENSE.txt",
        mode=0o444,
    )
    _copy_regular_file(
        dist_info / "METADATA", licenses_dir / "pyyaml-METADATA.txt", mode=0o444
    )


def assemble(out_dir: Path) -> dict:
    _require_supported_platform()
    if not out_dir.is_absolute():
        raise BuildError("bundle output path must be absolute")
    lock, lock_sha256 = _load_lock_snapshot()
    source_revision = _git_source_revision()
    _verify_locked_cache(lock)
    with staged_inputs() as (staged_cpython, staged_yaml):
        traces = run_tracers(staged_cpython, staged_yaml)
        traced = merge_traces(traces)
        _validate_locked_sources(lock, staged_cpython, staged_yaml, traces)
        _verify_locked_cache(lock)

        # Keep the previous complete output intact until all locked sources
        # for this exact snapshot have passed validation.
        _remove_existing_tree(out_dir)
        out_dir.mkdir(parents=True)

        launcher_src = _launcher_path(staged_cpython)
        _require_real_launcher(launcher_src)
        launcher_dst = out_dir / "bin" / "python3.11"
        _copy_regular_file(launcher_src, launcher_dst, mode=0o555)

        stdlib_root = _stdlib_root(staged_cpython)
        lib_root = out_dir / "lib" / "python3.11"
        for rel in _unique_relpaths(traced["stdlib"], stdlib_root):
            _copy_regular_file(stdlib_root / rel, lib_root / rel, mode=0o444)

        for rel in _unique_relpaths(traced["yaml"], staged_yaml):
            _copy_regular_file(staged_yaml / rel, out_dir / rel, mode=0o444)

        for rel in _unique_relpaths(traced["extension"], REPO_ROOT):
            _copy_regular_file(REPO_ROOT / rel, out_dir / rel, mode=0o444)
        for relpath in EXTRA_PRODUCER_FILES:
            _copy_regular_file(REPO_ROOT / relpath, out_dir / relpath, mode=0o444)

        _write_licenses(out_dir, staged_cpython, staged_yaml)
        # Bind copied bytes back to the same lock snapshot. This catches a
        # producer-source change during copy and prevents old/new lock mixing.
        _verify_locked_output_bytes(out_dir, lock)
    _seal_directory_modes(out_dir)

    for required in REQUIRED_BUNDLE_FILES:
        if not (out_dir / required).is_file():
            raise BuildError(f"assembled bundle is missing a required file: {required}")

    return {
        "out_dir": out_dir,
        "launcher": launcher_dst,
        "lock": lock,
        "runtime_lock_sha256": lock_sha256,
        "source_revision": source_revision,
    }


def _require_supported_platform() -> None:
    system, machine = platform.system(), platform.machine()
    normalized_machine = "x86_64" if machine in ("x86_64", "AMD64") else machine
    if (system, normalized_machine) != SUPPORTED_PLATFORM:
        raise BuildError(
            f"unsupported build platform {system}/{machine}: this packet's only "
            f"supported target is {SUPPORTED_PLATFORM[0]}/{SUPPORTED_PLATFORM[1]} "
            "GNU/glibc"
        )


# --------------------------------------------------------------------------
# smoke (sealed CLI invocation + sealed stdio-MCP server)
# --------------------------------------------------------------------------


def _sealed_env(out_dir: Path) -> dict[str, str]:
    # Exactly the three env vars the trusted Rust spawner sets after
    # env_clear(): no PATH, no HOME, no PYTHONPATH, no inherited user/system
    # site authority.
    return {
        "PYTHONHOME": str(out_dir),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def verify(out_dir: Path, *, lock: dict | None = None) -> dict:
    if not out_dir.is_absolute():
        raise BuildError("bundle path must be absolute")
    launcher = out_dir / "bin" / "python3.11"
    _require_real_launcher(launcher)
    for required in REQUIRED_BUNDLE_FILES:
        if not (out_dir / required).is_file():
            raise BuildError(f"bundle is missing a required file: {required}")
    try:
        active_lock = lock if lock is not None else _load_lock_snapshot()[0]
        _verify_layout(out_dir, _expected_bundle_files(active_lock))
        _verify_locked_output_bytes(out_dir, active_lock)
        return {
            "launcher_sha256": tree_hash.hash_file(launcher),
            "bundle_tree_sha256": tree_hash.hash_producer_bundle(out_dir),
        }
    except (OSError, tree_hash.TreeHashError) as exc:
        raise BuildError(f"bundle verification failed: {exc}") from exc


def _verify_layout(out_dir: Path, expected_files: set[str]) -> None:
    """Enforce the mode/type/inventory contract omitted from the tree digest."""
    actual_files: set[str] = set()
    seen_files: set[tuple[int, int]] = set()
    for dirpath, dirnames, filenames in os.walk(out_dir, topdown=True, followlinks=False):
        directory = Path(dirpath)
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise BuildError(f"bundle directory is not a real directory: {directory}")
        if stat.S_IMODE(info.st_mode) != 0o555:
            raise BuildError(f"bundle directory mode must be 0555: {directory}")
        for name in [*dirnames, *filenames]:
            _safe_relpath((directory / name).relative_to(out_dir).as_posix())
        for name in dirnames:
            child = directory / name
            child_info = os.lstat(child)
            if stat.S_ISLNK(child_info.st_mode) or not stat.S_ISDIR(child_info.st_mode):
                raise BuildError(f"bundle contains a linked/non-directory path: {child}")
        for name in filenames:
            child = directory / name
            rel = child.relative_to(out_dir).as_posix()
            child_info = os.lstat(child)
            if stat.S_ISLNK(child_info.st_mode) or not stat.S_ISREG(child_info.st_mode):
                raise BuildError(f"bundle contains a linked/non-regular file: {child}")
            identity = (child_info.st_dev, child_info.st_ino)
            if child_info.st_nlink != 1 or identity in seen_files:
                raise BuildError(f"bundle contains a hardlinked file: {child}")
            seen_files.add(identity)
            expected_mode = 0o555 if rel == LAUNCHER_RELPATH else 0o444
            if stat.S_IMODE(child_info.st_mode) != expected_mode:
                raise BuildError(
                    f"bundle file mode must be {expected_mode:04o}: {child}"
                )
            actual_files.add(rel)
    missing = sorted(expected_files - actual_files)
    extra = sorted(actual_files - expected_files)
    if missing or extra:
        raise BuildError(f"bundle file inventory mismatch: missing={missing} extra={extra}")


def smoke(out_dir: Path, *, timeout: float = 30.0) -> dict:
    launcher = out_dir / "bin" / "python3.11"
    _require_real_launcher(launcher)
    env = _sealed_env(out_dir)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ctf-runtime-custody-") as tmp:
        artifact_dir = Path(tmp) / "attempt"
        artifact_dir.mkdir(mode=0o700)
        proc = subprocess.run(
            [
                str(launcher),
                "-S",
                "-m",
                "extension",
                "invoke",
                *INVOKE_ARGV,
                "--attempt-id",
                _ATTEMPT_ID,
                "--artifact-dir",
                str(artifact_dir),
            ],
            cwd=str(out_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        artifact_names = sorted(os.listdir(artifact_dir))
        artifact_details = []
        for name in artifact_names:
            path = artifact_dir / name
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise BuildError(f"smoke produced a non-regular artifact: {name}")
            if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise BuildError(f"smoke artifact mode/link contract failed: {name}")
            artifact_details.append(
                {"name": name, "size": info.st_size, "sha256": tree_hash.hash_file(path)}
            )
    elapsed_s = time.monotonic() - started
    if proc.returncode != 0:
        raise BuildError(
            f"smoke invocation exited {proc.returncode}: {proc.stderr.strip()}"
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise BuildError(f"smoke invocation did not print JSON: {exc}") from exc
    if payload.get("capability_id") != CAPABILITY_ID or payload.get("status") != "complete":
        raise BuildError(
            f"smoke invocation did not return a complete {CAPABILITY_ID} envelope: "
            f"{payload}"
        )
    if payload.get("attempt_id") != _ATTEMPT_ID:
        raise BuildError("smoke invocation did not preserve the validator attempt id")
    claimed = sorted(item["digest"] for item in payload.get("artifacts", []))
    observed = sorted(item["sha256"] for item in artifact_details)
    if not claimed or claimed != observed:
        raise BuildError(
            f"smoke artifact custody mismatch: claimed={claimed} observed={observed}"
        )
    return {
        "elapsed_s": elapsed_s,
        "artifact_count": len(artifact_details),
        "artifact_digests": observed,
        "envelope": payload,
    }


def smoke_mcp(out_dir: Path, *, timeout: float = 30.0) -> dict:
    """Drive the sealed stdio-MCP server through its real ndjson serve loop.

    This is the X4-VAL deployment shape: the same launcher and bundle as
    the CLI smoke, the same sealed environment, but the
    ``-m extension.mcp_server`` entrypoint talking JSON-RPC over stdio.
    The fixed read-only handshake (initialize, notifications/initialized,
    tools/list, EOF) is written to the child's pipe; the child must answer
    both requests per the shared exchange contract and exit 0 on EOF.
    """
    launcher = out_dir / "bin" / "python3.11"
    _require_real_launcher(launcher)
    started = time.monotonic()
    with subprocess.Popen(
        [str(launcher), "-S", "-m", "extension.mcp_server"],
        cwd=str(out_dir),
        env=_sealed_env(out_dir),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as proc:
        try:
            stdout_text, stderr_text = proc.communicate(
                input=_tracer.MCP_TRACE_STDIN, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise BuildError("smoke MCP server did not exit within the timeout") from None
    elapsed_s = time.monotonic() - started
    if proc.returncode != 0:
        raise BuildError(
            f"smoke MCP server exited {proc.returncode}: {stderr_text.strip()}"
        )
    try:
        responses = _tracer.validate_mcp_exchange(stdout_text)
    except RuntimeError as exc:
        raise BuildError(f"smoke MCP exchange failed its contract: {exc}") from exc
    return {
        "elapsed_s": elapsed_s,
        "response_count": len(responses),
        "protocol_version": responses[0]["result"]["protocolVersion"],
    }


# --------------------------------------------------------------------------
# pack / unpack (deterministic tar.gz for distribution, not for hashing)
# --------------------------------------------------------------------------


def pack(out_dir: Path, tar_path: Path) -> None:
    """A byte-reproducible tar.gz: sorted names, mtime=0, uid/gid=0, no
    owner/group names. The verification digest never depends on this —
    :func:`tree_hash.hash_producer_bundle` is timestamp/ownership-blind by
    construction — this is purely for a reproducible distribution artifact.
    """
    import gzip

    def reset(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        return info

    paths = sorted(out_dir.rglob("*"))
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    with tar_path.open("wb") as raw:
        # filename="" prevents the destination filename from entering the
        # gzip header, so distinct output paths remain byte-identical.
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                tar.add(out_dir, arcname=".", filter=reset, recursive=False)
                for path in paths:
                    tar.add(
                        path,
                        arcname=str(path.relative_to(out_dir)),
                        filter=reset,
                        recursive=False,
                    )


def unpack(tar_path: Path, dest_dir: Path) -> None:
    _remove_existing_tree(dest_dir)
    dest_dir.mkdir(parents=True)
    with tarfile.open(tar_path) as tar:
        _safe_extract_tar(tar, dest_dir)
    # Python's safe `data` extraction filter intentionally widens some modes
    # to owner-readable/writable defaults. Reapply this format's much narrower
    # normalized modes without ever following a link, then verify the exact
    # inventory/type/link contract in the caller.
    for dirpath, dirnames, filenames in os.walk(
        dest_dir, topdown=False, followlinks=False
    ):
        directory = Path(dirpath)
        for name in [*dirnames, *filenames]:
            child = directory / name
            info = os.lstat(child)
            if stat.S_ISLNK(info.st_mode):
                raise BuildError(f"archive extracted a forbidden symlink: {child}")
            if stat.S_ISDIR(info.st_mode):
                os.chmod(child, 0o555)
            elif stat.S_ISREG(info.st_mode):
                rel = child.relative_to(dest_dir).as_posix()
                os.chmod(child, 0o555 if rel == LAUNCHER_RELPATH else 0o444)
            else:
                raise BuildError(f"archive extracted a non-regular entry: {child}")
        os.chmod(directory, 0o555)


# --------------------------------------------------------------------------
# high-level pipelines
# --------------------------------------------------------------------------


def _git_source_revision() -> str:
    revision = "unknown"
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    return revision


def manifest_for(
    digests: dict,
    *,
    lock: dict | None = None,
    runtime_lock_sha256: str | None = None,
    source_revision: str | None = None,
) -> dict:
    if lock is None:
        lock, snapshot_sha256 = _load_lock_snapshot()
    else:
        snapshot_sha256 = runtime_lock_sha256
    if snapshot_sha256 is None:
        raise BuildError("manifest requires the exact runtime-lock snapshot digest")
    revision = source_revision if source_revision is not None else _git_source_revision()
    capability_manifest = lock["capability_manifest"]
    return {
        "schema": "specaudit-ctf.runtime-bundle.v1",
        "tool": lock["tool"],
        "capability_id": CAPABILITY_ID,
        "source_revision": revision,
        "runtime_lock_sha256": snapshot_sha256,
        "capability_manifest": {
            "path": capability_manifest["path"],
            "sha256": f"sha256:{capability_manifest['sha256']}",
        },
        "inputs": {
            "cpython": {
                key: lock["cpython"][key]
                for key in ("version", "asset", "size", "sha256", "platform")
            },
            "pyyaml": {
                key: lock["pyyaml"][key]
                for key in ("version", "wheel", "size", "sha256")
            },
        },
        "platform": {
            "os": "linux",
            "architecture": "x86_64",
            "abi": "gnu-glibc",
            "glibc_minimum": "2.17",
            "host_loader_outside_bundle": True,
            "host_abi_dependencies": lock["cpython"]["host_abi"],
        },
        "launcher_relpath": LAUNCHER_RELPATH,
        "required_bundle_files": list(REQUIRED_BUNDLE_FILES),
        **digests,
    }


def build(out_dir: Path) -> dict:
    timings: dict[str, float] = {}

    t0 = time.monotonic()
    info = assemble(out_dir)
    timings["assemble_s"] = time.monotonic() - t0

    t0 = time.monotonic()
    digests = verify(out_dir, lock=info["lock"])
    timings["verify_s"] = time.monotonic() - t0

    tar_path = out_dir.parent / (out_dir.name + ".tar.gz")
    t0 = time.monotonic()
    pack(out_dir, tar_path)
    timings["pack_s"] = time.monotonic() - t0

    reextracted = out_dir.parent / (out_dir.name + ".reextracted")
    t0 = time.monotonic()
    unpack(tar_path, reextracted)
    timings["unpack_s"] = time.monotonic() - t0

    t0 = time.monotonic()
    redigests = verify(reextracted, lock=info["lock"])
    timings["cold_verify_s"] = time.monotonic() - t0
    if redigests != digests:
        raise BuildError(
            "re-extracted bundle digests do not match the assembled bundle: "
            f"assembled={digests} re-extracted={redigests}"
        )

    t0 = time.monotonic()
    warm_digests = verify(reextracted, lock=info["lock"])
    timings["warm_verify_s"] = time.monotonic() - t0
    if warm_digests != digests:
        raise BuildError("warm verification changed the accepted bundle digests")

    t0 = time.monotonic()
    smoke_result = smoke(reextracted)
    timings["cold_launch_s"] = time.monotonic() - t0
    t0 = time.monotonic()
    smoke(reextracted)
    timings["repeat_launch_s"] = time.monotonic() - t0

    t0 = time.monotonic()
    smoke_mcp_result = smoke_mcp(reextracted)
    timings["mcp_cold_launch_s"] = time.monotonic() - t0
    t0 = time.monotonic()
    smoke_mcp(reextracted)
    timings["mcp_repeat_launch_s"] = time.monotonic() - t0

    manifest = manifest_for(
        digests,
        lock=info["lock"],
        runtime_lock_sha256=info["runtime_lock_sha256"],
        source_revision=info["source_revision"],
    )
    manifest_path = out_dir.parent / (out_dir.name + ".manifest.json")
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    manifest_path.write_bytes(manifest_bytes)
    manifest_sha256 = tree_hash.hash_file(manifest_path)
    timings_path = out_dir.parent / (out_dir.name + ".timings.json")
    timings_path.write_text(json.dumps(timings, indent=2, sort_keys=True) + "\n")
    log(f"manifest written: {manifest_path}")
    return {
        "info": info,
        "digests": digests,
        "timings": timings,
        "manifest_path": manifest_path,
        "manifest_sha256": manifest_sha256,
        "timings_path": timings_path,
        "smoke": smoke_result,
        "smoke_mcp": smoke_mcp_result,
    }


def selfcheck(base_dir: Path) -> dict:
    """Two archive-backed assemblies and their archives must be identical."""
    out_a = base_dir / "selfcheck-a"
    out_b = base_dir / "selfcheck-b"
    info_a = assemble(out_a)
    archive_a = base_dir / "selfcheck-a.tar.gz"
    pack(out_a, archive_a)
    info_b = assemble(out_b)
    archive_b = base_dir / "selfcheck-b.tar.gz"
    pack(out_b, archive_b)
    if info_a["runtime_lock_sha256"] != info_b["runtime_lock_sha256"]:
        raise BuildError("runtime lock changed between reproducibility assemblies")
    digest_a = verify(out_a, lock=info_a["lock"])
    digest_b = verify(out_b, lock=info_b["lock"])
    if digest_a != digest_b:
        raise BuildError(
            f"two clean builds from the same locked inputs produced different "
            f"digests: {digest_a} != {digest_b}"
        )
    archive_digest_a = tree_hash.hash_file(archive_a)
    archive_digest_b = tree_hash.hash_file(archive_b)
    if archive_digest_a != archive_digest_b:
        raise BuildError(
            "two normalized archives from the same locked inputs were not "
            f"byte-identical: {archive_digest_a} != {archive_digest_b}"
        )
    return {**digest_a, "archive_sha256": archive_digest_a}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _default_out_dir() -> Path:
    return CACHE_DIR / "build-out" / "bundle"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m runtime.build")
    sub = parser.add_subparsers(dest="cmd", required=True)

    fetch_p = sub.add_parser("fetch", help="download+verify locked inputs")
    fetch_p.add_argument("--offline", action="store_true")

    lc_p = sub.add_parser("lock-check", help="verify lock.json has not drifted")
    lc_p.add_argument("--full", action="store_true", help="also re-trace (needs cache/network)")

    sub.add_parser("lock-write", help="regenerate lock.json from the current repo")

    build_p = sub.add_parser("build", help="assemble+verify+pack+reverify+smoke")
    build_p.add_argument("--out", type=Path, default=None)

    verify_p = sub.add_parser("verify", help="recompute digests for a built bundle")
    verify_p.add_argument("path", type=Path)

    smoke_p = sub.add_parser("smoke", help="spawn the sealed argv against a built bundle")
    smoke_p.add_argument("path", type=Path)

    sub.add_parser("selfcheck", help="two independent builds must digest identically")

    sub.add_parser("all", help="fetch + build + selfcheck, with timings")

    ns = parser.parse_args(argv)
    try:
        if ns.cmd == "fetch":
            fetch(offline=ns.offline)
        elif ns.cmd == "lock-check":
            lock_check(full=ns.full)
        elif ns.cmd == "lock-write":
            lock_write()
        elif ns.cmd == "build":
            out_dir = ns.out or _default_out_dir()
            result = build(out_dir)
            print(
                json.dumps(
                    {
                        "timings": result["timings"],
                        "digests": result["digests"],
                        "manifest_sha256": result["manifest_sha256"],
                    },
                    indent=2,
                )
            )
        elif ns.cmd == "verify":
            print(json.dumps(verify(ns.path), indent=2))
        elif ns.cmd == "smoke":
            result = smoke(ns.path)
            print(json.dumps(result, indent=2))
        elif ns.cmd == "selfcheck":
            t0 = time.monotonic()
            digests = selfcheck(CACHE_DIR / "build-out")
            print(json.dumps({"elapsed_s": time.monotonic() - t0, "digests": digests}, indent=2))
        elif ns.cmd == "all":
            t0 = time.monotonic()
            fetch()
            fetch_s = time.monotonic() - t0
            out_dir = _default_out_dir()
            result = build(out_dir)
            selfcheck_started = time.monotonic()
            reproducible = selfcheck(CACHE_DIR / "build-out")
            report = {
                "fetch_s": fetch_s,
                **result["timings"],
                "digests": result["digests"],
                "manifest_sha256": result["manifest_sha256"],
                "selfcheck_s": time.monotonic() - selfcheck_started,
                "reproducible": reproducible,
            }
            print(json.dumps(report, indent=2, sort_keys=True))
    except BuildError as exc:
        log(f"FAILED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
