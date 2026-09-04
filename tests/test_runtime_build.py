"""Fast, network-free locks for the X3 deployable runtime builder."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from runtime import _tracer, build, tree_hash

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "runtime" / "tree-v1-vector.json"


def _chmod_tree(root: Path, *, dirs: int, files: int) -> None:
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        directory = Path(dirpath)
        for name in filenames:
            path = directory / name
            if not path.is_symlink():
                path.chmod(files)
        directory.chmod(dirs)


def _seal(root: Path, *, launcher: str | None = None) -> None:
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        directory = Path(dirpath)
        for name in filenames:
            path = directory / name
            if not path.is_symlink():
                rel = path.relative_to(root).as_posix()
                path.chmod(0o555 if rel == launcher else 0o444)
        directory.chmod(0o555)


def _unseal(root: Path) -> None:
    if root.exists():
        _chmod_tree(root, dirs=0o755, files=0o644)


def test_locked_inputs_and_source_closure_are_exact() -> None:
    lock = json.loads(build.LOCK_PATH.read_text())
    assert lock["schema"] == "specaudit-ctf.runtime-lock.v1"
    assert lock["cpython"] == {
        "asset": "cpython-3.11.16+20260825-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
        "host_abi": {
            "elf_interpreter": "/lib64/ld-linux-x86-64.so.2",
            "maximum_glibc_symbol_version": "2.17",
            "needed": [
                "libc.so.6",
                "libdl.so.2",
                "libm.so.6",
                "libpthread.so.0",
                "librt.so.1",
                "libutil.so.1",
            ],
        },
        "launcher_sha256": "bba9c5269e5794349c1b3bf2bcec677315462a4419dadcc3caefd43fb24d8c94",
        "platform": "x86_64-unknown-linux-gnu",
        "python_build_standalone_release": "20260825",
        "sha256": "232f75c9dd6733b41a8101b5076b2a248360722dedded5688f4ac7d5931d8eac",
        "size": 30931922,
        "url": "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.11.16+20260825-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
        "version": "3.11.16",
    }
    assert lock["pyyaml"]["sha256"] == (
        "b8bb0864c5a28024fac8a632c443c87c5aa6f215c0b126c449ae1a150412f31d"
    )
    assert lock["pyyaml"]["size"] == 806638
    # 99 after the nmap arm joined the catalog (96 for the stdio-MCP
    # surface: the X4-PUB closure plus extension/mcp_server.py, the
    # execution-result schema it reads at module level, and the DAST-role
    # note refresh; +3 for the nmap arm package files).
    assert len(lock["producer_source_files"]) == 99
    # 107 at the 2026-08 nmap regen; +7 for the transport-gate imports
    # (base64, hashlib, http.server, secrets and their traced deps).
    assert len(lock["included_stdlib_files"]) == 114
    assert len(lock["included_yaml_files"]) == 18
    assert lock["capability_manifest"] == {
        "path": "tests/goldens/capability-manifest/agent-wiz.list_tools.json",
        "sha256": "5bbb55e6c8cb8ceb143f4a72740802b31e451375b3f1e780ca94a5ca6b76efcc",
    }
    for rel, expected in lock["producer_source_files"].items():
        assert hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() == expected
    expected_bundle = build._expected_bundle_files(lock)
    assert "runtime/lock.json" not in expected_bundle
    assert "runtime/tree-v1-vector.json" not in expected_bundle


def test_fast_lock_check_is_network_free(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        build.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("lock-check touched the network"),
    )
    build.lock_check(full=False)


def test_offline_fetch_refuses_missing_cache_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(build, "CACHE_DIR", tmp_path / "empty-cache")
    monkeypatch.setattr(
        build.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("offline fetch touched the network"),
    )
    with pytest.raises(build.BuildError, match="--offline"):
        build.fetch(offline=True)


def test_merged_trace_is_deduplicated_union_of_invocations() -> None:
    shared = {"name": "json", "file": "/repo/extension/__init__.py"}
    cli_only = {"name": "extension.dispatch", "file": "/repo/extension/dispatch.py"}
    mcp_only = {"name": "extension.range", "file": "/repo/extension/range/__init__.py"}
    merged = build.merge_traces(
        {
            "cli-json-invoke": {
                "stdlib": [shared],
                "yaml": [],
                "extension": [cli_only, shared],
            },
            "stdio-mcp-server": {
                "stdlib": [shared],
                "yaml": [],
                "extension": [mcp_only],
            },
        }
    )
    assert merged["extension"] == sorted(
        [cli_only, shared, mcp_only], key=lambda rec: (rec["name"], rec["file"])
    )
    assert merged["stdlib"] == [shared]


def test_merged_trace_rejects_disagreeing_records() -> None:
    with pytest.raises(build.BuildError, match="resolves to two files"):
        build.merge_traces(
            {
                "cli-json-invoke": {
                    "stdlib": [{"name": "json", "file": "/a/json.py"}],
                    "yaml": [],
                    "extension": [],
                },
                "stdio-mcp-server": {
                    "stdlib": [{"name": "json", "file": "/b/json.py"}],
                    "yaml": [],
                    "extension": [],
                },
            }
        )


def test_mcp_server_entrypoints_are_locked_producer_roots() -> None:
    lock = json.loads(build.LOCK_PATH.read_text())
    for relpath in (
        "extension/__main__.py",
        "extension/mcp_server.py",
        "extension/schema/execution-result.v1.schema.json",
    ):
        assert relpath in build.EXTRA_PRODUCER_FILES
        assert relpath in lock["producer_source_files"]
    # The stdio-MCP sealed invocation has its own per-invocation record.
    assert sorted(lock["invocations"]) == sorted(build.TRACE_INVOCATIONS)
    for invocation in build.TRACE_INVOCATIONS:
        record = lock["invocations"][invocation]
        assert sorted(record) == [
            "extension_paths",
            "stdlib_module_names",
            "yaml_module_names",
        ]


def test_tracer_handshake_drives_real_server_serve_loop() -> None:
    stdout = io.StringIO()
    from extension import mcp_server

    saved_stdin = mcp_server.sys.stdin
    mcp_server.sys.stdin = io.StringIO(_tracer.MCP_TRACE_STDIN)
    try:
        code = mcp_server.McpServer().serve(stdout=stdout)
    finally:
        mcp_server.sys.stdin = saved_stdin
    assert code == 0
    _tracer.validate_mcp_exchange(stdout.getvalue())


def test_validate_mcp_exchange_rejects_contract_violations() -> None:
    good = (
        '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25",'
        '"capabilities":{},"serverInfo":{"name":"x","version":"0"}}}\n'
        '{"jsonrpc":"2.0","id":2,"result":{"tools":['
        '{"name":"list"},{"name":"describe"},{"name":"invoke"},'
        '{"name":"run_range"}]}}\n'
    )
    _tracer.validate_mcp_exchange(good)
    bad_exchanges = [
        good.replace('"name":"run_range"', '"name":"other"'),
        good.replace("2025-11-25", "1999-01-01"),
        good.replace(
            '"id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},'
            '"serverInfo":{"name":"x","version":"0"}}',
            '"id":1,"error":{"code":-32000,"message":"x"}',
        ),
        good.splitlines()[0] + "\n",
    ]
    for text in bad_exchanges:
        with pytest.raises(RuntimeError):
            _tracer.validate_mcp_exchange(text)


def test_smoke_mcp_fail_closed_on_bad_child_behavior(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    monkeypatch.setattr(build, "_require_real_launcher", lambda _path: None)

    class _FakeProc:
        def __init__(self, returncode: int, stdout: str) -> None:
            self.returncode = returncode
            self._stdout = stdout

        def communicate(self, input: str, timeout: float | None = None):
            return self._stdout, ""

        def kill(self) -> None:
            return

        def wait(self) -> int:
            return self.returncode

        def __enter__(self):
            return self

        def __exit__(self, *exc: object):
            return False

    good_stdout = (
        '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}\n'
        '{"jsonrpc":"2.0","id":2,"result":{"tools":['
        '{"name":"list"},{"name":"describe"},{"name":"invoke"},'
        '{"name":"run_range"}]}}\n'
    )
    monkeypatch.setattr(
        build.subprocess,
        "Popen",
        lambda *_a, **_k: _FakeProc(0, good_stdout),
    )
    result = build.smoke_mcp(bundle)
    assert result["response_count"] == 2

    monkeypatch.setattr(
        build.subprocess, "Popen", lambda *_a, **_k: _FakeProc(1, good_stdout)
    )
    with pytest.raises(build.BuildError, match="exited 1"):
        build.smoke_mcp(bundle)

    monkeypatch.setattr(
        build.subprocess, "Popen", lambda *_a, **_k: _FakeProc(0, "garbage\n")
    )
    with pytest.raises(build.BuildError, match="contract"):
        build.smoke_mcp(bundle)


def test_smoke_rejects_claimed_observed_custody_digest_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    monkeypatch.setattr(build, "_require_real_launcher", lambda _path: None)

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        artifact_dir = Path(argv[argv.index("--artifact-dir") + 1])
        artifact = artifact_dir / "agentwiz-tools.json"
        artifact.write_bytes(b'{"tools":[]}\n')
        artifact.chmod(0o600)
        envelope = {
            "capability_id": build.CAPABILITY_ID,
            "status": "complete",
            "attempt_id": build._ATTEMPT_ID,
            "artifacts": [{"digest": "sha256:" + "0" * 64}],
        }
        return subprocess.CompletedProcess(argv, 0, json.dumps(envelope), "")

    monkeypatch.setattr(build.subprocess, "run", fake_run)

    with pytest.raises(build.BuildError, match="smoke artifact custody mismatch"):
        build.smoke(bundle)


def test_tree_v1_vector_matches_cross_language_contract(tmp_path: Path) -> None:
    vector = json.loads(VECTOR.read_text())
    root = tmp_path / "bundle"
    root.mkdir()
    try:
        for rel in vector["directories"]:
            (root / rel).mkdir(parents=True, exist_ok=True)
        for rel, content_hex in vector["files_hex"].items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bytes.fromhex(content_hex))
        _seal(root)
        assert tree_hash.hash_producer_bundle(root) == vector["expected_sha256"]
    finally:
        _unseal(root)


def test_tree_hash_rejects_rust_control_and_invalid_utf8_names(tmp_path: Path) -> None:
    raw_names: list[str | bytes] = ["c1-\u0085"]
    if os.name == "posix":
        raw_names.append(b"invalid-\xff")
    for raw_name in raw_names:
        root = tmp_path / ("unicode" if isinstance(raw_name, str) else "bytes")
        root.mkdir()
        try:
            if isinstance(raw_name, str):
                (root / raw_name).write_bytes(b"x")
            else:
                fd = os.open(os.fsencode(root) + b"/" + raw_name, os.O_CREAT | os.O_WRONLY, 0o444)
                os.close(fd)
            _seal(root)
            with pytest.raises(tree_hash.TreeHashError):
                tree_hash.hash_producer_bundle(root)
        finally:
            _unseal(root)


@pytest.mark.parametrize("kind", ["writable", "symlink", "hardlink", "extra"])
def test_layout_rejects_mode_links_and_extra_files(tmp_path: Path, kind: str) -> None:
    root = tmp_path / kind
    (root / "bin").mkdir(parents=True)
    launcher = root / build.LAUNCHER_RELPATH
    launcher.write_bytes(b"launcher")
    data = root / "data.txt"
    data.write_bytes(b"data")
    expected = {build.LAUNCHER_RELPATH, "data.txt"}
    if kind == "symlink":
        (root / "link").symlink_to("data.txt")
        expected.add("link")
    elif kind == "hardlink":
        os.link(data, root / "alias")
        expected.add("alias")
    elif kind == "extra":
        (root / "extra").write_bytes(b"extra")
    _seal(root, launcher=build.LAUNCHER_RELPATH)
    if kind == "writable":
        data.chmod(0o644)
    try:
        with pytest.raises(build.BuildError):
            build._verify_layout(root, expected)
    finally:
        _unseal(root)


def test_normalized_archive_is_path_time_umask_and_locale_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archives = []
    for index, mask in enumerate((0o022, 0o077)):
        root = tmp_path / f"tree-{index}"
        previous = os.umask(mask)
        try:
            (root / "nested").mkdir(parents=True)
            (root / "nested" / "value").write_bytes(b"same bytes\n")
        finally:
            os.umask(previous)
        os.utime(root / "nested" / "value", (100 + index, 200 + index))
        _seal(root)
        monkeypatch.setenv("LC_ALL", "C" if index == 0 else "C.UTF-8")
        archive = tmp_path / f"different-name-{index}.tar.gz"
        build.pack(root, archive)
        archives.append(archive.read_bytes())
        _unseal(root)
    assert archives[0] == archives[1]


def test_prior_sealed_output_is_replaceable_but_symlink_output_is_refused(
    tmp_path: Path,
) -> None:
    prior = tmp_path / "prior"
    (prior / "nested").mkdir(parents=True)
    (prior / "nested" / "value").write_bytes(b"old")
    _seal(prior)
    build._remove_existing_tree(prior)
    assert not prior.exists()

    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(build.BuildError, match="linked/non-directory"):
        build._remove_existing_tree(linked)
    assert real.is_dir()


def test_assemble_requires_absolute_output_path() -> None:
    with pytest.raises(build.BuildError, match="absolute"):
        build.assemble(Path("relative-bundle"))


def test_artifact_manifest_is_deterministic_and_separates_timings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_lock = json.loads(build.LOCK_PATH.read_text())
    digests = {
        "launcher_sha256": "sha256:" + "1" * 64,
        "bundle_tree_sha256": "sha256:" + "2" * 64,
    }
    first = build.manifest_for(digests)
    second = build.manifest_for(digests)
    assert first == second
    assert "timings" not in first
    assert first["capability_manifest"]["sha256"] == (
        "sha256:5bbb55e6c8cb8ceb143f4a72740802b31e451375b3f1e780ca94a5ca6b76efcc"
    )
    assert first["platform"] == {
        "os": "linux",
        "architecture": "x86_64",
        "abi": "gnu-glibc",
        "glibc_minimum": "2.17",
        "host_loader_outside_bundle": True,
        "host_abi_dependencies": runtime_lock["cpython"]["host_abi"],
    }

    lock, lock_sha256 = build._load_lock_snapshot()
    monkeypatch.setattr(
        build,
        "_load_lock_snapshot",
        lambda: pytest.fail("manifest reread the lock instead of using its snapshot"),
    )
    bound = build.manifest_for(
        digests,
        lock=lock,
        runtime_lock_sha256=lock_sha256,
        source_revision="reviewed-revision",
    )
    assert bound["runtime_lock_sha256"] == lock_sha256
    assert bound["source_revision"] == "reviewed-revision"
