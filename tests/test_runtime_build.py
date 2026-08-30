"""Fast, network-free locks for the X3 deployable runtime builder."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from runtime import build, tree_hash

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
    assert len(lock["producer_source_files"]) == 93
    assert len(lock["included_stdlib_files"]) == 107
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
    for raw_name in ("c1-\u0085", b"invalid-\xff"):
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
