"""Fast, network-free locks for the X3 deployable runtime builder."""

from __future__ import annotations

import contextlib
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
RESEARCH_READER_PACKAGES = (
    "security_detections_mcp",
    "agentseal",
    "vulnify",
    "leonidas",
    "specterops_skills",
    "detection_in_the_cloud",
    "pentestkit",
    "collinear",
    "ad_pathfinder",
    "gpohound",
    "claude_ad",
    "numasec",
    "rubeus",
    "m365pwned",
)


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


def _init_revision_repo(
    tmp_path: Path, *, object_format: str = "sha1"
) -> tuple[Path, dict, str, str]:
    git = build.GIT_EXECUTABLE
    assert git is not None
    repo = tmp_path / "revision-repo"
    producer = repo / "extension" / "producer.py"
    capability = repo / "tests" / "goldens" / "capability.json"
    producer.parent.mkdir(parents=True)
    capability.parent.mkdir(parents=True)
    producer.write_text("producer = 1\n", encoding="utf-8")
    capability.write_text("{}\n", encoding="utf-8")
    (repo / "LICENSE").write_text("test license\n", encoding="utf-8")
    for relpath in build.TRUSTED_PRODUCER_TOOL_FILES:
        path = repo / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {relpath}\n", encoding="utf-8")
    (repo / "notes.txt").write_text("initial\n", encoding="utf-8")
    lock = {
        "producer_source_files": {
            "extension/producer.py": hashlib.sha256(producer.read_bytes()).hexdigest()
        },
        "capability_manifest": {
            "path": "tests/goldens/capability.json",
            "sha256": hashlib.sha256(capability.read_bytes()).hexdigest(),
        },
        "license_files": {
            "licenses/specaudit-ctf-LICENSE.txt": {
                "sha256": hashlib.sha256((repo / "LICENSE").read_bytes()).hexdigest()
            }
        },
    }
    lock_path = repo / "runtime" / "lock.json"
    lock_path.write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lock_sha256 = "sha256:" + hashlib.sha256(lock_path.read_bytes()).hexdigest()
    init_argv = [git, "init", "-q"]
    if object_format != "sha1":
        init_argv.append(f"--object-format={object_format}")
    initialized = subprocess.run(
        init_argv, cwd=repo, capture_output=True, check=False
    )
    if initialized.returncode != 0 and object_format == "sha256":
        pytest.skip("installed Git does not support SHA-256 repositories")
    initialized.check_returncode()
    subprocess.run([git, "add", "."], cwd=repo, check=True)
    subprocess.run(
        [
            git,
            "-c",
            "user.name=Runtime Test",
            "-c",
            "user.email=runtime-test@example.invalid",
            "commit",
            "-qm",
            "initial",
        ],
        cwd=repo,
        check=True,
    )
    revision = subprocess.run(
        [git, "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return repo, lock, lock_sha256, revision


def test_locked_inputs_and_source_closure_are_exact() -> None:
    lock = json.loads(build.LOCK_PATH.read_text())
    assert build.TRUSTED_PRODUCER_TOOL_FILES == (
        "runtime/__init__.py",
        "runtime/build.py",
        "runtime/_tracer.py",
        "runtime/tree_hash.py",
    )
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
    # 104 after extension/trace.py joined the traced closure (the
    # agent-head lane's server-side capture; 2026-09-05). Previously 103:
    # the attack-stix-data arm's +4 package files (__init__, arm, policy,
    # reader — the demo bundle is caller data, not part of the closure).
    # Asset recon established a 122-file producer closure; the 14 readers
    # add three imported Python modules apiece, plus their shared strict-data
    # decoder/structure guard.
    assert len(lock["producer_source_files"]) == 165
    assert len(lock["included_stdlib_files"]) == 118
    assert len(lock["included_yaml_files"]) == 18
    expected_reader_sources = {"extension/arms/strict_data.py"}
    expected_reader_sources.update(
        f"extension/arms/{package}/{filename}"
        for package in RESEARCH_READER_PACKAGES
        for filename in ("__init__.py", "arm.py", "policy.py")
    )
    assert expected_reader_sources <= set(lock["producer_source_files"])
    traced_sources = {
        path
        for invocation in lock["invocations"].values()
        for path in invocation["extension_paths"]
    }
    assert expected_reader_sources <= traced_sources
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


def test_committed_source_revision_binds_only_clean_trusted_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, lock, lock_sha256, revision = _init_revision_repo(tmp_path)
    monkeypatch.setattr(build, "REPO_ROOT", repo)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "hostile-git-dir"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "hostile-index"))
    assert (
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )
        == revision
    )

    # Documentation and unrelated work do not supply executable producer bytes.
    (repo / "runtime" / "README.md").write_text("dirty docs\n", encoding="utf-8")
    (repo / "unrelated.txt").write_text("unrelated\n", encoding="utf-8")
    assert (
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )
        == revision
    )

    # The exact lock snapshot is itself part of the committed source identity.
    (repo / "runtime" / "lock.json").write_text("dirty lock\n", encoding="utf-8")
    dirty_lock_sha256 = "sha256:" + hashlib.sha256(
        (repo / "runtime" / "lock.json").read_bytes()
    ).hexdigest()
    with pytest.raises(build.BuildError, match="trusted producer inputs"):
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=dirty_lock_sha256
        )


@pytest.mark.parametrize(
    "relpath,lock_section",
    [
        ("extension/producer.py", "producer"),
        ("tests/goldens/capability.json", "capability"),
        ("LICENSE", "license"),
        ("runtime/build.py", "tool"),
        ("runtime/lock.json", "lock"),
    ],
)
@pytest.mark.parametrize("staged", [False, True], ids=["unstaged", "staged"])
def test_committed_source_revision_refuses_dirty_trusted_inputs_even_if_relocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relpath: str,
    lock_section: str,
    staged: bool,
) -> None:
    repo, lock, lock_sha256, _revision = _init_revision_repo(tmp_path)
    git = build.GIT_EXECUTABLE
    assert git is not None
    path = repo / relpath
    path.write_text(path.read_text(encoding="utf-8") + "dirty\n", encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if lock_section == "producer":
        lock["producer_source_files"][relpath] = digest
    elif lock_section == "capability":
        lock["capability_manifest"]["sha256"] = digest
    elif lock_section == "license":
        lock["license_files"]["licenses/specaudit-ctf-LICENSE.txt"]["sha256"] = digest
    elif lock_section == "lock":
        lock_sha256 = "sha256:" + digest
    if staged:
        subprocess.run([git, "add", relpath], cwd=repo, check=True)
    monkeypatch.setattr(build, "REPO_ROOT", repo)
    with pytest.raises(build.BuildError, match="trusted producer inputs"):
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )


@pytest.mark.parametrize(
    "relpath",
    [
        "extension/producer.py",
        "tests/goldens/capability.json",
        "LICENSE",
        "runtime/lock.json",
        "runtime/_tracer.py",
    ],
    ids=["producer", "capability", "license", "lock", "tool"],
)
def test_committed_source_revision_refuses_staged_only_trusted_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relpath: str
) -> None:
    repo, lock, lock_sha256, _revision = _init_revision_repo(tmp_path)
    git = build.GIT_EXECUTABLE
    assert git is not None
    trusted_path = repo / relpath
    committed = trusted_path.read_bytes()
    trusted_path.write_bytes(committed + b"staged-only divergence\n")
    subprocess.run([git, "add", relpath], cwd=repo, check=True)
    trusted_path.write_bytes(committed)
    monkeypatch.setattr(build, "REPO_ROOT", repo)
    with pytest.raises(build.BuildError, match="uncommitted changes"):
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )


def test_committed_source_revision_refuses_untracked_locked_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, lock, lock_sha256, _revision = _init_revision_repo(tmp_path)
    untracked = repo / "extension" / "new_producer.py"
    untracked.write_text("new = True\n", encoding="utf-8")
    lock["producer_source_files"]["extension/new_producer.py"] = hashlib.sha256(
        untracked.read_bytes()
    ).hexdigest()
    monkeypatch.setattr(build, "REPO_ROOT", repo)
    with pytest.raises(build.BuildError, match="exactly match trusted producer inputs"):
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )


def test_committed_source_revision_refuses_missing_git_or_changed_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, lock, lock_sha256, revision = _init_revision_repo(tmp_path)
    git = build.GIT_EXECUTABLE
    assert git is not None
    monkeypatch.setattr(build, "GIT_EXECUTABLE", None)
    with pytest.raises(build.BuildError, match="committed source revision"):
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )

    monkeypatch.setattr(build, "GIT_EXECUTABLE", git)
    monkeypatch.setattr(build, "REPO_ROOT", tmp_path / "not-a-repository")
    with pytest.raises(build.BuildError, match="committed source revision"):
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )

    monkeypatch.setattr(build, "REPO_ROOT", repo)
    (repo / "notes.txt").write_text("next\n", encoding="utf-8")
    subprocess.run([git, "add", "notes.txt"], cwd=repo, check=True)
    subprocess.run(
        [
            git,
            "-c",
            "user.name=Runtime Test",
            "-c",
            "user.email=runtime-test@example.invalid",
            "commit",
            "-qm",
            "advance unrelated head",
        ],
        cwd=repo,
        check=True,
    )
    with pytest.raises(build.BuildError, match="revision changed"):
        build._require_committed_source_revision(
            lock,
            runtime_lock_sha256=lock_sha256,
            expected_revision=revision,
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"a" * 39,
        b"A" * 40,
        b"g" * 40,
        b"a" * 40 + b"\n" + b"b" * 40,
        b"\xff" * 40,
    ],
)
def test_git_source_revision_parser_refuses_malformed_ids(raw: bytes) -> None:
    with pytest.raises(build.BuildError, match="malformed source revision"):
        build._parse_git_revision(raw)


@pytest.mark.parametrize(
    "raw,expected",
    [(b"sha1\n", ("sha1", 40)), (b"sha256\n", ("sha256", 64))],
)
def test_git_object_format_parser_accepts_supported_storage_formats(
    raw: bytes, expected: tuple[str, int]
) -> None:
    assert build._parse_git_object_format(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [b"", b"sha512\n", b"sha1\nsha256\n", b"SHA1\n", b"\xff\n"],
)
def test_git_object_format_parser_refuses_ambiguous_or_unknown_values(
    raw: bytes,
) -> None:
    with pytest.raises(build.BuildError, match="object format"):
        build._parse_git_object_format(raw)


@pytest.mark.parametrize(
    "object_format,revision",
    [(b"sha1\n", "a" * 64), (b"sha256\n", "a" * 40)],
)
def test_git_object_integrity_refuses_revision_width_mismatch(
    monkeypatch: pytest.MonkeyPatch, object_format: bytes, revision: str
) -> None:
    monkeypatch.setattr(
        build,
        "_run_git_for_source_revision",
        lambda *_args, **_kwargs: object_format,
    )
    with pytest.raises(build.BuildError, match="revision width"):
        build._require_git_object_integrity(revision)


def test_git_object_integrity_uses_strict_full_non_connectivity_fsck(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def run(*args: str, input_bytes: bytes | None = None) -> bytes:
        assert input_bytes is None
        calls.append(args)
        if args == ("rev-parse", "--show-object-format=storage"):
            return b"sha1\n"
        return b""

    monkeypatch.setattr(build, "_run_git_for_source_revision", run)
    revision = "a" * 40
    build._require_git_object_integrity(revision)
    assert calls == [
        ("rev-parse", "--show-object-format=storage"),
        (
            "-c",
            f"fsck.skipList={os.devnull}",
            "fsck",
            "--strict",
            "--full",
            "--no-connectivity-only",
            "--no-dangling",
            "--no-reflogs",
            "--no-progress",
            "--no-cache",
            "--no-references",
            revision,
        ),
    ]
    assert "--connectivity-only" not in calls[1]


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_committed_source_revision_refuses_substituted_loose_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    object_format: str,
) -> None:
    repo, lock, lock_sha256, _revision = _init_revision_repo(
        tmp_path, object_format=object_format
    )
    git = build.GIT_EXECUTABLE
    assert git is not None
    tracer = repo / "runtime" / "_tracer.py"
    old_object_id = subprocess.run(
        [git, "rev-parse", "HEAD:runtime/_tracer.py"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    alternate = b"# substituted trusted tracer\nchanged = True\n"
    new_object_id = subprocess.run(
        [git, "hash-object", "-w", "--stdin"],
        cwd=repo,
        check=True,
        capture_output=True,
        input=alternate,
    ).stdout.decode("ascii").strip()
    assert new_object_id != old_object_id
    old_object = repo / ".git" / "objects" / old_object_id[:2] / old_object_id[2:]
    new_object = repo / ".git" / "objects" / new_object_id[:2] / new_object_id[2:]
    assert old_object.is_file() and new_object.is_file()
    old_object.chmod(old_object.stat().st_mode | stat.S_IWUSR)
    old_object.write_bytes(new_object.read_bytes())
    tracer.write_bytes(alternate)

    returned = subprocess.run(
        [git, "cat-file", "blob", old_object_id],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    returned_object_id = subprocess.run(
        [git, "hash-object", "--stdin"],
        cwd=repo,
        check=True,
        capture_output=True,
        input=returned,
    ).stdout.decode("ascii").strip()
    assert returned == alternate
    assert returned_object_id == new_object_id
    assert returned_object_id != old_object_id

    monkeypatch.setattr(build, "REPO_ROOT", repo)
    with pytest.raises(build.BuildError, match="object graph.*integrity"):
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )


def test_git_source_runner_translates_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)

    monkeypatch.setattr(build.subprocess, "run", timeout)
    with pytest.raises(build.BuildError, match="committed source revision"):
        build._run_git_for_source_revision("rev-parse", "HEAD")


def test_git_source_runner_uses_isolated_literal_offline_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def run(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout=b"ok\n")

    monkeypatch.setenv("GIT_DIR", "/hostile/repository")
    monkeypatch.setenv("GIT_INDEX_FILE", "/hostile/index")
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", "/hostile/objects")
    monkeypatch.setattr(build.subprocess, "run", run)

    assert build._run_git_for_source_revision("rev-parse", "HEAD") == b"ok\n"
    assert captured["argv"] == [
        build.GIT_EXECUTABLE,
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "rev-parse",
        "HEAD",
    ]
    git_env = captured["env"]
    assert isinstance(git_env, dict)
    assert "GIT_DIR" not in git_env
    assert "GIT_INDEX_FILE" not in git_env
    assert "GIT_OBJECT_DIRECTORY" not in git_env
    assert {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }.items() <= git_env.items()
    assert captured["check"] is True
    assert captured["timeout"] == 10


def test_committed_source_revision_refuses_head_change_during_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, lock, lock_sha256, _revision = _init_revision_repo(tmp_path)
    git = build.GIT_EXECUTABLE
    assert git is not None
    monkeypatch.setattr(build, "REPO_ROOT", repo)
    original_runner = build._run_git_for_source_revision
    advanced = False

    def advance_after_status(*args: str, input_bytes: bytes | None = None) -> bytes:
        nonlocal advanced
        output = original_runner(*args, input_bytes=input_bytes)
        if args[:2] == ("diff", "--cached") and not advanced:
            advanced = True
            (repo / "notes.txt").write_text("advanced\n", encoding="utf-8")
            subprocess.run([git, "add", "notes.txt"], cwd=repo, check=True)
            subprocess.run(
                [
                    git,
                    "-c",
                    "user.name=Runtime Test",
                    "-c",
                    "user.email=runtime-test@example.invalid",
                    "commit",
                    "-qm",
                    "advance during check",
                ],
                cwd=repo,
                check=True,
            )
        return output

    monkeypatch.setattr(build, "_run_git_for_source_revision", advance_after_status)
    with pytest.raises(build.BuildError, match="changed while checking"):
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )
    assert advanced is True


def test_committed_source_revision_checks_only_staged_diff_without_helpers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, lock, lock_sha256, revision = _init_revision_repo(tmp_path)
    monkeypatch.setattr(build, "REPO_ROOT", repo)
    original_runner = build._run_git_for_source_revision
    calls: list[tuple[str, ...]] = []

    def record(*args: str, input_bytes: bytes | None = None) -> bytes:
        calls.append(args)
        return original_runner(*args, input_bytes=input_bytes)

    monkeypatch.setattr(build, "_run_git_for_source_revision", record)
    assert (
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )
        == revision
    )
    diff_calls = [call for call in calls if call[:1] == ("diff",)]
    assert len(diff_calls) == 1
    assert diff_calls[0][:4] == (
        "diff",
        "--cached",
        "--no-ext-diff",
        "--no-textconv",
    )
    separator = diff_calls[0].index("--")
    assert set(diff_calls[0][separator + 1 :]) == {
        "LICENSE",
        "extension/producer.py",
        "runtime/__init__.py",
        "runtime/_tracer.py",
        "runtime/build.py",
        "runtime/lock.json",
        "runtime/tree_hash.py",
        "tests/goldens/capability.json",
    }


def test_committed_source_revision_refuses_committed_symlink_materialized_as_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, lock, _lock_sha256, _revision = _init_revision_repo(tmp_path)
    git = build.GIT_EXECUTABLE
    assert git is not None
    producer = repo / "extension" / "producer.py"
    producer.unlink()
    producer.symlink_to("producer-target.py")
    lock["producer_source_files"]["extension/producer.py"] = hashlib.sha256(
        b"producer-target.py"
    ).hexdigest()
    lock_path = repo / "runtime" / "lock.json"
    lock_path.write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lock_sha256 = "sha256:" + hashlib.sha256(lock_path.read_bytes()).hexdigest()
    subprocess.run(
        [git, "add", "extension/producer.py", "runtime/lock.json"],
        cwd=repo,
        check=True,
    )
    subprocess.run(
        [
            git,
            "-c",
            "user.name=Runtime Test",
            "-c",
            "user.email=runtime-test@example.invalid",
            "commit",
            "-qm",
            "commit symlink producer",
        ],
        cwd=repo,
        check=True,
    )

    # Reproduce a core.symlinks=false checkout: the symlink blob is materialized
    # as a regular file, so a worktree-only type check would incorrectly admit it.
    producer.unlink()
    subprocess.run(
        [
            git,
            "-c",
            "core.symlinks=false",
            "checkout",
            "HEAD",
            "--",
            "extension/producer.py",
        ],
        cwd=repo,
        check=True,
    )
    assert producer.is_file() and not producer.is_symlink()
    assert producer.read_bytes() == b"producer-target.py"

    monkeypatch.setattr(build, "REPO_ROOT", repo)
    with pytest.raises(build.BuildError, match="regular-file modes"):
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )


def test_committed_source_revision_ignores_local_replace_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, lock, lock_sha256, revision = _init_revision_repo(tmp_path)
    git = build.GIT_EXECUTABLE
    assert git is not None
    producer = repo / "extension" / "producer.py"
    producer.write_text("producer = 2\n", encoding="utf-8")
    subprocess.run([git, "add", "extension/producer.py"], cwd=repo, check=True)
    subprocess.run(
        [
            git,
            "-c",
            "user.name=Runtime Test",
            "-c",
            "user.email=runtime-test@example.invalid",
            "commit",
            "-qm",
            "replacement commit",
        ],
        cwd=repo,
        check=True,
    )
    replacement = subprocess.run(
        [git, "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        [git, "checkout", "--detach", "-q", revision], cwd=repo, check=True
    )
    subprocess.run([git, "replace", revision, replacement], cwd=repo, check=True)

    monkeypatch.setattr(build, "REPO_ROOT", repo)
    assert (
        build._require_committed_source_revision(
            lock, runtime_lock_sha256=lock_sha256
        )
        == revision
    )


@pytest.mark.parametrize(
    "response,match",
    [
        (b"", "truncated committed-source response"),
        (b"object missing\n", "regular blob"),
        (b"object blob nope\n", "malformed committed-source size"),
        (b"object blob -1\n", "malformed committed-source size"),
        (b"object blob 2\nx\n", "truncated committed-source blob"),
        (b"object blob 1\nx\nextra", "excess committed-source data"),
    ],
)
def test_committed_source_batch_parser_refuses_malformed_responses(
    monkeypatch: pytest.MonkeyPatch, response: bytes, match: str
) -> None:
    monkeypatch.setattr(
        build, "_run_git_for_source_revision", lambda *_args, **_kwargs: response
    )
    with pytest.raises(build.BuildError, match=match):
        build._committed_source_hashes("a" * 40, ("extension/producer.py",))


def test_assemble_rechecks_same_committed_revision_after_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock: dict = {}
    lock_sha256 = "sha256:" + ("1" * 64)
    revision = "a" * 40
    events: list[str] = []

    def require_revision(
        received_lock: dict,
        *,
        runtime_lock_sha256: str,
        expected_revision: str | None = None,
    ) -> str:
        assert received_lock is lock
        assert runtime_lock_sha256 == lock_sha256
        events.append(f"revision:{expected_revision or 'none'}")
        return revision

    staged_cpython = tmp_path / "cpython"
    staged_yaml = tmp_path / "yaml"
    monkeypatch.setattr(build, "_require_supported_platform", lambda: None)
    monkeypatch.setattr(build, "_load_lock_snapshot", lambda: (lock, lock_sha256))
    monkeypatch.setattr(build, "_require_committed_source_revision", require_revision)
    monkeypatch.setattr(build, "_verify_locked_cache", lambda _lock: None)
    monkeypatch.setattr(
        build,
        "staged_inputs",
        lambda: contextlib.nullcontext((staged_cpython, staged_yaml)),
    )
    monkeypatch.setattr(build, "run_tracers", lambda *_args: {})
    monkeypatch.setattr(
        build,
        "merge_traces",
        lambda _traces: {"stdlib": [], "yaml": [], "extension": []},
    )
    monkeypatch.setattr(build, "_validate_locked_sources", lambda *_args: None)
    monkeypatch.setattr(build, "_launcher_path", lambda _root: tmp_path / "python")
    monkeypatch.setattr(build, "_require_real_launcher", lambda _path: None)
    monkeypatch.setattr(build, "_copy_regular_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(build, "_stdlib_root", lambda _root: tmp_path / "stdlib")
    monkeypatch.setattr(build, "_unique_relpaths", lambda *_args: [])
    monkeypatch.setattr(build, "_write_licenses", lambda *_args: None)
    monkeypatch.setattr(
        build,
        "_verify_locked_output_bytes",
        lambda *_args: events.append("output-bytes-verified"),
    )
    monkeypatch.setattr(build, "_seal_directory_modes", lambda _root: None)
    monkeypatch.setattr(build, "REQUIRED_BUNDLE_FILES", ())

    result = build.assemble((tmp_path / "bundle").resolve())

    assert result["source_revision"] == revision
    assert events == [
        "revision:none",
        "output-bytes-verified",
        f"revision:{revision}",
    ]


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
        "extension/arms/assetrecon/worker.py",
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


@pytest.mark.skipif(os.name != "posix", reason="live worker requires POSIX")
def test_worker_trace_refuses_before_network_subprocess_or_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    import resource
    import socket
    import subprocess
    import urllib.request

    def forbidden(*args, **kwargs):
        pytest.fail("worker refusal attempted an effect")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(resource, "setrlimit", forbidden)
    marker = {"stdlib": [], "yaml": [], "extension": []}
    # This pytest process includes unrelated third-party imports; the real
    # trace runs in a fresh locked interpreter. Only classification is stubbed.
    monkeypatch.setattr(_tracer, "_classify_final_modules", lambda: marker)
    assert _tracer.trace_asset_recon_worker() is marker
    assert _tracer.WORKER_TRACE_STDIN == b'{"operation":"runtime-refusal-check"}'


def test_worker_dependency_closure_is_locked() -> None:
    lock = json.loads(build.LOCK_PATH.read_text())
    worker = lock["invocations"]["asset-recon-worker"]
    # resource is built into the locked ELF and has no standalone file.
    # Successful worker startup proves that import; file-backed dependencies
    # must be present in the measured closure, including XML scanner parsing.
    assert {"ssl", "socket", "subprocess", "urllib.request", "xml.etree.ElementTree"} <= set(worker["stdlib_module_names"])
    assert "extension/arms/assetrecon/worker.py" in lock["producer_source_files"]


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
    reviewed_revision = "a" * 40
    first = build.manifest_for(digests, source_revision=reviewed_revision)
    second = build.manifest_for(digests, source_revision=reviewed_revision)
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
        source_revision=reviewed_revision,
    )
    assert bound["runtime_lock_sha256"] == lock_sha256
    assert bound["source_revision"] == reviewed_revision
