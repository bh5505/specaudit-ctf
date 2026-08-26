"""Real locked-runtime integration tests; skipped until inputs are fetched."""

from __future__ import annotations

import concurrent.futures
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from runtime import build, tree_hash


def _locked_inputs_available() -> bool:
    lock = json.loads(build.LOCK_PATH.read_text())
    return build._verify_cached(
        build.CACHE_DIR / "cpython.tar.gz",
        lock["cpython"]["size"],
        lock["cpython"]["sha256"],
    ) and build._verify_cached(
        build.CACHE_DIR / "pyyaml.whl",
        lock["pyyaml"]["size"],
        lock["pyyaml"]["sha256"],
    )


pytestmark = pytest.mark.skipif(
    platform.system() != "Linux"
    or platform.machine() not in ("x86_64", "AMD64")
    or not _locked_inputs_available(),
    reason="requires explicitly fetched locked Linux x86-64 runtime inputs",
)


def _unseal(root: Path) -> None:
    if not root.exists():
        return
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        directory = Path(dirpath)
        for name in filenames:
            path = directory / name
            if not path.is_symlink():
                path.chmod(0o644)
        directory.chmod(0o755)


def _sealed_env(root: Path) -> dict[str, str]:
    return {
        "PYTHONHOME": str(root),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def test_offline_build_reextract_and_real_mode_a_smoke(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        build.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("offline build touched the network"),
    )
    bundle = tmp_path / "bundle"
    try:
        result = build.build(bundle)
        assert result["digests"] == build.verify(bundle)
        assert result["smoke"]["envelope"]["status"] == "complete"
        assert result["smoke"]["envelope"]["attempt_id"].startswith("attempt-")
        assert result["smoke"]["artifact_count"] == 1
        assert result["smoke"]["artifact_digests"] == [
            result["smoke"]["envelope"]["artifacts"][0]["digest"]
        ]
        assert {"cold_verify_s", "warm_verify_s", "cold_launch_s", "repeat_launch_s"} <= set(
            result["timings"]
        )

        manifest = json.loads(result["manifest_path"].read_text())
        assert "timings" not in manifest
        assert result["manifest_sha256"] == tree_hash.hash_file(
            result["manifest_path"]
        )
        assert json.loads(result["timings_path"].read_text()) == result["timings"]

        # The CLI intentionally refuses this as unmanifested. Exercise the
        # lower Extension/arm layer directly to lock the narrower contract:
        # absent agent-wiz binary => NotInstalled, never a subprocess fallback.
        script = """
from extension.contract import Extension, NotInstalledError
try:
    Extension().invoke("agent-wiz", "extract", {})
except NotInstalledError:
    print("NOT_INSTALLED")
else:
    raise SystemExit("agent-wiz extract unexpectedly became available")
"""
        proc = subprocess.run(
            [str(bundle / build.LAUNCHER_RELPATH), "-S", "-c", script],
            cwd=bundle,
            env=_sealed_env(bundle),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "NOT_INSTALLED"
    finally:
        _unseal(bundle)
        _unseal(tmp_path / "bundle.reextracted")


def test_two_archive_backed_builds_are_reproducible(tmp_path: Path) -> None:
    try:
        result = build.selfcheck(tmp_path)
        assert result["launcher_sha256"].startswith("sha256:")
        assert result["bundle_tree_sha256"].startswith("sha256:")
        assert result["archive_sha256"].startswith("sha256:")
        assert (tmp_path / "selfcheck-a.tar.gz").read_bytes() == (
            tmp_path / "selfcheck-b.tar.gz"
        ).read_bytes()
    finally:
        _unseal(tmp_path / "selfcheck-a")
        _unseal(tmp_path / "selfcheck-b")


def test_parallel_full_lock_checks_use_isolated_staging() -> None:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    argv = [sys.executable, "-m", "runtime.build", "lock-check", "--full"]
    processes = [
        subprocess.Popen(
            argv,
            cwd=build.REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    results = [process.communicate(timeout=30) for process in processes]
    for process, (stdout, stderr) in zip(processes, results, strict=True):
        assert process.returncode == 0, stdout + stderr
        assert "lock-check (full)" in stderr


def test_parallel_stage_lifetimes_are_private_and_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_cache = build.CACHE_DIR
    isolated_cache = tmp_path / "cache"
    isolated_cache.mkdir()
    for name in ("cpython.tar.gz", "pyyaml.whl"):
        try:
            os.link(original_cache / name, isolated_cache / name)
        except OSError:
            shutil.copyfile(original_cache / name, isolated_cache / name)
    monkeypatch.setattr(build, "CACHE_DIR", isolated_cache)
    barrier = threading.Barrier(2)

    def exercise() -> tuple[Path, bool, bool]:
        with build.staged_inputs() as (cpython, yaml):
            barrier.wait(timeout=15)
            return (
                cpython.parent,
                (cpython / "python" / "bin" / "python3.11").is_file(),
                any(yaml.glob("yaml/__init__.py")),
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: exercise(), range(2)))
    assert results[0][0] != results[1][0]
    assert all(has_launcher and has_yaml for _root, has_launcher, has_yaml in results)
    assert not list(isolated_cache.glob(".stage-*"))
