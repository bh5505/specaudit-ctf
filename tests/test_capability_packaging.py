"""The built distribution must provide the public CTF runtime.

Build with the already-installed build backend, never with dependency fetching,
and import from an extracted wheel in an isolated interpreter outside either
source tree. A source-checkout import cannot establish this contract.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


HELPERS = {
    "audit_workpaper": "grade_workpaper",
    "extension.contract": "Extension",
    "extension.range.runner": "run_range",
    "score.grading": "grade_files",
    "exercise.runner": "run_exercise",
    "learning.agent_security_harness": "grade",
}

REMOVED_PACKAGES = (
    "attempt_ledger", "caller_path_binding", "candidate_admission",
    "capability_records", "challenger_head", "containment",
    "containment_evidence", "deliverable_substrate", "formal_assessment",
    "frozen_slices", "governance", "promotion_verifier", "reader_evidence",
    "runtime", "safety", "telecom_case",
)


def test_built_wheel_provides_ctf_runtime_outside_checkout(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    source = tmp_path / "source"
    shutil.copytree(
        root,
        source,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.pyc", ".pytest_cache", "build", "dist",
            "*.egg-info",
        ),
    )
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()
    build = subprocess.run(
        [sys.executable, "-I", "-c",
         "import setuptools.build_meta as backend; "
         "import sys; backend.build_wheel(sys.argv[1])", str(wheel_dir)],
        cwd=source, capture_output=True, text=True, timeout=120,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    installed = tmp_path / "installed"
    installed.mkdir()
    with zipfile.ZipFile(wheels[0]) as archive:
        assert not any(name.startswith(tuple(f"{package}/" for package in REMOVED_PACKAGES))
                       for name in archive.namelist())
        archive.extractall(installed)

    probe = """
import importlib, json, pathlib, sys
installed = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(installed))
helpers = json.loads(sys.argv[2])
for name, export in helpers.items():
    module = importlib.import_module(name)
    assert pathlib.Path(module.__file__).resolve().is_relative_to(installed), name
    assert callable(getattr(module, export)), (name, export)
print(json.dumps(sorted(helpers)))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(installed), json.dumps(HELPERS)],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == sorted(HELPERS)

    smoke = subprocess.run(
        [sys.executable, "-I", "-c",
         "import runpy, sys; "
         "sys.path.insert(0, sys.argv[1]); "
         "runpy.run_path(sys.argv[2], run_name='__main__')",
         str(installed), str(root / "tests" / "wheel_smoke.py")],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert smoke.returncode == 0, smoke.stdout + smoke.stderr
    assert "installed-wheel offline workflows passed" in smoke.stdout
