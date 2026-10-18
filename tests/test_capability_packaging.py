"""The built distribution must provide every advertised capability helper.

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
    "attempt_ledger.risk_metrics": "compute_risk_sensitive_metrics",
    "audit_workpaper": "grade_workpaper",
    "caller_path_binding": "bind_caller_path",
    "candidate_admission": "validate_candidate_admission",
    "challenger_head": "run_experiment",
    "containment_evidence": "verify_containment",
    "deliverable_substrate": "validate_deliverable",
    "formal_assessment": "validate_formal_assessment",
    "frozen_slices": "validate_vuln_slice",
    "promotion_verifier": "verify_promotion",
    "telecom_case": "validate_telecom_case",
    "capability_records": "is_sha256_digest",
}


def test_built_wheel_provides_capability_helpers_outside_checkout(tmp_path: Path):
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
        assert not any(name.startswith(("governance/", "safety/"))
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
assert callable(importlib.import_module('frozen_slices').validate_rule_slice)
print(json.dumps(sorted(helpers)))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(installed), json.dumps(HELPERS)],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == sorted(HELPERS)
