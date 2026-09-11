"""Shared fixtures for the specaudit-ctf test suite.

The suite promises hermeticity: no live scanner, no live cloud. On a
host with real tool binaries on PATH that promise silently breaks — an
arm's PATH fallback resolves nmap/wapiti/routersploit and any test
asserting a not-installed state fails. Every test therefore runs with
a PATH containing no binaries. Tests that need a binary point *_BIN at
a fixture (absolute path) or set their own PATH, exactly as the suite
always has; a scanner-equipped host now behaves like the validated
scanner-less hosts.

Two deliberate consequences: subprocesses spawned with an explicit
``env=`` override the fixture's PATH by design (do not "simplify" those
sites away), and test-built runtime manifests record an "unknown"
source revision because runtime.build's bare ``git`` lookup no longer
resolves — independent of ambient repo state, which is the point.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def seed():
    """Deterministic seed for reproducible tests."""
    return 42


@pytest.fixture(scope="session")
def sample_report_json():
    with (FIXTURES_DIR / "report.json").open() as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def sample_report_sarif():
    with (FIXTURES_DIR / "report.sarif").open() as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def sample_rubric():
    with (FIXTURES_DIR / "rubric.yaml").open() as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="session")
def sample_evidence_bundle():
    return (FIXTURES_DIR / "evidence_bundle.csv").read_text()


@pytest.fixture(scope="session")
def sample_finding_candidate():
    return (FIXTURES_DIR / "finding_candidate.csv").read_text()


@pytest.fixture(scope="session")
def sample_iam_principal():
    return (FIXTURES_DIR / "iam_principal.csv").read_text()


@pytest.fixture(scope="session")
def sample_rule():
    return (FIXTURES_DIR / "rule.csv").read_text()


@pytest.fixture(scope="session")
def sample_check_run():
    return (FIXTURES_DIR / "check_run.csv").read_text()


@pytest.fixture(scope="session")
def sample_agent_card():
    with (FIXTURES_DIR / "agent-card.json").open() as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def inventory_pages():
    pages_dir = FIXTURES_DIR / "inventory_pages"
    return {path.stem: path.read_text() for path in pages_dir.glob("*.html")}


@pytest.fixture(autouse=True)
def deterministic_random(seed):
    """Ensure deterministic random state for each test."""
    import random

    try:
        import numpy as np
    except ImportError:
        np = None
    random.seed(seed)
    if np is not None:
        np.random.seed(seed)
    yield
    random.seed()
    if np is not None:
        np.random.seed()


@pytest.fixture(autouse=True)
def _hermetic_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    empty = tmp_path_factory.mktemp("hermetic-path")
    monkeypatch.setenv("PATH", str(empty))
