"""Shared fixtures for the specaudit-ctf test suite.

The suite promises hermeticity: no live scanner, no live cloud. On a
host with real tool binaries on PATH that promise silently breaks — an
arm's PATH fallback resolves nmap/wapiti/routersploit and any test
asserting a not-installed state fails. Every test therefore runs with
a PATH containing no binaries. Tests that need a binary point *_BIN at
a fixture (absolute path) or set their own PATH, exactly as the suite
always has; a scanner-equipped host now behaves like the validated
scanner-less hosts.

Subprocesses spawned with an explicit ``env=`` override the fixture's PATH by
design (do not "simplify" those sites away). Runtime builds resolve their
required Git executable before this per-test fixture is applied and fail
closed if no executable was available; they never substitute an ``unknown``
source revision.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _hermetic_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    empty = tmp_path_factory.mktemp("hermetic-path")
    monkeypatch.setenv("PATH", str(empty))
