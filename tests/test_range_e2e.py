"""Range runner e2e: emit a Mode-B-loadable document. No live AWS."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from extension.arms.burp import ARM_ID, BurpArm
from extension.arms.burp.policy import ENV_ENDPOINT
from extension.contract import Extension
from extension.range import (
    ARM_ACTION,
    DEFAULT_SEED,
    FIXTURE_IAM_OPEN,
    FIXTURE_S3_PUBLIC,
    SCHEMA_ID,
    run_range,
)
from tests.test_arm_burp import _StubState, _make_handler

ROOT = Path(__file__).resolve().parents[1]
MODE_B_FIELDS = {"id", "ok", "exposure", "path", "impact"}


@pytest.fixture
def stub_sse() -> Any:
    state = _StubState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    url = "http://%s:%d" % (host, port)
    try:
        yield url, state
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _assert_mode_b_loadable(document: dict[str, Any]) -> None:
    assert document["schema"] == SCHEMA_ID
    assert document["live_aws"] is False
    assert document["ok"] is True
    assert document["seed"] == DEFAULT_SEED
    by_id = {row["id"]: row for row in document["fixtures"]}
    assert set(by_id) == {FIXTURE_S3_PUBLIC, FIXTURE_IAM_OPEN}
    for row in by_id.values():
        assert set(row) >= MODE_B_FIELDS
        assert row["ok"] is True
        assert isinstance(row["exposure"], dict)
        assert isinstance(row["path"], list)
        assert isinstance(row["impact"], dict)
        assert row["exposure"]["asset_id"]
        assert row["impact"]["asset_id"]
        assert row["path"]


def test_range_cli_writes_mode_b_loadable_document(tmp_path: Path) -> None:
    out = tmp_path / "range-result.json"
    env = os.environ.copy()
    env.pop(ENV_ENDPOINT, None)
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "extension.range",
            "--out",
            str(out),
            "--seed",
            str(DEFAULT_SEED),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=15,
    )
    assert proc.returncode == 0, proc.stderr
    loaded = json.loads(out.read_text(encoding="utf-8"))
    _assert_mode_b_loadable(loaded)
    again = json.loads(out.read_text(encoding="utf-8"))
    assert again == loaded


def test_range_runner_document_is_mode_b_loadable(tmp_path: Path) -> None:
    document = run_range(arm_ids=())
    path = tmp_path / "range-result.json"
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    loaded = json.loads(path.read_text(encoding="utf-8"))
    _assert_mode_b_loadable(loaded)
    assert loaded == json.loads(json.dumps(document, sort_keys=True))


def test_range_with_burp_stub_stays_mode_b_loadable(
    stub_sse: tuple[str, _StubState],
) -> None:
    url, _state = stub_sse
    ext = Extension(arms={ARM_ID: BurpArm(endpoint=url, timeout=5)})
    document = run_range(extension=ext)
    _assert_mode_b_loadable(document)
    curated_ids = sorted(
        entry.id
        for entry in ext.list_entries()
        if entry.kind == "arm" and entry.curated
    )
    for row in document["fixtures"]:
        by_id = {item["arm_id"]: item for item in row["arms"]}
        assert set(by_id) == set(curated_ids)
        burp_row = by_id[ARM_ID]
        assert burp_row["status"] == "error"
        assert burp_row["output"] == {"edition": "professional"}
        assert burp_row["error"] == "tool 'observe' is not on the allowlist"
        for arm_id in curated_ids:
            if arm_id != ARM_ID:
                # Curated but unhandled in this wiring: fail-closed error row.
                assert by_id[arm_id]["status"] == "error", arm_id
