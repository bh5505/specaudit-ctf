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
from extension.envelopes import RESULT_SCHEMA_ID, parse_execution_result
from extension.range import (
    ARM_ACTION,
    DEFAULT_SEED,
    SCHEMA_ID,
    run_range,
)
from tests.test_arm_burp import _StubState, _make_handler
from tests.test_range_lifecycle import apply_no_curated_tools

ROOT = Path(__file__).resolve().parents[1]
MODE_B_FIELDS = {
    "id",
    "ok",
    "status",
    "matched_expected",
    "coverage",
    "exposure",
    "path",
    "impact",
    "exposures",
    "chains",
    "arms",
}
RANGE_SCHEMA_V3 = "range.lifecycle.v3"


def _manifest_fixtures() -> set[str]:
    manifest = json.loads(
        (ROOT / "extension" / "range" / "manifest.json").read_text(encoding="utf-8")
    )
    return set(manifest["fixtures"])


@pytest.fixture
def no_curated_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    apply_no_curated_tools(monkeypatch)


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


def _assert_mode_b_loadable(document: dict[str, Any], *, status: str) -> None:
    assert SCHEMA_ID == RANGE_SCHEMA_V3
    assert document["schema"] == RANGE_SCHEMA_V3
    assert document["live_aws"] is False
    assert document["status"] == status
    assert document["ok"] is (status == "complete")
    assert document["seed"] == DEFAULT_SEED
    assert set(document["coverage"]) == {"attempted", "complete", "skipped", "error"}
    by_id = {row["id"]: row for row in document["fixtures"]}
    assert set(by_id) == _manifest_fixtures()
    for row in by_id.values():
        assert set(row) >= MODE_B_FIELDS
        assert row["ok"] is (row["status"] == "complete")
        assert row["status"] in {"complete", "degraded", "failed"}
        assert isinstance(row["exposure"], dict)
        assert isinstance(row["path"], list)
        assert isinstance(row["impact"], dict)
        assert isinstance(row["exposures"], list)
        assert isinstance(row["chains"], list)
        assert row["exposure"]["asset_id"]
        assert row["impact"]["asset_id"]
        assert row["path"]


def test_range_cli_out_writes_execution_result_v1(
    tmp_path: Path, no_curated_tools: None
) -> None:
    out = tmp_path / "range-result.json"
    env = os.environ.copy()
    env.pop(ENV_ENDPOINT, None)
    # Subprocess cannot inherit resolve_binary stubs; keep python's dir
    # so the interpreter starts, but do not search the host PATH.
    env["PATH"] = str(Path(sys.executable).parent)
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
    assert out.is_file(), proc.stderr or proc.stdout
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["schema"] == RESULT_SCHEMA_ID
    # Default CLI omits arm_ids (auto-discover); no curated tools → degraded.
    assert loaded["status"] == "degraded"
    assert "ok" not in loaded
    assert "fixtures" not in loaded
    assert proc.returncode == 1, proc.stderr
    parsed = parse_execution_result(loaded)
    assert parsed.schema_ok is True
    assert parsed.status == "degraded"
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
    _assert_mode_b_loadable(loaded, status="complete")
    assert loaded == json.loads(json.dumps(document, sort_keys=True))


def test_range_with_burp_stub_stays_mode_b_loadable(
    stub_sse: tuple[str, _StubState],
) -> None:
    url, _state = stub_sse
    ext = Extension(arms={ARM_ID: BurpArm(endpoint=url, timeout=5)})
    document = run_range(extension=ext)
    _assert_mode_b_loadable(document, status="degraded")
    curated_ids = sorted(
        entry.id
        for entry in ext.list_entries()
        if entry.kind == "arm" and entry.curated
    )
    for row in document["fixtures"]:
        by_id = {item["arm_id"]: item for item in row["arms"]}
        assert set(by_id) == set(curated_ids)
        burp_row = by_id[ARM_ID]
        # Research tier (doc-21 dossier): the stub is really dialed
        # (edition detection succeeded through the hardened transport);
        # the non-allowlisted observe action still fails closed.
        assert burp_row["status"] == "error"
        assert burp_row["output"] == {"edition": "professional"}
        assert "not on the allowlist" in (burp_row.get("error") or "")
        for arm_id in curated_ids:
            if arm_id != ARM_ID:
                # Curated but unhandled in this wiring: fail-closed error row.
                assert by_id[arm_id]["status"] == "error", arm_id
