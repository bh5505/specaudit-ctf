"""Reader arms in the exercise report: honest statuses never read as all-clear.

End-to-end checks for the 2026-10-23 bounded offline readers (hostbadger,
idwolf, osv) through the registered catalog: the arms lane must classify
partial/unknown reader results as degraded and keep the overall exercise
incomplete, a complete reader result may contribute to a complete run, and
partial data actions must surface as CLI exit 1 / MCP isError true. The
retained arm row carries only the redacted source/completeness projection —
never raw evidence rows or identity material.
"""

from __future__ import annotations

import json
from pathlib import Path

from extension.contract import Extension, _default_arms
from extension.dispatch import dispatch_invoke
from extension.arms.osv import OsvArm
from exercise.runner import run_exercise

ROOT = Path(__file__).resolve().parents[1]
from tests.test_arm_osv import FakeResponse, _page, _live_record


HOSTBADGER_DEMO = ROOT / "extension/arms/hostbadger/data/demo-hostbadger-report.jsonl"
IDWOLF_PARTIAL = ROOT / "extension/arms/idwolf/data/demo-idwolf-partial.jsonl"
IDWOLF_AD = ROOT / "extension/arms/idwolf/data/demo-idwolf-ad.jsonl"


def _exercise(arms: list[dict], extension: Extension | None = None) -> dict:
    return run_exercise(extension=extension, arms=arms)


def test_registered_readers_resolve_and_list_tools() -> None:
    ext = Extension()
    for arm_id in ("hostbadger", "idwolf", "osv"):
        spec = ext.arm_spec(arm_id)
        assert spec.id == arm_id
        result = ext.invoke(arm_id, "list_tools", {})
        assert result.ok is True


def test_hostbadger_partial_demo_degrades_not_completes() -> None:
    document = _exercise(
        [{"arm_id": "hostbadger", "action": "summary", "args": {"report": str(HOSTBADGER_DEMO)}}]
    )
    row = next(row for row in document["arms"] if row["arm_id"] == "hostbadger")
    assert row["status"] == "degraded"
    assert document["status"] == "degraded"
    assert document["ok"] is False


def test_degraded_row_keeps_redacted_projection_only() -> None:
    document = _exercise(
        [{"arm_id": "hostbadger", "action": "list_findings", "args": {"report": str(HOSTBADGER_DEMO)}}]
    )
    row = next(row for row in document["arms"] if row["arm_id"] == "hostbadger")
    projection = row["result"]
    assert projection["status"] == "partial"
    assert projection["source"]["kind"] == "operator-file"
    assert projection["source"]["sha256"].startswith("sha256:")
    # Raw evidence rows and identity material never enter the report.
    serialized = json.dumps(document)
    assert "DemoOnly-NotReal-token" not in serialized
    assert "evidence" not in projection


def test_idwolf_partial_run_degrades_and_unknown_reports_too() -> None:
    document = _exercise(
        [{"arm_id": "idwolf", "action": "summary", "args": {"report": str(IDWOLF_PARTIAL)}}]
    )
    row = next(row for row in document["arms"] if row["arm_id"] == "idwolf")
    assert row["status"] == "degraded"
    assert row["result"]["status"] == "partial"
    assert document["status"] == "degraded"

    no_summary = IDWOLF_PARTIAL.read_text(encoding="utf-8").splitlines()
    no_summary = [line for line in no_summary if '"event_type":"summary"' not in line]
    path = IDWOLF_PARTIAL.with_name("tmp-no-summary.jsonl")
    path.write_text("\n".join(no_summary) + "\n", encoding="utf-8")
    try:
        document = _exercise(
            [{"arm_id": "idwolf", "action": "summary", "args": {"report": str(path)}}]
        )
        row = next(row for row in document["arms"] if row["arm_id"] == "idwolf")
        assert row["status"] == "degraded"
        assert row["result"]["status"] == "unknown"
        assert document["status"] == "degraded"
    finally:
        path.unlink()


def test_complete_reader_row_contributes_to_complete_run() -> None:
    document = _exercise(
        [{"arm_id": "idwolf", "action": "summary", "args": {"report": str(IDWOLF_AD)}}]
    )
    row = next(row for row in document["arms"] if row["arm_id"] == "idwolf")
    assert row["status"] == "complete"
    assert document["status"] == "complete"
    assert document["ok"] is True


def test_osv_truncated_pagination_degrades_the_exercise() -> None:
    pages = [
        FakeResponse(200, _page([_live_record(f"OSV-SYNTH-{n:04d}")], token=f"p{n + 1}"))
        for n in range(10)
    ]  # every page offers another token: the 10-page cap cuts off mid-pagination
    calls: list = []

    def capped_transport(request, timeout):
        calls.append(request)
        return pages[len(calls) - 1]

    arms = _default_arms()
    arms["osv"] = OsvArm(transport=capped_transport)
    document = _exercise(
        [{"arm_id": "osv", "action": "query_package", "args": {"ecosystem": "PyPI", "name": "demo-package", "version": "1.2.3"}}],
        extension=Extension(arms=arms),
    )
    row = next(row for row in document["arms"] if row["arm_id"] == "osv")
    assert row["status"] == "degraded"
    assert row["result"]["status"] == "partial"
    assert document["status"] == "degraded"
    assert document["ok"] is False


def test_osv_transport_error_fails_the_exercise_not_degrades() -> None:
    def dead_transport(payload, timeout):
        raise OSError("unreachable")

    arms = _default_arms()
    arms["osv"] = OsvArm(transport=dead_transport)
    document = _exercise(
        [{"arm_id": "osv", "action": "query_commit", "args": {"commit": "a" * 40}}],
        extension=Extension(arms=arms),
    )
    row = next(row for row in document["arms"] if row["arm_id"] == "osv")
    assert row["status"] == "failed"
    assert document["status"] == "failed"


def test_partial_data_actions_exit_one_over_cli_and_mcp() -> None:
    ext = Extension()
    outcome = dispatch_invoke(
        ext,
        arm_id="idwolf",
        action="summary",
        args={"report": str(IDWOLF_PARTIAL)},
    )
    assert outcome.exit_code == 1
    document = outcome.document
    assert document["ok"] is False
    assert document["output"]["status"] == "partial"
    assert document["output"]["evidence"]

    server_reply = ext  # dispatch is the shared path for CLI and MCP
    assert server_reply is not None
    from extension.mcp_server import McpServer

    response = McpServer(extension=Extension()).handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "invoke",
                "arguments": {
                    "id": "idwolf",
                    "action": "summary",
                    "args": {"report": str(IDWOLF_PARTIAL)},
                },
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["output"]["status"] == "partial"
