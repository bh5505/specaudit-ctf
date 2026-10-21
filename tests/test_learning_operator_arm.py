"""Learning-operator samples run through the arm, CLI dispatch, and MCP."""

from __future__ import annotations

import hashlib
import json

import pytest

from extension.arms.learning_operator import ARM_ID, SAMPLE_ACTIONS, _sample
from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.mcp_server import McpServer
from tests.test_alt_head_mcp import _call, _content_json


@pytest.mark.parametrize("action", sorted(SAMPLE_ACTIONS))
def test_sample_assessments_have_matching_direct_cli_and_mcp_results(action: str) -> None:
    args = _sample(action)
    local = dispatch_invoke(Extension(), arm_id=ARM_ID, action=action, args=args)
    assert local.exit_code == 0
    assert local.document["ok"] is True
    mcp = _call(McpServer(extension=Extension()), "invoke", {"id": ARM_ID, "action": action, "args": args})
    assert mcp["result"]["isError"] is False
    assert _content_json(mcp) == local.document
    assessment = local.document["output"]["assessment"]
    assert assessment
    assert local.document["output"]["request_args_sha256"] == hashlib.sha256(
        json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def test_sample_outcomes_are_actual_assessments() -> None:
    ext = Extension()
    graph = ext.invoke(ARM_ID, "graph_path", _sample("graph_path")).output["assessment"]
    assert {path["verdict"] for path in graph["paths"]} == {
        "configured_candidate", "blocked", "unknown"
    }
    k8s = ext.invoke(ARM_ID, "k8s_review", _sample("k8s_review")).output["assessment"]
    assert {row["outcome"] for row in k8s["case_evaluations"]} == {
        "allowed-check-candidate", "blocked-permission", "unknown-prerequisite"
    }
    claim = _sample("agent_grade")
    claim["submission"]["assessments"][0]["classification"] = "rejected"
    assert ext.invoke(ARM_ID, "agent_grade", claim).output["assessment"]["passed"] is False


def test_analyze_pack_returns_structured_findings() -> None:
    args = {"report": {"run_id": "capture-1", "findings": [{
        "check_id": "demo_pack_t3_technique_context",
        "record_locator": "203.0.113.7:443 / service:capture-1",
        "title": "Technique context on captured service 203.0.113.7:443",
        "details": "technique=T1190 - Capture; tactic=TA0001 - Initial Access",
        "severity": "high", "risk_score": 40,
    }]}}
    outcome = dispatch_invoke(Extension(), arm_id=ARM_ID, action="analyze_pack", args=args)
    assert outcome.exit_code == 0
    report = outcome.document["output"]
    assert report["assessment"]["targets"][0]["ip"] == "203.0.113.7"
    mcp = _call(McpServer(extension=Extension()), "invoke", {"id": ARM_ID, "action": "analyze_pack", "args": args})
    assert _content_json(mcp) == outcome.document


def test_unknown_learning_action_reports_failure() -> None:
    outcome = dispatch_invoke(Extension(), arm_id=ARM_ID, action="not_an_action", args={})
    assert outcome.exit_code != 0
    assert outcome.document["ok"] is False
    assert outcome.document["error"]
