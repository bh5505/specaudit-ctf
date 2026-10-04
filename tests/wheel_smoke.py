"""Run installed-wheel E1 paths from outside the checkout without pytest."""

import hashlib
import json
import tempfile
import uuid
from pathlib import Path
from importlib.resources import files

from extension.triage.siftrank import CaptureBinding, evaluate_capture
from graph_evidence.importer import evaluate as evaluate_graph
from k8s_path_evidence.__main__ import normalize
from learning.agent_security_harness import answer, grade, trace
from review_workpaper.__main__ import validate
from extension.arms.learning_operator import ACTIONS, ARM_ID, _sample
from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from learning.operator import _read_report


def main():
    graph = files("graph_evidence").joinpath("fixtures/synthetic-aws.rage.ndjson").read_bytes()
    reviewed = evaluate_graph(
        graph, hashlib.sha256(graph).hexdigest(),
        "aws|000000000000|aws:iam:role|trainee",
        "aws|000000000000|aws:s3:bucket|practice-data",
    )
    assert {path["verdict"] for path in reviewed["paths"]} == {
        "configured_candidate", "blocked", "unknown"
    }

    k8s = files("k8s_path_evidence").joinpath("fixture")
    captured = normalize(k8s.joinpath("report.json").read_bytes(),
                         json.loads(k8s.joinpath("capture.json").read_bytes()))
    assert {row["outcome"] for row in captured["case_evaluations"]} == {
        "allowed-check-candidate", "blocked-permission", "unknown-prerequisite"
    }

    packet = files("review_workpaper").joinpath("packet")
    claim = {
        "id": "bounded-read", "status": "supported", "hypothesis": "read was accepted",
        "boundary": "gateway", "observation": "gateway receipt", "inference": "one read only",
        "alternative": "other route unknown", "validation": "recheck ledger",
        "residual_risk": "unobserved channels", "evidence_ids": ["gateway"],
    }
    submission = {
        "schema": "specaudit.review-workpaper.v1", "subject": "Harbor Notes",
        "version": "0.4", "period": "fixture interval", "boundary": "BLUE only",
        "criterion": "gateway policy", "reviewer": "wheel smoke",
        "assets": ["note"], "trust_boundaries": ["note to assistant"],
        "attacker_goals": ["induce export"], "untested": ["other channel"],
        "limitations": ["partial ledger"], "recommendation": ["review"],
        "retest": ["collect ledger"], "claims": [claim],
        "coverage": [{"surface": "gateway", "disposition": "bounded", "claim_ids": ["bounded-read"]}],
        "overall": "inconclusive",
    }
    assert not validate(json.loads(packet.joinpath("manifest.json").read_bytes()),
                        submission, packet)

    events = trace(str(uuid.uuid4()))
    assessment = {
        "schema": "specaudit.agent-tool-submission.v1",
        "attempt_id": events["attempt_id"], "trace_sha256": events["trace_sha256"],
        "assessments": [answer(event) for event in events["events"]],
    }
    assert grade(events, assessment)["passed"]

    triage = files("extension.triage").joinpath("fixtures")
    metrics = evaluate_capture(
        triage.joinpath("candidates.json").read_bytes(),
        triage.joinpath("ranking.synthetic.json").read_bytes(),
        CaptureBinding(**json.loads(triage.joinpath("binding.synthetic.json").read_bytes())),
        triage.joinpath("labels.synthetic.json").read_bytes(),
    )
    assert metrics["evaluation_scope"] == "synthetic-format-fixture"
    with tempfile.TemporaryDirectory() as temp:
        for index, action in enumerate(sorted(ACTIONS)):
            artifact_dir = Path(temp) / str(index)
            artifact_dir.mkdir()
            outcome = dispatch_invoke(Extension(), arm_id=ARM_ID, action=action,
                                      args=_sample(action), attempt_id="attempt-" + f"{index+1:064x}",
                                      artifact_dir=str(artifact_dir))
            assert outcome.exit_code == 0, (action, outcome.stderr_line)
            assert outcome.envelope["status"] == "complete"
            report = _read_report(str(artifact_dir), outcome.envelope["artifacts"][0]["digest"])
            assert report["workflow"] == action and report["assessment"]
    print("installed-wheel offline workflows passed")


if __name__ == "__main__":
    main()
