"""Offline operator adapter for bounded PR4 evidence and exercise workflows.

All caller evidence is inline. This handler never opens a caller path, starts an
upstream executable, contacts an endpoint, or treats source prose as authority.
"""
from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any, Mapping

from ..contract import ArmSpec, NotInstalledError, Result, TRANSPORT_CLI
from .mcp_client import redact

ARM_ID = "learning-operator"
# Leave ample framing room under the attached MCP server's 1 MiB line cap.
MAX_ARGS_BYTES = 256_000
MAX_RESULT_BYTES = 256_000
ACTIONS = {
    "graph_path": frozenset({"graph_ndjson", "sha256", "source", "target", "project"}),
    "k8s_review": frozenset({"report_json", "capture"}),
    "workpaper_review": frozenset({"manifest", "submission", "evidence"}),
    "agent_grade": frozenset({"trace", "submission"}),
    "detection_review": frozenset({"packet", "submission"}),
    "triage_evaluate": frozenset({"candidates_json", "ranking_json", "binding", "labels_json"}),
}
REQUIRED = {
    "graph_path": ACTIONS["graph_path"] - {"project"},
    "k8s_review": ACTIONS["k8s_review"],
    "workpaper_review": ACTIONS["workpaper_review"],
    "agent_grade": ACTIONS["agent_grade"],
    "detection_review": ACTIONS["detection_review"] - {"submission"},
    "triage_evaluate": ACTIONS["triage_evaluate"],
}
CAVEATS = (
    "offline import and synthetic exercise only; no upstream collector, provider, or target dispatch",
    "hashes bind supplied bytes but do not authenticate source or custody",
    "graph paths and Kubernetes checks do not establish effective access",
    "workpaper structure needs human conclusion review; triage ranking is review order, not evidence",
    "inline captured data can be real; apply host egress, identity, and data controls externally",
)


class LearningOperatorArm:
    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(self, spec: ArmSpec, action: str, args: Mapping[str, Any]) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        try:
            payload = dict(args)
            if action == "list_tools":
                _shape(payload, frozenset(), frozenset())
                return _ok(spec, action, {"read_actions": sorted((*ACTIONS, "sample", "list_tools")),
                                          "dispatch_actions": [],
                                          "arg_keys": {key: sorted(value) for key, value in ACTIONS.items()},
                                          "sample_arg_keys": ["workflow"], "caveats": list(CAVEATS)})
            if action == "sample":
                _shape(payload, {"workflow"}, {"workflow"})
                workflow = payload["workflow"]
                if not isinstance(workflow, str) or workflow not in ACTIONS:
                    raise ValueError("workflow must name a listed offline action")
                return _ok(spec, action, {"arm_id": ARM_ID, "action": workflow, "args": _sample(workflow),
                                          "classification": "bundled synthetic teaching example"})
            if action not in ACTIONS:
                raise ValueError("action is not on the offline allowlist")
            _shape(payload, ACTIONS[action], REQUIRED[action])
            canonical_args = _json(payload)
            if len(canonical_args) > MAX_ARGS_BYTES:
                raise ValueError("inline input exceeds 256000 bytes")
            result = _run(action, payload)
            return _ok(spec, action, {"workflow": action, "assessment": result,
                                      "request_args_sha256": hashlib.sha256(canonical_args).hexdigest(),
                                      "source_class": "caller-supplied-declaration",
                                      "limitations": list(CAVEATS)})
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
            return _fail(spec, action, str(exc))


def _shape(value: dict, allowed: frozenset[str] | set[str], required: frozenset[str] | set[str]) -> None:
    if any(not isinstance(k, str) for k in value) or set(value) - allowed or not required <= set(value):
        raise ValueError(f"expected keys {sorted(required)}; allowed keys {sorted(allowed)}")


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _raw(value: Any, label: str, limit: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be exact UTF-8 text")
    raw = value.encode("utf-8")
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return raw


def _run(action: str, args: dict) -> dict:
    if action == "graph_path":
        from graph_evidence.importer import MAX_BYTES, evaluate
        if "project" in args and type(args["project"]) is not bool:
            raise ValueError("project must be boolean")
        return evaluate(_raw(args["graph_ndjson"], "graph_ndjson", MAX_BYTES), args["sha256"],
                        args["source"], args["target"], project_mode=args.get("project", False))
    if action == "k8s_review":
        from k8s_path_evidence.__main__ import MAX_BYTES, normalize
        return normalize(_raw(args["report_json"], "report_json", MAX_BYTES), args["capture"])
    if action == "workpaper_review":
        from review_workpaper.__main__ import MAX_EVIDENCE_BYTES, MAX_RECORDS, validate
        evidence = args["evidence"]
        if not isinstance(evidence, dict) or len(evidence) > MAX_RECORDS:
            raise ValueError("evidence must be a bounded file-name to exact-text mapping")
        contents = {key: _raw(value, "evidence", MAX_EVIDENCE_BYTES) for key, value in evidence.items()
                    if isinstance(key, str)}
        if len(contents) != len(evidence):
            raise ValueError("evidence names must be text")
        errors = validate(args["manifest"], args["submission"], evidence_bytes=contents)
        return {"structurally_valid": not errors, "human_review_required": True, "errors": errors}
    if action == "agent_grade":
        from learning.agent_security_harness import grade
        return grade(args["trace"], args["submission"])
    if action == "detection_review":
        from learning.detection_validation import evaluate, grade
        return grade(args["packet"], args["submission"]) if "submission" in args else evaluate(args["packet"])
    from extension.triage.siftrank import CaptureBinding, MAX_INPUT_BYTES, MAX_BINDING_BYTES, evaluate_capture
    binding = args["binding"]
    if not isinstance(binding, dict) or set(binding) != set(CaptureBinding.__dataclass_fields__):
        raise ValueError("binding requires the exact capture fields")
    return evaluate_capture(_raw(args["candidates_json"], "candidates_json", MAX_INPUT_BYTES),
                            _raw(args["ranking_json"], "ranking_json", MAX_INPUT_BYTES),
                            CaptureBinding(**binding), _raw(args["labels_json"], "labels_json", MAX_BINDING_BYTES))


def _sample(workflow: str) -> dict:
    if workflow == "graph_path":
        raw = files("graph_evidence").joinpath("fixtures/synthetic-aws.rage.ndjson").read_bytes()
        return {"graph_ndjson": raw.decode("utf-8"), "sha256": hashlib.sha256(raw).hexdigest(),
                "source": "aws|000000000000|aws:iam:role|trainee",
                "target": "aws|000000000000|aws:s3:bucket|practice-data"}
    if workflow == "k8s_review":
        fixture = files("k8s_path_evidence").joinpath("fixture")
        return {"report_json": fixture.joinpath("report.json").read_text(encoding="utf-8"),
                "capture": json.loads(fixture.joinpath("capture.json").read_bytes())}
    if workflow == "workpaper_review":
        fixture = files("review_workpaper").joinpath("packet")
        manifest = json.loads(fixture.joinpath("manifest.json").read_bytes())
        submission = {"schema": "specaudit.review-workpaper.v1", "subject": "Harbor Notes",
                      "version": "0.4", "period": "fixture interval", "boundary": "BLUE only",
                      "criterion": "gateway policy", "reviewer": "synthetic operator example",
                      "assets": ["note"], "trust_boundaries": ["note to assistant"],
                      "attacker_goals": ["induce export"], "untested": ["other channel"],
                      "limitations": ["partial ledger"], "recommendation": ["review"],
                      "retest": ["collect ledger"], "claims": [{"id": "bounded-read", "status": "supported",
                      "hypothesis": "read accepted", "boundary": "gateway", "observation": "gateway receipt",
                      "inference": "one read only", "alternative": "other route unknown",
                      "validation": "recheck ledger", "residual_risk": "unobserved channels",
                      "evidence_ids": ["gateway"]}],
                      "coverage": [{"surface": "gateway", "disposition": "bounded",
                                    "claim_ids": ["bounded-read"]}], "overall": "inconclusive"}
        return {"manifest": manifest, "submission": submission,
                "evidence": {row["file"]: fixture.joinpath(row["file"]).read_text(encoding="utf-8")
                             for row in manifest["evidence"]}}
    if workflow == "agent_grade":
        from learning.agent_security_harness import answer, trace
        events = trace("00000000-0000-4000-8000-000000000001")
        return {"trace": events, "submission": {"schema": "specaudit.agent-tool-submission.v1",
                "attempt_id": events["attempt_id"], "trace_sha256": events["trace_sha256"],
                "assessments": [answer(event) for event in events["events"]]}}
    if workflow == "detection_review":
        return {"packet": json.loads(files("learning").joinpath("data/detection/missing-telemetry.json").read_bytes())}
    fixture = files("extension.triage").joinpath("fixtures")
    return {"candidates_json": fixture.joinpath("candidates.json").read_text(encoding="utf-8"),
            "ranking_json": fixture.joinpath("ranking.synthetic.json").read_text(encoding="utf-8"),
            "binding": json.loads(fixture.joinpath("binding.synthetic.json").read_bytes()),
            "labels_json": fixture.joinpath("labels.synthetic.json").read_text(encoding="utf-8")}


def _ok(spec: ArmSpec, action: str, output: Any) -> Result:
    if len(_json(output)) > MAX_RESULT_BYTES:
        return _fail(spec, action, "result exceeds 256000 bytes; narrow the input")
    return Result(ok=True, arm_id=spec.id, action=action, output=output, error=None)


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(ok=False, arm_id=spec.id, action=action, output=None, error=redact(error)[:512])
