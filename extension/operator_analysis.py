"""Bind supplementary offline reviews to exact findings in an operator pack run.

These are caller-supplied captures, never independent proof of provenance or
authority. A malformed or orphaned binding is refused rather than silently
attached to a different target.
"""
from __future__ import annotations

import hashlib
import json


def finding_id(finding: dict) -> str:
    identity = [finding.get("check_id"), finding.get("record_locator")]
    if any(not isinstance(x, str) or not x for x in identity):
        raise ValueError("finding requires check_id and record_locator")
    return "finding:" + hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()[:24]


def triage_source_ref(findings: list[dict]) -> str:
    """Bind captured triage candidates to the complete current finding set."""
    raw = json.dumps(findings, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "pack-report-sha256:" + hashlib.sha256(raw).hexdigest()


def _raw(value: object, limit: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} requires exact UTF-8 text")
    raw = value.encode("utf-8")
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return raw


def _shape(value: object, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError(f"expected {sorted(required)}, optional {sorted(optional)}")
    return value


def _graph(data: dict, finding: dict) -> dict:
    from graph_evidence.importer import MAX_BYTES, evaluate

    _shape(data, {"graph_ndjson", "sha256", "source", "target"}, {"project"})
    locator = finding["record_locator"].split(" / ")
    target = data["target"]
    node = target.split("|") if isinstance(target, str) else []
    # The checked-in AWS bucket check has a stable bucket/account locator.
    # Require the requested graph target to name that same bucket and realm.
    bucket_match = (finding["check_id"].endswith("_aws_t1_trust_boundary") and
                    len(locator) >= 2 and len(node) == 4 and node[0] == "aws" and
                    node[1] == locator[1] and node[2] == "aws:s3:bucket" and
                    node[3] == locator[0])
    generic_match = (not finding["check_id"].endswith("_aws_t1_trust_boundary") and
                     len(node) == 4 and node[0] == "aws" and target in locator)
    if not (bucket_match or generic_match):
        raise ValueError("graph target does not match the AWS finding")
    if type(data.get("project", False)) is not bool:
        raise ValueError("graph project must be boolean")
    review = evaluate(_raw(data["graph_ndjson"], MAX_BYTES, "graph_ndjson"),
                      data["sha256"], data["source"], target,
                      project_mode=data.get("project", False))
    verdicts = sorted({path["verdict"] for path in review["paths"]})
    return {"source_class": "caller-supplied-graph", "input_sha256": review["input_sha256"],
            "path_verdicts": verdicts, "paths": review["paths"],
            "next_validation": ["independently verify effective cloud permission and receipt custody"
                                if "configured_candidate" in verdicts else
                                "resolve blocked or unknown graph prerequisites and receipt custody"],
            "limitations": review["limitations"]}


def _k8s(data: dict, finding: dict) -> dict:
    from k8s_path_evidence.__main__ import MAX_BYTES, normalize

    _shape(data, {"report_json", "capture"})
    review = normalize(_raw(data["report_json"], MAX_BYTES, "report_json"), data["capture"])
    # The pack has no native Kubernetes target type. An exact finding identity
    # plus an explicit subject in that finding's locator is mandatory.
    if review["subject"] not in finding["record_locator"].split(" / "):
        raise ValueError("Kubernetes service account is absent from finding locator")
    return {"source_class": "caller-supplied-k8s", "subject": review["subject"],
            "raw_sha256": review["raw_sha256"], "cases": review["case_evaluations"],
            "path_hypotheses": review["findings"],
            "next_validation": ["verify the reported SSAR and path prerequisites against the authorized cluster"],
            "limitations": [review["conclusion"], review["limitations"]]}


def _workpaper(data: dict, finding: dict) -> dict:
    from review_workpaper.__main__ import MAX_EVIDENCE_BYTES, MAX_RECORDS, validate

    _shape(data, {"manifest", "submission", "evidence"})
    submission = data["submission"]
    if not isinstance(submission, dict) or not isinstance(submission.get("subject"), str):
        raise ValueError("workpaper requires a subject")
    if submission["subject"] != finding["record_locator"]:
        raise ValueError("workpaper subject differs from finding locator")
    files = data["evidence"]
    if not isinstance(files, dict) or len(files) > MAX_RECORDS:
        raise ValueError("workpaper evidence mapping exceeds bound")
    raw = {name: _raw(content, MAX_EVIDENCE_BYTES, "workpaper evidence") for name, content in files.items()
           if isinstance(name, str)}
    if len(raw) != len(files):
        raise ValueError("workpaper evidence names must be strings")
    errors = validate(data["manifest"], submission, evidence_bytes=raw)
    claims = submission.get("claims", [])
    return {"source_class": "caller-supplied-workpaper", "structure_valid": not errors,
            "errors": errors, "claims": [{"id": c.get("id"), "status": c.get("status"),
                                   "validation": c.get("validation"), "residual_risk": c.get("residual_risk")}
                                  for c in claims if isinstance(c, dict)][:32],
            "next_validation": ["human review of claim conclusions and evidence custody"] if not errors else
                               ["repair workpaper structure and evidence references before analyst sign-off"],
            "limitations": ["structural review does not establish the truth of workpaper conclusions"]}


def _detection(data: dict, finding: dict, techniques: set[str]) -> dict:
    from learning.detection_validation import evaluate_operational

    _shape(data, {"packet"})
    packet = data["packet"]
    _shape(packet, {"schema", "target", "technique_id", "prerequisite", "rule", "events",
                    "alerts", "actions", "retests"})
    if packet["target"] != finding["record_locator"]:
        raise ValueError("detection target differs from finding locator")
    if packet["technique_id"] not in techniques:
        raise ValueError("detection technique is absent from pack attack chain")
    review = evaluate_operational(packet)
    gaps = [stage for stage, result in review["stages"].items() if result["state"] != "met"]
    return {"source_class": "caller-supplied-detection", "technique_id": packet["technique_id"],
            "stages": review["stages"], "retest_result": review["retest_result"],
            "disposition": "needs-validation" if gaps or review["retest_result"] != "effective"
                           else "reported-effective-retest-needs-independent-confirmation",
            "next_validation": ["validate detection stages: " + ", ".join(gaps)] if gaps else
                               ["independently confirm reported retest and telemetry custody"],
            "limitations": ["caller-supplied stage records and hashes do not authenticate telemetry or effectiveness"]}


def _agent(data: dict, finding: dict) -> dict:
    from exercise.attempt import AGENT_TRACE_SCHEMA

    _shape(data, {"trace_review", "target"})
    if data["target"] != finding["record_locator"]:
        raise ValueError("agent review target differs from finding locator")
    review = _shape(data["trace_review"], {"schema", "kind", "status",
                                           "observed_calls", "claims", "trace"},
                    {"trace_sha256", "omitted_calls", "claims_status"})
    if (review["schema"] != AGENT_TRACE_SCHEMA or review["kind"] != "agent" or
            review["status"] not in {"verified", "no_tool_calls", "unverified"}):
        raise ValueError("invalid agent trace review")
    if (not isinstance(review["observed_calls"], list) or len(review["observed_calls"]) > 128 or
            not isinstance(review["claims"], list) or len(review["claims"]) > 128):
        raise ValueError("invalid agent trace counts")
    if review["status"] != "unverified":
        digest = review.get("trace_sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("agent trace digest invalid")
        omitted = review.get("omitted_calls")
        if type(omitted) is not int or omitted < 0:
            raise ValueError("agent omitted call count invalid")
    return {"source_class": "caller-supplied-agent-trace-review",
            "declared_trace_status": review["status"], "trace_sha256_declared": review.get("trace_sha256"),
            "observed_calls": review["observed_calls"], "claims_status": review.get("claims_status", "unbound"),
            "next_validation": ["operator independently authenticates the attempt HMAC, scope, and tool-event claims"],
            "limitations": ["inline review and per-finding association are declarations; the operator's trusted trace key is not available to this reader"]}


def _task(kind: str, review: dict, finding: dict) -> dict:
    """Actionable operator review queue, not a dispatch or authorization."""
    if kind == "graph":
        verdicts = review["path_verdicts"]
        action = "verify-effective-permission" if "configured_candidate" in verdicts else "resolve-path-prerequisite"
        capability = "prowler-mcp (research read tier; verify admission)"
    elif kind == "k8s":
        action = "verify-ssar-and-path-prerequisites"
        capability = "independent authorized Kubernetes observation"
    elif kind == "workpaper":
        action = "review-claim-and-custody" if review["structure_valid"] else "repair-workpaper"
        capability = "human reviewer"
    elif kind == "detection":
        action = "retest-detection-chain" if review["disposition"].startswith("reported-effective") else "resolve-detection-gaps"
        capability = "authorized telemetry and detection validation"
    else:
        action = "authenticate-agent-attempt"
        capability = "operator-side attempt trace verifier"
    return {"action": action, "finding": {"check_id": finding["check_id"],
            "record_locator": finding["record_locator"]}, "suggested_capability": capability,
            "status": "pending human authorization and validation", "source": kind}


def correlate(findings: list[dict], targets: list[dict], packet: dict | None) -> dict:
    """Augment target decisions without modifying pack findings or risk scores."""
    if packet is None:
        return {"supplemental_reviews": 0, "triage_available": False,
                "triage_source_ref": triage_source_ref(findings)}
    _shape(packet, {"schema", "items"}, {"triage"})
    if packet["schema"] != "specaudit.operator-evidence.v1" or not isinstance(packet["items"], list) or len(packet["items"]) > 64:
        raise ValueError("operator evidence schema or item bound invalid")
    indexed = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("pack finding must be an object")
        key = finding_id(finding)
        if key in indexed:
            raise ValueError("ambiguous duplicate pack finding identity")
        indexed[key] = finding
    by_id = {t["target_id"]: t for t in targets}
    by_finding = {ref: target for target in targets for ref in target["finding_ids"]}
    seen = set()
    for item in packet["items"]:
        _shape(item, {"finding", "kind", "input"})
        ref = _shape(item["finding"], {"check_id", "record_locator"})
        key = finding_id(ref)
        if key not in indexed or (key, item["kind"]) in seen:
            raise ValueError("orphan, ambiguous, or repeated supplemental finding binding")
        seen.add((key, item["kind"]))
        target = by_finding.get(key)
        if target is None:
            raise ValueError("no target for supplemental finding binding")
        kind, data = item["kind"], item["input"]
        if kind == "graph":
            review = _graph(data, indexed[key])
        elif kind == "k8s":
            review = _k8s(data, indexed[key])
        elif kind == "workpaper":
            review = _workpaper(data, indexed[key])
        elif kind == "detection":
            techniques = {step["technique"] for step in target["attack_chain"]}
            review = _detection(data, indexed[key], techniques)
        elif kind == "agent":
            review = _agent(data, indexed[key])
        else:
            raise ValueError("unrecognized operator evidence kind")
        target["operational_reviews"].setdefault(kind, []).append({"finding_id": key, "review": review})
        target["threat_model"]["validation_status"] = "supplemental evidence requires human validation"
        target["next_validation"].extend(review["next_validation"])
        target["validation_tasks"].append(_task(kind, review, indexed[key]))
    if "triage" in packet:
        from extension.triage.siftrank import CaptureBinding, import_capture

        triage = _shape(packet["triage"], {"candidates_json", "ranking_json", "binding"})
        raw_input = _raw(triage["candidates_json"], 256_000, "triage candidates")
        raw_rank = _raw(triage["ranking_json"], 1_000_000, "triage ranking")
        binding = CaptureBinding(**triage["binding"])
        ranked = import_capture(raw_input, raw_rank, binding)
        ids = [entry["id"] for entry in ranked["review_order"]]
        if set(ids) != set(by_id):
            raise ValueError("triage ranking must cover every pack target exactly")
        candidates = json.loads(raw_input)
        if any(candidate.get("source") != triage_source_ref(findings) for candidate in candidates):
            raise ValueError("triage candidates must bind the current complete pack findings digest")
        for entry in ranked["review_order"]:
            target = by_id[entry["id"]]
            target["review_order"] = entry["rank"]
            target["next_validation"].append("review captured triage order; retain all lower-ranked targets")
    return {"supplemental_reviews": len(seen), "triage_available": "triage" in packet,
            "triage_source_ref": triage_source_ref(findings),
            "source_class": "caller-supplied-captures", "finding_binding": "exact check_id and record_locator"}
