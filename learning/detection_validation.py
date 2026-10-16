"""Offline, synthetic technique-to-detection evidence chain.

This is an instructional worksheet, not a telemetry collector or a trusted
observation. It never contacts a target or executes an emulation technique.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from importlib import resources
from pathlib import Path

STAGES = ("rule_exists", "events_collected", "rule_fired", "analyst_acted", "outcome_retested")
STATES = {"met", "not_met", "unknown", "blocked"}
SOURCE_SHA256 = "704f253c5754d84c4dd19831c3369e9800165239276a3cb7c23b315d7fe47219"
KEY_SCHEMA = "specaudit.detect-key.v1"
KEY_CANARY = "INSTRUCTOR-CANARY-DETECT-01-EXPECTED"
RETEST_RESULTS = frozenset({"effective", "ineffective", "unknown"})


class PacketError(ValueError):
    pass


def _fields(item: object, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(item, dict) or not required <= item.keys() or item.keys() - required - optional:
        raise PacketError(f"expected fields {sorted(required)}; allowed optional {sorted(optional)}")
    return item


def _string(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise PacketError("expected a nonempty bounded string")
    return value


def _records(value: object, required: set[str]) -> list[dict]:
    if not isinstance(value, list) or len(value) > 100:
        raise PacketError("records must be a bounded list")
    out = [_fields(v, required) for v in value]
    for row in out:
        for field in required:
            _string(row[field])
    ids = [v["id"] for v in out]
    if len(set(ids)) != len(ids):
        raise PacketError("duplicate record id")
    return out


def _source_check(mapping: dict) -> None:
    _fields(mapping, {"technique_id", "source_path", "source_sha256"})
    if mapping != {"technique_id": "T1078", "source_path": "extension/arms/attackstix/data/demo-enterprise-sample.json", "source_sha256": SOURCE_SHA256}:
        raise PacketError("unrecognized or unpinned technique mapping")
    raw = resources.files("extension.arms.attackstix").joinpath("data/demo-enterprise-sample.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise PacketError("technique source changed")
    objects = json.loads(raw)["objects"]
    if not any(any(ref.get("external_id") == "T1078" and ref.get("source_name") == "mitre-attack"
                   for ref in obj.get("external_references", [])) for obj in objects):
        raise PacketError("technique absent from pinned source")


def evaluate(packet: object) -> dict:
    """Validate closed synthetic evidence and derive five separate stage verdicts."""
    p = _fields(packet, {"schema", "case_id", "technique", "prerequisite", "rule", "events", "alerts", "actions", "retests"})
    if p["schema"] != "synthetic-detection-chain/v1":
        raise PacketError("unsupported packet schema")
    _string(p["case_id"])
    _source_check(p["technique"])
    prerequisite = _fields(p["prerequisite"], {"datasource", "collection", "attempt"})
    if prerequisite["datasource"] != "identity-audit" or prerequisite["collection"] not in {"on", "off", "unknown"} or prerequisite["attempt"] not in {"allowed", "blocked", "unknown"}:
        raise PacketError("invalid prerequisite")
    rule = _fields(p["rule"], {"id", "deployed", "event_kind", "outcome"})
    if rule["id"] != "rule-privileged-session" or type(rule["deployed"]) is not bool or rule["event_kind"] != "privileged-session" or rule["outcome"] != "allowed":
        raise PacketError("invalid rule")
    events = _records(p["events"], {"id", "datasource", "kind", "outcome", "subject"})
    alerts = _records(p["alerts"], {"id", "rule_id", "event_id"})
    actions = _records(p["actions"], {"id", "alert_id", "decision"})
    retests = _records(p["retests"], {"id", "action_id", "result"})
    if any(e["outcome"] not in {"allowed", "blocked"} for e in events) or any(a["decision"] not in {"triaged", "dismissed"} for a in actions) or any(r["result"] not in {"effective", "ineffective"} for r in retests):
        raise PacketError("invalid record value")
    event_ids = {e["id"] for e in events}
    alert_ids = {a["id"] for a in alerts}
    action_ids = {a["id"] for a in actions}
    if any(a["event_id"] not in event_ids for a in alerts) or any(a["alert_id"] not in alert_ids for a in actions) or any(r["action_id"] not in action_ids for r in retests):
        raise PacketError("dangling evidence reference")

    verdict = {stage: {"state": "unknown", "evidence": []} for stage in STAGES}
    retest_result = "unknown"
    verdict["rule_exists"] = {"state": "met" if rule["deployed"] else "not_met", "evidence": [rule["id"]]}
    if prerequisite["collection"] == "off":
        verdict["events_collected"] = {"state": "not_met", "evidence": []}
    elif prerequisite["collection"] == "on":
        relevant = [e for e in events if e["datasource"] == prerequisite["datasource"] and e["kind"] == rule["event_kind"]]
        verdict["events_collected"] = {"state": "met" if relevant else "not_met", "evidence": [e["id"] for e in relevant]}
    else:
        relevant = []
    if prerequisite["attempt"] == "blocked":
        # A prevented technique is a useful control observation, not a detection pass.
        verdict["rule_fired"]["state"] = "blocked"
    elif prerequisite["attempt"] == "allowed" and verdict["events_collected"]["state"] == "met" and rule["deployed"]:
        matched = {e["id"] for e in relevant if e["outcome"] == rule["outcome"]}
        fired = [a for a in alerts if a["rule_id"] == rule["id"] and a["event_id"] in matched]
        verdict["rule_fired"] = {"state": "met" if fired else "not_met", "evidence": [a["id"] for a in fired]}
        if fired:
            triaged = [a for a in actions if a["alert_id"] in {f["id"] for f in fired} and a["decision"] == "triaged"]
            verdict["analyst_acted"] = {"state": "met" if triaged else "not_met", "evidence": [a["id"] for a in triaged]}
            if triaged:
                checked = [r for r in retests if r["action_id"] in {a["id"] for a in triaged}]
                verdict["outcome_retested"] = {"state": "met" if checked else "not_met", "evidence": [r["id"] for r in checked]}
                if checked:
                    retest_result = "effective" if all(r["result"] == "effective" for r in checked) else "ineffective"
    return {"schema": "synthetic-detection-verdict/v1", "case_id": p["case_id"], "stages": verdict, "retest_result": retest_result}


def evaluate_operational(packet: object) -> dict:
    """Review a target-bound captured chain with the five-stage logic.

    Unlike the fixed teaching packet, this accepts the caller's own rule and
    event identities. It establishes internal linkage only; event provenance,
    rule deployment and effectiveness still need independent validation.
    """
    p = _fields(packet, {"schema", "target", "technique_id", "prerequisite", "rule",
                         "events", "alerts", "actions", "retests"})
    if p["schema"] != "specaudit.operational-detection.v1":
        raise PacketError("unsupported operational detection schema")
    _string(p["target"])
    _string(p["technique_id"])
    pre = _fields(p["prerequisite"], {"datasource", "collection", "attempt"})
    _string(pre["datasource"])
    if pre["collection"] not in {"on", "off", "unknown"} or pre["attempt"] not in {"allowed", "blocked", "unknown"}:
        raise PacketError("invalid operational prerequisite")
    rule = _fields(p["rule"], {"id", "deployed", "event_kind", "outcome"})
    _string(rule["id"])
    _string(rule["event_kind"])
    if type(rule["deployed"]) is not bool or rule["outcome"] not in {"allowed", "blocked"}:
        raise PacketError("invalid operational rule")
    events = _records(p["events"], {"id", "datasource", "kind", "outcome", "subject"})
    alerts = _records(p["alerts"], {"id", "rule_id", "event_id"})
    actions = _records(p["actions"], {"id", "alert_id", "decision"})
    retests = _records(p["retests"], {"id", "action_id", "result"})
    if any(e["subject"] != p["target"] or e["outcome"] not in {"allowed", "blocked"} for e in events):
        raise PacketError("event subject differs from target or has invalid outcome")
    if pre["attempt"] != "unknown" and any(e["outcome"] != pre["attempt"] for e in events):
        raise PacketError("event outcome contradicts the declared attempt outcome")
    if any(a["decision"] not in {"triaged", "dismissed"} for a in actions) or any(r["result"] not in {"effective", "ineffective"} for r in retests):
        raise PacketError("invalid analyst decision or retest")
    event_ids, alert_ids, action_ids = ({row["id"] for row in rows} for rows in (events, alerts, actions))
    if any(a["event_id"] not in event_ids or a["rule_id"] != rule["id"] for a in alerts) or any(a["alert_id"] not in alert_ids for a in actions) or any(r["action_id"] not in action_ids for r in retests):
        raise PacketError("unbound operational detection record")
    stages = {stage: {"state": "unknown", "evidence": []} for stage in STAGES}
    stages["rule_exists"] = {"state": "met" if rule["deployed"] else "not_met", "evidence": [rule["id"]]}
    relevant = [e for e in events if e["datasource"] == pre["datasource"] and e["kind"] == rule["event_kind"]]
    if pre["collection"] != "unknown":
        stages["events_collected"] = {"state": "met" if relevant and pre["collection"] == "on" else "not_met",
                                      "evidence": [e["id"] for e in relevant] if pre["collection"] == "on" else []}
    retest_result = "unknown"
    if pre["attempt"] == "blocked":
        stages["rule_fired"]["state"] = "blocked"
    elif pre["attempt"] == "allowed" and rule["deployed"] and stages["events_collected"]["state"] == "met":
        matched = {e["id"] for e in relevant if e["outcome"] == rule["outcome"]}
        fired = [a for a in alerts if a["event_id"] in matched]
        stages["rule_fired"] = {"state": "met" if fired else "not_met", "evidence": [a["id"] for a in fired]}
        if fired:
            triaged = [a for a in actions if a["alert_id"] in {f["id"] for f in fired} and a["decision"] == "triaged"]
            stages["analyst_acted"] = {"state": "met" if triaged else "not_met", "evidence": [a["id"] for a in triaged]}
            if triaged:
                checked = [r for r in retests if r["action_id"] in {a["id"] for a in triaged}]
                stages["outcome_retested"] = {"state": "met" if checked else "not_met", "evidence": [r["id"] for r in checked]}
                if checked:
                    retest_result = "effective" if all(r["result"] == "effective" for r in checked) else "ineffective"
    return {"schema": "specaudit.operational-detection-review.v1", "target": p["target"],
            "technique_id": p["technique_id"], "stages": stages, "retest_result": retest_result}


def grade(packet: object, submission: object) -> dict:
    expected = evaluate(packet)
    s = _fields(submission, {"schema", "case_id", "stages", "retest_result"})
    if s["schema"] != "synthetic-detection-submission/v1" or s["case_id"] != expected["case_id"]:
        raise PacketError("submission schema or case mismatch")
    if not isinstance(s["stages"], dict) or set(s["stages"]) != set(STAGES) or any(v not in STATES for v in s["stages"].values()):
        raise PacketError("submission must name exactly five valid states")
    if s["retest_result"] not in {"effective", "ineffective", "unknown"}:
        raise PacketError("invalid retest result")
    differences = {stage: {"submitted": s["stages"][stage], "expected": expected["stages"][stage]["state"]}
                   for stage in STAGES if s["stages"][stage] != expected["stages"][stage]["state"]}
    if s["retest_result"] != expected["retest_result"]:
        differences["retest_result"] = {"submitted": s["retest_result"], "expected": expected["retest_result"]}
    return {"case_id": expected["case_id"], "pass": not differences, "differences": differences}


def load_expected_key(key: object) -> dict:
    """Validate the closed instructor expected-outcome key; return its cases.

    Refuses (fail closed): any shape deviation including extra or missing
    fields at every level, a missing or wrong canary, a stage state outside
    the vocabulary, and an unknown retest result. The transparent self-study
    flow never calls this; only the instructor-controlled assessment path
    consumes the key.
    """
    k = _fields(key, {"schema", "canary", "cases"})
    if k["schema"] != KEY_SCHEMA:
        raise PacketError("unsupported assessment key schema")
    if k["canary"] != KEY_CANARY:
        raise PacketError("assessment key canary missing or wrong")
    cases = k["cases"]
    if not isinstance(cases, dict) or not cases or len(cases) > 100 \
            or any(not isinstance(case_id, str) or not case_id for case_id in cases):
        raise PacketError("assessment key cases must be a nonempty bounded mapping")
    expected = {}
    for case_id, row in cases.items():
        r = _fields(row, {"stages", "retest_result"})
        if not isinstance(r["stages"], dict) or set(r["stages"]) != set(STAGES) \
                or any(v not in STATES for v in r["stages"].values()):
            raise PacketError("assessment key must name exactly five valid states per case")
        if r["retest_result"] not in RETEST_RESULTS:
            raise PacketError("invalid assessment key retest result")
        expected[case_id] = {"stages": dict(r["stages"]), "retest_result": r["retest_result"]}
    return expected


def _assessment_submission(document: object) -> tuple[str, dict, str]:
    s = _fields(document, {"schema", "case_id", "stages", "retest_result"})
    if s["schema"] != "synthetic-detection-submission/v1":
        raise PacketError("assessment submission schema mismatch")
    _string(s["case_id"])
    if not isinstance(s["stages"], dict) or set(s["stages"]) != set(STAGES) \
            or any(v not in STATES for v in s["stages"].values()):
        raise PacketError("assessment submission must name exactly five valid states")
    if s["retest_result"] not in RETEST_RESULTS:
        raise PacketError("invalid assessment submission retest result")
    return s["case_id"], s["stages"], s["retest_result"]


def grade_assessment(learner_assessments: object, key_document: object,
                     case_ids: object) -> dict:
    """Grade learner stage assessments against the instructor key only.

    Pure and instructor-controlled: no packet is read, no verdict is derived,
    and the transparent self-study flow is untouched. Refuses key shape or
    canary violations, requested cases absent from the key, learner documents
    for cases outside the requested set, missing or duplicate learner
    documents, and any malformed submission.
    """
    expected = load_expected_key(key_document)
    if not isinstance(case_ids, (list, tuple)) or not case_ids or len(case_ids) > 100 \
            or any(not isinstance(case_id, str) or not case_id for case_id in case_ids) \
            or len(set(case_ids)) != len(case_ids):
        raise PacketError("case_ids must be a nonempty bounded list of unique strings")
    if any(case_id not in expected for case_id in case_ids):
        raise PacketError("requested case is not bound by this assessment key")
    requested = set(case_ids)
    if not isinstance(learner_assessments, list) or len(learner_assessments) > 100:
        raise PacketError("learner assessments must be a bounded list")
    submitted: dict[str, tuple[dict, str]] = {}
    for document in learner_assessments:
        case_id, stages, retest_result = _assessment_submission(document)
        if case_id not in requested:
            raise PacketError("assessment document is not bound to a requested case")
        if case_id in submitted:
            raise PacketError("duplicate assessment document for a case")
        submitted[case_id] = (stages, retest_result)
    missing = [case_id for case_id in case_ids if case_id not in submitted]
    if missing:
        raise PacketError(f"missing assessment document for requested cases: {sorted(missing)}")
    results = []
    for case_id in case_ids:
        stages, retest_result = submitted[case_id]
        key_row = expected[case_id]
        differences = {stage: {"submitted": stages[stage], "expected": key_row["stages"][stage]}
                       for stage in STAGES if stages[stage] != key_row["stages"][stage]}
        if retest_result != key_row["retest_result"]:
            differences["retest_result"] = {"submitted": retest_result,
                                            "expected": key_row["retest_result"]}
        results.append({"case_id": case_id, "pass": not differences, "differences": differences})
    return {"schema": "specaudit.detect-assessment-grade.v1",
            "cases": results, "passed": all(row["pass"] for row in results)}


CASES = ("positive", "missing-telemetry", "benign-near-miss", "blocked", "alert-untriaged", "retest-failed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("packet", nargs="?", type=Path)
    source.add_argument("--case", choices=CASES)
    parser.add_argument("--submission", type=Path, help="grade a five-stage learner submission")
    parser.add_argument("--assessment-key", type=Path,
                        help="operator-held instructor key: grade --submission (a JSON list of "
                             "per-case assessment submissions) against the key, not the worksheet")
    args = parser.parse_args(argv)
    if args.assessment_key is None and args.packet is None and args.case is None:
        parser.error("one of the arguments packet --case --assessment-key is required")
    if args.assessment_key is not None and args.packet is not None:
        parser.error("--assessment-key grades against the instructor key; pass --case or "
                     "nothing, not a packet path")
    try:
        if args.assessment_key is not None:
            if args.submission is None:
                parser.error("--assessment-key requires --submission")
            key_document = json.loads(args.assessment_key.read_text(encoding="utf-8"))
            assessments = json.loads(args.submission.read_text(encoding="utf-8"))
            case_ids: list[str] = []
            for document in assessments:
                case_id = _assessment_submission(document)[0]
                if case_id not in case_ids:
                    case_ids.append(case_id)
            result = grade_assessment(assessments, key_document, case_ids)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["passed"] else 1
        raw = (resources.files("learning").joinpath(f"data/detection/{args.case}.json").read_text(encoding="utf-8")
               if args.case else args.packet.read_text(encoding="utf-8"))
        packet = json.loads(raw)
        result = grade(packet, json.loads(args.submission.read_text(encoding="utf-8"))) if args.submission else evaluate(packet)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not args.submission or result["pass"] else 1
    except (PacketError, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"error": str(exc), "status": "invalid"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
