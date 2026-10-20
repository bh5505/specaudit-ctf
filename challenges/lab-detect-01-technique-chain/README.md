# Lab Detect 01 — technique-to-detection validation

**Status:** design-ready offline teaching slice with an instructor-controlled assessment variant; not a promoted assessment. **Version:** 1.1. **Domains:** T04, CYB-06, DATA-02. **Audience:** learners who have completed `telecom-aws-05` and the ATT&CK mapping rehearsal; intermediate detection analysts. No live Caldera operation, AD account, SIEM, credential or network is involved.

The learning outcome is to distinguish five claims: a rule is deployed, relevant events were collected, a correlated alert fired, an analyst triaged that alert, and the outcome was retested. The mapped hypothesis is ATT&CK **T1078 Valid Accounts**, checked against the existing pinned local demo ATT&CK STIX bundle. The packet and rule are independently authored synthetic teaching data; they are **not** a reproduced rule or telemetry record from Purple-Team-Automation or Ekitji/siem. The candidate repositories inspired the methodological question only; their reported detection outcomes were not replayed here, and their source artifacts have not cleared redistribution review.

Run from the repository root with Python 3.11+:

```sh
python -m learning.detection_validation --case positive
python -m learning.detection_validation --case missing-telemetry
python -m learning.detection_validation --case positive --submission my-answer.json
```

The first two commands print a JSON explanation of each stage. Submit exactly five states in this format:

```json
{"schema":"synthetic-detection-submission/v1","case_id":"positive","stages":{"rule_exists":"met","events_collected":"met","rule_fired":"met","analyst_acted":"met","outcome_retested":"met"},"retest_result":"effective"}
```

Valid stage states are `met`, `not_met`, `unknown`, and `blocked`; `retest_result` is `effective`, `ineffective`, or `unknown`. The example demonstrates the schema for the positive packet; for the other cases, work from the evidence, not this example. The grader exits 0 on exact agreement, 1 on a mismatch (with differences in JSON), and 2 on invalid input. The inspector prints its own derived verdict, so the default flow is a transparent self-study worksheet: every command above behaves exactly as before the assessment variant was added, and it must never be exposed to a learner as a protected exam.

## Instructor-controlled assessment variant

For assessment use, the instructor holds `instructor/expected.json` (schema `specaudit.detect-key.v1`, canary `INSTRUCTOR-CANARY-DETECT-01-EXPECTED`): the exact five stage states and retest result for each of the six cases, checked against the same derivation the worksheet prints. The learner receives instead an `instructor/assessment/<case>.json` packet (`synthetic-detection-assessment/v1`): the case's scenario prose and its complete event, alert, analyst-action and retest records, with the three machine verdict-gate declarations stripped — `rule.deployed`, `prerequisite.collection`, and `prerequisite.attempt`. Those are the fields the worksheet consumes as direct encodings of the `rule_exists`, `events_collected`, and `rule_fired` outcomes; in the packet they exist only as scenario prose. The closed worksheet shape therefore **refuses** the learner packet (extra `scenario` field, missing declarations), so no shipped code path derives the expected verdicts from anything a learner holds, and reconstructing declarations to re-run the worksheet requires exactly the reasoning the assessment grades. Evidence records — including each retest's captured `result` — are kept intact so linkage reasoning and the retest-occurrence-versus-outcome distinction stay assessable.

Learners submit the same five-stage JSON documents as in self-study. The instructor grades them against the key only; no packet is read and no verdict is derived:

```sh
python -m learning.detection_validation --assessment-key instructor/expected.json --submission my-assessments.json
```

`my-assessments.json` is a JSON list of per-case submissions, each with exactly `schema` (`synthetic-detection-submission/v1`), `case_id`, `stages`, and `retest_result`. The command exits 0 when every case matches the key, 1 with per-case `differences` otherwise, and 2 on any invalid input: a key that fails the closed shape or canary check, a requested case the key does not bind, a submission naming a case outside the requested set, a missing or duplicate case document, or a malformed submission. The expected outcomes live only in the instructor-held key; `instructor/` must stay outside the learner context, and both key documents carry canary strings so any accidental export is detectable by byte scan.

## Packet contract and interpretation

The six frozen cases are `positive`, `missing-telemetry`, `benign-near-miss`, `blocked`, `alert-untriaged`, and `retest-failed`. Each packet declares collection and attempted-action prerequisites, a deployed rule definition, and separately linked event, alert, analyst action and retest records. Identifiers link stages; a text claim about a rule firing never creates an alert. A blocked action demonstrates prevention, not detection success. A missing datasource leaves downstream stages `unknown`, not passing. An ineffective retest still establishes that a retest happened, with `retest_result: ineffective` called out separately. An alert without analyst triage does not establish response. A benign maintenance event is not a match to the allowed privileged-session selector.

Only the checked local STIX bundle bytes establish the technique label. This mapping does not prove that the synthetic identity event represents actual adversary behavior. Packet records are declarations, not independently trusted captured telemetry. The evaluator validates schema, source hash, duplicate IDs and references; it cannot establish real event authenticity, clock order, deployment, completeness, custody, analyst intent, remediation, or control effectiveness. The `positive` result means only that the five synthetic records are present and linked. A real assessment would require independent custody, deployment and end-to-end observation in an authorized environment.

The packet files live in `learning/data/detection/`. No external dataset, source rule, or copied campaign artifact is bundled. The source mapping is pinned to `extension/arms/attackstix/data/demo-enterprise-sample.json` at SHA-256 `704f253c5754d84c4dd19831c3369e9800165239276a3cb7c23b315d7fe47219`; a changed source fails closed. Revisit mapping, datasource schema and rubric when the bundle or program criteria change.

## Instructor notes

The human workpaper asks for the five state claims, their linked record IDs, the missing prerequisite in each nonpositive packet, and the difference between retest occurrence and outcome. The machine result checks stage agreement. Review the explanation separately and reset altered local packets from a clean checkout before another attempt.
