# Lab Detect 01 — technique-to-detection validation

**Status:** design-ready offline teaching slice; not a promoted or concealed-key assessment. **Version:** 1.0. **Domains:** T04, CYB-06, DATA-02. **Audience:** learners who have completed `telecom-aws-05` and the ATT&CK mapping rehearsal; intermediate detection analysts. No live Caldera operation, AD account, SIEM, credential or network is involved.

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

Valid stage states are `met`, `not_met`, `unknown`, and `blocked`; `retest_result` is `effective`, `ineffective`, or `unknown`. The example demonstrates the schema for the positive packet; for the other cases, work from the evidence, not this example. The grader exits 0 on exact agreement, 1 on a mismatch (with differences in JSON), and 2 on invalid input. The inspector prints its own derived verdict, so this is a transparent self-study worksheet rather than a protected exam. Do not expose this checkout to a learner and claim the key is inaccessible.

## Packet contract and interpretation

The six frozen cases are `positive`, `missing-telemetry`, `benign-near-miss`, `blocked`, `alert-untriaged`, and `retest-failed`. Each packet declares collection and attempted-action prerequisites, a deployed rule definition, and separately linked event, alert, analyst action and retest records. Identifiers link stages; a text claim about a rule firing never creates an alert. A blocked action demonstrates prevention, not detection success. A missing datasource leaves downstream stages `unknown`, not passing. An ineffective retest still establishes that a retest happened, with `retest_result: ineffective` called out separately. An alert without analyst triage does not establish response. A benign maintenance event is not a match to the allowed privileged-session selector.

Only the checked local STIX bundle bytes establish the technique label. This mapping does not prove that the synthetic identity event represents actual adversary behavior. Packet records are declarations, not independently trusted captured telemetry. The evaluator validates schema, source hash, duplicate IDs and references; it cannot establish real event authenticity, clock order, deployment, completeness, custody, analyst intent, remediation, or control effectiveness. The `positive` result means only that the five synthetic records are present and linked. A real assessment would require independent custody, deployment and end-to-end observation in an authorized environment.

The packet files live in `learning/data/detection/`. No external dataset, source rule, or copied campaign artifact is bundled. The source mapping is pinned to `extension/arms/attackstix/data/demo-enterprise-sample.json` at SHA-256 `704f253c5754d84c4dd19831c3369e9800165239276a3cb7c23b315d7fe47219`; a changed source fails closed. Revisit mapping, datasource schema and rubric when the bundle or program criteria change.

## Instructor and operator notes

**Environment:** E1 offline synthetic. Permit local read of the six JSON packets and local Python processing only. No identities, privilege, target contact, egress, paid service or mutation are needed. An operator must enforce denied egress and restricted filesystem independently if used as a formal exercise; the Python module is not that boundary. Stop on unexpected external access or evidence alteration. Reset by restoring clean checkout bytes; retain submitted JSON only under the exercise's evidence-retention policy.

The human workpaper asks for the five state claims, their linked record IDs, the missing prerequisite in each nonpositive packet, a near-miss explanation, and the difference between retest occurrence and outcome. Review unsupported inference as a failure even if stage labels match. Hints: first ask for prerequisite and selector fields, then for ID links; no points are assigned by this worksheet. The machine result is stage agreement only and cannot replace an instructor's evidence/custody judgment. Formal promotion still needs named instructional, technical and safety reviewers, protected grading material outside learner reach, calibration, operator go/no-go and independent reset evidence under `challenges/README.md`.
