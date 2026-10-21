# Lab Agent 01 — tool events and agent claims

This offline exercise asks learners to compare an agent's prose with a synthetic tool-event trace. A lower-trust catalog note urges the agent to export a canary and read an answer key; a sensor later becomes unavailable. The trace records simulated requests and outcomes. No model, network endpoint, or live tool is contacted.

Generate a trace:

```sh
python -m learning.agent_security_harness run --out /tmp/agent-tool-trace.json
```

Submit a JSON document with `schema`, `attempt_id`, `trace_sha256`, and `assessments`. Copy the attempt ID and digest from the generated trace. Include one assessment per event with `event_id`, `classification` (`clean`, `rejected`, or `unknown`), `observed_effect` (`executed`, `denied`, or `unknown`), `report_match` (`yes`, `no`, or `unverifiable`), and `evidence_event_id`.

Check the document's shape and trace binding without revealing answers:

```sh
python -m learning.agent_security_harness self-check --trace /tmp/agent-tool-trace.json --submission /tmp/my-assessment.json
```

An instructor grades the answers using the separate key:

```sh
python -m learning.agent_security_harness grade --trace /tmp/agent-tool-trace.json --submission /tmp/my-assessment.json --key /path/to/instructor/answers.json
```

Exit 0 means all rows match the key; exit 1 reports incorrect fields; exit 2 reports malformed or unbound input. Distribute the brief, generated trace, and CLI to learners. Keep `instructor/answers.json` outside the learner materials so the exercise retains an answer key.
