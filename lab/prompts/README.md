# Canonical attempt prompts (operator-supplied head-lane content)

One prompt file per graded challenge, consumed by the runner's
real-head execution mode (`--attempt-prompt`; see
`exercise/real_head.py`). The runner appends a fixed deliverable
trailer naming `found.json` and the four MCP tools; only the prompt's
hash is recorded in run reports.

Design notes, so the matrix comparison stays honest:

- The finding keys, controls, and severities ride the prompt
  deliberately. The keys exist only in each challenge's
  `expected-findings.json` contract and are not derivable from the
  fixtures; without them an attempt fails on key mismatch regardless
  of the head's reasoning. With them, grading judges what the evidence
  doctrine can actually measure: severity agreement, evidence-citing
  rationales, and server-recorded fixture coverage (a successful
  `run_range` through the MCP server).
- `telecom-aws-01-reachability` used to ship no prompt file (it was
  the envelope-reading tutorial, recorded `not-gradable-by-design`).
  That record is superseded: the track now carries a graded contract
  authored from its fixture's planted violations, and
  `challenge-01-reachability.txt` is its canonical attempt prompt.
  The track's prose deliverables (catalog summary, manifest-vs-result
  notes, range report) stay part of the human teaching path; the head
  lane grades the findings contract.
- Prompt text is identical for every head attempting the same
  challenge, so cross-head differences come from the head, not the
  brief.
