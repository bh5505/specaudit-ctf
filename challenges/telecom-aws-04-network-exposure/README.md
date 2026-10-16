# Telecom AWS 04 — network exposure and the near-miss discipline

Fourth challenge in the rehearsal lane: the **network reachability
track**, with a trap. The fixtures are
`extension/range/tf_sg_open_ingress/` (world-open ingress on an
administrative port and a database port) and
`extension/range/tf_s3_policy_blocked_trap/` — a bucket whose policy
*would* grant anonymous reads but whose Block Public Access settings
neutralize the grant. The trap teaches the near-miss discipline: a
policy that looks public is not a live exposure when the block is on,
and an auditor who reports it as one has misread the control stack.

Everything is **synthetic**: no live accounts, no packets, fixed seed.

## Objectives

1. **Separate live exposure from neutralized misconfiguration.**
   Read both fixtures' `main.tf`. For the security groups: why is
   world-open ingress on port 22 a different severity than on 3306?
   For the trap bucket: what exactly neutralizes the anonymous grant
   (name the control and its effect), and what single change to the
   bucket policy would flip the verdict even with the block on? Write
   `reachability-notes.md`.

2. **Ship the finding set — including the contained one.**
   Produce `my-findings.json` against
   `artifacts/expected-findings.json`. The contract expects the trap
   reported at its honest severity: a contained misconfiguration, not
   a public exposure. Reporting it as public exposure is an extra with
   the wrong story; omitting it entirely is a miss.

3. **Grade yourself.**
   ```
   python -m score --grade my-findings.json --expected artifacts/expected-findings.json
   ```
   Exact coverage or nothing: misses, extras, and evidence-less rows
   all fail. Severity flags are surfaced for you to defend in
   `severity-notes.md`.

## Out of scope (by design)

No live probing, no credential use, no speculation beyond the
fixtures' bytes.
