# Telecom AWS 05 — logging and detection-gap rehearsal

Fifth challenge in the rehearsal lane: the **logging/monitoring
track**. The planted gaps are a disabled management trail
(`extension/range/tf_cloudtrail_disabled/`) and an audit-artifact
bucket without server access logging
(`extension/range/tf_s3_no_access_logging/`). Detection gaps are
findings in their own right: an auditor who only reports exposures
misses the reason an exposure would go unnoticed.

Everything is **synthetic**: no live accounts, no log ingestion, fixed
seed.

## Objectives

1. **Reason about what goes unrecorded.**
   Read both fixtures. For the disabled trail: which control-plane
   actions would leave no durable record while it is off? For the
   bucket: which audit question becomes unanswerable without server
   access logs? Write `detection-notes.md`.

2. **Ship the finding set.**
   Produce `my-findings.json` against
   `artifacts/expected-findings.json`. Severity is calibration: the
   trail is the broader gap (all management events), the bucket gap is
   narrower (one storage surface) — the grader surfaces disagreements
   as flags for you to defend.

3. **Grade yourself.**
   ```
   python -m score --grade my-findings.json --expected artifacts/expected-findings.json
   ```

## Out of scope (by design)

No live logging changes, no credential use, no speculation beyond the
fixtures' bytes.
