# Telecom AWS 01 — reachability rehearsal

This challenge uses a local synthetic Terraform fixture. No live AWS account or credential is needed. Inspect the planted bucket configuration, run the range, and report the three findings in the expected-findings contract.

## Exercise

1. From the repository root, run `python -m extension list` and `python -m extension describe agent-wiz`. The catalog says which entries are invocable arms and which are descriptive. Try `python -m extension invoke agent-wiz list_tools` and record the direct `ok`, `output`, and `error` fields. A missing external binary is an availability result, not a grade for this challenge.
2. Run `python -m extension.range --arm-ids "" --out range-result.json`. The empty arm list runs the packaged lifecycle alone, so optional tools on this host do not change the fixture result. Find the `tf_s3_public_access` row and its exposure, path, and impact. Re-run with the same seed to compare the result, then use `--seed 456` to see which values depend on the seed.
3. Read `extension/range/tf_s3_public_access/input/main.tf`. Identify the bucket's `public-read` ACL, the missing public-access-block resource, and the missing server-side encryption configuration. Write `my-findings.json` with one finding per planted issue. For each finding include a `finding_key`, `control`, `severity`, a short `rationale`, and `traces_to` identifying the HCL setting or absence.
4. Grade the submission from this challenge directory with `python -m score --grade my-findings.json --expected artifacts/expected-findings.json`. Fix misses and extra findings, then explain what the range actually showed. The grade compares the submission with the planted contract; it does not represent a live AWS assessment.

An agent with this repository's stdio MCP server attached can use `list`, `describe`, and `run_range` for the same exercise. The [walkthrough](solution/walkthrough.md) explains the planted findings after the attempt.
