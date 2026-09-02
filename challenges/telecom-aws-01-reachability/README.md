# Telecom AWS 01 — reachability rehearsal

## Scenario

You are the lead auditor preparing for a telecom-sector AWS posture audit
next quarter. Before that engagement you will rehearse the **AWS
reachability lane** end to end against this repository's synthetic
surface: survey the capability catalog, read a capability manifest,
invoke the one maintained capability, run the synthetic range, and
produce machine-readable deliverables that a real audit cycle would hand
to its workbench.

Everything in this challenge is **synthetic**. There are no live AWS
accounts, no network probes, no real credentials. The range runs with a
fixed seed, so its output is deterministic, and every finding you ship
must trace to a planted violation in the fixtures — the correspondence
contract in `challenges/README.md`.

## Objectives

Work through the objectives in order. Each ends in a concrete artifact.

1. **Survey the catalog honestly.**
   Run `python -m extension list`. Count the rows by `kind` and `tier`,
   and answer: how many rows are *curated arms* (executable today when
   their binary is present) versus methodology-only survey rows? Which
   single arm is `tier: maintained`, and why do the others not claim
   that? Write your answer as `catalog-summary.json` mapping each tier
   to the count of rows carrying it.

2. **Read the capability manifest before dispatch.**
   Run `python -m extension describe agent-wiz`. From that row, state
   which action is the maintained capability, what its side effects and
   safety class are, and what "read tier" means for a rehearsal. Then
   run `python -m extension invoke agent-wiz list_tools {}` and capture
   the `specaudit.ctf.execution-result.v1` envelope. Record in
   `manifest-vs-result.md`: which manifest claims the result actually
   exercised, and which (e.g. budget, cleanup) you can verify only from
   the envelope.

3. **Run the synthetic reachability range.**
   Run `python -m extension.range`. The range evaluates the synthetic
   Terraform fixtures (`extension/range/tf_s3_public_access/`) and
   invokes the curated arms it can. From the envelope, produce
   `range-report.md` answering:
   - What is the overall `status`, and which limitations explain it on
     your host (optional arms not installed is the expected cause —
     that is the honest-degradation contract working, not a failure to
     hide)?
   - In the `coverage` buckets (`complete` / `failed` / `skipped` /
     `unsupported` / `attempted` / `required`), why is `complete` empty
     on a host with no optional tools installed? What would change if
     one curated arm's binary were present?
   - The range-report artifact carries a digest. Re-run with the same
     seed and confirm the digest is byte-stable; re-run with
     `--seed 456` and confirm it changes.

4. **Read the planted exposure like an auditor.**
   Open `extension/range/tf_s3_public_access/input/main.tf`. Identify
   the planted public-exposure violations: the `acl = "public-read"`
   setting on the bucket, the absence of an
   `aws_s3_bucket_public_access_block` resource that would override
   any ACL, and the absence of server-side encryption configuration.
   Produce `findings.json`: one entry per planted violation, each with
   `finding_key`, a one-sentence exposure statement, and the exact HCL
   lines (or absence) it traces to.

5. **Produce the deliverable set.**
   From the same run, emit:
   - `report.json` — one entry per finding from objective 4, plus the
     run metadata (seed, schema id) bound to the range artifact digest;
   - `report.sarif` — a valid SARIF 2.1.0 skeleton with the same
     findings as `results[].ruleId` / `results[].message`.
   Every finding must map to exactly one planted violation; every
   planted violation must appear at least once.

6. **(Optional, agent-head attachment.)** If you have an agent CLI that
   speaks stdio MCP, start this repository's server
   (`python -m extension.mcp_server`) as its tool server and redo
   objective 1 through the `list` tool. Confirm the MCP `run_range`
   result equals the CLI envelope modulo timestamps — the transport
   parity contract.

## Out of scope (by design)

No live AWS reachability probing, no scanner installation, no attempt to
make `degraded` look like `complete`. The rehearsal value is in the
discipline, not in the synthetic data.
