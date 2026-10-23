# Lab Contract 01 — Solidity review rehearsal

## Scenario

You are rehearsing a **manual Solidity security review**: a synthetic
treasury/payout contract (`planted/Treasury.sol`) ships with one planted
access-control defect, and your grade is the finding set you can defend from
the source alone. This is a planted-code challenge graded against the
expected findings — a repository-based self-study exercise like
`lab-code-01-semgrep-review`, with the expected contract public in this
checkout. Follow `METHODOLOGY.md` for the review workflow.

## What you need

This checkout and Python 3.11+ (for the `score` grader). The property
witness in `test/` additionally needs a local Foundry toolchain
(`forge` with Solc 0.8.28); the source-based grade never requires one.

## Objectives

1. **Review the shipped contract.**
   Read `planted/Treasury.sol` and work the `METHODOLOGY.md` workflow:
   frame the invariant and roles, keep a coverage ledger, record
   candidates with source traces, verify independently, and keep
   rejected near misses out of the submission.

2. **Optionally reproduce the property witness.**
   With a local toolchain:
   `cd challenges/lab-contract-01-solidity-review && forge build && forge test`
   The recorded instructor run ships in `artifacts/property-witness.md`.

3. **Ship the found-findings document.**
   One row — the confirmed finding — with `finding_key`, `control`,
   `severity`, a `rationale` in your own words, and a `traces_to` that
   names the shipped file and the exact constructs. Track:
   `lab-contract-01-solidity-review`.

4. **Grade.**
   ```sh
   python -m score --grade found-findings.json --expected challenges/lab-contract-01-solidity-review/artifacts/expected-findings.json
   ```

## Notes

- The CTF never runs Cloudflare/Pashov skills automatically: the pinned
  references in `METHODOLOGY.md` are methodology-only, describing a
  workflow you perform (with or without an assistant); nothing installs
  or invokes them, and their output is never a CTF arm or verdict.
- A fuzz/property failure alone is not proof of impact. A failing
  property is evidence to be interpreted; the instructor contract
  (`artifacts/expected-findings.json`, explained in
  `instructor/EXPLANATION.md`) owns the ground truth, and only the
  `score` grader decides the grade.
- No RPC, no chain, no deployment: the contract is never deployed, and
  no real funds, tokens, or accounts exist anywhere in this challenge.
  All addresses and amounts are synthetic.
- The catalog id `foundry` is an agentic-security evaluation
  specification and is unrelated to the Foundry/Solc toolchain this
  challenge pins.
- `exercise_operator prepare` does not serve this lane: it supports
  fixture-backed packets and refuses planted-code ones, so this
  challenge is graded from the checkout via standalone `score`/`exercise`
  with no protected packet delivery or ground-truth secrecy.
