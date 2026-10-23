# Lab Contract 01 — review methodology and participant artifact map

This challenge grades a review of the shipped Solidity contract, not a tool
run. The workflow below is adapted, in original wording, from two pinned
methodology references. The CTF never installs or executes them, and the
`pashov-*` catalog rows here are `methodology-only` (describable, never
invocable). Note that the unrelated catalog id `foundry` names an
agentic-security evaluation specification, not the Solidity toolchain some of
these references build on.

Pinned references (both MIT):

- [pashov/skills @ eacfc09](https://github.com/pashov/skills/tree/eacfc09b365d2697b83355909d0300607e596ffc)
  — `x-ray/` (pre-audit architecture and invariant framing),
  `solidity-auditor/` (parallel review passes producing source-anchored
  candidates), `fizz/` (Echidna/Medusa property-suite drafting).
- [cloudflare/security-audit-skill @ c1c8a8c](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8)
  — coverage-ledger hunting, structured findings, and independent record
  verification.

## Workflow

1. **Frame the target.** From the shipped source alone, write down the
   assets, actors/roles, entry points, trust boundaries, and the invariant
   the contract is supposed to enforce (for a treasury contract: only the
   administrator may change the payout destination).
2. **Hunt with a coverage ledger.** Keep a plain list (JSON or text) with one
   row per entry point and state variable, marking each looked/not-yet and
   what you concluded. Coverage is your own bookkeeping; it proves nothing by
   itself.
3. **Record a candidate with a source trace.** Each suspected issue gets a
   note naming the exact file and construct. A candidate is unverified.
4. **Build a local property witness.** Express the invariant as a check: with
   a local Solidity toolchain, an Echidna/Medusa-style property that a
   non-admin call cannot change the treasury; without one, a careful manual
   argument written out step by step. Record the commands and tool versions
   you used, or state plainly that no fuzzer ran. The source-based grade
   never requires a fuzzer.
5. **Verify independently.** Re-derive each candidate from the source alone —
   ideally by a different person, at minimum by a fresh pass that starts from
   the code rather than from your note — and assign a verdict.
6. **Submit.** Copy only findings that completed step 5 into
   `found-findings.json` and grade it:

   ```sh
   python -m score --grade found-findings.json --expected challenges/lab-contract-01-solidity-review/artifacts/expected-findings.json
   ```

## Mapping working artifacts to grader fields

The grader (`score/grading.py`) reads five string fields per finding:
`finding_key`, `control`, `severity`, `rationale`, `traces_to`. A hit counts
only with non-empty `traces_to`, `control`, and `rationale`.

| Working artifact (reference) | Feeds |
|---|---|
| Invariant/architecture/entry-point notes (`x-ray` style) | `control`: the intended control the shipped code should enforce; the map used to name `traces_to` precisely |
| Coverage ledger (`cloudflare` style) | No grader field. It supports your confidence that `traces_to` names the right construct, but is never submitted |
| Audit candidate with source trace (`solidity-auditor` style) | The draft of `finding_key`, `traces_to`, `control`, `rationale` — only after verification |
| Property witness (`fizz` style: `PROPERTIES.md`, a failing-then-fixed property) | Evidence inside `rationale`; a witness is never a substitute for the owned trace fields |
| `findings.json` verdict (`cloudflare` style) | The gate that decides whether a candidate may be submitted at all (states below) |

## Finding states

Every suspected issue is in exactly one of four states:

- **candidate** — noted during hunting, not yet verified;
- **rejected** — the independent pass disproved it (stay out of the
  submission; keep it in your working notes);
- **needs-validation** — plausible but not proven (do not submit);
- **confirmed** — an independent re-derivation from the source reproduced it.

Only a **confirmed** finding with owned evidence (non-empty `traces_to`,
`control`, `rationale`) belongs in the found-findings submission. A
candidate-shaped row or a rejected near miss in the submission is a miss, an
extra, or an invalid row — each of which fails the grade.

## Example source trace

For a shipped treasury contract whose `setTreasury(address)` setter lacks the
intended administrator check, a confirmed finding's trace names the file and
the construct:

```json
{
  "finding_key": "treasury-setter-unauthorized",
  "control": "access control: only the administrator may change the payout destination",
  "severity": "high",
  "rationale": "Any caller can redirect the payout destination, so funds leave to an attacker-chosen address; a nearby owner-guarded setter shows the check was intended here too.",
  "traces_to": "challenges/lab-contract-01-solidity-review/<shipped contract file>, setTreasury(address) setter without an administrator check"
}
```

(The challenge ships the actual contract file, key, and expected contract;
`traces_to` must name the shipped file and function, as above.)

## A generated report is supporting evidence only

Any report produced by an assistant, agent, or script — including one styled
after the references above — is supporting evidence for you, the reviewer.
The grader reads only your submission's owned fields. A generated report can
never by itself pass the grader: with missing or empty `traces_to`,
`control`, or `rationale`, the row is invalid no matter what the report
claims, and the grader does not accept report files as input at all.

## Manual walkthrough (plain text editor; no agent vendor required)

1. Open the shipped contract in any text editor and write `invariants.md`
   (assets, roles, entry points, the treasury invariant).
2. Write `coverage-ledger.json` by hand: one line per entry point, with
   `looked` and `verdict` fields.
3. Write one candidate note per suspected issue with its source trace.
4. Write the property as a short test if you have a local toolchain, or as an
   explicit step-by-step argument if you do not; record what you ran.
5. Hand the candidate notes to a peer for re-derivation, or set them aside
   and re-derive each from the source alone; mark the verdict.
6. Build `found-findings.json` from the confirmed rows only, using the
   example shape above and the `score` command from step 6 of the workflow.
