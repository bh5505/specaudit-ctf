# Telecom AWS 02 — IAM/S3 misconfiguration rehearsal

Second challenge in the rehearsal lane; assumes the envelope-reading
skills from `telecom-aws-01-reachability/`.

## Scenario

You are the lead auditor preparing for the same telecom-sector AWS
posture audit. This rehearsal focuses on the **IAM/S3 misconfiguration
track**: identity trust boundaries, over-permissive statements, and the
S3 settings that turn an IAM mistake into an exposure. You will drive
the same catalog with a narrower, deeper intent — an auditor who can
already read envelopes and now has to reason about *what the findings
mean*, not just how to produce them.

Everything is **synthetic**: no live accounts, no credentials, fixed
seed, planted violations only.

## Objectives

1. **Read the trust boundary in the fixture.**
   Open `extension/range/tf_iam_open/input/main.tf`. It is deliberately
   small: one identity policy statement. Identify every dimension in
   which it widens a trust boundary — the `Action` wildcard and the
   `Resource` wildcard are two separate control violations, not one —
   and write, for each, what an attacker gains and what the correct
   boundary would be (`iam-boundary.md`). Then reason across fixtures:
   what does this identity grant imply when combined with the
   `public-read` ACL planted in `tf_s3_public_access` (challenge 01's
   fixture)? The chain is the audit insight; neither fixture shows it
   alone.

2. **Select the right capability for the question.**
   Using `python -m extension list` and `describe`, choose which arm(s)
   you would dispatch for IAM policy reasoning vs S3 posture reading,
   and justify the choice in `selection.md`: match the question to the
   capability's documented scope and side-effect class, not to its
   name. Note which selections are impossible today on a scanner-less
   host and what the honest envelope says when you try.

3. **Attempt the dispatches and capture the contract.**
   Invoke your selected arms (or `agent-wiz list_tools {}` as the
   maintained floor). For each result, record in `dispatch-log.json`:
   the envelope `status`, the reason the result gives for any
   non-complete outcome, and whether the failure is a *capability
   boundary* (held, not installed, not curated) or an *evaluated
   non-success* (the arm ran and reported a problem). These two classes
   must never be confused in an audit deliverable.

4. **Produce `expected-findings.json`.**
   From the planted violations in the fixture, write the finding set a
   correct auditor would ship: one entry per violation with
   `finding_key`, the IAM/S3 control it violates, severity (critical /
   high / medium / low) and a one-sentence rationale. Compare against
   `artifacts/expected-findings.json` in this directory — reconcile
   every difference and justify it or fix your set.

5. **Defend the mapping.**
   Write `mapping.md`: map each finding to exactly one violation class
   (identity-trust, permission-scope, resource-exposure), state the
   evidence line it traces to, and mark any finding that depends on
   information *not present* in the fixture as out-of-scope rather
   than guessing. An audit finding that cannot cite its evidence is a
   liability, not a deliverable.

## Out of scope (by design)

No live IAM enumeration, no credential use, no speculation beyond the
fixture's bytes. Where the fixture is silent, say so.
