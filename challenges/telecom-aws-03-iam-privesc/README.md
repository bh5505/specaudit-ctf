# Telecom AWS 03 — IAM privilege-escalation rehearsal

Third challenge in the rehearsal lane; assumes the envelope-reading
skills from challenge 02. This lane is the **identity escalation
track**: not just reading a policy, but recognising the two classic
AWS identity-escalation shapes — an assumable administrator role and
an externally-trusted role without MFA — planted in
`extension/range/tf_iam_assume_role/` and
`extension/range/tf_iam_external_trust/`.

Everything is **synthetic**: no live accounts, no credentials, fixed
seed, planted violations only.

## Objectives

1. **Trace the escalation path, not just the finding.**
   Open both fixtures' `main.tf`. For the assumable role: which three
   facts combine into the escalation (a role that can be assumed by
   any in-account principal, an `sts:AssumeRole` grant policy, and
   administrator-level permissions)? For the external trust: which two
   dimensions make it a finding (an external principal, and no MFA
   condition) and why they are two separate control violations, not
   one? Write the paths in `escalation-paths.md`.

2. **Ship the finding set.**
   Produce `my-findings.json` in the same schema as
   `artifacts/expected-findings.json` (`track`, `total`, `findings`
   with `finding_key`, `control`, `severity`, `rationale`,
   `traces_to`). Every finding must trace to exactly one planted
   violation; copy the `finding_key` vocabulary from the contract.

3. **Grade yourself and defend the deltas.**
   Run:
   ```
   python -m score --grade my-findings.json --expected artifacts/expected-findings.json
   ```
   The verdict passes only on exact coverage: misses, extras, and
   evidence-less rows all fail it, and severity disagreements are
   reported as flags for you to defend or fix. A partial finding set
   never reads as all-clear.

## Out of scope (by design)

No live IAM enumeration, no credential use, no speculation beyond the
fixtures' bytes.
