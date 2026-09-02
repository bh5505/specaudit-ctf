# Telecom AWS 02 — walkthrough

## 1 — The trust boundary

The fixture's one statement widens two boundaries at once:

- `Action = "*"` violates least-privilege on the *action* axis: any
  holder can eventually perform any action the account allows. The fix
  is an explicit action list matching the workload's needs.
- `Resource = "*"` violates containment on the *resource* axis: even a
  narrow action list would apply to everything. The fix is an explicit
  resource ARN set.

Treating these as one finding ("the policy is too open") is the
beginner's merge: they are independent controls with independent fixes,
and a remediation review will track them separately.

The cross-fixture chain: challenge 01's `tf_s3_public_access` plants a
`public-read` ACL on its bucket. An identity holding this wildcard
policy can read every object in that bucket regardless of the ACL — the
ACL makes it world-readable to *everyone*, the wildcard identity makes
it readable to *this principal's* whole action surface; the findings
compound.
`demo-iam-to-exposure-chain` in `artifacts/expected-findings.json`
records that reasoning; note it cites both fixtures, which is what
makes it an audit insight rather than two tool outputs.

## 2 — Capability selection

For IAM policy reasoning, the catalog today offers methodology rows and
gated arms — the honest answer on a scanner-less host is that no
maintained capability answers this question yet, and the selection
write-up should *say so* rather than force a dispatch. `agent-wiz`'s
maintained read tier (`list_tools`) is the floor that always works and
demonstrates you can drive the dispatch path. Selecting by documented
scope and side-effect class (not by name matching "iam" or "s3") is the
skill.

## 3 — The dispatch log

Each result falls into exactly one of:

- **capability boundary** — the envelope's reason is `held`,
  `not-installed`, `not-curated`, or an unknown id: the dispatch never
  reached evaluation. In an audit deliverable this is reported as a
  limitation, never as a finding.
- **evaluated non-success** — the arm ran and reported `degraded` /
  `failed` or an inner error: a real observation about the target, worth
  a finding or a follow-up.

Confusing the two classes is how synthetic tooling noise becomes fake
audit findings. The `status` + reason vocabulary in the envelope exists
precisely to keep them apart.

## 4 — Reconciling against the expected set

`artifacts/expected-findings.json` plants three findings: the two
least-privilege violations (critical and high) and the cross-fixture
chain (high). If your set has more, check each extra traces to fixture
bytes — inventing findings the fixture cannot support is the failure
mode this exercise exists to break. If your set has fewer, the common
miss is either the action/resource split or the chain entry.

## 5 — Defending the mapping

Identity-trust (who may act), permission-scope (what they may do), and
resource-exposure (what is reachable) are the three classes. The
wildcard-action finding is permission-scope; wildcard-resource spans
permission-scope and identity-trust (defend your choice either way, in
writing); the chain is resource-exposure with a cited identity
precondition. Anything you could not ground in fixture bytes belongs in
an out-of-scope note — "the fixture is silent on X" is a professional
answer; guessing is not.
