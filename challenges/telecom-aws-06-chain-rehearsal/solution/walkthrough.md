# Solution — telecom-aws-06

## Stage 1 — host surface

`python -m extension.range --arm-ids ""` reports all ten fixtures
matched. Inside `tf_chain_ingress_role` the two direct exposures are:

| finding_key | severity | traces to |
|---|---|---|
| `demo-chain-sg-open-admin` | high | `aws_security_group.jump`, tcp/22 from 0.0.0.0/0 |
| `demo-chain-role-assumable` | critical | `aws_iam_role.escalation` + `AdministratorAccess` |

## Stage 2 — the chain

The connectivity edge `sg-jump -> role-escalate via sts:AssumeRole` is
what turns two findings into one: an attacker on the internet-reachable
surface can assume the administrator role. `demo-chain-internet-to-identity`
(critical) traces to that edge — the fixture's derived lifecycle
already emits this as its `chains` entry.

## Stage 3 — cross-fixture chain

`demo-chain-iam-open-to-s3-public` (high): the wildcard identity in
`tf_iam_open` chained with the public-read bucket in
`tf_s3_public_access`. Neither fixture shows the chain alone; the
audit insight is the combination (challenge 02's lesson, restated at
the chain level).

## Stage 4 — the deliverable

The union, `artifacts/expected-findings.json`:

| finding_key | severity |
|---|---|
| `demo-chain-sg-open-admin` | high |
| `demo-chain-role-assumable` | critical |
| `demo-chain-internet-to-identity` | critical |
| `demo-chain-iam-open-to-s3-public` | high |
| `demo-chain-iam-wildcard` | critical |

## Grading discipline

Grade each stage as you finish it. The engine reports misses, extras,
and evidence-less invalid rows; severity disagreements are flags to
defend. The challenge passes only 4/4 — stage 4 is the union, so a
stage-4 pass implies exact coverage of the whole chain story.
