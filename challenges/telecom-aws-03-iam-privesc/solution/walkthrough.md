# Solution — telecom-aws-03

## Escalation paths

**Assumable admin (`tf_iam_assume_role`).** Three planted facts
combine: (1) `aws_iam_role.admin`'s trust policy allows
`sts:AssumeRole` from the account root, i.e. any principal in the
account; (2) `aws_iam_policy.assume_broadly` grants `sts:AssumeRole`
on the role to whoever holds it; (3) the role carries
`AdministratorAccess`. Any principal with (2) becomes the admin role —
a one-step privilege escalation. A correct report separates the role
shape (critical) from the standing grant (high): removing either one
breaks the chain, so they are two control violations.

**External trust (`tf_iam_external_trust`).** The trust policy admits
`arn:aws:iam::999999999999:root` — a different account — with no
`Condition` block, so there is no MFA (and no external-id) requirement.
The principal dimension (critical: the boundary is external) and the
missing MFA condition (high: the second factor is absent) are separate
violations; fixing MFA alone still leaves an external trust boundary.

## Expected finding set

| finding_key | severity | traces to |
|---|---|---|
| `demo-iam-assumable-admin-role` | critical | `aws_iam_role.admin` + attachment |
| `demo-iam-broad-assume-grant` | high | `aws_iam_policy.assume_broadly` |
| `demo-iam-external-trust-principal` | critical | trust `Statement[0].Principal` |
| `demo-iam-external-trust-no-mfa` | high | trust `Statement[0]` (no Condition) |

## Grading

`python -m score --grade my-findings.json --expected artifacts/expected-findings.json`
passes only on exact coverage. The evidence doctrine applies to you
too: a row with a blank `traces_to` is an unowned finding and is
reported as invalid — it can never count as a hit.
