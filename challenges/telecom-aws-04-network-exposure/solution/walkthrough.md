# Solution — telecom-aws-04

## Reachability reasoning

**Security groups (`tf_sg_open_ingress`).** Both groups admit
`0.0.0.0/0` ingress, but the services behind them differ: port 22
exposes an interactive shell (high — credential guessing and key
attacks against a login surface), port 3306 exposes the database
engine itself (critical — the remaining barriers are engine auth and
patch level, and data-bearing services should never be
internet-reachable). Same misconfiguration shape, different severity:
the service defines the impact.

**The trap (`tf_s3_policy_blocked_trap`).** The bucket policy grants
`s3:GetObject` to `"*"`. But all four Block Public Access toggles are
on, and `RestrictPublicBuckets` confines a bucket that has a public
policy to AWS service principals and owner-account principals — the
anonymous grant never takes effect. The honest finding is a **low**
contained misconfiguration: the policy is wrong and should be cleaned
up, but reporting it as "bucket publicly readable" misreads the
control stack. The flip condition: a policy `Condition` carve-out
(specific `aws:SourceVpce`, source IP, or org-id) would make the grant
non-public and the bucket's posture *correct* — block-on never means
"skip reading policies".

## Expected finding set

| finding_key | severity | traces to |
|---|---|---|
| `demo-sg-open-admin-port` | high | sg admin, tcp/22 from 0.0.0.0/0 |
| `demo-sg-open-db-port` | critical | sg db, tcp/3306 from 0.0.0.0/0 |
| `demo-trap-anonymous-policy-contained` | low | policy neutralized by public access block |

## Grading

Exact coverage: an `extras` row for a "public bucket" claim on the
trap fixture is the trap springing; a `misses` row for the contained
finding means the policy was never read.
