# Challenges — synthetic rehearsal exercises

Each challenge is a self-contained teaching exercise against this
repository's real surface: the catalog, the CLI, the stdio MCP server, and
the synthetic range fixtures. The teaching path needs only **Python 3.11+
and this checkout** (plus, optionally, any agent CLI that speaks stdio MCP
for the attachment exercises). No internal trees, no product binaries, no
live cloud accounts, and no real credentials are involved.

Everything is deterministic per host: the range runs with a fixed seed,
so on a given host the planted violations and the range-report digest
are reproducible byte-for-byte. Arm rows, limitations, and the
range-report digest vary with the host's installed state — the planted
fixture ground truth does not.

| Challenge | Lane | Fixtures |
|---|---|---|
| `telecom-aws-01-reachability/` | AWS reachability rehearsal | `tf_s3_public_access` |
| `telecom-aws-02-iam-s3-misconfig/` | IAM/S3 misconfiguration rehearsal | `tf_iam_open` |
| `telecom-aws-03-iam-privesc/` | IAM privilege-escalation rehearsal | `tf_iam_assume_role`, `tf_iam_external_trust` |
| `telecom-aws-04-network-exposure/` | Network exposure + near-miss discipline | `tf_sg_open_ingress`, `tf_s3_policy_blocked_trap` |
| `telecom-aws-05-logging-gaps/` | Logging/detection-gap rehearsal | `tf_cloudtrail_disabled`, `tf_s3_no_access_logging` |
| `telecom-aws-06-chain-rehearsal/` | Flagship multi-stage chain engagement | `tf_chain_ingress_role`, `tf_iam_open`, `tf_s3_public_access` |

Start with `telecom-aws-01-reachability/`; each challenge assumes the
skills of its predecessors. Challenge 06 is the flagship: four graded
stages composing discovery, exposure, and chain reasoning into one
deliverable. Solutions are included (`solution/`) — the exercises are
about producing and defending the deliverables, not about guessing.

## Correspondence contract (all challenges)

Every finding you ship must trace to exactly one planted violation in the
synthetic fixture. A finding you cannot trace is wrong; a planted
violation with no finding is a miss. This is the discipline a real audit
cycle demands of machine-generated deliverables, rehearsed here against
data that cannot lie to you.

## Grading

Challenges 03–06 ship an expected-findings contract
(`artifacts/expected-findings.json`; challenge 06 adds per-stage
contracts). Grade yourself:

```
python -m score --grade my-findings.json --expected artifacts/expected-findings.json
```

The verdict passes only on exact coverage — misses, extras, and
evidence-less rows all fail it, and a partial finding set never reads
as all-clear. Severity disagreements are surfaced as flags, not
failures. See `score/grading.py` for the semantics.
