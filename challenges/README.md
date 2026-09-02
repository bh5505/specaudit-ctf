# Challenges — synthetic rehearsal exercises

Each challenge is a self-contained teaching exercise against this
repository's real surface: the catalog, the CLI, the stdio MCP server, and
the synthetic range fixtures. The teaching path needs only **Python 3.11+
and this checkout** (plus, optionally, any agent CLI that speaks stdio MCP
for the attachment exercises). No internal trees, no product binaries, no
live cloud accounts, and no real credentials are involved.

Everything is deterministic: the range runs with a fixed seed, so the
planted violations and their finding rows are reproducible byte-for-byte
on every host.

| Challenge | Lane | Fixtures |
|---|---|---|
| `telecom-aws-01-reachability/` | AWS reachability rehearsal | `tf_s3_public_access` |
| `telecom-aws-02-iam-s3-misconfig/` | IAM/S3 misconfiguration rehearsal | `tf_iam_open` |

Start with `telecom-aws-01-reachability/`; challenge 02 assumes its
envelope-reading skills. Solutions are included (`solution/`) — the
exercises are about producing and defending the deliverables, not about
guessing.

## Correspondence contract (both challenges)

Every finding you ship must trace to exactly one planted violation in the
synthetic fixture. A finding you cannot trace is wrong; a planted
violation with no finding is a miss. This is the discipline a real audit
cycle demands of machine-generated deliverables, rehearsed here against
data that cannot lie to you.
