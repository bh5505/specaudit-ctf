# Knowledge-lane head cells + challenge-01 first matrix appearance (2026-09-06)

The first head-matrix cells for the two newly graded tracks —
`telecom-aws-01-reachability` (its contract landed in the grad01
packet) and `lab-knowledge-01-attack-mapping` (this packet). Every
cell is one runner command on the operator-armed real-head mode,
identical prompts per challenge across heads
(`lab/prompts/challenge-01-reachability.txt`,
`lab/prompts/challenge-knowledge-01-attack-mapping.txt`).

## Results: 7 of 8 cells passed

| challenge | claude@kali | claude@ubuntu | codex@kali | codex@ubuntu |
|---|---|---|---|---|
| 01-reachability | pass 3/3v, 1 call | pass 3/3v, 1 call | pass 3/3v, 8 calls | pass 3/3v, 9 calls |
| lab-knowledge-01-attack-mapping | pass 3/3v, 6 calls | pass 3/3v, 13 calls | pass 3/3v, 6 calls | **FAILED** (recorded) |

Every passing cell: trace chain verified, close record present,
claims == verified, full score.

## The failed cell is a finding, not a defect to hide

`codex@ubuntu x lab-knowledge-01-attack-mapping` exited 0 but never
wrote `found.json`; the grader refused the attempt
("attempt has no found.json"). The head's stderr shows what happened:
it went down an improvisation tangent on the invoke tool's optional
`artifact_dir` parameter (the Mode A custody sink), hit the sink's
by-design refusal — `artifact directory must be empty` — retried,
and exhausted its session without delivering. The prompt never
mentions that parameter; the head discovered it in the tool schema.
The evidence doctrine graded the empty delivery honestly. This cell
is the seed observation for the variance packet's stability stats.

## Process evidence on the knowledge lane

Both heads' knowledge traces carry exactly three `technique` invokes
(one per mapping: T1530, T1562.008, T1078) over the shipped demo
bundle — the lookups the challenge exists to rehearse are visible in
the server-side trace, while coverage still comes from `run_range`.

Records: per-cell `report.json` under
`lab/records/matrix-2026-09-06-knowledge/<head>-<host>/<track>/`.
