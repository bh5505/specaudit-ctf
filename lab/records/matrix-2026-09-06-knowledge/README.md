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

Server-side traces name every tool call, so the lookup claims are
auditable per cell. Technique-lookup counts per knowledge cell
(trace-derived histograms; the failed cell's trace survives even
though its lane failed on the missing deliverable):

| cell | run_range | technique lookups | other calls |
|---|---|---|---|
| claude@kali | 1 | 3 | list 1, describe 1 |
| codex@kali | 1 | 3 | list 1, describe 1 |
| claude@ubuntu | 1 | 9 | list 1, describe 1, list_tools 1 |
| codex@ubuntu (failed) | 2 | 4 | list 1, describe 1 |

Every cell performed the lookups the challenge rehearses; claude@ubuntu
chose a heavier session (9 lookups across its 13 calls) — session
shape, not a different verdict. Coverage still comes only from
`run_range`.

Records: per-cell `report.json` under
`lab/records/matrix-2026-09-06-knowledge/<head>-<host>/<track>/`.
