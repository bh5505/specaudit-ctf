# Walkthrough — lab-knowledge-01-attack-mapping (worked pass, 2026-09-06)

Recorded from the committed head cells (this packet's matrix records);
the human path below uses the CLI and grades identically.

## 1. Ground the techniques

```
python -m extension invoke attack-stix-data technique '{"bundle": "extension/arms/attackstix/data/demo-enterprise-sample.json", "id": "T1530"}'
```

returns the bundle's record for Data from Cloud Storage (name,
description, detection guidance). Repeat for `T1562.008` (Disable or
Modify Cloud Logs) and `T1078` (Valid Accounts). These are R0
local-read lookups over the in-repo demo bundle — offline by
construction.

## 2. The mappings (exactly the contract's three)

1. `demo-knowledge-t1530-public-storage` — the planted public-read
   ACL is the condition T1530 exploits: unauthenticated reads of
   cloud-stored objects.
2. `demo-knowledge-t1562-008-cloud-logs` — the planted disabled
   management trail is the state T1562.008 leaves behind: no durable
   control-plane record.
3. `demo-knowledge-t1078-wildcard-accounts` — the planted wildcard
   identity policy removes every boundary a valid account would
   otherwise face, which is what makes T1078 critical here.

## 3. The graded pass

`python -m score --grade found-findings.json --expected
challenges/lab-knowledge-01-attack-mapping/artifacts/expected-findings.json`
→ `passed: true, score: 1.0`.

## 4. The head-matrix evidence

All four head instances attempted the canonical prompt (records in
`lab/records/matrix-2026-09-06-knowledge/`). Three passed 3/3
verified; the fourth (codex@ubuntu) is recorded as an honest failure
— the head improvised on the optional `artifact_dir` custody
parameter, hit the sink's by-design refusal, and never delivered
`found.json`. The doctrine graded the empty delivery as a failure,
which is the point of the lane.
