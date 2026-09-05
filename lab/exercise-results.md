# Exercise runner — measured lab record

A measured end-to-end run of `python -m exercise` (the harness core)
in the single-host lab: the synthetic range, the flagship challenge's
grading, one admitted dispatch-class arm against the spawned lab
target, and the agent-head readiness probe, composed into one report.

- **Date**: 2026-09-04
- **Host**: Kali-WSL dev instance (`/root/ctf`, `/opt/ctf` venv,
  editable install), orchestrated from Windows per `lab/README.md`
- **Target**: ephemeral golden-image WSL instance spawned by
  `lab/spawn-target.sh` (inert static site on :8080), torn down after
- **Command** (abridged; the found document was the challenge's own
  contract — a controlled perfect submission, exercising the grader's
  pass path end to end):

```text
export NMAP_DISPATCH_SCOPE=172.19.89.77
python -m exercise \
  --challenge telecom-aws-06-chain-rehearsal \
  --fixtures tf_chain_ingress_role,tf_iam_open,tf_s3_public_access \
  --found /tmp/found.json \
  --expected challenges/telecom-aws-06-chain-rehearsal/artifacts/expected-findings.json \
  --arms '[{"arm_id":"nmap","action":"scan","args":{"target":"172.19.89.77"}}]' \
  --head claude-code \
  --out exercise-run-2026-09-04.json
```

- **Outcome**: `complete` — summary line:
  `exercise complete; range complete (3 fixtures); grading passed; score 1.00; arms 1/1; head available`
- **Lanes**: range matched all three named fixtures and derived the
  `internet_to_identity` chain; grading passed with 5/5 hits, zero
  misses/extras/invalid; `nmap.scan` ran against the spawned target
  through the admitted X2-PUB dispatch path (scope-armed, envelope
  `complete`); the claude-code head launcher probed ready.
- **Credentials**: none. No operator credentials were used or
  present; the scan touched only the disposable lab target.

The committed machine-readable report is
`lab/exercise-run-2026-09-04.json` (schema `exercise.run.v1`; the
report is deterministic — no wall-clock fields — so the JSON is the
measured record, not a transcript).


---

# 2026-09-05 — rehearsal battery, real-head attempt, page-fetch

Second measured session on the same single-host lab (Kali-WSL dev
instance, `/root/ctf` checkout, `/opt/ctf` venv; golden-image target
spawned by `lab/spawn-target.sh` and torn down after; no operator
credentials spent).

## Rehearsal battery + target-facing arm (measured)

```text
export CHECKOV_BIN=/opt/ctf/bin/checkov SEMGREP_BIN=/opt/ctf/bin/semgrep
export SEMGREP_SCAN_ROOT=/root/ctf/extension/range
export ZGRAB2_DISPATCH_SCOPE=172.19.89.77
python -m exercise --battery   --arms '[{"arm_id":"zgrab2","action":"scan","args":{"target":"172.19.89.77","module":"http"}}]'   --challenge telecom-aws-02-iam-s3-misconfig
```

Outcome: exit 0, `exercise complete; range complete (10 fixtures);
arms 1/1; battery 2/2`.

- `checkov.scan` `complete` — offline IaC scan over the packaged
  range (checkov 3.3.16: 75 passed / 56 failed findings, exit 0 via
  `--soft-fail`; findings live in the JSON output). The measurement
  caught real CLI drift the hermetic fake binary could not: checkov
  3.3.16 rejects the `scan` subcommand and exits 1 on findings, so the
  arm's fixed argv was corrected in the same packet.
- `semgrep-mcp.semgrep_scan` `complete` — inline rule pack under
  `SEMGREP_SCAN_ROOT` containment (semgrep 1.176.1).
- `zgrab2.scan` `complete` — target-facing arm through explicit
  `--arms` against the spawned target, `[dispatch]` audit line on
  stderr, scope `172.19.89.77`.

Committed report: `lab/records/battery-demo.json`
(schema `exercise.run.v1`, deterministic — no wall-clock fields).

## Real-head attempt: codex-cli × challenge 02 (measured, passed)

The agent CLI is operator-installed and operator-credentialed
(codex-cli 0.153.4, headless, custom model provider; no credentials
in the repo or the attempt directory). MCP attach follows
[extension/heads/codex-cli.md](../extension/heads/codex-cli.md):
user-global `config.toml` `[mcp_servers.specaudit-ctf]` spawning this
checkout's launcher with `env_vars` forwarding the three trace vars.

```text
codex exec --sandbox workspace-write --skip-git-repo-check -C <attempt-dir>   "$(cat prompt.txt)"          # challenge 02 attempt prompt
python -m exercise --challenge telecom-aws-02-iam-s3-misconfig   --attempt-dir <attempt-dir>   --expected challenges/telecom-aws-02-iam-s3-misconfig/artifacts/expected-findings.json
```

Outcome: **run `complete`, head lane `passed`** — 5 `tools/call`
recorded server-side, HMAC chain verified, close record present
(graceful termination), 3 findings claimed / 3 verified / 0
unverified, `grade.passed` true. Attempt id `b42a4ca4…`; trace file
sha256 `35ca7437…`; 48,733 model tokens on the operator's provider.

Committed evidence: `lab/records/head-attempt-report.json` (the graded
report), `lab/records/head-attempt-found.json` (the agent's claimed
findings — plain prose, never the evidence),
`lab/records/head-attempt-trace.ndjson` (the server-side trace; the
chain key is not stored beside it).

The first attempt run is part of the record too: with the pre-fix
server it produced a fully intact 6-call chain with no close record
(agent CLIs terminate their servers with a signal, not an EOF) and the
lane refused to grade it — the honest failure that motivated the
graceful-termination attestation now in `mcp_server.serve`.
