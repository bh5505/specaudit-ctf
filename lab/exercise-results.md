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

---

# 2026-09-06 — battery breadth (5/5 vs the spawned target), first claude-code attempt

Third measured session on the same single-host lab (Kali-WSL dev
instance, `/root/ctf` checkout at the battery-breadth head;
golden-image target spawned by `lab/spawn-target.sh` at
`172.19.89.77` and torn down after; no operator credentials spent).

## Rehearsal battery, full breadth (measured)

The preset grew from the offline/contained pair to one member per
exercise domain: checkov (IaC), semgrep-mcp (code audit),
attack-stix-data.technique (knowledge/reasoning, over the shipped demo
bundle), and the dual-gated target-facing pair wapiti (web/DAST) and
nmap (network) — armed by their scope envs AND `LAB_TARGET_HOST`
(a bare host/IP; the target is never derived from the scope env).

```text
export LAB_TARGET_HOST=172.19.89.77 WAPITI_DISPATCH_SCOPE=172.19.89.77 NMAP_DISPATCH_SCOPE=172.19.89.77
export CHECKOV_BIN=/opt/ctf/bin/checkov SEMGREP_BIN=/opt/ctf/bin/semgrep SEMGREP_SCAN_ROOT=/root/ctf/extension/range
/opt/ctf/bin/python -m exercise --battery --challenge telecom-aws-02-iam-s3-misconfig
```

Outcome: exit 0, `exercise complete; range complete (10 fixtures);
battery 5/5` — every member `complete`, including both live arms
against the spawned target with their `[dispatch]` audit lines
(`arm=wapiti … target=http://172.19.89.77:8080/`,
`arm=nmap … target=172.19.89.77`). Committed report:
`lab/records/battery-breadth-demo.json` (schema `exercise.run.v1`,
deterministic).

## First claude-code real-head attempt (measured, passed)

The claude-code CLI (2.1.261 on the lab host, operator-installed,
LiteLLM tier router) attempted challenge telecom-aws-02 through the
four-tool MCP server — the first claude-code evidence in the record,
and the calibration for the runner-driven head matrix that follows.
MCP attach used the documented hermetic path: a private
`--mcp-config` JSON (server `specaudit-ctf` spawning this checkout's
`launch_mcp.py`, per-server `env` map carrying the three trace vars)
with `--strict-mcp-config` and `--allowedTools "mcp__specaudit-ctf__*"
Write`; the run's working directory was the attempt directory so the
head could write `found.json`. Prompt: `claude-first-prompt.txt`
(the per-challenge attempt prompt the matrix reuses).

```text
cd <attempt-dir> && claude -p "$(cat prompt.txt)" --output-format json \
  --max-turns 30 --allowedTools "mcp__specaudit-ctf__*" Write \
  --mcp-config ./mcp.json --strict-mcp-config
python -m exercise --challenge telecom-aws-02-iam-s3-misconfig \
  --attempt-dir <attempt-dir> --expected challenges/telecom-aws-02-iam-s3-misconfig/artifacts/expected-findings.json
```

Outcome: **run `complete`, head lane `passed`** — 3 `tools/call`
recorded server-side, HMAC chain verified, close record present, 3
findings claimed / 3 verified / 0 unverified / 0 misses, 5 agent
turns. The documented per-server `env` map is thereby live-measured:
the trace vars reached the server process through `--mcp-config` and
the chain graded clean.

Committed evidence: `lab/records/claude-first-report.json`,
`lab/records/claude-first-found.json`,
`lab/records/claude-first-trace.ndjson`,
`lab/records/claude-first-claude-out.json` (the CLI's own result
envelope — transport noise, never the evidence), and
`lab/records/claude-first-prompt.txt` (the trace key and the
mcp-config stay on the lab host; a byte-level key-leak check ran on
every committed artifact).

---

# 2026-09-06 — the head matrix: 4 head instances x 5 graded challenges, 20/20 through the runner

The runner-driven head matrix (comparative report:
[`lab/records/matrix-2026-09-06.md`](records/matrix-2026-09-06.md)):
claude-code 2.1.261 and codex-cli 0.153.4 on both WSL lab hosts
(kali-linux and Ubuntu — codex was replicated onto Ubuntu this
session from the kali setup: standalone musl binary, abliteration
provider, env-key auth, `env_vars` allowlist), each sweep driven by
`lab/matrix-run.sh` — one runner command per cell, zero hand-held
steps. Every cell passed: chain verified, close record present,
claims fully verified, full scores; the flagship four-stage
challenge 06 is the centerpiece row. All sweeps ran branch commit
`c6622be`; per-cell `report.json` files are committed under
`lab/records/matrix-2026-09-06/`. Honest failure on record: the
pre-matrix smoke cell failed gradably (a head copied quote-baiting
prompt hints into invalid JSON; grader refused; prompt fixed and
pinned) — the failure taxonomy is part of the report.
