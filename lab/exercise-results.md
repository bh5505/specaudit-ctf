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
