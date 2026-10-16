# Qualification dry-run runbook (operator procedure)

This runbook is the procedure a named operator follows to produce one
completed dry-run artifact set for one design-ready pilot. It is **shipped,
not executed**: no dry-run directory produced by this procedure exists yet,
and a pilot's record stays `dry_run: procedure-shipped-not-executed` until an
operator signs one off. The procedure exercises the learner path only; it is
never itself a promotion signal.

The artifact set this procedure must produce (all paths relative to one
dry-run directory, called `DIR` below):

| Artifact | Meaning |
|---|---|
| `packet/BRIEF.md` | the learner brief actually handed to the learner context |
| `packet/inputs/` | the learner input files (no instructor material of any kind) |
| `attempt-ledger.jsonl` | one append-only attempt-ledger row per attempt (see class table) |
| `evidence-chain.json` | one closed `evidence_chain` document closing the run |
| `dry-run-summary.json` | operator summary: schema `specaudit.ctf.dry-run-summary.v1`, pilot, recorded_at, operator, notes |

`challenges/qualification/dry-run/validate.py --dir DIR --as-of YYYY-MM-DD`
machine-checks the internal consistency of that set (exit 0 pass, exit 1
named reasons, exit 2 invocation error). Read its failure output; do not read
exit 0 as more than it is:

**validate.py pass means the artifact set is internally consistent — it does not prove the runbook was followed, that a real learner path executed, or that no leak occurred outside the provided outputs.**

## 1. Prepare

1. Confirm the pilot's qualification record
   (`challenges/qualification/records/<pilot>.qualification.v1.yaml`) is
   `design-ready` and that you are the named operator for this dry run.
   Review lanes are assigned, unstaffed, wholly operator-gated: a dry run
   does not staff them and does not substitute for them.
2. Build the learner packet in a fresh operator-owned directory: write
   `packet/BRIEF.md` (the pilot's learner brief, instructor material
   excluded) and stage only learner input files under `packet/inputs/`.
   For pilots with an instructor key, mount **only** `packet/` into the
   learner context; the instructor directory stays outside every learner,
   target and agent mount.
3. Prepare a containment profile for the run:
   `approved_root` = the staged packet root, `scratch_root` = an empty
   operator-owned scratch directory, `canaries` = the pilot's
   `INSTRUCTOR-CANARY-*` markers where one exists.

## 2. Containment-guarded learner execution

Run the learner-path attempt under the containment guard, exactly as the
[containment package](../../../containment/README.md) documents. The matrix
form takes a roster of arm cases and an operator-supplied attempt ledger:

```sh
python -m containment \
  --approved-root /srv/operator/approved \
  --scratch-root /srv/operator/scratch \
  --fixtures-root /srv/operator/approved/fixtures \
  --roster-json roster.json \
  --ledger DIR/attempt-ledger.jsonl
```

In-process guarded single cases use `containment.harness.run_case` with the
same profile; hostile-input cases (`blocked` outcomes) are expected dry-run
material, not failures. On Windows the trusted acquisition gate types
`platform-unsupported` and the run is labeled `partial`; POSIX-only hostile
classes are skipped explicitly, never silently.

## 3. Attempt-ledger rows for every expected attempt class

Every attempt the dry run makes gets exactly one row in
`DIR/attempt-ledger.jsonl` (canonical JSON lines,
`attempt_ledger.append_row` chaining). The denominator is every row: the
runbook requires **at least one `completion` row and at least one negative
class row** from `refusal`, `blocked-before-dispatch` failures mapped to
`refusal`, `parse-failure`, `timeout`, `interruption`, `abstention` or
`safety-stop`. A dry run whose ledger holds only completions has not
exercised the false-assurance cases and fails validation
(`ledger-missing-negative-class-row`). Lanes follow the attempt taxonomy
(`self-study` for learner-path cases, `operator-rehearsal` for
containment-local rows); structured detail documents live OUTSIDE the
ledger, referenced by digest.

## 4. Machine grade where applicable

Where the pilot ships a machine grader (`learning` modules), run it against
the submitted artifact and retain the graded output under `DIR/`. The
machine verdict is exact fixture/scene coverage only and inherits
`machine-verdict-is-exact-fixture-coverage-only` wherever it enters a chain.
It never replaces the human reviewer, and it never upgrades a `declared`
observation.

## 5. Evidence-chain close

Close the run with one `evidence_chain.build_chain` document written to
`DIR/evidence-chain.json`: raw digests for the packet inputs actually used,
observations carried with their honest `evidence_class`, the analyst-role
inference, the adjudication layer (reviewer and retained scores; seed
adjudications use reviewer `calibration-seed` with `adjusted_score: null`
and are refused as human calibration by
`challenges/qualification/loader.py`), and the workpaper conclusion. Verify
with `evidence_chain.verify_chain(chain, as_of=<the --as-of date>)`; a
`future-decision`, `unanchored-observation`, `inference-reference-mismatch`
or `override-verdict-present` refusal means the close is not done.

## 6. Summary and operator sign-off checklist

Write `DIR/dry-run-summary.json` (schema
`specaudit.ctf.dry-run-summary.v1`). Then run `validate.py` and attach its
output. Sign off only when every box is checked:

- [ ] New learner actions stopped and the attempt/evidence channel closed
      (OPERATIONS.md, "Close, reset and retain", step 1).
- [ ] Final monitoring, service, identity and cost state captured (step 2).
- [ ] Lab changes reverted or destroyed via the tested path (step 3).
- [ ] Baseline verified **independently** — "cleanup command exited zero"
      is not enough (step 4).
- [ ] Temporary credentials, tokens, certificates and canaries revoked or
      rotated (step 5).
- [ ] Routes, listeners, mounts and temporary privileges removed (step 6).
- [ ] Retained evidence hashed and sealed; learner submissions, raw
      evidence, instructor ground truth and incident records separated by
      access need (step 7).
- [ ] Approved teaching copies sanitized without overwriting originals
      (step 8).
- [ ] Retention and deletion rules applied, including model/provider
      retention where applicable (step 9).
- [ ] Operator close recorded, or an unresolved exception left open and
      visible (step 10).
- [ ] `validate.py --dir DIR --as-of <date>` exited 0 and its output is
      retained with the artifact set.

A cleanup failure remains open and visible; do not reuse a dirty range or
unresolved identity for the next cohort (rebuild from an admitted source
when reset confidence is insufficient).
