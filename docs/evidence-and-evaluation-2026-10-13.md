# Trusted input acquisition, attempt ledger, and evidence chain (2026-10-13)

Operator-side mechanisms for the #90 track: generalized trusted observations
for caller-file readers, frozen first-party data slices, an all-attempt
evaluation ledger, and separately attributable evidence layers. All are
opt-in, pure where possible, never read a clock (times are explicit flags or
arguments), and add no invoke profile, catalog row, MCP tool, or grading
semantics. Exact fixture grading is unchanged.

## Reader evidence acquisition (`reader_evidence`)

`python -m reader_evidence` acquires a caller-file input on the trusted side
*before* dispatch: a bounded no-follow regular-file read inside an
operator-approved root, recording size, sha256, and the resolved locator,
with typed refusals for missing paths, symlinks, non-regular files, bad
suffixes, oversize, traversal, and root escape. Directory inputs get a
deterministic manifest (sorted relative paths, per-entry digests, entry,
byte, and depth caps) that refuses symlinks anywhere in the walk. Hosts
without `O_NOFOLLOW`-style flags refuse with `platform-unsupported` rather
than silently weakening the read discipline.

The acquired record binds into a `specaudit.ctf.reader-observation.v1`
document with the attempt id, arm, action, and handler revision. Honesty
boundaries, stated in the document itself:

- the digest covers the bytes acquired in a bounded read window;
  `verify_unchanged` re-attests stability later by repeating the same fd
  discipline. Neither proves those were exactly the bytes a handler parsed —
  that link is the recorded `execution_result_digest` correlation;
- custody is `operator-asserted-root`, not verified custody;
- the resolved locator is recorded for audit and is explicitly not identity;
- the record is content-bound but unsigned; every observation stays evidence
  class `declared` with applicability not assessed;
- the replay set for `verify_reader_observation` is caller-supplied and
  never stored module-side.

This is the I/O half that the pure four-profile sidecar
(`extension.observations`) deliberately lacks; it does not widen, import, or
modify that frozen sidecar.

## Frozen first-party data slices (`reader_evidence.data_slices`)

DATA-01 and DATA-02 mechanisms pin the shipped first-party **synthetic demo**
snapshots: the vulnify demo vulnerability snapshot and a synthetic
detection-rule index. Each slice record carries `provenance:
first-party-synthetic-demo`. Since the 2026-10-14 operator authorization
(docs/governance/promotion-authorization-2026-10-14.md), R01 and R43 are
admitted sources and both slices carry `upstream_admission: admitted` for
their narrow scope — the pinned first-party synthetic slice bytes and format
only; the upstream vulnify aggregate database and upstream rule corpora stay
outside the admission and nothing upstream is bundled. Lookups verify the
pinned digest before running, refuse as stale after the recorded review
window, and keep unknown lookups unknown (never an all-clear). The slices do
not constrain other caller-supplied inputs to those readers.

## All-attempt ledger (`attempt_ledger`)

`python -m attempt_ledger record|verify|summarize` maintains an append-only
JSON-lines ledger of every attempt: setup failure, refusal, parse failure,
not-found, timeout, crash, safety stop, interruption, abstention, and
completion — with lane and assistance state (first-pass, assisted, tuned,
held-out). A failed grade is a completed attempt with wrong findings, never
a refusal. `summarize` derives numerators only from retained rows; the
denominator is every row, and lanes are never compared as equivalent.
Regrading the same submission appends a legitimate retry row; reusing an
attempt id with a conflicting class/assistance/lane triple is refused.

Integrity, honestly stated: the default sha256 chain detects in-place edits
only when the verifier holds the retained head (tail truncation alone is
*not* detectable without it); the optional operator-held HMAC key matches
the repo's trace-chain precedent and authenticates rows to that key. Either
way the ledger is integrity-checked, not immutable. The grade CLI writes the
new head digest into its manifest (`ledger_head_digest`) for out-of-band
anchoring.

## Wiring

- `python -m exercise_operator grade ... --ledger PATH [--ledger-key-hex ...]
  --at ISO [--assistance ...]` appends one row per grade run (completion /
  refusal / parse-failure) and fails closed — exit 2, JSON error — if the
  ledger cannot be verified, appended, or imported. Without `--ledger`,
  output records are byte-identical to before.
- `python -m learning operator run ... --ledger PATH ...` appends completion,
  refusal, or parse-failure rows for the self-study lane the same way.

The exercise runner's head-lane failure reasons are not yet mapped into
ledger rows; that mapping remains open under EVAL-01.

## Evidence chain (`evidence_chain`)

`specaudit.ctf.evidence-chain.v1` keeps five layers separately attributable:
raw artifacts (digest + advisory locator + custody note), observations
(evidence class carried through unchanged — chaining never upgrades
`declared` to `observed`), analyst inference, reviewer adjudication
(original and adjusted scores both retained with reviewer identity and
rationale), and the final workpaper. Machine and human verdicts ride as
siblings; no field can override one with the other, and a chain built on the
exact grader inherits its limitation verbatim
(`machine-verdict-is-exact-fixture-coverage-only`). This is a record
contract for AUDIT-01 attribution, not a rubric or calibration mechanism —
those belong to the challenge authoring track.
