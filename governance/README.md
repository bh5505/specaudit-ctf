# Governance register

This directory is a repository-maintainer surface. It records module, source,
runtime, relationship, currentness, and promotion evidence; it grants no
execution authority and is not imported by `extension` or the sealed runtime.
The executable admission authority remains
`extension.invoke_profiles.INVOKE_PROFILES`.

`register.v1.yaml` is deliberately partial. Its detailed records cover the 14
research readers added in PR 97: 14 `list_tools` capabilities and 38 local-data
actions. Its inventory section separately binds the exact semantic snapshot of
all 227 admitted profiles (including eight offline learning-operator
profiles and one inline pack-analysis action) so removal or profile drift cannot look like a clean
governance check. The source records are research candidates, not selected or
admitted upstream material. Their `research-mapping` relationships assert no
consumption, compatibility, provenance, custody, license, or data-rights claim.

For this PR 97 slice, the checker also loads `extension/coverage.yaml` against
the independently pinned canonical coverage-schema bytes. It requires the exact
14 reader ids and their `arm` / `[cli]` / curated / research classifications,
reconciles each classification with all 52 detailed register and authoritative
profile records, binds every real specialized handler's canonical immediate
truthy-payload refusal structure, and exercises both `list_tools` and
`tools/list`. The full 68-row catalog is not globally frozen: the report binds
the exact catalog bytes and its complete semantic snapshot, while the literal
governance baseline freezes only the 14 PR 97 reader classifications.

The three statuses stay independent:

- a module status never promotes a source or runtime capability;
- selecting or admitting a source never admits or promotes an action; and
- an admitted or maintained runtime action never makes learning material
  shipped.

The date-window portion of currentness is derived from `reviewed_on` and
`review_due_on` at a caller-supplied `--as-of` date. There is no stored
`current: true` flag. V1 records explicit drift triggers but has no observation
source proving that a listed trigger did not fire, so even an otherwise valid
date window reports `drift-triggers-unverified` and cannot satisfy `current`.
The initial records also intentionally have no completed currentness review, so
a current or complete check fails visibly.

From a development checkout with the dev dependencies installed:

```bash
# Validates the closed schemas, exact inventory, PR97 roster, catalog rows,
# live discovery aliases, profile contracts, relationships, and promotions.
python3 -m governance check --scope pr97-readers --require integrity \
  --as-of 2026-09-08 --format json

# The default completeness requirement is intentionally nonzero until GOV-01
# covers the complete module/source/runtime architecture and currentness queue.
python3 -m governance check --as-of 2026-09-08 --format json
```

## Register v2 — complete inventory (2026-10-13)

`register.v2.yaml` (schema `governance/schema/register.v2.schema.json`,
byte-pinned by the checker) extends the frozen v1 foundation additively. The
v1 file, the v1 schema, and every v1 validation rule are unchanged; the
reader-safety register and all v1 tests keep validating the v1 bytes. v2 is
opt-in through an explicit version flag — the loaded document never selects
its own validator:

```bash
python3 -m governance check --register-version 2 --scope full-v2 \
  --require integrity --as-of 2026-10-13 --format json   # exit 0
python3 -m governance check --register-version 2 --scope full-v2 \
  --require current --as-of 2026-10-13 --format json     # exit 0
python3 -m governance check --register-version 2 --scope full-v2 \
  --require complete --as-of 2026-10-13 --format json    # exit 0
```

What v2 adds, and what it still refuses to claim:

- **Roster completeness**: all 29 program modules (FND/AUD/CYC/TEL/capstones
  from `PROGRAM.md`), all 109 source rows (42 R-register candidates, 12
  supplemental S-families, 9 decided E1 pilot sources with their
  `source-decisions-2026-10-03.md` pins, and the 46 authoritative
  source-spine entries as `reference`-status rows), and detailed runtime
  records for the full 227-capability authoritative inventory. The PR97 slice
  is carried forward value-identically: the checker projects it back to v1
  shape, re-runs the untouched v1 rules on it, and additionally compares every
  row against the frozen v1 file (currentness is deliberately upgraded; all
  other fields must match exactly).
- **Per-candidate admission evidence**: the fourteen research-reader families
  carry canonical upstream custodian, verified immutable revision (tags or
  pinned commits from the 2026-10-13 primary-source review), supported-range
  honesty, code license separated from data/content rights, and a
  compatibility-schema correspondence record with known losses and explicit
  unknown semantics. Unresolved rights cells stay `OPEN` strings; see
  `docs/governance/source-verification-2026-10-13.md` for the evidence
  record behind every row.
- **Currentness with trigger checks**: every row's review window carries a
  reviewer and one recorded check per drift trigger, with a controlled
  `checked_via` vocabulary (`checker-rederived-inventory-reconciliation`,
  `primary-source-review`, `architecture-review`) and evidence references
  that must resolve to real repository headings. The report labels its basis
  `attributed-review-and-rederived-checks`: trigger checks are attributed
  review records and machine re-derivations, not proof that an upstream did
  not change. The recurring queue section binds per-class cadences to every
  row's window.
- **Promotion boundary**: the initial v2 baseline contained zero promotion
  events and refused `selected`/`admitted` sources. The twelve source
  exceptions recorded on 2026-10-14 are described below; `shipped` modules
  and module/runtime promotion evidence remain refused. The one
  maintained and the experimental runtime tiers predate the register; their
  rows carry optional `tier_provenance` notes that are inert by construction
  — the authoritative `INVOKE_PROFILES` tier is reconciled on every check and
  no register note can authorize or override it (a dedicated test strips all
  provenance and re-passes every requirement).
- **`repository_complete: true` means register coverage only** — every module,
  source family, and admitted capability rowed, reviewed, and queued. It is
  not a shipping, admission, catalog, or maintained-support claim, and it
  changes no runtime surface.

v2 uses larger register-only parse budgets (1 MiB bytes, 40,000 nodes, 1 MiB
total strings); the v1 and coverage budgets are untouched.

### Operator-authorized source promotions (2026-10-14)

The first promotions exist under the [promotion
authorization](../docs/governance/promotion-authorization-2026-10-14.md):
R01 vulnify and R43 security-detections-mcp are **admitted** for their
pinned first-party synthetic DATA-01/DATA-02 slices (the upstream aggregate
database and upstream rule corpora stay outside the admission), and ten
families (R02 R03 R08 R17 R25 R33 R34 R35 R36 R42) are **selected** for
recorded-export import. R15 and R38 stay research with recorded refusal
decisions. The checker's `V2_AUTHORIZED_PROMOTIONS` table is a frozen
allowlist — not evidence by itself: each accepted decision must bind the
operator authorization heading, the upstream-verified pin, and (for admitted
rows) a digest re-derivable from bytes on disk. Any promotion outside the
table, any field drift from an anchor, any unanchored or orphan event, and
every module/runtime promotion path remain integrity failures. Adding a
future promotion requires editing the anchor table in code — a register
edit alone can never authorize one. The PR97-slice fidelity rule masks
exactly the promotion-affected fields on promoted rows; everything else on
those rows must still equal the frozen v1 register.

U-GOV.a correction (2026-10-18): the 2026-10-14 decision cited
`tests/test_synthetic_readers.py` for the ten selected families, but that
file is absent from the verified public baseline. The anchor table now freezes the corrected
per-source citations (R03/R33/R34/R35/R42 →
`tests/test_arm_batch7.py`; R02/R08/R17/R25/R36 →
`tests/test_arm_batch8.py`) and the checker additionally requires both
`regression_case` and `exercised_path` to resolve to bounded
repo-contained real `tests/*.py` files; existence is not execution proof.
History (`decided_on`, reviewer, revision, digests, authorization text) is
unchanged — see
[the correction and inventory](../docs/governance/w1a-source-evidence-and-inventory-2026-10-18.md).

U-GOV.c (2026-10-18) additionally freezes each of those twelve complete
historical events with a literal source-to-event-ID mapping and canonical JSON
SHA-256 digest, independent of the supplied register. Every promoted source
must reference its one recorded event exactly once; missing, extra, renamed,
cloned, duplicate, or cross-source events/references fail integrity. The digest
covers every field, including `from_status`, `verification_result`,
`supported_versions`, and `source_revisions`, and preserves array order. It
checks fidelity to the recorded decisions after the citation correction; it
does not authenticate the operator, prove regression execution, clear rights,
or authorize another promotion. Changing a historical snapshot requires a
reviewed code change as well as the register change.

Exit `0` means the explicitly requested requirement passed, `1` means the
register has semantic/currentness/completeness gaps, and `2` means the register,
schema, arguments, or other input is invalid. Schema-valid validation reports
state both requested and stored scopes, the requested requirement, every
completeness dimension, the register revision, exact register/schema byte
digests, the authoritative profile-snapshot digest, and the coverage catalog's
exact-byte and semantic-snapshot digests. Register, coverage, and schema inputs
are read through bounded regular-file descriptors with final-component symlinks
refused and pre/post identity checked. These hashes identify the bytes read; they
neither sign those bytes nor make the checkout immutable. The loaders reject
external schema references, aliases, duplicate keys, non-finite numbers, unsafe
Unicode, and over-budget input trees. Relationship evidence is restricted to
existing repo-relative ATX CommonMark headings. Evidence documents are capped at
128 KiB and 20,000 logical lines. Because v1 evidence fragments are ASCII,
heading-slug validation accepts ASCII text and removable non-ASCII dash
punctuation; any other non-ASCII heading text is rejected rather than guessed.
The v1 stored scope is fixed to `pr97-readers`; `full` is a permitted requested
target, while the default full/complete check remains nonzero until a later
schema owns the complete module/source/runtime anchors. Alternate `--schema` and
`--coverage-schema` paths may relocate their canonical schemas but cannot
redefine them: their bytes must match the independently pinned digests.
`--coverage` may likewise select the catalog snapshot whose bytes the report
identifies. Argument errors fail loudly on stderr with exit `2` and may use
argparse's plain text; loader/input errors use a validation-error JSON object on
stderr. Silence is never success.

For Python callers, `validate_register(registry, inventory, ...)` retains its
original call shape and strictly loads the canonical coverage snapshot when the
new third argument is omitted. `CoverageInventory`, `load_coverage_inventory`,
and `snapshot_coverage_catalog` are exported for callers that need to validate
an explicit alternate snapshot.

## Reader safety register

The checkout-only [reader-safety register](../safety/README.md) inventories
requirements that remain permanently unverified by the checkout for the named
PR97 caller-file reader surfaces. Its integrity check proves only
correspondence to those named PR97 checkout surfaces. It provisions no approved
input root, stable nofollow snapshot, trusted custody/classification, egress
denial, ambient-credential isolation, independent hard kill/monitoring,
untrusted-content boundary, or grader-plane separation. It grants no authority
and does not satisfy `SAFE-01`. The checkout cannot produce a passing `ready`
result.

That safety inventory is not `EVID-01` trusted observation, custody, or grading
evidence; `GOV-01` source/runtime promotion or currentness; or `DATA-01` /
`DATA-02` source admission, rights, snapshot, and denied-egress evidence. Those
gates remain independent.

The promotion-event shape reserves the subject and contract digests,
implementation revision, reviewer, exercised path, regression result, supported
versions, source revisions, and accepted limitations needed by a future
verifier. V1 checks internal consistency only: it cannot authenticate a reviewer
or prove that a named artifact, regression, or path exists and was exercised.
It therefore refuses every nonempty promotion event and every state that needs
promotion with `promotion-verifier-unimplemented`. No v1 promotion is
authoritative. Research records legitimately have no promotion event, and the
three registers remain independent.

## Attributed review history (U-GOV.b, 2026-10-18)

`governance/reviews.py` is a revision-bound attributed review-history
verifier, separate from the `governance check` promotion/currentness
checker above. It reconciles the full authoritative population —
109 sources + 29 modules + 227 runtimes = 365 entities, each with three
declared triggers = 1,095 entity/trigger pairs — against the committed
initial import `governance/reviews/2026-10-13.attributed.json`
(schema `governance/schema/review-evidence.v1.schema.json`, closed).

Every record's evidence files and its authoritative
`governance/register.v2.yaml` resolve from offline local Git objects at
that record's exact 40-hex `inspected_revision` (absolute binary,
subprocess argv, local `cat-file`/`ls-tree` only, no fetch or network),
never from the working tree and never from a caller-supplied path. Git
runs with a fresh closed environment (no ambient copy): neutral
system/global config, `GIT_NO_LAZY_FETCH=1`, prompts and optional locks
disabled, deterministic C locale, `--no-replace-objects` before `-C`,
and stdin closed, so ambient `GIT_DIR`/`GIT_WORK_TREE`/
`GIT_OBJECT_DIRECTORY`/config redirection, local replace refs, and lazy
promisor fetches cannot change the result; legitimate linked-worktree
discovery still resolves from the filesystem. Only `cat-file`/`ls-tree`
are admitted; anything else is refused. The former `--register` and
`--review-schema` overrides are removed: the CLI accepts only
`--history`, `--as-of`, and `--require`, the schema is always the
digest-pinned canonical bytes, and each record reconciles against its
own revision-bound epoch register (parsed and semantically validated
with Draft7 FormatChecker, including duplicate identities, exact
per-class trigger sets, and one-check-per-trigger cardinality). Exact
source and module IDs are checked against the frozen v2 authorities;
runtime rows must match their sorted 227-ID inventory, preserve
`capability_id == arm_id + "." + action`, and match the independently
pinned genesis roster in every appended epoch. Coordinated substitutions
therefore fail even when all 365 entity and 1,095 pair counts stay the
same. A revision must be a commit, each tree entry a regular blob
(symlinks/submodules refused), sizes bounded, and digests, lengths, and
heading anchors checked against the exact blob bytes; missing
commits/paths, ambiguous or non-blob entries, decode/parse failures,
oversized blobs, and digest differences fail closed. Blobs are cached
per unique revision/path pair, so Git never runs per observation. The
pinned schema file is traversed from an anchored repository directory
fd with no-follow semantics for every component and `O_NONBLOCK` on the
final open (FIFO/device substitution is refused without hanging); the
history file itself stays an explicit bounded input with no
repository-custody claim. That no-follow directory-fd custody path is
verified on POSIX; native Windows verifier compatibility is not yet
established.

Strict duplicate-key JSON parsing applies throughout, and every NaN,
infinity, and overflow-to-infinity value (including JSON `1e999`) is
rejected recursively before schema validation. The checker fails closed
on malformed/unknown/duplicate/missing entities or triggers, changed
referenced evidence bytes, future observations, broken predecessor
links, an altered pinned initial history, and unsupported positive
outcomes.

The committed artifact faithfully imports the already recorded
2026-10-13 attribution from the canonical register and
`docs/governance/source-verification-2026-10-13.md`, and distinguishes:

- `reviewed_on: 2026-10-13` — imported historical attribution;
- `recorded_on: 2026-10-18` — the actual import record;
- the inspected revision (`7499dd12cdc87efc93d7a53d51b5dd785a27221d`)
  with sha256-bound evidence files as recorded on 2026-10-18.

This JSON artifact, its checker, and their hashes did not exist on
October 13. The source document's historical wording discrepancy is
preserved as an explicit limitation: it says 30 module rows while the
verified current population is 29. The canonical initial record digest
is pinned independently in `governance/reviews.py`; later records bind
their predecessor digest. The immutable envelope identity (`schema`,
`schema_version`, exact `history_id`) is pinned together with the
genesis record — in code and, via a `const`, in the closed schema —
while only records may append. Historical declarations, newly executed
checks, unknown outcomes, and limitations stay in separate sections.
Reviewer attribution is evidence, not authentication.

Epoch trigger semantics are exact for v1 (a policy change needs a
later explicit version, not silent acceptance): source rows carry exactly
`upstream-revision-change`, `license-or-data-rights-change`,
`link-or-availability-change`; module rows carry exactly
`criteria-or-threat-change`, `scenario-or-grading-change`,
`dependency-or-source-change`; runtime rows carry exactly
`profile-contract-change`, `implementation-or-dependency-change`,
`supported-version-change`. Exactly one `trigger_check` is required per
declared trigger (duplicate checks fail even when other fields differ;
orphan check names fail), and exactly 1,095 pairs are required per
epoch. Coverage/count reporting describes the latest record, never the
union of earlier complete observations, so a latest-record gap stays
visible.

Epoch currentness dates are validated with Draft7 FormatChecker plus
semantic checks: every `reviewed_on`/`review_due_on` must be a real
calendar date, `reviewed_on` < `review_due_on`, and `reviewed_on` cannot
be after the enclosing record's `recorded_on`. Each due must equal its
`reviewed_on` plus the epoch queue cadence (source 90 days, module 182
days, runtime 90 days), and those three values are fixed v1 policy:
rewriting a cadence and every matching due consistently still fails
integrity and requires a later explicit version. `next_review_on` must
equal the earliest governed due date, so the recorded cadence is
actually verified. For
`historical-declaration` observations, `observed_on` must equal that
entity's epoch `reviewed_on` as well as the record `reviewed_on`.

The base checker hashes currentness into promotion subject/contract
digests, so this unit never rewrites those frozen snapshots and never
overlays effective currentness. The initial import establishes
integrity and full coverage only: schema/history v1 defines no
independently verifiable executed-result protocol, so
`recurring_operation_ok` remains false for every history — including a
different/descendant/unrelated commit with all 1,095 observations
relabeled to `executed-check`, advanced dates, and copied pass
declarations, which is still a replay. A record asserting recurrence
true fails integrity as an unsupported positive. `--require recurrence`
stays an honest explicit exit-1 requirement; a future version enables
it only by defining and binding a closed executed-result artifact whose
dated results reconcile one-to-one to all governed pairs. Strict
chronology is integrity, independent of recurrence: each record needs
`recorded_on >= reviewed_on`, and a successor whose dates move
backwards or overlap its predecessor fails. Reported next dues:
source/runtime `2027-01-11`, module `2027-04-13` for the initial import.
For later valid epochs, each class field reports its earliest obligation
from the latest validated epoch; a staggered later deadline cannot hide
an earlier row. No W2, admission, or promotion work is implemented here,
and no forward ancestry is added as an integrity policy: ancestry alone
is not specified and does not fix recurrence.

```bash
python3 -m governance.reviews check \
  --history governance/reviews/2026-10-13.attributed.json \
  --as-of 2026-10-18 --require integrity   # exit 0
python3 -m governance.reviews check \
  --history governance/reviews/2026-10-13.attributed.json \
  --as-of 2026-10-18 --require coverage    # exit 0
python3 -m governance.reviews check \
  --history governance/reviews/2026-10-13.attributed.json \
  --as-of 2026-10-18 --require recurrence  # exit 1: not established
```

Exit `0` means only the requested requirement passed; `1` means the
history has gaps for it; `2` means the history, schema, arguments, or
Git environment are invalid. Causal coverage lives in
`tests/test_governance_reviews.py`: tmp history copies plus synthetic
offline Git clones for every historical-file transition (never a
tracked-file write), including the empty-commit relabel construction
(different/descendant/unrelated commits, all 1,095 relabeled
observations, advanced dates, copied passes, asserted-true refusal),
ambient repository/object/config redirection, local replace refs,
missing promisor blobs without fetch, exact trigger sets with one
removed trigger/check/observation (1,094), duplicate versus orphan
checks, latest-record counts, invalid-calendar/inverted/future windows,
due cadence and queue-next enforcement, historical observed_on binding,
substitute/duplicate registers, substitute schemas with unknown fields
and `1e999`, revision-bound evidence across later working-tree edits,
missing/wrong revisions and blobs, symlink substitution, FIFO refusal
without hanging, backdated successors, and renamed envelopes. No test
claims a satisfiable positive recurrence in v1.

## Executed review results (U-GOV.d, 2026-10-19)

`governance/result.py` is the revision-bound executed-review-result
verifier for the closed review-result v1 protocol (schema
`governance/schema/review-result.v1.schema.json`, byte-pinned by the
verifier). It reconciles one result cycle's dated `executed-check`
outcomes one-to-one against the exact governed population — 109 sources
+ 29 modules + 227 runtimes = 365 entities, each with three declared
triggers = 1,095 entity/trigger pairs — at that cycle's own
revision-bound register epoch, re-hashes sha256-bound evidence from
offline local Git blobs at the cycle's exact 40-hex `inspected_revision`
(same closed `cat-file`/`ls-tree` environment as U-GOV.b, never the
working tree, never a caller-supplied path), checks heading anchors,
cross-checks each row's `checked_via`/`evidence_ref` against the epoch
register's declared trigger check (as in U-GOV.b, mismatches fail as
`observation-mismatch`), requires the epoch at the same revision to
record the cycle date itself (a 2027-04-14 cycle against the stale
2026-10-13 epoch fails as `epoch-cycle-mismatch` without advancing the
register), binds the cycle to the independently pinned v1 genesis record
digest, and refuses premature cycles, stale epochs, future observations,
and unsupported positive claims. The epoch runtime roster is anchored to
the register at the pinned genesis inspected revision, so coordinated
substitutions that preserve every count still fail. Resource bounds mirror
the history verifier (1 MiB result/evidence/register blobs, 40,000 nodes,
bounded blob cache with one fetch per unique revision/path pair).
The JSON report keeps the fixed policy cardinalities visible when a cycle's
register cannot be validated, and marks `counts.epoch_validated=false` so
those policy counts are not mistaken for a reconciled epoch population.
Reported dues (`next_due`, `queue_next_review_on`) are the epoch
register's dues at `inspected_revision` with explicit
`cycle_reviewed_on`/`epoch_reviewed_on` provenance
(`provenance: epoch-dues-at-inspected-revision`), not a post-cycle
projection: they predate the cycle when the epoch was not advanced, and a
complete cycle advances the epoch so they lie after the cycle date.

A cycle additionally names a new
`governance/reviews/executed/<review-date>.<id>.json` source blob. The
closed schema requires 1,095 detailed, dated result rows in that blob;
the verifier checks its Git bytes and digest, requires that the path was
absent at the genesis revision, and compares every source row to the
caller-selected cycle summary. A different or empty commit that only
relabels the 2026 trigger metadata cannot supply this source and fails.

What the protocol proves, and what it does not:

- **Protocol**: the closed shape a genuine re-review cycle must take
  and the checks that decide it. A well-formed future cycle verifies
  `complete`; causal coverage lives in
  `tests/test_governance_result.py` (tmp cycle files plus a shared
  synthetic offline clone for epoch variants, never a tracked-file write),
  covering duplicates, missing/extra pairs, wrong entities/triggers,
  checked_via/evidence_ref mismatches against the epoch declaration,
  stale epochs against complete-looking cycles, non-executed bases, date
  and digest tampering, unbound evidence, premature dates, empty-commit
  relabels, mismatched or missing executed sources, reused genesis
  revisions, broken history bindings, substitute schemas, non-finite
  numbers, and missing/wrong Git revisions/blobs. A new evidence file
  binds only when the same-revision epoch declares its anchor; an
  undeclared new anchor fails as `observation-mismatch`.
- **Operation**: no executed cycle has been performed under this
  protocol. The committed tree ships **no result artifact**, the
  governed source/runtime dues (`2027-01-11`) and module due
  (`2027-04-13`) are unsatisfied, and the v1 history verifier's
  `recurring_operation_ok` remains false. A cycle dated before the
  latest governed due date (`2027-04-13`; v1 defines only
  full-population cycles) fails closed as `cycle-too-early`, and new
  dates on the exact genesis revision or an empty successor fail as
  relabeled replays, so recurrence stays false before genuine future
  cycles. Fail outcomes do
  not block completion by themselves: the protocol verifies custody,
  one-to-one reconciliation and internal consistency of attributed result
  records, not that every check passed. Reviewer attribution is evidence,
  not authentication; the verifier cannot prove the human checks occurred or
  that their conclusions are true. Independent review of the source content
  remains necessary when an actual cycle is recorded.
- **W1/W2 closure**: this unit closes neither. No source admission, no
  runtime/module promotion, no shipment or support claim, and no W2 work
  is implemented here; the twelve frozen 2026-10-14 promotion snapshots
  are never rewritten.

```bash
# No tracked result artifact exists, so there is nothing to check yet:
# every --require against a future cycle file reports on that file only.
python3 -m governance.result check \
  --result /tmp/<future-cycle>.json \
  --as-of 2027-04-16 --require complete
```

Exit `0` means only the requested requirement passed (`integrity`,
`coverage`, or `complete`); `1` means the cycle has gaps for it; `2`
means the result file, schema, arguments, or Git environment are
invalid. The v1 history check above is unchanged: its bytes, digests,
and verdict are preserved, and a future history version — not a result
file alone — is what could one day bind a completed cycle to
recurrence.

## Promotion qualification contract (U-GOV.e, 2026-10-19)

`governance/qualification.py` defines and verifies the intended
admission/promotion decision contract over the twelve frozen
2026-10-14 historical promotion events in `register.v2.yaml`. The
criterion set is EXACTLY
[`candidate_admission.REQUIRED_ADMISSION_FIELDS`](../candidate_admission/admission.py),
imported by identity as the sole criterion authority — no new taxonomy.
The GOV-01 item-3 clause "owner, regression, side-effect and egress
contracts enforced" names four elements (`named_owner`,
`regression_case`, `side_effects`, `egress`) already inside that field
set: it is emphasis, not an addition. Each loaded event is projected
onto those criteria with fail-closed attestation states:

- `evidenced` — the criterion is attested in bounded form and, for the
  six executed criteria (`regression_case`, `side_effects`, `egress`,
  `named_owner`, `code_license`, `data_rights`), a valid executed-evidence
  store record with outcome `passed` also resolves;
- `partial` — declared or cited but not executed: on all twelve events
  `regression_case` is partial with outcome `authorized-not-executed`
  (`verification_result: operator-authorized` is not an executed
  outcome; citations resolve to recorded files and existence is never
  execution proof), and `revision_hashes` is partial because
  `source_revisions` are git commit pins, not sha256 content digests
  (the admitted-slice content digests live on the source rows, not on
  the events);
- `unevidenced` — the event carries nothing for the criterion: a
  selection/admission decision records no `data_classification`,
  `action_surface`, `cost_behavior`, `cleanup_semantics`,
  `provenance_semantics`, test cases, owner (`reviewer` attribution is
  not ownership), side-effect/egress contract, or independent
  promotion evidence (the event's own id is its row's
  `promotion_evidence` citation; self-reference satisfies nothing);
- `contradicted` — `code_license` and `data_rights` on all twelve:
  every frozen decision accepts `no-license-or-data-rights-clearance`,
  so the events affirmatively document non-clearance, which no protocol
  output can un-document.

An event qualifies only when every criterion is evidenced AND the
executed-evidence store returns outcome `passed` for the regression,
egress, side-effects, rights, and owner criteria. The outcome over the
shipped tree is **computed, not asserted: zero of twelve qualify**, and
it falls out of that conjunction — never a hardcoded count. The nearest
pair is R01/R43 (the two admitted events whose rows pin re-derivable
content digests), and they still carry the full seventeen unmet
criteria: rights contradicted, regression authorized-not-executed, and
thirteen unevidenced contract fields. Roster enforcement is read-only:
each loaded event's canonical-JSON digest is recomputed and compared
only against the frozen `V2_AUTHORIZED_PROMOTION_EVENTS` literals in
`check.py` (never against digests derived from the register), so any
thirteenth event, missing event, subject binding break, or digest drift
fails as `qualification-roster-mismatch` /
`qualification-event-digest-mismatch` and halts the assessment
fail-closed. Freezing alone satisfies nothing: snapshot fidelity is not
qualification evidence, and a synthetic qualifying event under a
synthetic store does qualify, proving the conjunction is real.

Executed-evidence protocol: the store maps a recomputed event digest to
records `{criterion, ref, outcome, dated_on, content_sha256}`; a record
counts only when its `ref` matches the reserved convention
`governance/reviews/executed/<event-id>.<YYYY-MM-DD>.json` (the frozen
event ids already begin with `promotion-`; the filename date must equal
the record's `dated_on`) and resolves through the bounded
no-follow file snapshot to bytes matching `content_sha256`, its outcome
is exactly `passed`, and its `dated_on` is on or after the event's
`decided_on`. Event citations (`verification_result`,
`regression_case`, `exercised_path`) are never resolved as references
or paths. The shipped default is `NULL_EVIDENCE_STORE` — nothing
satisfies it. The future path for executed evidence is triple-code-gated
(roster table + anchor table + committed artifact under the reserved
prefix, each requiring a reviewed code change): nothing is shipped in
this increment, and no `governance/reviews/executed/` directory or
artifact exists.

What this contract does not do: it grants no promotion authority and
no admission, shipment, or support claim; the register is never mutated
and its YAML is never re-parsed (assessment is read-only over
`Registry.document` copies); the R15/R38 refusal decisions are
preserved untouched (no event subjects them); the register inventory
and the frozen event snapshots are not operational promotion evidence;
reviewer attribution is not authentication; and source-plane events
never imply runtime or module admission (a `module:` or `runtime:`
subject is refused, not assessed). A decision dated after the assessed
`--as-of` fails integrity, so a population cannot be qualified as of a
date before its decisions existed.

```bash
# Read-only assessment of the frozen twelve; integrity holds today.
python3 -m governance.qualification check \
  --as-of 2026-10-14 --format json                      # exit 0
# No event qualifies under the shipped null evidence store.
python3 -m governance.qualification check \
  --as-of 2026-10-14 --format json --require qualify    # exit 1
```

Exit `0` means the requested requirement passed, `1` means the
population has gaps for it (today: every event carries unmet
criteria), and `2` means the arguments or register input are invalid.
There is no `--register` override: the assessment always reads the
canonical register v2 through its bounded loader. Causal coverage lives
in `tests/test_gov_qualification.py`: roster/drift negatives via
in-memory deep copies only, plane-independence refusals, the
limitation-drop and reference-swap non-flips, the tmp_path positive
control with missing/failed/mismatched store variants, one full
register validation, and a tracked-file tripwire.
