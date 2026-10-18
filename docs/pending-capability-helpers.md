# Pending-capability Python helpers

These installed Python APIs support development of the proposed campaign in
[PROGRAM.md](../PROGRAM.md#proposed-roadmap). They are standalone library
functions, with no new CLI action, MCP tool, invoke profile, runtime caller,
source promotion or challenge-grading integration. Existing operator workflows
remain the entry points for execution. Importing a helper grants no authority.

The helpers validate supplied records and calculate over supplied measurements.
They do not authenticate an author, resolve an evidence reference, run an
experiment, enforce a sandbox, or establish professional audit assurance.
Result limitations travel with positive results. A structurally valid record
must not be used as proof that its declared event happened.

## APIs and evidence limits

| Module / function | What it checks or calculates | What remains outside this API |
|---|---|---|
| `audit_workpaper.grade_workpaper` | Typed evidence and claim references, bounded scope, structural rubric, and separately attributed human adjudication bound to the document digest | Evidence/source authenticity, actual human review, calibration and professional assurance |
| `attempt_ledger.risk_metrics.compute_risk_sensitive_metrics` | All-row execution counts and finding metrics from explicit truth and adjudicated disposition labels, including unknown coverage and joint strata | Ledger authentication, finding adjudication and completeness of the source attempt population |
| `caller_path_binding.bind_caller_path` | Digest/length of supplied bytes and well-formed declared attempt, locator and collection metadata | Reading the locator, approved-root enforcement, actual handler consumption, verified custody and durable replay rejection |
| `candidate_admission.validate_candidate_admission` | Required admission fields, digests and nonempty typed test/evidence references | Rights clearance, execution of the referenced tests or a governance promotion |
| `promotion_verifier.verify_promotion` | Promotion-record shape and field values, including digest grammar and declared passing regression | Reviewer authentication, existence of artifacts/results and authorization to change an existing register |
| `frozen_slices.validate_vuln_slice` / `validate_rule_slice` | Metadata fields, SHA-256 grammar, explicit source time and declared read/fallback/control contracts | Rederiving corpus bytes/counts, freshness at a consultation time or empirical denied-egress/no-mutation results |
| `containment_evidence.verify_containment` | Required declared control records, bounded references and reported pass/fail outcomes, including extra declared controls | Independent measurement, enforcement or SAFE-01 acceptance |
| `deliverable_substrate.validate_deliverable` | Required component types and artifact-manifest bindings | Existence/delivery of the referenced pack, learner accessibility or a unified product workpaper engine |
| `formal_assessment.validate_formal_assessment` | Typed assessment, review, calibration, dry-run and isolation references | Proof that reviews, calibration, learner separation and the dry-run actually occurred |
| `telecom_case.validate_telecom_case` | Stable identity, a declared TEL module and substantive typed sections | Delivery/promotion of a governed telecom exercise or activation of a private product pack |
| `challenger_head.run_experiment` | Comparison of supplied finite measurements on the same declared frozen holdout identity and digest | Running a head, authenticating measurements, satisfying prerequisites, enforcing a budget or integration authority |

`capability_records` supplies bounded value predicates shared by these new
record helpers. It does not replace any existing governance or safety schema.

## Workpaper structure and human review

`grade_workpaper(document, *, evidence_bytes=None)` keeps structural validity
separate from the human verdict. Missing human adjudication remains `pending`;
it cannot produce an overall quality pass merely because all sections exist.

Evidence entries have stable `id`, a lowercase 64-character `sha256`, `kind`
(`observed`, `declared` or `inferred`), attributable source/version/time/custody
metadata, limitations, and subject/population/period. Claims and finding,
non-finding and inconclusive records cite existing `evidence_ids` and the same
bounded subject/population/period. A nonempty conclusion also carries
`conclusion_evidence_ids`. Optional supplied artifact bytes allow digest
rederivation; absent bytes remain a visible verification limit.

The first structural result supplies `review_subject_digest`. A supplied
`human_adjudication` records reviewer, rationale, ISO `decided_on` date, that
`document_digest`, and boolean `evidence_sufficient` and `supportedness`
judgments. The digest excludes the adjudication itself, so changing the reviewed
document invalidates the binding. This is a caller-declared review record;
neither a name nor a digest authenticates a reviewer or establishes calibration.
Human and machine verdicts remain separately visible.

## Risk-sensitive metrics

Verify the existing ledger with `attempt_ledger.verify_ledger` before passing
its rows to the metrics function. A completed attempt can have a failed grade;
completion therefore contributes to execution counts, not to finding truth.

`AttemptLabel` carries caller-supplied `is_true_finding`, `severity`, and
`adjudicated_disposition` (`present`, `absent` or `unknown`). A true high/critical
finding adjudicated absent is a critical miss; a benign subject adjudicated
present contributes false review burden. Missing truth or disposition is
reported as unknown, with coverage counts, rather than treated as a clean
result. Every row stays in the denominator, including refusals, timeouts,
failures, stops and abstentions.

False review burden is an unweighted count: each benign row adjudicated present
counts once regardless of its severity label. It does not estimate review time
or apply a severity weight.

The label's `evaluation_split` is separate from the ledger's legacy assistance
classification. Joint strata preserve lane and assistance distinctions rather
than reconstructing comparisons from marginal counts. Retry labels can bind a
specific retained `row_digest`; ambiguous retry attribution must not silently
reuse one outcome. Saturated public subjects remain `regression-only`.

## Record formats

SHA-256 references use `sha256:<64 lowercase hexadecimal characters>` unless a
field explicitly names the raw `sha256` value above. Source timestamps use
RFC3339 with an explicit timezone. Blank strings, false/null placeholders,
malformed nested entries and over-budget structures are rejected.

A deliverable's `evidence_manifest` is a mapping with a nonempty `artifacts`
list. Each artifact binds `artifact_id`, `path`, `digest` and `media_type`.
Formal assessment uses named `{reviewer, review_ref}` records, calibration
`{reviewer, evidence_refs}`, a dry-run `{status: "pass", result_ref,
evidence_refs}`, and isolation records `{state: "proven", evidence_refs}`.
Those state words are declarations whose references remain unverified by the
pure helper. Actual qualification remains governed by the
[challenge authoring contract](../challenges/README.md#validation-and-promotion).

## Remaining campaign gates

Use the existing [reader acquisition, ledger and evidence-chain
mechanisms](evidence-and-evaluation-2026-10-13.md), canonical governance
registers and containment implementation when completing the later campaign
units. The read-only source admissions already recorded for synthetic slices
do not authorize upstream corpus redistribution or maintained runtime support.

HEAD-01 still requires accepted EVAL-01, SAFE-01 and PACK-01 evidence, a
measured gap, one new frozen holdout, the same capabilities/evidence rules and
aggregate budget, and at most one experiment or explicit deferral. A numeric
`recommendation` is comparison output with no execution or promotion authority.
