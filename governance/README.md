# Governance register

This directory is a repository-maintainer surface. It records module, source,
runtime, relationship, currentness, and promotion evidence; it grants no
execution authority and is not imported by `extension` or the sealed runtime.
The executable admission authority remains
`extension.invoke_profiles.INVOKE_PROFILES`.

`register.v1.yaml` is deliberately partial. Its detailed records cover the 14
research readers added in PR 97: 14 `list_tools` capabilities and 38 local-data
actions. Its inventory section separately binds the exact semantic snapshot of
all 212 admitted profiles so removal or profile drift cannot look like a clean
governance check. The source records are research candidates, not selected or
admitted upstream material. Their `research-mapping` relationships assert no
consumption, compatibility, provenance, custody, license, or data-rights claim.

For this PR 97 slice, the checker also loads `extension/coverage.yaml` against
the independently pinned canonical coverage-schema bytes. It requires the exact
14 reader ids and their `arm` / `[cli]` / curated / research classifications,
reconciles each classification with all 52 detailed register and authoritative
profile records, binds every real specialized handler's canonical immediate
truthy-payload refusal structure, and exercises both `list_tools` and
`tools/list`. The full 63-row catalog is not globally frozen: the report binds
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

The promotion-event shape reserves the subject and contract digests,
implementation revision, reviewer, exercised path, regression result, supported
versions, source revisions, and accepted limitations needed by a future
verifier. V1 checks internal consistency only: it cannot authenticate a reviewer
or prove that a named artifact, regression, or path exists and was exercised.
It therefore refuses every nonempty promotion event and every state that needs
promotion with `promotion-verifier-unimplemented`. No v1 promotion is
authoritative. Research records legitimately have no promotion event, and the
three registers remain independent.
