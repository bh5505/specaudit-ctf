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
# Validates the closed schema, exact inventory, PR97 roster, action surfaces,
# profile contracts, relationships, and promotion invariants.
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
digests, and the authoritative profile-snapshot digest. Register and schema
inputs are read through bounded regular-file descriptors with final-component
symlinks refused and pre/post identity checked. These hashes identify the bytes
read; they neither sign those bytes nor make the checkout immutable. The loader
rejects external schema references, aliases, duplicate keys, non-finite numbers,
unsafe Unicode, and over-budget input trees. Relationship evidence is restricted to existing
repo-relative Markdown headings. The v1 stored scope is fixed to
`pr97-readers`; `full` is a permitted requested target and remains nonzero until
a later schema owns the complete module/source/runtime anchors. Argument errors
fail loudly on stderr with exit `2` and may use argparse's plain text;
loader/input errors use a validation-error JSON object on stderr. Silence is
never success.

The promotion-event shape reserves the subject and contract digests,
implementation revision, reviewer, exercised path, regression result, supported
versions, source revisions, and accepted limitations needed by a future
verifier. V1 checks internal consistency only: it cannot authenticate a reviewer
or prove that a named artifact, regression, or path exists and was exercised.
It therefore refuses every nonempty promotion event and every state that needs
promotion with `promotion-verifier-unimplemented`. No v1 promotion is
authoritative. Research records legitimately have no promotion event, and the
three registers remain independent.
