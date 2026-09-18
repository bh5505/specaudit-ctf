# PR97 reader safety register

This directory is a checkout-only maintainer surface for the 14 caller-file
readers introduced in PR 97. It binds 14 static `list_tools` profiles and 38
local-data actions to their exact policy, invoke-profile, coverage, governance,
source, research-relationship, and named reader-implementation records. It is
not packaged by `pyproject.toml`, is not imported by `extension`, and changes no
runtime action.

The register is deliberately and permanently unverified in v1. Its integrity
result means only that the checked-out safety description still matches the
independently frozen PR97 surface. It does not prove an operator environment,
approve a caller path or artifact, establish custody or classification, grant
execution or data authority, or satisfy `SAFE-01`.

## Commands and exit contract

Run from a development checkout with the dev dependencies installed:

```bash
# Closed schema, exact 14/38 inventory, and five scoped surface projections.
python3 -m safety check --scope pr97-readers --require integrity \
  --as-of 2026-09-09 --format json

# The default readiness requirement is intentionally nonzero in v1.
python3 -m safety check --scope pr97-readers --require ready \
  --as-of 2026-09-09 --format json
```

`--require` defaults to `ready`; `--as-of` is always required so later versions
cannot silently rely on wall-clock state. For an executed `check`, exit `0` means
the explicitly requested condition passed, exit `1` means a schema-valid
register has integrity or readiness gaps, and exit `2` means arguments, input
bytes, schema, a canonical surface, or the checker itself failed. Executed
checks with exits 0 and 1 always write a complete JSON report to stdout. Exit 2
writes a JSON error to stderr. Silence is never success. Standard `-h` / `--help`
requests are not checks: argparse prints usage prose and exits 0 without loading
or validating any surface.

Only the safety `--register` and a byte-identical canonical `--schema` can be
relocated. Coverage, governance, profile, handler-selection, dispatch, shared
reader-helper, and per-reader package/implementation/policy files are read as
data from fixed checkout paths. Governed `extension` modules are never imported
by this checker. The validator freshly reloads the register and rereads every
named source before reporting provenance; self-consistent caller-supplied hash
objects are not authority.

The reader-runtime projection is an exact-byte implementation binding for the
named files, not a transitive Python import closure or proof of loaded-code,
dependency, transport, result-envelope, or environment behavior. Whole-file
hashes identify the bytes read; they neither sign the checkout nor make it
immutable. A locally modified checker can of course modify its own literals, so
independent review of a deliberate baseline update remains part of the gate.

## What v1 records

Every reader remains exposed to the common requirements below:

- an approved input root;
- a stable no-follow input descriptor, immutable copy, or directory snapshot;
- trusted input custody and data classification;
- denied egress and removal of ambient credentials;
- externally enforced resource limits and independent monitoring;
- a boundary that treats parsed hostile content only as data; and
- exclusion of reusable secrets from inputs and derived channels.

`detection-in-the-cloud` additionally records directory-snapshot drift.
`collinear` additionally requires grader-plane isolation so the learner or agent
cannot read expected findings or trace keys. All controls have
`status: unverified` and empty evidence. The closed schema rejects any attempt to
change those facts; accepting verified evidence requires a new schema and a real
verifier.

The checker intentionally duplicates the 14 arms, 38 data-action/input
contracts, source mappings, profile membership and lookup expectations, handler
classes, policy modules, field rosters, hazard/control assignments, and expected
semantic and source digests. It does not import the governance checker's PR97
expectation maps or execute the extension modules. Changing a named checkout
surface and the safety YAML together therefore remains red until the independent
checker baseline is also reviewed deliberately.

Operational requirements and the still-open exit intent remain authoritative in
the [operations guide](../OPERATIONS.md) and [program roadmap](../PROGRAM.md).
The [extension guide](../extension/README.md) describes the callable reader
surface; the [governance guide](../governance/README.md) describes the separate
GOV-01 state. None of those documents grants execution authority.
