# Telecom offsec loopback pack

This is the declarative, synthetic-test mirror of the AuditPack
`ext_telecom_offsec` external pack. It combines AWS posture, ASM/VM
reconciliation, and receipt-backed Technology validation under one pack identity.
The product pack in AuditPack is the
authoritative source for these declarations.

The mirror includes the 41-check manifest, mappings, classifier hints, migrations,
checks, audit program, and workpaper declarations needed for local loopback
validation. It contains no customer exports, live target list, credentials, or
authority to probe a system. CTF action admission remains governed by
[`OPERATIONS.md`](../../OPERATIONS.md) and the extension runtime.

The two Technology checks reconcile selected AWS, GCP, and Azure source
findings with validator results for the same project, engagement, finding,
source run, inventory snapshot, resource, and account. The separate
[technology validator fixtures](../../tests/fixtures/technology_validator/README.md)
exercise the production probe evaluator with synthetic provider replies. Live
cloud reads and receipt creation belong to the AuditPack validator
binary in an explicitly authorized environment.

Run the checks on synthetic evidence with
`python tools/ctf_run_checks.py --pack packs/ext_telecom_offsec --evidence-dir
<synthetic-evidence-dir> --out-dir <output-dir> --db sqlite`. The same check SQL
also runs under DuckDB when installed. The loopback report is a test artifact;
it is not a product ingest or deployment result.

New reports use the `ext_telecom_offsec` pack ID and renamed check IDs. Old
pack IDs and aliases are not supported by this mirror.
