# Technology validator fixtures

Run the compiled validator binary against the synthetic cases:

```bash
python3 tools/validator_technology_harness.py \
  --validator-bin /absolute/path/to/validator-binary
```

The harness reads `manifest.json` and reports one pass or failure per case. A
single case can be selected with `--case aws_ssh_public.case.json`. A missing
validator binary is an error; this suite is not a replacement for compiling
the Rust validator.

Each case passes a synthetic candidate and explicit scope to the validator's
`--evaluate-technology-fixture` entry point. Provider response files contain
raw JSON objects. GCP bundles capture effective configuration, project and
bucket identity, and bucket IAM policy replies. Azure bundles capture cloud,
account, and NSG replies. The Rust fixture path feeds them to the production
evaluator in memory and does not launch a provider executable. The harness
checks a small result projection. A preflight refusal must assert that no
provider command was planned. An identity mismatch discovered in a supplied
provider reply asserts that the necessary read was planned; the fixture path
still executes no provider process. The harness does not decide whether a cloud
configuration is public.
Those decisions are made by the same Rust parser and evaluator used by the
live technology probes.

The cases cover a public S3 bucket ACL and the same grant blocked by all four
bucket BPA controls, both with and without synthetic anonymous-access replies;
public and private AWS security-group rules, including
IPv6 RDP; public, scoped, and conditional GCP bucket IAM; Azure public and
private NSG rules,
a replaced saved rule, list-only source and port ranges, and priority
uncertainty; and missing or mismatched authorization, provider identity, and
claim identity. GCP and Azure nonzero provider exits remain inconclusive even
when the captured reply looks positive.
GCP candidates use the CAI bucket UID `//storage.googleapis.com/demo-bucket`.
The captured project and bucket responses must bind to the explicitly scoped
project number. Foreign bucket identities and malformed bucket UIDs fail closed.
For Azure, the candidate and finding detail `account_id` are the tenant GUID
emitted by the collector. The NSG resource ID and provider account response
carry the separate subscription GUID. Cases check wrong or missing tenant
scope, a subscription mismatch in the NSG resource ID or provider response,
an NSG response that returns the right name under a different subscription,
and case-insensitive UUID matching across the tenant and NSG resource ID.
The positive and private GCP/Azure cases omit `details.reason`, as the
producing checks do; separate changed-reason cases require a command-free
inconclusive result.
`configuration_status` only describes the observed configuration. S3 cases
with supplied anonymous replies exercise the validator's reachability
classifier, but do not prove access to a real bucket. All other cases report
`reachability_status: unknown`; they do not prove internet reachability or
access to a workload. No case targets a live cloud account, network endpoint,
or engagement. The harness supplies no provider executable or credentials.
