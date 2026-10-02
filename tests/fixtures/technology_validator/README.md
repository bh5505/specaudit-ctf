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
raw JSON objects. GCP and Azure bundles capture configuration, identity, and
policy or NSG replies; the Rust fixture path feeds them to the production
evaluator in memory and does not launch a provider executable. The harness
checks a small result projection and, where relevant, absence of a planned
live command. It does not decide whether a cloud configuration is public.
Those decisions are made by the same Rust parser and evaluator used by the
live technology probes.

The cases cover a public S3 bucket ACL and the same grant blocked by all four
bucket BPA controls, both with and without synthetic anonymous-access replies;
public and private AWS security-group rules, including
IPv6 RDP; scoped and conditional GCP IAM; Azure public and private NSG rules,
a replaced saved rule, and priority uncertainty; and missing or mismatched
authorization, provider identity, and claim identity.
The positive and private GCP/Azure cases omit `details.reason`, as the
producing checks do; separate changed-reason cases require a command-free
inconclusive result.
`configuration_status` only describes the observed configuration. S3 cases
with supplied anonymous replies exercise the validator's reachability
classifier, but do not prove access to a real bucket. All other cases report
`reachability_status: unknown`; they do not prove internet reachability or
access to a workload. No case targets a live cloud account, network endpoint,
or engagement. The harness supplies no provider executable or credentials.
