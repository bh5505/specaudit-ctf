# Telecom AWS 01 — walkthrough

The catalog's `kind` distinguishes invocable arms from descriptive entries. `describe agent-wiz` shows its protocols and notes; `invoke agent-wiz list_tools` returns the handler's direct result. These fields describe and report tool behavior. They do not decide whether a target is eligible for testing.

Running `python -m extension.range --arm-ids ""` exercises the packaged fixtures without optional external arms. The `tf_s3_public_access` row reports the planted exposure, path, and impact. With the same seed and inputs it is reproducible. Adding arms changes the report according to which handlers are configured and what they return; it does not change the planted Terraform.

The expected findings are in [the contract](../artifacts/expected-findings.json):

- `demo-s3-public-read-acl`: `aws_s3_bucket.public_bucket` sets `acl = "public-read"`.
- `demo-s3-no-public-access-block`: the fixture defines no `aws_s3_bucket_public_access_block` resource.
- `demo-s3-no-encryption`: the bucket defines no server-side encryption configuration.

A strong submission names those exact facts and avoids turning a missing setting into an invented observation. The grader checks the submitted findings against the contract. The explanation still needs to connect each finding to the fixture.
