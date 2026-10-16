# Solution — telecom-aws-05

## Detection reasoning

**Disabled trail (`tf_cloudtrail_disabled`).** The trail is the
account-wide management-event record. While logging is stopped,
control-plane actions — policy edits, role assumptions, bucket policy
changes, trail manipulation itself — leave no durable record. The gap
is environment-wide, hence high.

**Access logging (`tf_s3_no_access_logging`).** The bucket stores
audit artifacts, but with no `aws_s3_bucket_logging` resource there is
no per-request record for that surface. The gap is scoped to one
bucket, hence medium — narrower blast radius than the trail, but the
same class of finding: an audit question that cannot be answered after
the fact.

## Expected finding set

| finding_key | severity | traces to |
|---|---|---|
| `demo-trail-disabled` | high | `aws_cloudtrail.main`, logging stopped |
| `demo-s3-access-logging-missing` | medium | `aws_s3_bucket.audit_logs`, no logging resource |

## Grading

Exact coverage. If the grader flags a severity disagreement, defend it
in severity terms (blast radius of the unrecorded events), not by
re-labeling the control.
