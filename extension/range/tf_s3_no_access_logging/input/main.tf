# Synthetic audit bucket without access logging. No live cloud.
resource "aws_s3_bucket" "audit_logs" {
  bucket = "demo-audit-logs"
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# No aws_s3_bucket_logging resource: server access logging is absent
# (the CKV_AWS_18 misconfiguration class).
