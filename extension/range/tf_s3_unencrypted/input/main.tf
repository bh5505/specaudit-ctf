# Synthetic unencrypted private bucket. No live cloud.
resource "aws_s3_bucket" "data_lake" {
  bucket = "demo-data-lake"
}

resource "aws_s3_bucket_public_access_block" "data_lake" {
  bucket                  = aws_s3_bucket.data_lake.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# No aws_s3_bucket_server_side_encryption_configuration: objects persist
# without SSE (the CKV_AWS_144/145 misconfiguration class).
