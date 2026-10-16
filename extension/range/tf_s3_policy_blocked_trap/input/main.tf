# Synthetic negative control: a policy that would grant anonymous
# reads, neutralized by block public access. No live cloud.
resource "aws_s3_bucket" "trap" {
  bucket = "demo-trap-bucket"
}

# All four toggles on: RestrictPublicBuckets confines a bucket with a
# public policy to AWS service principals and owner-account principals,
# so the anonymous grant below never takes effect. The planted lesson:
# the policy is a misconfiguration, not a live public exposure — and a
# policy condition carve-out (org id, source VPC, source IP) would
# change this verdict, so block-on never means "skip reading policies".
resource "aws_s3_bucket_policy" "trap" {
  bucket = aws_s3_bucket.trap.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::demo-trap-bucket/*"
    }]
  })
}

resource "aws_s3_bucket_public_access_block" "trap" {
  bucket                  = aws_s3_bucket.trap.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
