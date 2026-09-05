# Synthetic externally-trusted role without MFA. No live cloud.
resource "aws_iam_role" "external_trust" {
  name = "demo-external-trust-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::999999999999:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "read_sensitive" {
  name = "demo-read-sensitive"
  role = aws_iam_role.external_trust.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "*"
    }]
  })
}
