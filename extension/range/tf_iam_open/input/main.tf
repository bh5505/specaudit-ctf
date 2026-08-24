# Synthetic wildcard identity policy. No live cloud.
resource "aws_iam_policy" "wildcard" {
  name = "demo-wildcard-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
