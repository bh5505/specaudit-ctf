# Synthetic multi-service chain: world-open ingress in front of an
# assumable administrator role. No live cloud.
resource "aws_security_group" "jump" {
  name        = "demo-jump-sg"
  description = "Internet-facing jump host"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "escalation" {
  name = "demo-escalation-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "escalation" {
  role       = aws_iam_role.escalation.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
