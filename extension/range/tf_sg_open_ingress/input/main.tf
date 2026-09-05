# Synthetic world-open ingress groups. No live cloud.
resource "aws_security_group" "admin" {
  name        = "demo-admin-sg"
  description = "Administrative shell access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name        = "demo-db-sg"
  description = "Database engine access"

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
