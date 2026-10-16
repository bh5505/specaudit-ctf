# Synthetic public ACL. No live cloud.
resource "aws_s3_bucket" "public_bucket" {
  bucket = "demo-public-bucket"
  acl    = "public-read"
}
