# Synthetic disabled management trail. No live cloud.
resource "aws_cloudtrail" "main" {
  name           = "demo-main-trail"
  s3_bucket_name = "demo-trail-logs"
  # enabled is false upstream of this fixture: logging is stopped and
  # the trail records nothing. Synthetic stand-in for IsLogging=false.
}
