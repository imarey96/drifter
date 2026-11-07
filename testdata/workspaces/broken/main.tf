resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
  tags = {
    Team = "platform"
}
