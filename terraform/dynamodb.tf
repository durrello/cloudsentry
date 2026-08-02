# DynamoDB table for storing scan history and trends
resource "aws_dynamodb_table" "history" {
  name         = "${var.project_name}-history"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "account_id"
  range_key    = "scan_date"

  attribute {
    name = "account_id"
    type = "S"
  }

  attribute {
    name = "scan_date"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name = "${var.project_name}-history"
  }
}
