output "lambda_function_name" {
  description = "Name of the CloudSentry Lambda function"
  value       = aws_lambda_function.scanner.function_name
}

output "lambda_function_arn" {
  description = "ARN of the CloudSentry Lambda function"
  value       = aws_lambda_function.scanner.arn
}

output "api_endpoint" {
  description = "API Gateway endpoint for on-demand scans"
  value       = "${aws_apigatewayv2_api.scan_api.api_endpoint}/scan"
}

output "sns_topic_arn" {
  description = "SNS topic ARN for notifications"
  value       = aws_sns_topic.notifications.arn
}

output "dynamodb_table_name" {
  description = "DynamoDB table name for scan history"
  value       = aws_dynamodb_table.history.name
}

output "s3_dashboard_bucket" {
  description = "S3 bucket for HTML dashboard reports"
  value       = aws_s3_bucket.dashboard.id
}

output "dashboard_url" {
  description = "CloudFront URL for the HTML dashboard"
  value       = "https://${aws_cloudfront_distribution.dashboard.domain_name}"
}

output "dashboard_cloudfront_domain" {
  description = "CloudFront domain name (point your CNAME here)"
  value       = aws_cloudfront_distribution.dashboard.domain_name
}

output "eventbridge_rule" {
  description = "EventBridge rule for weekly scan schedule"
  value       = aws_cloudwatch_event_rule.weekly_scan.name
}
