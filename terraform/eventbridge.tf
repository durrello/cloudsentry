# EventBridge rule for weekly scheduled scan
resource "aws_cloudwatch_event_rule" "weekly_scan" {
  name                = "${var.project_name}-weekly-scan"
  description         = "Triggers CloudSentry scan every Sunday at 7am UTC"
  schedule_expression = var.schedule_expression

  tags = {
    Name = "${var.project_name}-weekly-scan"
  }
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.weekly_scan.name
  target_id = "${var.project_name}-scanner"
  arn       = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.weekly_scan.arn
}
