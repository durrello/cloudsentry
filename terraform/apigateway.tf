# API Gateway HTTP API for on-demand scans
resource "aws_apigatewayv2_api" "scan_api" {
  name          = "${var.project_name}-api"
  protocol_type = "HTTP"
  description   = "CloudSentry on-demand scan endpoint"

  tags = {
    Name = "${var.project_name}-api"
  }
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.scan_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.scan_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.scanner.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "scan" {
  api_id    = aws_apigatewayv2_api.scan_api.id
  route_key = "GET /scan"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_lambda_permission" "apigateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.scan_api.execution_arn}/*/*"
}
