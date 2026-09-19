resource "aws_apigatewayv2_api" "webhook" {
  name          = "${var.project_name}-webhook-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["content-type", "x-hub-signature-256"]
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.webhook.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.guardrail.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "webhook_post" {
  api_id    = aws_apigatewayv2_api.webhook.id
  route_key = "POST /webhook"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "findings_get" {
  api_id    = aws_apigatewayv2_api.webhook.id
  route_key = "GET /findings"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.webhook.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardrail.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.webhook.execution_arn}/*/*"
}

output "webhook_url" {
  description = "Set this as the GitHub webhook Payload URL, path /webhook, content type application/json"
  value       = "${aws_apigatewayv2_api.webhook.api_endpoint}/webhook"
}

output "findings_api_url" {
  description = "Paste into frontend/index.html's Connect field to drive the dashboard from live DynamoDB data"
  value       = "${aws_apigatewayv2_api.webhook.api_endpoint}/findings"
}

output "dynamodb_table" {
  value = aws_dynamodb_table.findings.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
