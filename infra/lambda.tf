data "archive_file" "lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/guardrail-lambda.zip"
  # requirements are installed into src/ as a Lambda layer in CI before
  # `terraform apply` — see .github/workflows/deploy.yml — so this zip
  # only needs to contain application code, not third-party packages.
}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-lambda-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name = "${var.project_name}-lambda-permissions"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Scan"]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:TagResource"
        ]
        Resource = "arn:aws:secretsmanager:${var.aws_region}:*:secret:guardrail/quarantined/*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["events:PutEvents"]
        Resource = data.aws_cloudwatch_event_bus.default.arn
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = "arn:aws:bedrock:${var.aws_region}::foundation-model/${var.bedrock_model_id}"
      }
    ]
  })
}

resource "aws_lambda_function" "guardrail" {
  function_name    = "${var.project_name}-webhook-handler"
  role              = aws_iam_role.lambda_exec.arn
  handler           = "lambda_handler.lambda_handler"
  runtime           = "python3.12"
  timeout           = 30
  memory_size       = 256
  filename          = data.archive_file.lambda_package.output_path
  source_code_hash  = data.archive_file.lambda_package.output_base64sha256
  layers            = [aws_lambda_layer_version.dependencies.arn]

environment {
  variables = {
    GUARDRAIL_TABLE_NAME       = aws_dynamodb_table.findings.name
    GUARDRAIL_SNS_TOPIC_ARN    = aws_sns_topic.alerts.arn
    GUARDRAIL_EVENT_BUS        = "default"
    GUARDRAIL_USE_BEDROCK      = var.use_bedrock
    GUARDRAIL_BEDROCK_MODEL_ID = var.bedrock_model_id
    GITHUB_WEBHOOK_SECRET      = var.github_webhook_secret
    GITHUB_TOKEN               = var.github_token
  }
}
}

resource "aws_lambda_layer_version" "dependencies" {
  layer_name          = "${var.project_name}-deps"
  filename            = "${path.module}/build/dependencies-layer.zip"
  compatible_runtimes = ["python3.12"]
  # Build with: pip install -r requirements.txt -t infra/build/python/
  #             (cd infra/build && zip -r dependencies-layer.zip python)
}
