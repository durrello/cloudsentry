# Package Lambda source code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/.build/cloudsentry.zip"
}

# Lambda function
resource "aws_lambda_function" "scanner" {
  function_name    = "${var.project_name}-scanner"
  description      = "CloudSentry: AWS account security and operations auditor"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory
  role             = aws_iam_role.lambda_role.arn

  environment {
    variables = {
      ACCOUNT_NAME                      = var.account_name
      NOTIFICATION_EMAILS               = jsonencode(var.notification_emails)
      DYNAMODB_TABLE                    = aws_dynamodb_table.history.name
      SNS_TOPIC_ARN                     = aws_sns_topic.notifications.arn
      S3_BUCKET                         = aws_s3_bucket.dashboard.id
      SLACK_WEBHOOK_URL                 = var.slack_webhook_url
      ACCOUNTS                          = jsonencode(var.accounts)
      REQUIRED_TAGS                     = jsonencode(var.required_tags)
      ENVIRONMENT_VALUES                = jsonencode(var.environment_values)
      MANAGED_BY_VALUES                 = jsonencode(var.managed_by_values)
      APPROVED_REGIONS                  = jsonencode(var.approved_regions)
      APPROVED_INSTANCE_TYPES           = jsonencode(var.approved_instance_types)
      COST_ALERT_THRESHOLD              = tostring(var.cost_alert_threshold)
      EXCLUDED_SERVICES_FROM_COST_ALERT = jsonencode(var.excluded_services_from_cost_alert)
      BUDGET_CAPS                       = jsonencode(var.budget_caps)
      MAX_SNAPSHOT_AGE_DAYS             = tostring(var.max_snapshot_age_days)
      MAX_SANDBOX_AGE_DAYS              = tostring(var.max_sandbox_age_days)
      MAX_ACCESS_KEY_AGE_DAYS           = tostring(var.max_access_key_age_days)
    }
  }

  tags = {
    Name = "${var.project_name}-scanner"
  }
}

# Lambda IAM Role
resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# CloudWatch Logs policy
resource "aws_iam_role_policy" "lambda_logs" {
  name = "${var.project_name}-logs"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Read-only audit permissions (for local account scanning)
resource "aws_iam_role_policy" "lambda_audit" {
  name = "${var.project_name}-audit"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyAudit"
        Effect = "Allow"
        Action = [
          # IAM
          "iam:GetAccountSummary",
          "iam:GetAccountPasswordPolicy",
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:ListGroups",
          "iam:ListPolicies",
          "iam:ListMFADevices",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies",
          "iam:ListGroupsForUser",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListGroupPolicies",
          "iam:ListAttachedGroupPolicies",
          "iam:GetGroupPolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetLoginProfile",
          # EC2 / VPC / Networking
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeNatGateways",
          "ec2:DescribeAddresses",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeFlowLogs",
          "ec2:DescribeVpcPeeringConnections",
          "ec2:DescribeSnapshots",
          "ec2:DescribeImages",
          "ec2:DescribeRegions",
          "ec2:DescribeTags",
          # ELB
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeTags",
          # Lambda
          "lambda:ListFunctions",
          "lambda:GetFunction",
          "lambda:ListTags",
          "lambda:GetPolicy",
          # S3
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketTagging",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketEncryption",
          "s3:GetBucketVersioning",
          "s3:GetBucketLifecycleConfiguration",
          "s3:GetBucketLogging",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          # RDS
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:ListTagsForResource",
          # DynamoDB
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:ListTagsOfResource",
          # CloudTrail
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          # CloudWatch
          "cloudwatch:DescribeAlarms",
          "cloudwatch:GetMetricStatistics",
          # Config
          "config:DescribeConfigRules",
          "config:DescribeComplianceByConfigRule",
          # GuardDuty
          "guardduty:ListDetectors",
          # KMS
          "kms:ListKeys",
          "kms:DescribeKey",
          "kms:ListAliases",
          "kms:GetKeyPolicy",
          # Secrets Manager
          "secretsmanager:ListSecrets",
          "secretsmanager:DescribeSecret",
          # Route 53
          "route53:ListHostedZones",
          "route53:ListResourceRecordSets",
          # ACM
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          # Cost Explorer
          "ce:GetCostAndUsage",
          "ce:GetCostForecast",
          # SNS / SQS
          "sns:ListTopics",
          "sns:ListTagsForResource",
          "sqs:ListQueues",
          "sqs:ListQueueTags",
          # ECS
          "ecs:ListClusters",
          "ecs:DescribeClusters",
          "ecs:ListServices",
          "ecs:DescribeServices",
          # ECR
          "ecr:DescribeRepositories",
          "ecr:ListTagsForResource",
          # API Gateway
          "apigateway:GET",
          # CloudFront
          "cloudfront:ListDistributions",
          "cloudfront:ListTagsForResource"
        ]
        Resource = "*"
      }
    ]
  })
}

# STS AssumeRole for multi-account scanning
resource "aws_iam_role_policy" "lambda_assume_role" {
  count = length(var.accounts) > 0 ? 1 : 0
  name  = "${var.project_name}-assume-role"
  role  = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = [for account in var.accounts : account.role_arn]
      }
    ]
  })
}

# DynamoDB and SNS and S3 access
resource "aws_iam_role_policy" "lambda_services" {
  name = "${var.project_name}-services"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = aws_dynamodb_table.history.arn
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.notifications.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.dashboard.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}-scanner"
  retention_in_days = 14

  tags = {
    Name = "${var.project_name}-logs"
  }
}
