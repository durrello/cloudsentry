terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "hub_account_id" {
  description = "AWS account ID where CloudSentry Lambda is deployed"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "role_name" {
  description = "Name of the audit role to create"
  type        = string
  default     = "CloudSentryAuditRole"
}

# Read-only audit role that trusts the hub account
resource "aws_iam_role" "audit_role" {
  name        = var.role_name
  description = "Read-only role for CloudSentry to audit this account"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.hub_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "cloudsentry-audit"
          }
        }
      }
    ]
  })

  tags = {
    Project   = "cloudsentry"
    ManagedBy = "terraform"
    Purpose   = "cross-account-audit"
  }
}

# Attach AWS managed ReadOnlyAccess policy
resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.audit_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Additional policy for Cost Explorer (not included in ReadOnlyAccess)
resource "aws_iam_role_policy" "cost_explorer" {
  name = "cloudsentry-cost-explorer"
  role = aws_iam_role.audit_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ce:GetCostAndUsage",
          "ce:GetCostForecast"
        ]
        Resource = "*"
      }
    ]
  })
}

output "role_arn" {
  description = "ARN of the CloudSentry audit role (add this to your terraform.tfvars)"
  value       = aws_iam_role.audit_role.arn
}

output "role_name" {
  description = "Name of the audit role"
  value       = aws_iam_role.audit_role.name
}
