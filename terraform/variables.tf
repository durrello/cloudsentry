variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "cloudsentry"
}

variable "account_name" {
  description = "Display name for the local account (shown in reports)"
  type        = string
  default     = "Primary"
}

variable "aws_region" {
  description = "AWS region to deploy CloudSentry infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "notification_emails" {
  description = "Email addresses to receive weekly reports"
  type        = list(string)
}

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL for notifications (optional, leave empty to disable)"
  type        = string
  default     = ""
}

variable "schedule_expression" {
  description = "EventBridge cron expression for weekly scan"
  type        = string
  default     = "cron(0 7 ? * MON *)"
}

variable "accounts" {
  description = "List of AWS accounts to scan. Empty list means scan the local account only."
  type = list(object({
    name       = string
    account_id = string
    role_arn   = string
  }))
  default = []
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds (max 900)"
  type        = number
  default     = 300
}

variable "lambda_memory" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 256
}

variable "required_tags" {
  description = "Tags required on all taggable resources"
  type        = list(string)
  default     = ["Environment", "Project", "Owner", "CostCenter", "ManagedBy"]
}

variable "environment_values" {
  description = "Allowed values for the Environment tag"
  type        = list(string)
  default     = ["production", "staging", "development", "sandbox"]
}

variable "managed_by_values" {
  description = "Allowed values for the ManagedBy tag"
  type        = list(string)
  default     = ["terraform", "cloudformation", "manual", "cdk", "pulumi"]
}

variable "approved_regions" {
  description = "Regions where resources are expected to exist"
  type        = list(string)
  default     = ["us-east-1", "eu-west-1"]
}

variable "approved_instance_types" {
  description = "EC2 instance types allowed in the account"
  type        = list(string)
  default     = ["t3.micro", "t3.small", "t3.medium", "t3.large"]
}

variable "cost_alert_threshold" {
  description = "Monthly cost threshold per resource (USD) before flagging"
  type        = number
  default     = 50
}

variable "excluded_services_from_cost_alert" {
  description = "Services excluded from per-resource cost alerts"
  type        = list(string)
  default     = ["AmazonBedrock", "AmazonSageMaker"]
}

variable "budget_caps" {
  description = "Budget caps for approved expensive services"
  type = list(object({
    service     = string
    max_monthly = number
    reason      = string
  }))
  default = []
}

variable "max_snapshot_age_days" {
  description = "Max age for EBS snapshots before flagging"
  type        = number
  default     = 90
}

variable "max_sandbox_age_days" {
  description = "Max days a sandbox-tagged resource can exist"
  type        = number
  default     = 7
}

variable "max_access_key_age_days" {
  description = "Max age for IAM access keys before flagging"
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags applied to all CloudSentry infrastructure resources"
  type        = map(string)
  default = {
    Project   = "cloudsentry"
    ManagedBy = "terraform"
  }
}


# Dashboard / CloudFront
variable "dashboard_domain" {
  description = "Custom domain for the dashboard (e.g., cloudsentry.durrellgemuh.com). Leave empty for CloudFront default domain."
  type        = string
  default     = ""
}

variable "dashboard_acm_cert_arn" {
  description = "ACM certificate ARN for the custom dashboard domain (must be in us-east-1). Leave empty to use Cloudflare SSL."
  type        = string
  default     = ""
}


variable "total_credits_amount" {
  description = "Total AWS credits available in the account (for runway calculation). Set to 0 if no credits."
  type        = number
  default     = 0
}
