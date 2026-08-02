# CloudSentry

**An open-source, zero-cost AWS account security and operations watchdog that scores your infrastructure like a credit score, and tells you exactly how to fix what's wrong.**

CloudSentry is a serverless tool that runs weekly (or on-demand) to audit your AWS accounts for security misconfigurations, policy violations, resource waste, and infrastructure drift. It generates a prioritized action plan with copy-paste fix commands, tracks your security score over time, and costs under $0.25/month to run.

## Features

- **Multi-region active services inventory**: See everything running across all regions, grouped by region
- **Full security audit**: IAM, VPCs, security groups, NACLs, internet gateways, NAT gateways, Elastic IPs, load balancers, EC2, Lambda, S3, RDS, DynamoDB, KMS, Secrets Manager, CloudTrail, Route 53
- **Policy violations**: Tag compliance, naming conventions, lifecycle, cost, architecture, access
- **Security score**: 0-100 weighted score with CIS Benchmark mapping
- **Cost intelligence**: Spend, forecast, anomalies, budget cap tracking for approved expensive services
- **Resource waste detection**: Orphaned volumes, idle instances, unused functions, unattached EIPs
- **Prioritized action plan**: Every finding includes risk explanation, fix commands, compliance mapping, and effort estimate
- **Multi-account support**: Scan unlimited accounts from a single hub via STS AssumeRole
- **Week-over-week trends**: Track security score, cost trajectory, and findings over time
- **Email digest**: Formatted HTML report via SNS
- **Slack notifications**: Summary with link to full dashboard
- **On-demand scan**: API Gateway endpoint for instant scans after deployments
- **S3 HTML dashboard**: Historical charts and full report archive
- **Infrastructure drift detection**: Finds resources created outside Terraform/IaC

## Architecture

```
EventBridge (weekly Monday 7am UTC) + API Gateway (on-demand)
  -> Lambda (Python 3.12, boto3)
      |-- Multi-account: STS AssumeRole into target accounts
      |-- Multi-region: Scans all active regions per account
      |-- Scanners: IAM, Network, Compute, Storage, DB, DNS, Logging, Cost
      |-- Violations: Tags, Naming, Lifecycle, Cost, Architecture, Access
      |-- Scoring: Weighted security score (0-100) with CIS mapping
      |-- Remediation: Fix commands + explanations for every finding
      |-- Drift: Detects resources created outside IaC
      |-- Report: Compiles all sections into digest
      |-- DynamoDB: Stores history for week-over-week trends
      |-- SNS: Sends HTML email digest
      |-- Slack: Sends summary notification via webhook
      |-- S3: Publishes full HTML dashboard
```

## Cost

| Service | Monthly Cost |
|---|---|
| Lambda | $0.00 (always free: 1M requests/month) |
| EventBridge | $0.00 (always free) |
| DynamoDB | $0.00 (always free: 25GB) |
| SNS | $0.00 (always free: 1,000 emails/month) |
| CloudWatch Logs | $0.00 (always free: 5GB) |
| S3 | ~$0.01 |
| API Gateway | ~$0.00 |
| Cost Explorer API | ~$0.20 |
| **Total** | **~$0.21/month ($2.52/year)** |

## Quick Start

### Single Account (simplest)

```bash
git clone https://github.com/durrello/cloudsentry.git
cd cloudsentry/terraform

cp terraform.tfvars.example terraform.tfvars
# Edit: add your email address

terraform init
terraform apply
```

That's it. CloudSentry scans the account it's deployed in.

### Multi-Account

```bash
# 1. Deploy read-only audit role in each target account
cd terraform/cross-account-role
terraform apply -var="hub_account_id=YOUR_HUB_ACCOUNT_ID"
# Repeat for each account

# 2. Deploy CloudSentry in your hub account
cd ../
cp terraform.tfvars.example terraform.tfvars
# Edit: add account list, email, slack webhook

terraform init
terraform apply
```

### Run Immediately

```bash
aws lambda invoke --function-name cloudsentry-scanner --payload '{}' /dev/stdout
```

### On-Demand Scan via API

```bash
# Full scan
curl https://YOUR_API_ID.execute-api.REGION.amazonaws.com/scan

# Specific modules only
curl https://YOUR_API_ID.execute-api.REGION.amazonaws.com/scan?modules=iam,network,cost
```

### Tear Down Everything

```bash
terraform destroy
```

One command. Zero leftovers.

## Configuration

All configuration lives in `terraform.tfvars`. See `terraform.tfvars.example` for the full reference.

### Key Settings

```hcl
# Who gets the reports
notification_email = "you@example.com"
slack_webhook_url  = "https://hooks.slack.com/services/..."

# Accounts to scan (empty = local account only)
accounts = [
  {
    name       = "Production"
    account_id = "111111111111"
    role_arn   = "arn:aws:iam::111111111111:role/CloudSentryAuditRole"
  },
  {
    name       = "Staging"
    account_id = "222222222222"
    role_arn   = "arn:aws:iam::222222222222:role/CloudSentryAuditRole"
  },
]

# Tag policy
required_tags       = ["Environment", "Project", "Owner", "CostCenter", "ManagedBy"]
environment_values  = ["production", "staging", "development", "sandbox"]

# Cost policy
cost_alert_threshold              = 50
excluded_services_from_cost_alert = ["AmazonBedrock", "AmazonSageMaker"]
budget_caps = [
  { service = "AmazonBedrock", max_monthly = 200, reason = "AI development" },
]

# Regions where resources should exist
approved_regions = ["us-east-1", "eu-west-1", "af-south-1"]
```

## Report Output

CloudSentry generates a comprehensive report with these sections:

1. **Account Overview**: All active services by region
2. **Security Score**: 0-100 with deduction breakdown
3. **Security Audit**: Full findings across all services
4. **Policy Violations**: Tag compliance, naming, lifecycle, cost, architecture
5. **Cost Intelligence**: Spend, forecast, budget cap tracking
6. **Resource Waste**: Idle/orphaned resources with savings estimate
7. **Infrastructure Drift**: Resources outside IaC
8. **Action Plan**: Prioritized fixes grouped by severity (Critical, High, Medium, Low)
9. **Multi-Account Comparison**: Score and spend per account
10. **Trends**: Week-over-week charts

## How It Scores

Security score starts at 100 and deducts points per finding:

| Severity | Points Deducted | Examples |
|---|---|---|
| Critical | -10 | No root MFA, public S3 with data, wildcard admin on user |
| High | -5 | Old access keys, open security groups, no encryption |
| Medium | -2 | Missing tags, deprecated runtimes, no flow logs |
| Low | -1 | Unused functions, orphaned resources |

Minimum score is 0. Findings are mapped to CIS AWS Foundations Benchmark where applicable.

## Future Roadmap

- [ ] Auto-remediation (opt-in, safe fixes only)
- [ ] GitHub/GitLab issue creation for findings
- [ ] PDF report generation
- [ ] Custom compliance frameworks (SOC2, HIPAA, PCI-DSS)
- [ ] Terraform Cloud/Spacelift integration for drift
- [ ] Multi-cloud support (GCP, Azure)
- [ ] CLI tool for local scanning without deployment

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to add.

## License

MIT
