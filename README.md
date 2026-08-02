# CloudSentry

**An open-source, zero-cost AWS account security and operations watchdog that scores your infrastructure like a credit score, and tells you exactly how to fix what's wrong.**

CloudSentry is a serverless tool that runs weekly (or on-demand) to audit your AWS accounts for security misconfigurations, policy violations, resource waste, and infrastructure drift. It generates a prioritized action plan with copy-paste fix commands, tracks your security score over time, and costs under $0.25/month to run.

## Features

### Security Audit
- **IAM**: Root account MFA, access key age, password policy, users without MFA, inline policies, orphaned users, over-privileged roles, empty groups, unused policies
- **Networking**: VPCs without flow logs, security groups open to 0.0.0.0/0, risky ports (SSH, RDP, DB ports), NACLs, orphaned security groups, VPC peering
- **Load Balancers**: HTTP-only (no HTTPS), unhealthy targets, no access logging, outdated TLS
- **Compute**: EC2 with public IPs, IMDSv1 enabled, no IAM role, default security group, stopped instances, unapproved instance types
- **Storage**: S3 public access, no encryption, no versioning, no lifecycle policy, no logging
- **Databases**: RDS publicly accessible, unencrypted, no backups, no multi-AZ, DynamoDB without PITR
- **Encryption**: KMS wildcard policies, keys pending deletion, unrotated secrets
- **Logging**: CloudTrail disabled, no multi-region trail, log validation off, GuardDuty disabled
- **DNS**: Dangling CNAMEs (subdomain takeover risk), expiring ACM certificates

### Cost Intelligence
- **Gross spend**: Usage + subscriptions (matches your billing dashboard)
- **Service breakdown**: Cost per AWS service
- **Burn rate**: Daily, monthly, and annual rates
- **Credits tracking**: Total applied, this month, last month, coverage percentage
- **All data pulled from AWS APIs**: No hardcoded values or assumptions

### Policy Violations
- **Tag compliance**: Configurable required tags with allowed values
- **Naming conventions**: Flags auto-generated names (launch-wizard, etc.)
- **Lifecycle**: Old snapshots, stale sandbox resources
- **Cost policy**: Per-resource thresholds with exclusions for approved expensive services
- **Architecture**: Resources in unapproved regions, over-provisioned Lambda
- **Access**: Cross-account role trusts, unused credentials

### Infrastructure Drift
- Detects EC2 instances and security groups created outside Terraform/CloudFormation
- Flags resources missing the ManagedBy tag
- Provides terraform import commands

### Reporting
- **Security score**: 0-100 weighted score based on findings
- **Prioritized action plan**: Fix commands grouped by severity (Critical, High, Medium, Low)
- **HTML dashboard**: Dark-themed, hosted on CloudFront with custom domain support
- **Email notifications**: Styled HTML emails via SES (falls back to SNS plain text)
- **Slack notifications**: Summary with link to dashboard
- **Week-over-week trends**: Stored in DynamoDB for historical comparison
- **Multi-account comparison**: Score and spend side by side

### Infrastructure
- **Multi-account**: Scan unlimited accounts via STS AssumeRole
- **Multi-region**: Automatically discovers and scans all active regions
- **On-demand scan**: API Gateway endpoint for instant scans
- **Terraform managed**: One command to deploy, one command to destroy

## Architecture

```
EventBridge (weekly Sunday 7am UTC) + API Gateway (on-demand)
  -> Lambda (Python 3.12, boto3)
      |-- Multi-account: STS AssumeRole into target accounts
      |-- Multi-region: Scans all active regions per account
      |-- Scanners: IAM, Network, Compute, Storage, DB, DNS, Logging, Cost
      |-- Violations: Tags, Naming, Lifecycle, Cost, Architecture, Access
      |-- Drift: Detects resources outside IaC
      |-- Scoring: Weighted security score (0-100)
      |-- Remediation: Fix commands + explanations for every finding
      |-- DynamoDB: Stores history for week-over-week trends
      |-- SES/SNS: Sends HTML email digest
      |-- Slack: Sends summary notification via webhook
      |-- S3 + CloudFront: Publishes full HTML dashboard
```

## Cost

| Service | Monthly Cost |
|---|---|
| Lambda | $0.00 (always free: 1M requests/month) |
| EventBridge | $0.00 (always free) |
| DynamoDB | $0.00 (always free: 25GB) |
| SNS | $0.00 (always free: 1,000 emails/month) |
| SES | $0.00 (first 62,000 emails/month from Lambda) |
| CloudWatch Logs | $0.00 (always free: 5GB) |
| S3 | ~$0.01 |
| CloudFront | ~$0.00 (minimal traffic) |
| API Gateway | ~$0.00 |
| Cost Explorer API | ~$0.20 |
| **Total** | **~$0.21/month ($2.52/year)** |

## Quick Start

### Single Account (simplest)

```bash
git clone https://github.com/durrello/cloudsentry.git
cd cloudsentry/terraform

cp terraform.tfvars.example terraform.tfvars
# Edit: set notification_emails and account_name

terraform init
terraform apply
# Check your inbox and click the SES verification link(s)
```

That's it. One command deploys everything. SES verification emails are sent automatically during deploy.

### Multi-Account

```bash
# 1. Deploy read-only audit role in each target account
cd terraform/cross-account-role
terraform apply -var="hub_account_id=YOUR_HUB_ACCOUNT_ID"
# Repeat for each account

# 2. Deploy CloudSentry in your hub account
cd ../
cp terraform.tfvars.example terraform.tfvars
# Edit: add account list, emails, slack webhook

terraform init
terraform apply
```

### Run Immediately

```bash
aws lambda invoke --function-name cloudsentry-scanner --payload '{}' /dev/stdout --cli-read-timeout 300
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

### Custom Domain (Optional)

Host the dashboard on your own domain (e.g., `cloudsentry.yourdomain.com`):

```bash
# 1. Deploy CloudSentry first (creates CloudFront distribution)
terraform apply

# 2. Request ACM certificate (must be in us-east-1 for CloudFront)
aws acm request-certificate \
  --domain-name cloudsentry.yourdomain.com \
  --validation-method DNS \
  --region us-east-1

# 3. Get the DNS validation record
aws acm describe-certificate \
  --certificate-arn <ARN_FROM_STEP_2> \
  --region us-east-1 \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord'

# 4. Add the CNAME validation record to your DNS provider (Cloudflare, Route53, etc.)
#    Type: CNAME
#    Name: _xxx.cloudsentry  (from the output above)
#    Value: _yyy.acm-validations.aws.  (from the output above)
#    Proxy: OFF (DNS only if using Cloudflare)

# 5. Wait for cert to validate (1-5 minutes)
aws acm describe-certificate \
  --certificate-arn <ARN> \
  --region us-east-1 \
  --query 'Certificate.Status'
# Should return "ISSUED"

# 6. Update terraform.tfvars with the cert ARN and domain
#    dashboard_domain       = "cloudsentry.yourdomain.com"
#    dashboard_acm_cert_arn = "arn:aws:acm:us-east-1:..."

# 7. Apply the update
terraform apply

# 8. Add CNAME pointing your subdomain to CloudFront
#    Type: CNAME
#    Name: cloudsentry
#    Value: <dashboard_cloudfront_domain from terraform output>
#    Proxy: OFF (DNS only if using Cloudflare)
```

Your dashboard is now live at `https://cloudsentry.yourdomain.com`

### Email Setup (HTML emails via SES)

SES verification emails are sent automatically during `terraform apply`. Just click the verification link in each inbox. Once verified, you'll receive styled HTML reports.

If any email isn't verified, CloudSentry falls back to SNS plain-text notifications with a link to the dashboard.

To check verification status:

```bash
aws ses get-identity-verification-attributes \
  --identities you@example.com --region us-east-1
```

Note: SES in sandbox mode only sends to verified addresses (fine for personal/team use).

## Configuration

All configuration lives in `terraform.tfvars`. See `terraform.tfvars.example` for the full reference.

### Key Settings

```hcl
# Who gets the reports (multiple emails supported)
notification_emails = ["you@example.com", "team@example.com"]
slack_webhook_url   = "https://hooks.slack.com/services/..."

# Display name for the account in reports
account_name = "My Company"

# Custom domain for the dashboard
dashboard_domain       = "cloudsentry.yourdomain.com"
dashboard_acm_cert_arn = "arn:aws:acm:us-east-1:..."

# Accounts to scan (empty = local account only)
accounts = [
  {
    name       = "Production"
    account_id = "111111111111"
    role_arn   = "arn:aws:iam::111111111111:role/CloudSentryAuditRole"
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

## Report Sections

1. **Account Overview**: All active services by region
2. **Security Score**: 0-100 with grade (A-F)
3. **Cost Intelligence**: Gross spend, usage, subscriptions, credits, burn rate, service breakdown
4. **Security Findings**: Full audit results across all services
5. **Policy Violations**: Tags, naming, lifecycle, cost, architecture, access
6. **Infrastructure Drift**: Resources outside IaC
7. **Action Plan**: Prioritized fixes with commands, compliance mapping, effort estimates

## How It Scores

Security score starts at 100 and deducts points per finding:

| Severity | Points Deducted | Examples |
|---|---|---|
| Critical | -10 | No root MFA, public S3 with data, wildcard admin on user |
| High | -5 | Old access keys, open security groups, no encryption |
| Medium | -2 | Missing tags, deprecated runtimes, no flow logs |
| Low | -1 | Unused functions, orphaned resources |

Minimum score is 0. Findings are mapped to CIS AWS Foundations Benchmark where applicable.

## Project Structure

```
cloudsentry/
├── README.md
├── LICENSE
├── .gitignore
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── lambda.tf
│   ├── eventbridge.tf
│   ├── dynamodb.tf
│   ├── apigateway.tf
│   ├── s3.tf
│   ├── sns.tf
│   ├── ses.tf
│   ├── cloudfront.tf
│   ├── terraform.tfvars.example
│   └── cross-account-role/
│       └── main.tf
└── src/
    ├── handler.py
    ├── config.py
    ├── scanner/
    │   ├── inventory.py
    │   ├── iam_audit.py
    │   ├── network_audit.py
    │   ├── compute_audit.py
    │   ├── storage_audit.py
    │   ├── database_audit.py
    │   ├── dns_audit.py
    │   ├── encryption_audit.py
    │   ├── logging_audit.py
    │   ├── cost_audit.py
    │   └── drift_detection.py
    ├── violations/
    │   ├── tag_compliance.py
    │   ├── naming_policy.py
    │   ├── lifecycle_policy.py
    │   ├── cost_policy.py
    │   ├── architecture_policy.py
    │   └── access_policy.py
    ├── scoring/
    │   ├── calculator.py
    │   └── weights.py
    ├── remediation/
    │   └── actions.py
    ├── report/
    │   ├── builder.py
    │   ├── email_formatter.py
    │   ├── html_dashboard.py
    │   └── slack_formatter.py
    └── utils/
        ├── multi_account.py
        ├── regions.py
        ├── findings.py
        └── dynamo.py
```

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

## Author

Built by [Durrell Gemuh](https://durrellgemuh.com)
