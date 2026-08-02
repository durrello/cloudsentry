# Weekend Annoying Task Challenge: CloudSentry

**Tag: #productivity**

## Vision and What the App Does

Every Monday morning I used to manually check: are my security groups still locked down? Did anyone create resources outside Terraform? Are my IAM access keys getting old? Is my AWS bill tracking where I expect? Are my S3 buckets still private?

That's 30-45 minutes of clicking through the console, checking multiple regions, and piecing together a mental picture of my account's health. Across three AWS accounts. Every single week.

CloudSentry automates all of that into a single serverless function that runs weekly, scans your entire AWS account (or multiple accounts), and delivers a prioritized report with exact fix commands for every issue it finds. It scores your infrastructure like a credit score (0-100), tracks improvement over time, and tells you not just what's wrong, but exactly how to fix it.

The annoying task it eliminates: manually auditing your AWS accounts for security misconfigurations, policy violations, wasted resources, and infrastructure drift.

## How You Built It

I built CloudSentry in a single weekend using Python and Terraform. The approach was modular from the start: each security domain (IAM, networking, compute, storage, databases, DNS, encryption, logging) gets its own scanner module. A violations engine checks tag compliance, naming conventions, lifecycle policies, cost thresholds, and architecture standards. A scoring engine calculates a weighted security score, and a remediation engine generates copy-paste AWS CLI commands for every finding.

Key decisions:

- **Python 3.12 on Lambda** for the scanner: boto3 is included in the runtime, so no dependencies to package. The function scans all active regions in under 5 minutes.
- **Terraform for all infrastructure**: One `terraform apply` creates everything, one `terraform destroy` removes it. No orphaned resources, no manual cleanup.
- **Multi-account via STS AssumeRole**: A single deployment can scan unlimited AWS accounts by assuming a read-only role in each target.
- **SES for HTML emails**: SNS only supports plain text. SES renders proper styled emails with severity badges, fix commands, and a link to the full dashboard.
- **CloudFront for the dashboard**: The HTML report is pushed to S3 and served via CloudFront with optional custom domain support.

Challenges I overcame:

1. **Cost Explorer showing $0**: The UnblendedCost metric returns net-after-credits, which was $0 in my case. I had to query by RECORD_TYPE to separate raw usage ($138/month), subscriptions ($210/month), and credits ($348/month) to show what the billing dashboard actually shows.
2. **CloudFront caching**: After each scan, I invalidate the CloudFront cache so the dashboard always shows the latest report.
3. **Email rendering**: Gmail strips `<style>` tags from emails. I rewrote the email template with table-based layouts and all inline styles for cross-client compatibility.

## AWS Services Used / Architecture Overview

```
EventBridge (weekly Monday 7am UTC) + API Gateway (on-demand)
  -> Lambda (Python 3.12, boto3, 5min timeout)
      |-- STS AssumeRole (multi-account)
      |-- EC2, IAM, S3, RDS, Lambda, Route53, ACM, KMS,
      |   CloudTrail, GuardDuty, ELB, DynamoDB, CloudWatch
      |   (read-only describe/list calls across all regions)
      |-- Cost Explorer API (spend, forecast, credits)
      |-- DynamoDB (stores scan history for trends)
      |-- SES (sends HTML email report)
      |-- SNS (fallback plain-text notifications)
      |-- S3 (uploads HTML dashboard)
      |-- CloudFront (serves dashboard with custom domain)
```

**Services used:**

| Service | Role |
|---|---|
| AWS Lambda | Runs the scanner (Python 3.12) |
| Amazon EventBridge | Weekly cron trigger |
| Amazon DynamoDB | Stores scan history for week-over-week trends |
| Amazon S3 | Hosts the HTML dashboard reports |
| Amazon CloudFront | CDN for the dashboard with custom domain |
| Amazon SNS | Email notifications (fallback) |
| Amazon SES | Styled HTML email delivery |
| Amazon API Gateway | On-demand scan endpoint |
| AWS Cost Explorer | Spend, forecast, and credits data |
| AWS IAM | Cross-account assume role for multi-account scanning |

Total monthly cost: ~$0.21 (Cost Explorer API is the only non-free-tier charge).

## What You Learned

1. **Cost Explorer has a 24-48 hour data delay** and the UnblendedCost metric nets out credits. To show what the billing dashboard shows, you need to group by RECORD_TYPE and sum Usage + FlatRateSubscription separately.

2. **AWS doesn't expose a "remaining credits balance" API**. You can see credits applied (negative amounts in Cost Explorer), but there's no endpoint that says "you have $X left." I built the credits section to show applied amounts and coverage percentage instead of guessing.

3. **Email clients are hostile to CSS**. Gmail removes `<style>` blocks entirely. Outlook ignores margin/padding on divs. The only reliable approach for email HTML is table-based layout with every style inlined. Dark themes work well in Gmail if you use background-color on `<td>` elements, not on `<body>`.

4. **Terraform's archive_file data source** auto-zips the Python source code and triggers a Lambda update whenever the code changes. No manual zip/upload step needed.

5. **CloudFront Origin Access Control (OAC)** replaced the old Origin Access Identity (OAI) pattern. OAC uses sigv4 signing and is the recommended approach for S3 origins.

6. **Multi-region scanning is slower than expected**. Checking all 18+ regions for active resources takes time. I optimized by first doing a quick check (any EC2, Lambda, or RDS?) in each region before running the full scan, reducing total execution from 12 minutes to under 5.

## Link to App or Repo

- **GitHub**: https://github.com/durrello/cloudsentry
- **Live Dashboard**: https://cloudsentry.durrellgemuh.com/reports/latest.html
- **On-demand scan API**: https://xoek9xoktk.execute-api.us-east-1.amazonaws.com/scan

Deploy your own in under 5 minutes:

```bash
git clone https://github.com/durrello/cloudsentry.git
cd cloudsentry/terraform
cp terraform.tfvars.example terraform.tfvars
# Set notification_emails and account_name
terraform init
terraform apply
```
