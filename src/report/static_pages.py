"""
Static page generators for the CloudSentry dashboard.
Generates: index.html (nav), history.html, docs.html
"""

from scoring.calculator import get_score_grade


def generate_index_page():
    """Generate the main index/landing page with navigation."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudSentry Dashboard</title>
<style>{get_nav_css()}</style>
</head>
<body>
<div class="container">
<nav class="nav">
<a href="/reports/latest.html" class="nav-link active">Latest Report</a>
<a href="/history.html" class="nav-link">History</a>
<a href="/docs.html" class="nav-link">Documentation</a>
<a href="https://github.com/durrello/cloudsentry" class="nav-link" target="_blank">GitHub</a>
</nav>
<div class="hero">
<h1>CloudSentry</h1>
<p>AWS Account Security and Operations Watchdog</p>
<a href="/reports/latest.html" class="cta">View Latest Report</a>
</div>
</div>
</body>
</html>"""


def generate_history_page(scan_history):
    """
    Generate history page listing all past scans.
    scan_history: list of dicts with keys: scan_date, score, findings_count, violations_count
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudSentry - Scan History</title>
<style>{get_nav_css()}</style>
</head>
<body>
<div class="container">
<nav class="nav">
<a href="/reports/latest.html" class="nav-link">Latest Report</a>
<a href="/history.html" class="nav-link active">History</a>
<a href="/docs.html" class="nav-link">Documentation</a>
<a href="https://github.com/durrello/cloudsentry" class="nav-link" target="_blank">GitHub</a>
</nav>
<h1>Scan History</h1>
<p class="subtitle">All past CloudSentry scans with scores and findings.</p>
<table class="history-table">
<tr><th>Date</th><th>Score</th><th>Grade</th><th>Findings</th><th>Violations</th><th>Report</th></tr>
"""

    for scan in sorted(scan_history, key=lambda x: x.get("scan_date", ""), reverse=True):
        date = scan.get("scan_date", "unknown")
        score = int(scan.get("score", 0))
        grade = get_score_grade(score)
        findings = scan.get("findings_count", 0)
        violations = scan.get("violations_count", 0)
        grade_class = f"grade-{grade.lower()}"

        html += f"""<tr>
<td>{date}</td>
<td><span class="score-pill {grade_class}">{score}</span></td>
<td>{grade}</td>
<td>{findings}</td>
<td>{violations}</td>
<td><a href="/reports/{date}.html" class="report-link">View</a></td>
</tr>
"""

    html += """</table>
</div>
</body>
</html>"""

    return html


def generate_docs_page():
    """Generate the documentation page."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudSentry - Documentation</title>
<style>""" + get_nav_css() + """</style>
</head>
<body>
<div class="container">
<nav class="nav">
<a href="/reports/latest.html" class="nav-link">Latest Report</a>
<a href="/history.html" class="nav-link">History</a>
<a href="/docs.html" class="nav-link active">Documentation</a>
<a href="https://github.com/durrello/cloudsentry" class="nav-link" target="_blank">GitHub</a>
</nav>

<h1>Documentation</h1>

<div class="doc-section">
<h2>Quick Start</h2>
<pre><code>git clone https://github.com/durrello/cloudsentry.git
cd cloudsentry/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit: set notification_emails and account_name
terraform init
terraform apply
# Check email inbox and click SES verification link</code></pre>
</div>

<div class="doc-section">
<h2>How It Works</h2>
<p>CloudSentry runs as a Lambda function triggered weekly by EventBridge (Sunday 7am UTC).
It scans your AWS account across all active regions, checks 10+ services for security
misconfigurations, and generates a report with fix commands.</p>
<h3>Flow</h3>
<pre><code>EventBridge (weekly cron) + API Gateway (on-demand)
  -> Lambda (Python 3.12, 5min timeout)
      |-- Scans all active regions
      |-- Checks: IAM, VPC, SGs, EC2, Lambda, S3, RDS, DynamoDB,
      |   KMS, CloudTrail, GuardDuty, Route 53, ACM, ELBs
      |-- Calculates security score (0-100)
      |-- Stores history in DynamoDB
      |-- Sends email via SES
      |-- Uploads HTML dashboard to S3 + CloudFront</code></pre>
</div>

<div class="doc-section">
<h2>On-Demand Scan</h2>
<p>Trigger a scan anytime without waiting for the weekly schedule:</p>
<pre><code># Full scan
aws lambda invoke --function-name cloudsentry-scanner \\
  --payload '{}' /dev/stdout --cli-read-timeout 300

# Via API Gateway
curl https://YOUR_API_ID.execute-api.REGION.amazonaws.com/scan

# Specific modules only
curl https://YOUR_API_ID.execute-api.REGION.amazonaws.com/scan?modules=iam,network,cost</code></pre>
</div>

<div class="doc-section">
<h2>Configuration</h2>
<p>All configuration lives in <code>terraform.tfvars</code>:</p>
<pre><code># Notification emails (SES verified)
notification_emails = ["you@example.com"]

# Account display name
account_name = "My Account"

# Tag policy (resources without these tags are flagged)
required_tags = ["Environment", "Project", "Owner", "CostCenter", "ManagedBy"]
environment_values = ["production", "staging", "development", "sandbox"]

# Approved regions (resources outside these are flagged)
approved_regions = ["us-east-1", "eu-west-1"]

# Cost thresholds
cost_alert_threshold = 50
excluded_services_from_cost_alert = ["AmazonBedrock", "AmazonSageMaker"]

# Budget caps for known expensive services
budget_caps = [
  { service = "AmazonBedrock", max_monthly = 200, reason = "AI development" },
]</code></pre>
</div>

<div class="doc-section">
<h2>Multi-Account Setup</h2>
<ol>
<li>Deploy the audit role in each target account:
<pre><code>cd terraform/cross-account-role
terraform apply -var="hub_account_id=YOUR_HUB_ACCOUNT_ID"</code></pre></li>
<li>Add accounts to your terraform.tfvars:
<pre><code>accounts = [
  {
    name       = "Production"
    account_id = "111111111111"
    role_arn   = "arn:aws:iam::111111111111:role/CloudSentryAuditRole"
  },
]</code></pre></li>
<li>Apply: <code>terraform apply</code></li>
</ol>
</div>

<div class="doc-section">
<h2>Custom Domain Setup</h2>
<ol>
<li>Deploy CloudSentry first (creates CloudFront)</li>
<li>Request ACM certificate:
<pre><code>aws acm request-certificate \\
  --domain-name cloudsentry.yourdomain.com \\
  --validation-method DNS --region us-east-1</code></pre></li>
<li>Get validation CNAME:
<pre><code>aws acm describe-certificate --certificate-arn ARN \\
  --region us-east-1 \\
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord'</code></pre></li>
<li>Add validation CNAME to DNS (Proxy: OFF)</li>
<li>Wait for cert to validate</li>
<li>Update terraform.tfvars:
<pre><code>dashboard_domain = "cloudsentry.yourdomain.com"
dashboard_acm_cert_arn = "arn:aws:acm:us-east-1:..."</code></pre></li>
<li>Apply: <code>terraform apply</code></li>
<li>Add CNAME: cloudsentry -> CloudFront domain (Proxy: OFF)</li>
</ol>
</div>

<div class="doc-section">
<h2>Troubleshooting</h2>

<h3>Lambda times out</h3>
<p>If scanning many regions/accounts, increase timeout:</p>
<pre><code># In terraform.tfvars:
lambda_timeout = 600  # 10 minutes (max is 900)</code></pre>

<h3>Cost Explorer shows $0</h3>
<p>Cost Explorer data has a 24-48 hour delay. If you just created the account or it's early
in the month, data may not be available yet. The billing dashboard updates faster than the API.</p>

<h3>Email not received</h3>
<p>Emails are sent via SES. Each recipient must verify their email:</p>
<pre><code>aws ses verify-email-identity --email-address you@example.com --region us-east-1
# Click the verification link in your inbox</code></pre>
<p>SES in sandbox mode only sends to verified addresses. If SES fails, CloudSentry falls back
to SNS (plain text with dashboard link).</p>

<h3>Dashboard shows old data</h3>
<p>CloudFront caches pages. Invalidate after a scan:</p>
<pre><code>aws cloudfront create-invalidation --distribution-id YOUR_DIST_ID --paths "/*"</code></pre>

<h3>Permission errors in Lambda logs</h3>
<p>The Lambda role needs read-only access to all services it scans. Check CloudWatch logs:</p>
<pre><code>aws logs get-log-events --log-group-name /aws/lambda/cloudsentry-scanner \\
  --log-stream-name LATEST_STREAM --region us-east-1</code></pre>
<p>If a specific service is denied, add the permission to the Lambda role in <code>terraform/lambda.tf</code>.</p>

<h3>Tag enforcement blocking legitimate deploys</h3>
<p>The RequireTagsOnCreate IAM policy blocks resource creation without tags. If Terraform or
CI/CD is failing, ensure your provider includes required tags:</p>
<pre><code># Terraform example:
resource "aws_instance" "example" {
  # ...
  tags = {
    Environment = "production"
    Project     = "myapp"
    Owner       = "durrell"
  }
}</code></pre>

<h3>DynamoDB "Float types not supported"</h3>
<p>DynamoDB doesn't accept Python floats. If you see this error, cost values need to be
converted to Decimal before storing. This is handled in <code>utils/dynamo.py</code>.</p>

<h3>Scan finds false positives</h3>
<p>Some findings are "by design" (e.g., production instance needs public IP). These can't
be suppressed yet. Future: add an allowlist in config to exclude specific resources.</p>
</div>

<div class="doc-section">
<h2>Destroy Everything</h2>
<pre><code>cd terraform
terraform destroy
# This removes ALL CloudSentry resources. No leftovers.</code></pre>
</div>

<div class="doc-section">
<h2>Cost</h2>
<table class="doc-table">
<tr><th>Service</th><th>Monthly</th></tr>
<tr><td>Lambda</td><td>$0.00 (always free)</td></tr>
<tr><td>EventBridge</td><td>$0.00 (always free)</td></tr>
<tr><td>DynamoDB</td><td>$0.00 (always free)</td></tr>
<tr><td>SNS</td><td>$0.00 (always free)</td></tr>
<tr><td>SES</td><td>$0.00 (free from Lambda)</td></tr>
<tr><td>CloudWatch Logs</td><td>$0.00 (always free)</td></tr>
<tr><td>S3</td><td>~$0.01</td></tr>
<tr><td>CloudFront</td><td>~$0.00</td></tr>
<tr><td>Cost Explorer API</td><td>~$0.20</td></tr>
<tr><td><strong>Total</strong></td><td><strong>~$0.21/month</strong></td></tr>
</table>
</div>

</div>
</body>
</html>"""


def get_nav_css():
    """Shared CSS for all static pages."""
    return """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
.container { max-width: 900px; margin: 0 auto; padding: 2rem; }
.nav { display: flex; gap: 1rem; margin-bottom: 2rem; padding: 1rem; background: #1e293b; border-radius: 8px; flex-wrap: wrap; }
.nav-link { color: #94a3b8; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; font-size: 0.9rem; }
.nav-link:hover { color: #f8fafc; background: #334155; }
.nav-link.active { color: #f8fafc; background: #e94560; }
h1 { font-size: 2rem; color: #f8fafc; margin-bottom: 0.5rem; }
h2 { font-size: 1.4rem; color: #f8fafc; margin-bottom: 0.75rem; margin-top: 0; }
h3 { font-size: 1.1rem; color: #cbd5e1; margin: 1rem 0 0.5rem; }
p { margin-bottom: 0.75rem; color: #94a3b8; }
.subtitle { color: #64748b; margin-bottom: 2rem; }
.hero { text-align: center; padding: 4rem 0; }
.hero h1 { font-size: 3rem; color: #e94560; }
.hero p { font-size: 1.2rem; color: #94a3b8; margin-bottom: 2rem; }
.cta { display: inline-block; background: #e94560; color: #fff; padding: 12px 32px; border-radius: 6px; text-decoration: none; font-weight: 600; }
.history-table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
.history-table th, .history-table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }
.history-table th { color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; }
.score-pill { padding: 3px 10px; border-radius: 12px; font-size: 0.85rem; font-weight: bold; }
.score-pill.grade-a { background: #166534; color: #4ade80; }
.score-pill.grade-b { background: #1a5e1f; color: #86efac; }
.score-pill.grade-c { background: #854d0e; color: #fde047; }
.score-pill.grade-d { background: #9a3412; color: #fdba74; }
.score-pill.grade-f { background: #7f1d1d; color: #fca5a5; }
.report-link { color: #60a5fa; text-decoration: none; }
.report-link:hover { text-decoration: underline; }
.doc-section { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
.doc-section pre { background: #0f172a; border-radius: 6px; padding: 1rem; overflow-x: auto; margin: 0.75rem 0; }
.doc-section code { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; color: #e2e8f0; }
.doc-section ol, .doc-section ul { padding-left: 1.5rem; margin: 0.5rem 0; color: #94a3b8; }
.doc-section li { margin-bottom: 0.5rem; }
.doc-table { width: 100%; border-collapse: collapse; }
.doc-table th, .doc-table td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #334155; }
.doc-table th { color: #94a3b8; }
"""
