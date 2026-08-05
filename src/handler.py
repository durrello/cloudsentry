"""
CloudSentry Lambda Handler
Main entry point for the AWS account security and operations auditor.
"""

import json
import logging
import os
from datetime import datetime, timezone

from config import load_config
from utils.multi_account import get_sessions
from utils.regions import get_active_regions
from utils.dynamo import store_report, get_previous_report, get_report_history
from scanner.iam_audit import scan_iam
from scanner.network_audit import scan_network
from scanner.compute_audit import scan_compute
from scanner.storage_audit import scan_storage
from scanner.database_audit import scan_database
from scanner.encryption_audit import scan_encryption
from scanner.logging_audit import scan_logging
from scanner.dns_audit import scan_dns
from scanner.cost_audit import scan_cost
from scanner.inventory import scan_inventory
from scanner.drift_detection import detect_drift
from violations.tag_compliance import check_tag_compliance
from violations.naming_policy import check_naming_policy
from violations.lifecycle_policy import check_lifecycle_policy
from violations.cost_policy import check_cost_policy
from violations.architecture_policy import check_architecture_policy
from violations.access_policy import check_access_policy
from scoring.calculator import calculate_security_score
from remediation.actions import generate_action_plan
from report.builder import build_report
from report.email_formatter import format_email
from report.html_dashboard import generate_html_dashboard
from report.slack_formatter import format_slack_message
from report.static_pages import generate_history_page, generate_docs_page

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Main Lambda handler."""
    logger.info("CloudSentry scan starting")

    # Determine if this is an on-demand scan with specific modules
    modules = None
    if event.get("queryStringParameters"):
        modules_param = event["queryStringParameters"].get("modules")
        if modules_param:
            modules = [m.strip() for m in modules_param.split(",")]

    config = load_config()
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sessions = get_sessions(config)
    all_account_reports = []

    for session_info in sessions:
        account_name = session_info["name"]
        session = session_info["session"]
        account_id = session_info.get("account_id", "local")

        logger.info(f"Scanning account: {account_name} ({account_id})")

        # Get active regions for this account
        active_regions = get_active_regions(session)
        logger.info(f"Active regions: {active_regions}")

        # Run scanners
        account_report = {
            "account_name": account_name,
            "account_id": account_id,
            "scan_date": scan_date,
            "regions": active_regions,
            "findings": [],
            "violations": [],
            "inventory": {},
            "cost": {},
        }

        # Inventory (always runs)
        account_report["inventory"] = scan_inventory(session, active_regions)

        # Security scanners
        if should_run("iam", modules):
            findings = scan_iam(session, config)
            account_report["findings"].extend(findings)

        if should_run("network", modules):
            for region in active_regions:
                findings = scan_network(session, region, config)
                account_report["findings"].extend(findings)

        if should_run("compute", modules):
            for region in active_regions:
                findings = scan_compute(session, region, config)
                account_report["findings"].extend(findings)

        if should_run("storage", modules):
            findings = scan_storage(session, config)
            account_report["findings"].extend(findings)

        if should_run("database", modules):
            for region in active_regions:
                findings = scan_database(session, region, config)
                account_report["findings"].extend(findings)

        if should_run("encryption", modules):
            for region in active_regions:
                findings = scan_encryption(session, region, config)
                account_report["findings"].extend(findings)

        if should_run("logging", modules):
            findings = scan_logging(session, config)
            account_report["findings"].extend(findings)

        if should_run("dns", modules):
            findings = scan_dns(session, config)
            account_report["findings"].extend(findings)

        if should_run("cost", modules):
            account_report["cost"] = scan_cost(session, config)

        # Infrastructure drift detection
        if should_run("drift", modules):
            drift_findings = detect_drift(session, active_regions, config)
            account_report["findings"].extend(drift_findings)

        # Policy violations
        if should_run("violations", modules):
            account_report["violations"].extend(
                check_tag_compliance(account_report["inventory"], config)
            )
            account_report["violations"].extend(
                check_naming_policy(account_report["inventory"], config)
            )
            account_report["violations"].extend(
                check_lifecycle_policy(session, active_regions, config)
            )
            account_report["violations"].extend(
                check_cost_policy(account_report["cost"], config)
            )
            account_report["violations"].extend(
                check_architecture_policy(account_report["inventory"], config)
            )
            account_report["violations"].extend(
                check_access_policy(session, config)
            )

        # Calculate security score
        account_report["score"] = calculate_security_score(
            account_report["findings"], account_report["violations"]
        )

        # Generate action plan with remediation
        account_report["action_plan"] = generate_action_plan(
            account_report["findings"], account_report["violations"]
        )

        all_account_reports.append(account_report)

    # Get previous report for trend comparison
    previous_reports = {}
    for report in all_account_reports:
        prev = get_previous_report(report["account_id"])
        if prev:
            previous_reports[report["account_id"]] = prev

    # Build the full report
    full_report = build_report(all_account_reports, previous_reports, config)

    # Store in DynamoDB
    for report in all_account_reports:
        store_report(report)

    # Generate and upload HTML dashboard
    html = generate_html_dashboard(full_report)
    upload_dashboard(html, scan_date)

    # Generate and upload history + docs pages
    upload_static_pages(all_account_reports)

    # Send email via SNS
    email_body = format_email(full_report)
    send_email(email_body, scan_date)

    # Send Slack notification (if configured)
    if config.slack_webhook_url:
        slack_msg = format_slack_message(full_report)
        send_slack(slack_msg, config.slack_webhook_url)

    logger.info("CloudSentry scan complete")

    # Return response (for API Gateway)
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "status": "complete",
            "scan_date": scan_date,
            "accounts_scanned": len(all_account_reports),
            "total_findings": sum(
                len(r["findings"]) for r in all_account_reports
            ),
            "total_violations": sum(
                len(r["violations"]) for r in all_account_reports
            ),
            "scores": {
                r["account_name"]: r["score"] for r in all_account_reports
            },
        }),
    }


def should_run(module_name, requested_modules):
    """Check if a module should run based on request."""
    if requested_modules is None:
        return True
    return module_name in requested_modules


def upload_dashboard(html, scan_date):
    """Upload HTML dashboard to S3."""
    import boto3

    s3 = boto3.client("s3")
    bucket = os.environ["S3_BUCKET"]

    # Upload current report
    s3.put_object(
        Bucket=bucket,
        Key=f"reports/{scan_date}.html",
        Body=html.encode("utf-8"),
        ContentType="text/html",
    )

    # Also upload as latest
    s3.put_object(
        Bucket=bucket,
        Key="reports/latest.html",
        Body=html.encode("utf-8"),
        ContentType="text/html",
    )


def send_email(email_body, scan_date):
    """Send report via SES (HTML email) with SNS as fallback."""
    import boto3

    # Try SES first (renders HTML properly)
    ses = boto3.client("ses", region_name="us-east-1")
    notification_emails = json.loads(os.environ.get("NOTIFICATION_EMAILS", "[]"))

    if notification_emails:
        try:
            ses.send_email(
                Source=notification_emails[0],  # Send from first email (must be verified in SES)
                Destination={"ToAddresses": notification_emails},
                Message={
                    "Subject": {"Data": f"CloudSentry Report - {scan_date}", "Charset": "UTF-8"},
                    "Body": {
                        "Html": {"Data": email_body, "Charset": "UTF-8"},
                    },
                },
            )
            logger.info("Report sent via SES")
            return
        except Exception as e:
            logger.warning(f"SES send failed (falling back to SNS): {e}")

    # Fallback: send plain-text summary via SNS
    sns = boto3.client("sns")
    topic_arn = os.environ["SNS_TOPIC_ARN"]

    # Strip HTML for SNS fallback
    plain_text = f"""CloudSentry Report - {scan_date}

View the full HTML report at:
https://cloudsentry.durrellgemuh.com/reports/latest.html

(Email sent as plain text because SES is not configured. 
Verify your sender email in SES to receive styled HTML reports.)
"""
    sns.publish(
        TopicArn=topic_arn,
        Subject=f"CloudSentry Report - {scan_date}",
        Message=plain_text,
    )


def send_slack(message, webhook_url):
    """Send summary to Slack webhook."""
    from urllib.request import Request, urlopen

    req = Request(
        webhook_url,
        data=json.dumps({"text": message}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        urlopen(req)
    except Exception as e:
        logger.error(f"Failed to send Slack notification: {e}")


def upload_static_pages(account_reports):
    """Upload history and docs pages to S3."""
    import boto3

    s3 = boto3.client("s3")
    bucket = os.environ["S3_BUCKET"]

    # Get scan history from DynamoDB for all accounts
    all_history = []
    for report in account_reports:
        history = get_report_history(report["account_id"], weeks=52)
        all_history.extend(history)

    # Generate and upload history page
    history_html = generate_history_page(all_history)
    s3.put_object(
        Bucket=bucket,
        Key="history.html",
        Body=history_html.encode("utf-8"),
        ContentType="text/html",
    )

    # Generate and upload docs page
    docs_html = generate_docs_page()
    s3.put_object(
        Bucket=bucket,
        Key="docs.html",
        Body=docs_html.encode("utf-8"),
        ContentType="text/html",
    )
