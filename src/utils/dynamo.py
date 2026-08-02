"""
DynamoDB utilities for storing and retrieving scan history.
"""

import json
import logging
import os
from datetime import datetime, timezone
from decimal import Decimal

import boto3

logger = logging.getLogger(__name__)


def get_table():
    """Get DynamoDB table resource."""
    dynamodb = boto3.resource("dynamodb")
    table_name = os.environ.get("DYNAMODB_TABLE", "cloudsentry-history")
    return dynamodb.Table(table_name)


def store_report(account_report):
    """Store a scan report in DynamoDB."""
    table = get_table()

    # Convert floats to Decimal for DynamoDB
    item = {
        "account_id": account_report["account_id"],
        "scan_date": account_report["scan_date"],
        "account_name": account_report["account_name"],
        "score": Decimal(str(account_report["score"])),
        "findings_count": len(account_report["findings"]),
        "violations_count": len(account_report["violations"]),
        "findings_by_severity": count_by_severity(account_report["findings"]),
        "cost_mtd_gross": Decimal(str(round(account_report.get("cost", {}).get("month_to_date_gross", 0), 2))),
        "cost_last_month_gross": Decimal(str(round(account_report.get("cost", {}).get("last_month_gross", 0), 2))),
        "regions": account_report["regions"],
        # TTL: keep reports for 1 year
        "ttl": int(
            (datetime.now(timezone.utc).timestamp()) + (365 * 24 * 60 * 60)
        ),
    }

    try:
        table.put_item(Item=item)
        logger.info(f"Stored report for {account_report['account_name']} ({account_report['scan_date']})")
    except Exception as e:
        logger.error(f"Failed to store report: {e}")


def get_previous_report(account_id):
    """Get the most recent previous report for an account."""
    table = get_table()

    try:
        response = table.query(
            KeyConditionExpression="account_id = :aid",
            ExpressionAttributeValues={":aid": account_id},
            ScanIndexForward=False,  # Most recent first
            Limit=2,  # Get last 2 (current + previous)
        )

        items = response.get("Items", [])
        # Return the second item (previous report), skip current
        if len(items) >= 2:
            return items[1]
        return None
    except Exception as e:
        logger.error(f"Failed to get previous report: {e}")
        return None


def get_report_history(account_id, weeks=12):
    """Get report history for trend charts."""
    table = get_table()

    try:
        response = table.query(
            KeyConditionExpression="account_id = :aid",
            ExpressionAttributeValues={":aid": account_id},
            ScanIndexForward=False,
            Limit=weeks,
        )
        return list(reversed(response.get("Items", [])))
    except Exception as e:
        logger.error(f"Failed to get report history: {e}")
        return []


def count_by_severity(findings):
    """Count findings by severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding.get("severity", "low").lower()
        if severity in counts:
            counts[severity] += 1
    return counts
