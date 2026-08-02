"""
Report Builder.
Compiles all scan data into a unified report structure.
"""

import logging
from datetime import datetime, timezone

from scoring.calculator import get_score_breakdown, get_score_grade

logger = logging.getLogger(__name__)


def build_report(account_reports, previous_reports, config):
    """Build the unified report from all account scan data."""
    report = {
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "accounts": [],
        "summary": {},
    }

    total_findings = 0
    total_violations = 0
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0

    for acct_report in account_reports:
        account_id = acct_report["account_id"]
        prev = previous_reports.get(account_id)

        # Score trend
        prev_score = int(prev["score"]) if prev else None
        current_score = acct_report["score"]
        score_change = (current_score - prev_score) if prev_score else None

        # Findings counts
        findings = acct_report["findings"]
        violations = acct_report["violations"]
        breakdown = get_score_breakdown(findings, violations)

        severity_counts = {
            "critical": len([f for f in findings if f["severity"] == "critical"]),
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "low": len([f for f in findings if f["severity"] == "low"]),
        }

        total_findings += len(findings)
        total_violations += len(violations)
        total_critical += severity_counts["critical"]
        total_high += severity_counts["high"]
        total_medium += severity_counts["medium"]
        total_low += severity_counts["low"]

        account_data = {
            "name": acct_report["account_name"],
            "account_id": account_id,
            "score": current_score,
            "grade": get_score_grade(current_score),
            "score_change": score_change,
            "previous_score": prev_score,
            "regions": acct_report["regions"],
            "findings_count": len(findings),
            "violations_count": len(violations),
            "severity_counts": severity_counts,
            "inventory": acct_report["inventory"],
            "findings": findings,
            "violations": violations,
            "cost": acct_report.get("cost", {}),
            "action_plan": acct_report.get("action_plan", {}),
            "breakdown": breakdown,
        }

        report["accounts"].append(account_data)

    # Overall summary
    report["summary"] = {
        "total_accounts": len(account_reports),
        "total_findings": total_findings,
        "total_violations": total_violations,
        "severity": {
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
        },
        "average_score": (
            sum(a["score"] for a in report["accounts"]) / len(report["accounts"])
            if report["accounts"] else 0
        ),
    }

    return report
