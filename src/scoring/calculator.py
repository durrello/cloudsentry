"""
Security Score Calculator.
Computes a 0-100 score based on findings and violations.
"""

import logging

logger = logging.getLogger(__name__)

# Points deducted per severity level
SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
}

# Maximum deductions per category to prevent one bad area
# from tanking the entire score
MAX_DEDUCTION_PER_CATEGORY = 30


def calculate_security_score(findings, violations):
    """
    Calculate security score from 0-100.
    Starts at 100 and deducts points per finding/violation.
    """
    score = 100
    total_deductions = 0

    # Deduct for findings
    for finding in findings:
        severity = finding.get("severity", "low").lower()
        weight = SEVERITY_WEIGHTS.get(severity, 1)
        total_deductions += weight

    # Deduct for violations
    for violation in violations:
        severity = violation.get("severity", "low").lower()
        weight = SEVERITY_WEIGHTS.get(severity, 1)
        total_deductions += weight

    score = max(0, score - total_deductions)
    return score


def get_score_breakdown(findings, violations):
    """Get detailed breakdown of score deductions."""
    breakdown = {
        "starting_score": 100,
        "deductions": [],
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_category": {},
    }

    all_items = []
    for f in findings:
        all_items.append({
            "title": f["title"],
            "severity": f["severity"],
            "type": "finding",
            "resource_type": f.get("resource_type", ""),
        })
    for v in violations:
        all_items.append({
            "title": v["title"],
            "severity": v["severity"],
            "type": "violation",
            "category": v.get("category", ""),
        })

    total_deduction = 0
    for item in all_items:
        severity = item["severity"].lower()
        weight = SEVERITY_WEIGHTS.get(severity, 1)
        total_deduction += weight

        breakdown["by_severity"][severity] += weight

        category = item.get("category", item.get("resource_type", "other"))
        if category not in breakdown["by_category"]:
            breakdown["by_category"][category] = 0
        breakdown["by_category"][category] += weight

        breakdown["deductions"].append({
            "title": item["title"],
            "points": -weight,
            "severity": severity,
        })

    breakdown["total_deduction"] = total_deduction
    breakdown["final_score"] = max(0, 100 - total_deduction)

    return breakdown


def get_score_grade(score):
    """Convert numeric score to letter grade."""
    if score >= 85:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 50:
        return "C"
    elif score >= 35:
        return "D"
    else:
        return "F"


def get_score_bar(score, width=20):
    """Generate a text-based score bar."""
    filled = int((score / 100) * width)
    empty = width - filled
    return f"{'█' * filled}{'░' * empty} {score}/100 ({get_score_grade(score)})"
