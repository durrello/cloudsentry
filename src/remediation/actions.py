"""
Action Plan Generator.
Creates a prioritized, grouped action plan from findings and violations.
"""

import logging

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_action_plan(findings, violations):
    """
    Generate a prioritized action plan from findings and violations.
    Groups by severity, adds effort estimates and fix commands.
    """
    all_items = []

    for f in findings:
        all_items.append({
            "id": generate_id(f),
            "title": f["title"],
            "severity": f["severity"],
            "type": "security",
            "resource_type": f.get("resource_type", ""),
            "resource_id": f.get("resource_id", ""),
            "region": f.get("region", "global"),
            "risk": f.get("risk", ""),
            "description": f.get("description", ""),
            "fix_commands": f.get("fix_commands", []),
            "better_alternative": f.get("better_alternative", ""),
            "compliance": f.get("compliance", []),
            "effort": f.get("effort", "unknown"),
        })

    for v in violations:
        all_items.append({
            "id": generate_id(v),
            "title": v["title"],
            "severity": v["severity"],
            "type": "violation",
            "category": v.get("category", ""),
            "resource_type": v.get("resource_type", ""),
            "resource_id": v.get("resource_id", ""),
            "region": v.get("region", "global"),
            "description": v.get("description", ""),
            "fix_commands": v.get("fix_commands", []),
            "current_value": v.get("current_value", ""),
            "expected_value": v.get("expected_value", ""),
            "effort": estimate_effort(v),
        })

    # Sort by severity
    all_items.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"].lower(), 99))

    # Group by severity
    action_plan = {
        "critical": [i for i in all_items if i["severity"] == "critical"],
        "high": [i for i in all_items if i["severity"] == "high"],
        "medium": [i for i in all_items if i["severity"] == "medium"],
        "low": [i for i in all_items if i["severity"] == "low"],
    }

    # Calculate total effort
    action_plan["summary"] = {
        "total": len(all_items),
        "critical_count": len(action_plan["critical"]),
        "high_count": len(action_plan["high"]),
        "medium_count": len(action_plan["medium"]),
        "low_count": len(action_plan["low"]),
    }

    return action_plan


def generate_id(item):
    """Generate a short ID for the action item."""
    severity_prefix = item.get("severity", "l")[0].upper()
    resource = item.get("resource_id", "unknown")[:10]
    return f"{severity_prefix}-{resource}"


def estimate_effort(violation):
    """Estimate fix effort for a violation."""
    category = violation.get("category", "")

    if category == "tag":
        return "5 minutes"
    elif category == "naming":
        return "10 minutes"
    elif category == "lifecycle":
        return "5 minutes"
    elif category == "cost":
        return "varies"
    elif category == "architecture":
        return "30 minutes"
    elif category == "access":
        return "15 minutes"
    return "unknown"
