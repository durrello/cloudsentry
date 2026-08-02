"""
Finding and violation data structures.
Standard format used across all scanners and violation checkers.
"""


def create_finding(
    title,
    severity,
    resource_type,
    resource_id,
    region="global",
    description="",
    risk="",
    fix_commands=None,
    better_alternative="",
    compliance=None,
    effort="",
):
    """
    Create a standardized finding dict.

    Args:
        title: Short description of the finding
        severity: One of "critical", "high", "medium", "low"
        resource_type: AWS resource type (e.g., "IAM User", "Security Group")
        resource_id: Resource identifier (ARN, ID, or name)
        region: AWS region where the resource exists
        description: Detailed explanation
        risk: Why this matters
        fix_commands: List of CLI commands to fix the issue
        better_alternative: Suggested better approach
        compliance: List of compliance references (e.g., ["CIS 1.5", "SOC2 CC6.1"])
        effort: Estimated time to fix (e.g., "5 minutes", "30 minutes")
    """
    return {
        "title": title,
        "severity": severity,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "region": region,
        "description": description,
        "risk": risk,
        "fix_commands": fix_commands or [],
        "better_alternative": better_alternative,
        "compliance": compliance or [],
        "effort": effort,
    }


def create_violation(
    title,
    severity,
    category,
    resource_type,
    resource_id,
    region="global",
    description="",
    fix_commands=None,
    current_value="",
    expected_value="",
):
    """
    Create a standardized policy violation dict.

    Args:
        title: Short description of the violation
        severity: One of "critical", "high", "medium", "low"
        category: Violation category (tag, naming, lifecycle, cost, architecture, access)
        resource_type: AWS resource type
        resource_id: Resource identifier
        region: AWS region
        description: Detailed explanation
        fix_commands: List of CLI commands to fix
        current_value: What the current state is
        expected_value: What it should be
    """
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "region": region,
        "description": description,
        "fix_commands": fix_commands or [],
        "current_value": current_value,
        "expected_value": expected_value,
    }
