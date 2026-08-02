"""
Cost Policy Violation Checker.
Validates spending against thresholds and budget caps.
"""

import logging

from utils.findings import create_violation

logger = logging.getLogger(__name__)


def check_cost_policy(cost_data, config):
    """Check cost data against policy thresholds."""
    violations = []

    if not cost_data:
        return violations

    # Check per-service spend against threshold
    for service_info in cost_data.get("top_services", []):
        service = service_info["service"]
        amount = service_info["amount"]

        # Skip excluded services
        if service in config.excluded_services_from_cost_alert:
            continue

        if amount > config.cost_alert_threshold:
            violations.append(create_violation(
                title=f"Service '{service}' exceeds cost threshold: ${amount:.2f}/month",
                severity="medium",
                category="cost",
                resource_type="AWS Service",
                resource_id=service,
                description=f"Threshold: ${config.cost_alert_threshold}. No CostApproved tag found.",
                fix_commands=[
                    "# Review if this spend is expected. Options:",
                    "# 1. Optimize the service usage to reduce cost",
                    "# 2. Add to excluded_services_from_cost_alert in config",
                    "# 3. Add a budget_cap entry with an approved monthly limit",
                ],
                current_value=f"${amount:.2f}/month",
                expected_value=f"Under ${config.cost_alert_threshold}/month or explicitly approved",
            ))

    # Check budget caps (for approved expensive services)
    for budget in cost_data.get("budget_status", []):
        if budget["status"] == "over":
            violations.append(create_violation(
                title=f"Service '{budget['service']}' exceeded budget cap: ${budget['spend']:.2f} / ${budget['cap']:.2f}",
                severity="high",
                category="cost",
                resource_type="AWS Service",
                resource_id=budget["service"],
                description=f"Reason for cap: {budget['reason']}. At {budget['percentage']:.0f}% of budget.",
                fix_commands=[
                    f"# Investigate usage spike for {budget['service']}",
                    "# Consider throttling usage or increasing the budget cap",
                ],
                current_value=f"${budget['spend']:.2f} ({budget['percentage']:.0f}%)",
                expected_value=f"Under ${budget['cap']:.2f}/month",
            ))
        elif budget["status"] == "warning":
            violations.append(create_violation(
                title=f"Service '{budget['service']}' approaching budget cap: ${budget['spend']:.2f} / ${budget['cap']:.2f}",
                severity="medium",
                category="cost",
                resource_type="AWS Service",
                resource_id=budget["service"],
                description=f"At {budget['percentage']:.0f}% of approved budget ({budget['reason']}).",
                fix_commands=[
                    f"# Monitor usage for {budget['service']}",
                    "# Consider switching to cheaper model/tier if available",
                ],
                current_value=f"${budget['spend']:.2f} ({budget['percentage']:.0f}%)",
                expected_value=f"Under ${budget['cap']:.2f}/month",
            ))

    # Check month-over-month spike
    mtd = cost_data.get("month_to_date", 0)
    last_month = cost_data.get("last_month", 0)
    if last_month > 0 and mtd > 0:
        # Normalize MTD to full month estimate for comparison
        forecast = cost_data.get("forecast", 0)
        if forecast > 0 and last_month > 0:
            change_pct = ((forecast - last_month) / last_month) * 100
            if change_pct > 50:
                violations.append(create_violation(
                    title=f"Forecasted spend is {change_pct:.0f}% higher than last month",
                    severity="medium",
                    category="cost",
                    resource_type="Account",
                    resource_id="cost-forecast",
                    description=f"Last month: ${last_month:.2f}, Forecast: ${forecast:.2f}",
                    fix_commands=[
                        "# Review Cost Explorer for the spike:",
                        "# https://console.aws.amazon.com/cost-management/home#/cost-explorer",
                        "# Check for new resources or increased usage",
                    ],
                    current_value=f"Forecast: ${forecast:.2f} (+{change_pct:.0f}%)",
                    expected_value=f"Within 50% of last month (${last_month:.2f})",
                ))

    return violations
