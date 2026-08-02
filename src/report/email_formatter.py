"""
Email Report Formatter.
Formats the report as a plain-text email digest for SNS.
"""

from scoring.calculator import get_score_bar, get_score_grade


def format_email(report):
    """Format the full report as a plain-text email."""
    lines = []
    scan_date = report["scan_date"]
    summary = report["summary"]

    lines.append("=" * 56)
    lines.append(f"  CloudSentry Weekly Report - {scan_date}")
    lines.append("=" * 56)
    lines.append("")

    # Multi-account comparison
    if len(report["accounts"]) > 1:
        lines.append("ACCOUNT COMPARISON")
        lines.append("-" * 40)
        for acct in report["accounts"]:
            trend = ""
            if acct["score_change"] is not None:
                trend = f" ({'+' if acct['score_change'] >= 0 else ''}{acct['score_change']})"
            cost_mtd = acct.get("cost", {}).get("month_to_date", 0)
            lines.append(
                f"  {acct['name']:20s} Score: {acct['score']}/100{trend:8s} "
                f"Cost: ${cost_mtd:.2f}"
            )
        lines.append("")

    # Per-account details
    for acct in report["accounts"]:
        lines.append("=" * 56)
        lines.append(f"  {acct['name']} ({acct['account_id']})")
        lines.append("=" * 56)
        lines.append("")

        # Score
        lines.append("SECURITY SCORE")
        lines.append(f"  {get_score_bar(acct['score'])}")
        if acct["score_change"] is not None:
            direction = "improved" if acct["score_change"] > 0 else "declined"
            lines.append(f"  Last week: {acct['previous_score']}/100 ({direction} by {abs(acct['score_change'])})")
        lines.append("")

        # Inventory summary
        lines.append("ACTIVE REGIONS")
        lines.append(f"  {', '.join(acct['regions'])}")
        lines.append("")

        inventory = acct.get("inventory", {})
        totals = inventory.get("totals", {})
        if totals:
            lines.append("RESOURCE TOTALS")
            for service, count in sorted(totals.items()):
                if count > 0:
                    lines.append(f"  {service:25s} {count}")
            lines.append("")

        # Cost
        cost = acct.get("cost", {})
        if cost and cost.get("month_to_date"):
            lines.append("COST SNAPSHOT")
            lines.append(f"  Month-to-date:  ${cost['month_to_date']:.2f}")
            if cost.get("forecast"):
                lines.append(f"  Forecast:       ${cost['forecast']:.2f}")
            if cost.get("last_month"):
                change = ((cost.get("forecast", 0) - cost["last_month"]) / cost["last_month"] * 100) if cost["last_month"] > 0 else 0
                lines.append(f"  vs Last month:  {'+' if change >= 0 else ''}{change:.0f}%")
            lines.append("")

            if cost.get("top_services"):
                lines.append("  Top services:")
                for svc in cost["top_services"][:5]:
                    lines.append(f"    {svc['service']:35s} ${svc['amount']:.2f}")
                lines.append("")

            if cost.get("budget_status"):
                lines.append("  Budget tracking:")
                for b in cost["budget_status"]:
                    icon = "!" if b["status"] == "over" else "~" if b["status"] == "warning" else "ok"
                    lines.append(f"    [{icon}] {b['service']:25s} ${b['spend']:.2f} / ${b['cap']:.2f} ({b['percentage']:.0f}%)")
                lines.append("")

        # Findings summary
        sev = acct["severity_counts"]
        lines.append(f"FINDINGS: {acct['findings_count']} total, {acct['violations_count']} violations")
        lines.append(f"  Critical: {sev['critical']}  High: {sev['high']}  Medium: {sev['medium']}  Low: {sev['low']}")
        lines.append("")

        # Action plan
        action_plan = acct.get("action_plan", {})
        if action_plan.get("critical"):
            lines.append("ACTION PLAN: CRITICAL (fix today)")
            lines.append("-" * 40)
            for item in action_plan["critical"][:5]:
                lines.append(f"  [{item['id']}] {item['title']}")
                if item.get("risk"):
                    lines.append(f"    Risk: {item['risk'][:80]}")
                if item.get("fix_commands"):
                    lines.append(f"    Fix: {item['fix_commands'][0]}")
                lines.append("")

        if action_plan.get("high"):
            lines.append("ACTION PLAN: HIGH (fix this week)")
            lines.append("-" * 40)
            for item in action_plan["high"][:5]:
                lines.append(f"  [{item['id']}] {item['title']}")
                if item.get("fix_commands"):
                    lines.append(f"    Fix: {item['fix_commands'][0]}")
                lines.append("")

        if action_plan.get("medium"):
            lines.append(f"MEDIUM priority: {len(action_plan['medium'])} items (see full report)")
        if action_plan.get("low"):
            lines.append(f"LOW priority: {len(action_plan['low'])} items (cleanup when available)")
        lines.append("")

    # Footer
    lines.append("=" * 56)
    lines.append("  Generated by CloudSentry")
    lines.append("  https://github.com/durrello/cloudsentry")
    lines.append("=" * 56)

    return "\n".join(lines)
