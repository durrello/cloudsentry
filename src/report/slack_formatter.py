"""
Slack Message Formatter.
Creates a concise summary for Slack notifications.
"""

from scoring.calculator import get_score_grade


def format_slack_message(report):
    """Format report as a short Slack message."""
    summary = report["summary"]
    scan_date = report["scan_date"]

    lines = []
    lines.append(f"*CloudSentry Report - {scan_date}*")
    lines.append("")

    # Account scores
    for acct in report["accounts"]:
        grade = get_score_grade(acct["score"])
        trend = ""
        if acct["score_change"] is not None:
            emoji = ":arrow_up:" if acct["score_change"] > 0 else ":arrow_down:" if acct["score_change"] < 0 else ":left_right_arrow:"
            trend = f" {emoji} ({'+' if acct['score_change'] >= 0 else ''}{acct['score_change']})"
        lines.append(f"*{acct['name']}*: {acct['score']}/100 ({grade}){trend}")

    lines.append("")

    # Severity counts
    sev = summary["severity"]
    lines.append(
        f":red_circle: {sev['critical']} Critical  "
        f":large_orange_circle: {sev['high']} High  "
        f":large_yellow_circle: {sev['medium']} Medium  "
        f":white_circle: {sev['low']} Low"
    )

    # Cost summary
    total_mtd = sum(
        acct.get("cost", {}).get("month_to_date", 0) for acct in report["accounts"]
    )
    total_forecast = sum(
        acct.get("cost", {}).get("forecast", 0) for acct in report["accounts"]
    )
    if total_mtd > 0:
        lines.append(f":moneybag: MTD: ${total_mtd:.2f} | Forecast: ${total_forecast:.2f}")

    lines.append("")
    lines.append("Full report in your inbox and S3 dashboard.")

    return "\n".join(lines)
