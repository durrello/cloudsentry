"""
Email Report Formatter.
Formats the report as an HTML email optimized for Gmail/Outlook rendering.
Uses inline styles and table-based layout for maximum email client compatibility.
"""

from scoring.calculator import get_score_grade


def format_email(report):
    """Format the full report as Gmail-compatible HTML email."""
    scan_date = report["scan_date"]
    summary = report["summary"]
    sev = summary["severity"]

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudSentry Report - {scan_date}</title>
</head>
<body style="margin:0;padding:0;background-color:#1a1a2e;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#1a1a2e;">
<tr><td align="center" style="padding:20px 10px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#16213e;border-radius:12px;overflow:hidden;">

<!-- Header -->
<tr><td style="background-color:#0f3460;padding:24px;text-align:center;">
<h1 style="margin:0;font-size:24px;color:#e94560;font-weight:700;letter-spacing:1px;">CloudSentry</h1>
<p style="margin:6px 0 0;font-size:14px;color:#a8b2d1;">Weekly Security Report - {scan_date}</p>
</td></tr>

<!-- Severity Summary -->
<tr><td style="padding:20px 24px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
<tr>
<td align="center" style="padding:8px;"><span style="display:block;font-size:28px;font-weight:bold;color:#ff4757;">{sev['critical']}</span><span style="font-size:11px;color:#a8b2d1;text-transform:uppercase;">Critical</span></td>
<td align="center" style="padding:8px;"><span style="display:block;font-size:28px;font-weight:bold;color:#ffa502;">{sev['high']}</span><span style="font-size:11px;color:#a8b2d1;text-transform:uppercase;">High</span></td>
<td align="center" style="padding:8px;"><span style="display:block;font-size:28px;font-weight:bold;color:#eccc68;">{sev['medium']}</span><span style="font-size:11px;color:#a8b2d1;text-transform:uppercase;">Medium</span></td>
<td align="center" style="padding:8px;"><span style="display:block;font-size:28px;font-weight:bold;color:#57606f;">{sev['low']}</span><span style="font-size:11px;color:#a8b2d1;text-transform:uppercase;">Low</span></td>
</tr>
</table>
</td></tr>
"""

    for acct in report["accounts"]:
        grade = get_score_grade(acct["score"])
        score_color = "#ff4757" if grade == "F" else "#ffa502" if grade in ("D", "C") else "#2ed573"
        trend_text = ""
        if acct["score_change"] is not None:
            arrow = "+" if acct["score_change"] >= 0 else ""
            trend_color = "#2ed573" if acct["score_change"] >= 0 else "#ff4757"
            trend_text = f' <span style="color:{trend_color};font-size:12px;">({arrow}{acct["score_change"]})</span>'

        html += f"""
<!-- Account Section -->
<tr><td style="padding:0 24px 20px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#1a1a2e;border-radius:8px;overflow:hidden;">

<!-- Account Header -->
<tr><td style="padding:16px 20px;border-bottom:1px solid #2a2a4a;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
<tr>
<td><span style="font-size:16px;font-weight:600;color:#e8e8e8;">{acct['name']}</span></td>
<td align="right"><span style="background-color:{score_color};color:#fff;padding:4px 12px;border-radius:20px;font-size:13px;font-weight:bold;">{acct['score']}/100 {grade}</span>{trend_text}</td>
</tr>
</table>
<p style="margin:4px 0 0;font-size:12px;color:#57606f;">Regions: {', '.join(acct['regions'])}</p>
</td></tr>
"""

        # Cost
        cost = acct.get("cost", {})
        if cost:
            burn = cost.get("burn_rate", {})
            credits = cost.get("credits", {})

            html += f"""
<tr><td style="padding:12px 20px;">
<p style="margin:0 0 8px;font-size:11px;font-weight:600;color:#a8b2d1;text-transform:uppercase;letter-spacing:1px;">Cost</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;">
<tr><td style="padding:4px 0;color:#a8b2d1;">Month-to-date (gross)</td><td align="right" style="padding:4px 0;color:#e8e8e8;font-weight:500;">${cost.get('month_to_date_gross', 0):.2f}</td></tr>
"""
            if cost.get("last_month_gross"):
                html += f'<tr><td style="padding:4px 0;color:#a8b2d1;">Last month (gross)</td><td align="right" style="padding:4px 0;color:#e8e8e8;font-weight:500;">${cost["last_month_gross"]:.2f}</td></tr>'
            if cost.get("raw_usage_mtd"):
                html += f'<tr><td style="padding:4px 0;color:#a8b2d1;">Usage</td><td align="right" style="padding:4px 0;color:#e8e8e8;font-weight:500;">${cost["raw_usage_mtd"]:.2f}</td></tr>'
            if cost.get("subscriptions_mtd"):
                html += f'<tr><td style="padding:4px 0;color:#a8b2d1;">Subscriptions</td><td align="right" style="padding:4px 0;color:#e8e8e8;font-weight:500;">${cost["subscriptions_mtd"]:.2f}</td></tr>'
            if burn.get("daily_rate", 0) > 0:
                html += f'<tr><td style="padding:4px 0;color:#a8b2d1;">Daily burn</td><td align="right" style="padding:4px 0;color:#e8e8e8;font-weight:500;">${burn["daily_rate"]:.2f}/day</td></tr>'
                html += f'<tr><td style="padding:4px 0;color:#a8b2d1;">Annual rate</td><td align="right" style="padding:4px 0;color:#e8e8e8;font-weight:500;">${burn["annual_rate"]:.2f}/yr</td></tr>'

            # Credits
            if credits.get("has_credits"):
                total_applied = credits.get("total_credits_applied", 0)
                this_month_credits = credits.get("credits_this_month", 0)
                last_month_credits = credits.get("credits_last_month", 0)
                html += f'<tr><td style="padding:4px 0;color:#a8b2d1;">Credits applied (6mo)</td><td align="right" style="padding:4px 0;color:#e8e8e8;font-weight:500;">${total_applied:.2f}</td></tr>'
                html += f'<tr><td style="padding:4px 0;color:#a8b2d1;">Credits this month</td><td align="right" style="padding:4px 0;color:#2ed573;font-weight:500;">${this_month_credits:.2f}</td></tr>'
                html += f'<tr><td style="padding:4px 0;color:#a8b2d1;">Credits last month</td><td align="right" style="padding:4px 0;color:#2ed573;font-weight:500;">${last_month_credits:.2f}</td></tr>'
                coverage = burn.get("credits_coverage")
                if coverage:
                    html += f'<tr><td style="padding:4px 0;color:#a8b2d1;">Coverage</td><td align="right" style="padding:4px 0;color:#2ed573;font-weight:500;">{coverage} covered</td></tr>'

            html += '</table></td></tr>'

        # Critical findings
        action_plan = acct.get("action_plan", {})
        critical_items = action_plan.get("critical", [])
        high_items = action_plan.get("high", [])

        if critical_items:
            html += '<tr><td style="padding:12px 20px;border-top:1px solid #2a2a4a;">'
            html += '<p style="margin:0 0 8px;font-size:11px;font-weight:600;color:#ff4757;text-transform:uppercase;letter-spacing:1px;">Critical (fix today)</p>'
            for item in critical_items[:5]:
                html += f'<div style="padding:6px 0;border-bottom:1px solid #2a2a4a;">'
                html += f'<span style="background-color:#5c0a0a;color:#ff4757;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:bold;">CRITICAL</span> '
                html += f'<span style="color:#e8e8e8;font-size:13px;">{item["title"]}</span>'
                if item.get("fix_commands"):
                    cmd = item["fix_commands"][0]
                    if not cmd.startswith("#"):
                        html += f'<p style="margin:4px 0 0;font-size:11px;color:#70a1ff;font-family:monospace;word-break:break-all;">{cmd}</p>'
                html += '</div>'
            html += '</td></tr>'

        if high_items:
            html += '<tr><td style="padding:12px 20px;border-top:1px solid #2a2a4a;">'
            html += '<p style="margin:0 0 8px;font-size:11px;font-weight:600;color:#ffa502;text-transform:uppercase;letter-spacing:1px;">High (fix this week)</p>'
            for item in high_items[:5]:
                html += f'<div style="padding:6px 0;border-bottom:1px solid #2a2a4a;">'
                html += f'<span style="background-color:#5c3a0a;color:#ffa502;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:bold;">HIGH</span> '
                html += f'<span style="color:#e8e8e8;font-size:13px;">{item["title"]}</span>'
                if item.get("fix_commands"):
                    cmd = item["fix_commands"][0]
                    if not cmd.startswith("#"):
                        html += f'<p style="margin:4px 0 0;font-size:11px;color:#70a1ff;font-family:monospace;word-break:break-all;">{cmd}</p>'
                html += '</div>'
            html += '</td></tr>'

        # Remaining count
        medium_count = len(action_plan.get("medium", []))
        low_count = len(action_plan.get("low", []))
        if medium_count or low_count:
            html += f'<tr><td style="padding:12px 20px;border-top:1px solid #2a2a4a;">'
            html += f'<p style="margin:0;font-size:13px;color:#a8b2d1;">+ {medium_count} medium, {low_count} low priority items in full report</p>'
            html += '</td></tr>'

        html += '</table></td></tr>'  # Close account table

    # CTA Button
    html += f"""
<!-- CTA -->
<tr><td style="padding:20px 24px;text-align:center;">
<a href="https://cloudsentry.durrellgemuh.com/reports/latest.html" style="display:inline-block;background-color:#e94560;color:#ffffff;padding:12px 32px;border-radius:6px;text-decoration:none;font-size:14px;font-weight:600;">View Full Dashboard</a>
</td></tr>

<!-- Footer -->
<tr><td style="padding:16px 24px;text-align:center;border-top:1px solid #2a2a4a;">
<p style="margin:0;font-size:12px;color:#57606f;">Generated by <a href="https://github.com/durrello/cloudsentry" style="color:#70a1ff;text-decoration:none;">CloudSentry</a></p>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    return html
