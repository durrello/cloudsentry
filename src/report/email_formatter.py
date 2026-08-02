"""
Email Report Formatter.
Formats the report as an HTML email for SNS (mobile-friendly).
"""

from scoring.calculator import get_score_grade


def format_email(report):
    """Format the full report as an HTML email that looks good on mobile."""
    scan_date = report["scan_date"]
    summary = report["summary"]
    sev = summary["severity"]

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudSentry Report - {scan_date}</title>
<style>
body {{ margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }}
.wrapper {{ max-width: 600px; margin: 0 auto; padding: 16px; }}
.header {{ text-align: center; padding: 20px 0; border-bottom: 1px solid #334155; }}
.header h1 {{ margin: 0; font-size: 22px; color: #f8fafc; }}
.header p {{ margin: 4px 0 0; color: #94a3b8; font-size: 14px; }}
.severity-bar {{ display: flex; justify-content: center; gap: 12px; padding: 16px 0; flex-wrap: wrap; }}
.sev-item {{ text-align: center; min-width: 60px; }}
.sev-count {{ display: block; font-size: 24px; font-weight: bold; }}
.sev-label {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; }}
.critical .sev-count {{ color: #ef4444; }}
.high .sev-count {{ color: #f97316; }}
.medium .sev-count {{ color: #eab308; }}
.low .sev-count {{ color: #64748b; }}
.account {{ background: #1e293b; border-radius: 8px; padding: 16px; margin: 12px 0; border: 1px solid #334155; }}
.account-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
.account-name {{ font-size: 16px; font-weight: 600; color: #f8fafc; }}
.score-badge {{ background: #166534; color: #4ade80; padding: 4px 10px; border-radius: 12px; font-size: 14px; font-weight: bold; }}
.score-badge.grade-c {{ background: #854d0e; color: #fde047; }}
.score-badge.grade-d {{ background: #9a3412; color: #fdba74; }}
.score-badge.grade-f {{ background: #7f1d1d; color: #fca5a5; }}
.section-title {{ font-size: 13px; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin: 16px 0 8px; }}
.cost-row {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1e293b; font-size: 14px; }}
.cost-label {{ color: #94a3b8; }}
.cost-value {{ color: #f8fafc; font-weight: 500; }}
.finding {{ padding: 8px 0; border-bottom: 1px solid #334155; }}
.finding:last-child {{ border-bottom: none; }}
.finding-title {{ font-size: 13px; color: #e2e8f0; }}
.finding-fix {{ font-size: 12px; color: #60a5fa; font-family: monospace; margin-top: 4px; word-break: break-all; }}
.badge {{ display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; margin-right: 6px; }}
.badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
.badge-high {{ background: #7c2d12; color: #fdba74; }}
.badge-medium {{ background: #713f12; color: #fde047; }}
.badge-low {{ background: #1e293b; color: #94a3b8; border: 1px solid #475569; }}
.footer {{ text-align: center; padding: 20px 0; color: #64748b; font-size: 12px; }}
.footer a {{ color: #60a5fa; text-decoration: none; }}
.trend {{ font-size: 12px; margin-left: 6px; }}
.trend-up {{ color: #4ade80; }}
.trend-down {{ color: #ef4444; }}
.regions {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
.summary-line {{ font-size: 14px; color: #cbd5e1; margin: 4px 0; }}
</style>
</head>
<body>
<div class="wrapper">

<div class="header">
<h1>CloudSentry Report</h1>
<p>{scan_date}</p>
</div>

<div class="severity-bar">
<div class="sev-item critical"><span class="sev-count">{sev['critical']}</span><span class="sev-label">Critical</span></div>
<div class="sev-item high"><span class="sev-count">{sev['high']}</span><span class="sev-label">High</span></div>
<div class="sev-item medium"><span class="sev-count">{sev['medium']}</span><span class="sev-label">Medium</span></div>
<div class="sev-item low"><span class="sev-count">{sev['low']}</span><span class="sev-label">Low</span></div>
</div>
"""

    # Per-account sections
    for acct in report["accounts"]:
        grade = get_score_grade(acct["score"])
        grade_class = f"grade-{grade.lower()}" if grade in ("C", "D", "F") else ""
        trend_html = ""
        if acct["score_change"] is not None:
            trend_class = "trend-up" if acct["score_change"] >= 0 else "trend-down"
            arrow = "+" if acct["score_change"] >= 0 else ""
            trend_html = f'<span class="trend {trend_class}">{arrow}{acct["score_change"]}</span>'

        html += f"""
<div class="account">
<div class="account-header">
<span class="account-name">{acct['name']}</span>
<span class="score-badge {grade_class}">{acct['score']}/100 {grade}{trend_html}</span>
</div>
<div class="regions">Regions: {', '.join(acct['regions'])}</div>
"""

        # Cost section
        cost = acct.get("cost", {})
        if cost.get("month_to_date"):
            html += '<div class="section-title">Cost</div>'
            html += f'<div class="cost-row"><span class="cost-label">Month-to-date</span><span class="cost-value">${cost["month_to_date"]:.2f}</span></div>'
            if cost.get("forecast"):
                html += f'<div class="cost-row"><span class="cost-label">Forecast</span><span class="cost-value">${cost["forecast"]:.2f}</span></div>'
            if cost.get("last_month"):
                html += f'<div class="cost-row"><span class="cost-label">Last month</span><span class="cost-value">${cost["last_month"]:.2f}</span></div>'

            # Top services
            if cost.get("top_services"):
                for svc in cost["top_services"][:3]:
                    html += f'<div class="cost-row"><span class="cost-label">{svc["service"][:30]}</span><span class="cost-value">${svc["amount"]:.2f}</span></div>'

        # Critical and High findings
        action_plan = acct.get("action_plan", {})
        critical_items = action_plan.get("critical", [])
        high_items = action_plan.get("high", [])

        if critical_items:
            html += '<div class="section-title">Critical (fix today)</div>'
            for item in critical_items[:5]:
                html += f"""<div class="finding">
<span class="badge badge-critical">CRITICAL</span>
<span class="finding-title">{item['title']}</span>"""
                if item.get("fix_commands"):
                    html += f'<div class="finding-fix">{item["fix_commands"][0]}</div>'
                html += '</div>'

        if high_items:
            html += '<div class="section-title">High (fix this week)</div>'
            for item in high_items[:5]:
                html += f"""<div class="finding">
<span class="badge badge-high">HIGH</span>
<span class="finding-title">{item['title']}</span>"""
                if item.get("fix_commands"):
                    html += f'<div class="finding-fix">{item["fix_commands"][0]}</div>'
                html += '</div>'

        # Summary of remaining
        medium_count = len(action_plan.get("medium", []))
        low_count = len(action_plan.get("low", []))
        if medium_count > 0 or low_count > 0:
            html += f'<div class="summary-line" style="margin-top:12px">'
            if medium_count:
                html += f'{medium_count} medium '
            if low_count:
                html += f'{low_count} low '
            html += 'priority items in full report</div>'

        html += '</div>'  # close .account

    # Footer
    html += f"""
<div class="footer">
<p>Generated by <a href="https://github.com/durrello/cloudsentry">CloudSentry</a></p>
<p><a href="https://cloudsentry.durrellgemuh.com/reports/latest.html">View full dashboard</a></p>
</div>

</div>
</body>
</html>"""

    return html
