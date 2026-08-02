"""
Cost Intelligence Scanner.
Checks current spend, forecast, and identifies cost anomalies.
"""

import logging
from datetime import datetime, timezone, timedelta

from utils.findings import create_finding

logger = logging.getLogger(__name__)


def scan_cost(session, config):
    """Run cost intelligence scan. Returns cost data dict."""
    cost_data = {
        "month_to_date": 0.0,
        "forecast": 0.0,
        "last_month": 0.0,
        "top_services": [],
        "by_service": {},
        "budget_status": [],
    }

    try:
        ce = session.client("ce", region_name="us-east-1")
        now = datetime.now(timezone.utc)

        # Current month start
        month_start = now.strftime("%Y-%m-01")
        today = now.strftime("%Y-%m-%d")

        # Last month
        last_month_end = (now.replace(day=1) - timedelta(days=1))
        last_month_start = last_month_end.strftime("%Y-%m-01")
        last_month_end_str = last_month_end.strftime("%Y-%m-%d")

        # Month-to-date spend
        try:
            mtd = ce.get_cost_and_usage(
                TimePeriod={"Start": month_start, "End": today},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
            )
            for result in mtd["ResultsByTime"]:
                cost_data["month_to_date"] += float(
                    result["Total"]["UnblendedCost"]["Amount"]
                )
        except Exception as e:
            logger.error(f"Error getting MTD cost: {e}")

        # Last month total
        try:
            last = ce.get_cost_and_usage(
                TimePeriod={"Start": last_month_start, "End": month_start},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
            )
            for result in last["ResultsByTime"]:
                cost_data["last_month"] += float(
                    result["Total"]["UnblendedCost"]["Amount"]
                )
        except Exception as e:
            logger.error(f"Error getting last month cost: {e}")

        # Forecast
        try:
            # Only forecast if we're past day 3 (need data points)
            if now.day > 3:
                month_end = (now.replace(day=28) + timedelta(days=4)).replace(day=1)
                forecast = ce.get_cost_forecast(
                    TimePeriod={"Start": today, "End": month_end.strftime("%Y-%m-%d")},
                    Metric="UNBLENDED_COST",
                    Granularity="MONTHLY",
                )
                cost_data["forecast"] = cost_data["month_to_date"] + float(
                    forecast["Total"]["Amount"]
                )
        except Exception as e:
            logger.error(f"Error getting forecast: {e}")

        # Top services by spend
        try:
            by_service = ce.get_cost_and_usage(
                TimePeriod={"Start": month_start, "End": today},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )

            services = []
            for result in by_service["ResultsByTime"]:
                for group in result.get("Groups", []):
                    service_name = group["Keys"][0]
                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    if amount > 0.01:
                        services.append({"service": service_name, "amount": amount})

            services.sort(key=lambda x: x["amount"], reverse=True)
            cost_data["top_services"] = services[:10]
            cost_data["by_service"] = {s["service"]: s["amount"] for s in services}

        except Exception as e:
            logger.error(f"Error getting service breakdown: {e}")

        # Check budget caps
        for cap in config.budget_caps:
            service_spend = cost_data["by_service"].get(cap.service, 0.0)
            percentage = (service_spend / cap.max_monthly * 100) if cap.max_monthly > 0 else 0
            cost_data["budget_status"].append({
                "service": cap.service,
                "spend": service_spend,
                "cap": cap.max_monthly,
                "percentage": percentage,
                "reason": cap.reason,
                "status": "over" if percentage > 100 else "warning" if percentage > 80 else "ok",
            })

    except Exception as e:
        logger.error(f"Error in cost scan: {e}")

    return cost_data
