"""
Cost Intelligence Scanner.
Checks current spend, forecast, credits, and calculates burn rate.
"""

import logging
import os
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
        "credits": {},
        "burn_rate": {},
    }

    try:
        ce = session.client("ce", region_name="us-east-1")
        now = datetime.now(timezone.utc)

        # Current month date range
        month_start = now.strftime("%Y-%m-01")
        # End date must be today + 1 for Cost Explorer (exclusive end)
        tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%d")

        # Last month date range
        first_of_month = now.replace(day=1)
        last_month_end = first_of_month.strftime("%Y-%m-%d")
        last_month_start = (first_of_month - timedelta(days=1)).replace(day=1).strftime("%Y-%m-%d")

        # Month-to-date spend
        try:
            mtd = ce.get_cost_and_usage(
                TimePeriod={"Start": month_start, "End": tomorrow},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
            )
            for result in mtd["ResultsByTime"]:
                amount = float(result["Total"]["UnblendedCost"]["Amount"])
                cost_data["month_to_date"] += amount
        except Exception as e:
            logger.error(f"Error getting MTD cost: {e}")

        # Last month total
        try:
            last = ce.get_cost_and_usage(
                TimePeriod={"Start": last_month_start, "End": last_month_end},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
            )
            for result in last["ResultsByTime"]:
                cost_data["last_month"] += float(
                    result["Total"]["UnblendedCost"]["Amount"]
                )
        except Exception as e:
            logger.error(f"Error getting last month cost: {e}")

        # Forecast (need at least a few days of data)
        try:
            if now.day >= 3:
                # Calculate end of month
                if now.month == 12:
                    month_end = now.replace(year=now.year + 1, month=1, day=1)
                else:
                    month_end = now.replace(month=now.month + 1, day=1)

                forecast = ce.get_cost_forecast(
                    TimePeriod={
                        "Start": tomorrow,
                        "End": month_end.strftime("%Y-%m-%d"),
                    },
                    Metric="UNBLENDED_COST",
                    Granularity="MONTHLY",
                )
                remaining_forecast = float(forecast["Total"]["Amount"])
                cost_data["forecast"] = cost_data["month_to_date"] + remaining_forecast
            else:
                # Too early in the month for forecast, extrapolate
                if now.day > 0 and cost_data["month_to_date"] > 0:
                    days_in_month = 30
                    daily_rate = cost_data["month_to_date"] / now.day
                    cost_data["forecast"] = daily_rate * days_in_month
        except Exception as e:
            logger.error(f"Error getting forecast: {e}")

        # Top services by spend (this month)
        try:
            by_service = ce.get_cost_and_usage(
                TimePeriod={"Start": month_start, "End": tomorrow},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )

            services = []
            for result in by_service["ResultsByTime"]:
                for group in result.get("Groups", []):
                    service_name = group["Keys"][0]
                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    if amount > 0.001:
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

        # Credits and balance
        cost_data["credits"] = get_credits_info(ce, now)

        # Burn rate calculation
        cost_data["burn_rate"] = calculate_burn_rate(cost_data, now)

    except Exception as e:
        logger.error(f"Error in cost scan: {e}")

    return cost_data


def get_credits_info(ce, now):
    """Get AWS credits and balance information."""
    credits_info = {
        "total_credits": 0.0,
        "credits_used": 0.0,
        "credits_remaining": 0.0,
        "has_credits": False,
    }

    total_pool = float(os.environ.get("TOTAL_CREDITS_AMOUNT", "0"))

    try:
        # Get total credits used this year
        year_start = f"{now.year}-01-01"
        tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%d")

        try:
            credits_yearly = ce.get_cost_and_usage(
                TimePeriod={"Start": year_start, "End": tomorrow},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "RECORD_TYPE"}],
            )

            for result in credits_yearly["ResultsByTime"]:
                for group in result.get("Groups", []):
                    if group["Keys"][0] == "Credit":
                        credits_info["total_credits"] += abs(float(group["Metrics"]["UnblendedCost"]["Amount"]))
                        credits_info["has_credits"] = True

        except Exception as e:
            logger.error(f"Error getting yearly credits: {e}")

        # Calculate remaining
        if total_pool > 0:
            credits_info["credits_remaining"] = max(0, total_pool - credits_info["total_credits"])
        elif credits_info["total_credits"] > 0:
            # Estimate pool from common amounts
            common_pools = [200, 300, 500, 1000, 2000]
            for pool in common_pools:
                if credits_info["total_credits"] < pool:
                    credits_info["credits_remaining"] = pool - credits_info["total_credits"]
                    break

    except Exception as e:
        logger.error(f"Error getting credits info: {e}")

    return credits_info


def calculate_burn_rate(cost_data, now):
    """Calculate burn rate and time estimates."""
    burn_rate = {
        "daily_rate": 0.0,
        "monthly_rate": 0.0,
        "annual_rate": 0.0,
        "days_until_credits_expire": None,
        "credits_exhaust_date": None,
        "credits_exhaust_date_optimized": None,
        "potential_monthly_savings": 0.0,
        "optimized_monthly_rate": 0.0,
        "optimized_annual_rate": 0.0,
    }

    # Calculate daily burn rate from MTD
    mtd = cost_data.get("month_to_date", 0)
    days_elapsed = max(now.day, 1)

    # Use last month if MTD is too low (early in month)
    last_month = cost_data.get("last_month", 0)
    if mtd <= 0 and last_month > 0:
        burn_rate["daily_rate"] = last_month / 30
    elif mtd > 0:
        burn_rate["daily_rate"] = mtd / days_elapsed
    elif last_month > 0:
        burn_rate["daily_rate"] = last_month / 30

    if burn_rate["daily_rate"] > 0:
        burn_rate["monthly_rate"] = burn_rate["daily_rate"] * 30
        burn_rate["annual_rate"] = burn_rate["daily_rate"] * 365

    # Estimate potential savings from waste findings
    waste_savings = 0.0
    for budget in cost_data.get("budget_status", []):
        if budget["status"] == "over":
            overage = budget["spend"] - budget["cap"]
            waste_savings += overage

    burn_rate["potential_monthly_savings"] = waste_savings
    burn_rate["optimized_monthly_rate"] = max(0, burn_rate["monthly_rate"] - waste_savings)
    burn_rate["optimized_annual_rate"] = burn_rate["optimized_monthly_rate"] * 12

    # Credits runway calculation
    credits = cost_data.get("credits", {})
    credits_remaining = credits.get("credits_remaining", 0)

    if credits_remaining > 0 and burn_rate["daily_rate"] > 0:
        # At current rate
        days_left = int(credits_remaining / burn_rate["daily_rate"])
        burn_rate["days_until_credits_expire"] = days_left
        exhaust_date = now + timedelta(days=days_left)
        burn_rate["credits_exhaust_date"] = exhaust_date.strftime("%B %d, %Y")

        # With fixes applied (optimized rate)
        optimized_daily = burn_rate["optimized_monthly_rate"] / 30
        if optimized_daily > 0:
            optimized_days = int(credits_remaining / optimized_daily)
            optimized_exhaust = now + timedelta(days=optimized_days)
            burn_rate["credits_exhaust_date_optimized"] = optimized_exhaust.strftime("%B %d, %Y")
        else:
            burn_rate["credits_exhaust_date_optimized"] = "Never (no spend after fixes)"

    return burn_rate
