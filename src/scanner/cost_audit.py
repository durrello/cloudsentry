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
        "month_to_date_gross": 0.0,
        "forecast": 0.0,
        "last_month": 0.0,
        "last_month_gross": 0.0,
        "top_services": [],
        "by_service": {},
        "budget_status": [],
        "credits": {},
        "burn_rate": {},
        "raw_usage_mtd": 0.0,
        "subscriptions_mtd": 0.0,
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

            # Get breakdown by record type (usage, credits, subscriptions)
            mtd_breakdown = ce.get_cost_and_usage(
                TimePeriod={"Start": month_start, "End": tomorrow},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "RECORD_TYPE"}],
            )
            for result in mtd_breakdown["ResultsByTime"]:
                for group in result.get("Groups", []):
                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    rtype = group["Keys"][0]
                    if rtype == "Usage":
                        cost_data["raw_usage_mtd"] = amount
                    elif rtype == "FlatRateSubscription":
                        cost_data["subscriptions_mtd"] = amount

            cost_data["month_to_date_gross"] = cost_data["raw_usage_mtd"] + cost_data["subscriptions_mtd"]
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

            # Last month gross (usage + subscriptions)
            last_breakdown = ce.get_cost_and_usage(
                TimePeriod={"Start": last_month_start, "End": last_month_end},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "RECORD_TYPE"}],
            )
            last_usage = 0
            last_subs = 0
            for result in last_breakdown["ResultsByTime"]:
                for group in result.get("Groups", []):
                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    rtype = group["Keys"][0]
                    if rtype == "Usage":
                        last_usage = amount
                    elif rtype == "FlatRateSubscription":
                        last_subs = amount
            cost_data["last_month_gross"] = last_usage + last_subs
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
    """Get AWS credits information purely from AWS APIs. No hardcoded values."""
    credits_info = {
        "total_credits_applied": 0.0,
        "credits_this_month": 0.0,
        "credits_last_month": 0.0,
        "credits_remaining": 0.0,
        "has_credits": False,
        "monthly_credit_trend": [],
    }

    try:
        tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%d")
        
        # Get monthly credit application for the last 6 months
        six_months_ago = (now - timedelta(days=180)).replace(day=1).strftime("%Y-%m-%d")
        
        credits_history = ce.get_cost_and_usage(
            TimePeriod={"Start": six_months_ago, "End": tomorrow},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "RECORD_TYPE"}],
        )

        monthly_credits = []
        for result in credits_history["ResultsByTime"]:
            month = result["TimePeriod"]["Start"]
            for group in result.get("Groups", []):
                if group["Keys"][0] == "Credit":
                    amount = abs(float(group["Metrics"]["UnblendedCost"]["Amount"]))
                    if amount > 0:
                        monthly_credits.append({"month": month, "amount": amount})
                        credits_info["total_credits_applied"] += amount
                        credits_info["has_credits"] = True

        credits_info["monthly_credit_trend"] = monthly_credits

        # Current month credits
        if monthly_credits:
            credits_info["credits_this_month"] = monthly_credits[-1]["amount"] if monthly_credits else 0
            if len(monthly_credits) >= 2:
                credits_info["credits_last_month"] = monthly_credits[-2]["amount"]

        # Try to get remaining credits via the billing conductor or organizations API
        # AWS doesn't expose a direct "remaining credits" endpoint
        # But we can check if credits are still being applied (if yes, pool not exhausted)
        # The best signal is: are credits actively reducing our bill this month?
        if credits_info["credits_this_month"] > 0:
            # Credits are still active. Estimate remaining based on the pattern.
            # If last month used $348 in credits and this month is on track for similar,
            # credits are still available.
            pass

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

    # Calculate daily burn rate from gross spend (usage + subscriptions)
    gross_mtd = cost_data.get("month_to_date_gross", 0)
    last_month_gross = cost_data.get("last_month_gross", 0)
    days_elapsed = max(now.day, 1)

    # Use gross MTD if available, fall back to last month gross
    if gross_mtd > 0:
        burn_rate["daily_rate"] = gross_mtd / days_elapsed
    elif last_month_gross > 0:
        burn_rate["daily_rate"] = last_month_gross / 30

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

    # Credits runway calculation (data-driven, no assumptions)
    credits = cost_data.get("credits", {})
    
    # If credits are actively covering the bill, estimate how long they'll last
    # based on the trend of monthly credit application
    if credits.get("has_credits") and burn_rate["daily_rate"] > 0:
        credits_last_month = credits.get("credits_last_month", 0)
        gross_last_month = cost_data.get("last_month_gross", 0)
        
        # If credits fully covered last month (credit >= gross), they're still active
        if credits_last_month > 0 and gross_last_month > 0:
            coverage_ratio = credits_last_month / gross_last_month
            if coverage_ratio >= 0.95:
                burn_rate["credits_status"] = "fully_covered"
                burn_rate["credits_coverage"] = f"{coverage_ratio * 100:.0f}%"
            else:
                burn_rate["credits_status"] = "partially_covered"
                burn_rate["credits_coverage"] = f"{coverage_ratio * 100:.0f}%"
        
        # Total credits applied gives a lower bound of the pool size
        total_applied = credits.get("total_credits_applied", 0)
        if total_applied > 0:
            burn_rate["total_credits_applied"] = total_applied

    return burn_rate
