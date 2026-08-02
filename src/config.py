"""
CloudSentry Configuration
Loads configuration from Lambda environment variables.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class BudgetCap:
    service: str
    max_monthly: float
    reason: str


@dataclass
class Config:
    # Notification
    slack_webhook_url: str = ""

    # Accounts
    accounts: List[Dict] = field(default_factory=list)

    # Tag policy
    required_tags: List[str] = field(default_factory=lambda: [
        "Environment", "Project", "Owner", "CostCenter", "ManagedBy"
    ])
    environment_values: List[str] = field(default_factory=lambda: [
        "production", "staging", "development", "sandbox"
    ])
    managed_by_values: List[str] = field(default_factory=lambda: [
        "terraform", "cloudformation", "manual", "cdk", "pulumi"
    ])

    # Infrastructure policy
    approved_regions: List[str] = field(default_factory=lambda: [
        "us-east-1", "eu-west-1"
    ])
    approved_instance_types: List[str] = field(default_factory=lambda: [
        "t3.micro", "t3.small", "t3.medium", "t3.large"
    ])

    # Cost policy
    cost_alert_threshold: float = 50.0
    excluded_services_from_cost_alert: List[str] = field(default_factory=lambda: [
        "AmazonBedrock", "AmazonSageMaker"
    ])
    budget_caps: List[BudgetCap] = field(default_factory=list)

    # Lifecycle policy
    max_snapshot_age_days: int = 90
    max_sandbox_age_days: int = 7
    max_access_key_age_days: int = 90


def load_config() -> Config:
    """Load configuration from environment variables."""
    budget_caps_raw = json.loads(os.environ.get("BUDGET_CAPS", "[]"))
    budget_caps = [
        BudgetCap(
            service=cap["service"],
            max_monthly=cap["max_monthly"],
            reason=cap["reason"],
        )
        for cap in budget_caps_raw
    ]

    return Config(
        slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL", ""),
        accounts=json.loads(os.environ.get("ACCOUNTS", "[]")),
        required_tags=json.loads(os.environ.get("REQUIRED_TAGS", '["Environment","Project","Owner","CostCenter","ManagedBy"]')),
        environment_values=json.loads(os.environ.get("ENVIRONMENT_VALUES", '["production","staging","development","sandbox"]')),
        managed_by_values=json.loads(os.environ.get("MANAGED_BY_VALUES", '["terraform","cloudformation","manual","cdk","pulumi"]')),
        approved_regions=json.loads(os.environ.get("APPROVED_REGIONS", '["us-east-1","eu-west-1"]')),
        approved_instance_types=json.loads(os.environ.get("APPROVED_INSTANCE_TYPES", '["t3.micro","t3.small","t3.medium","t3.large"]')),
        cost_alert_threshold=float(os.environ.get("COST_ALERT_THRESHOLD", "50")),
        excluded_services_from_cost_alert=json.loads(os.environ.get("EXCLUDED_SERVICES_FROM_COST_ALERT", '["AmazonBedrock","AmazonSageMaker"]')),
        budget_caps=budget_caps,
        max_snapshot_age_days=int(os.environ.get("MAX_SNAPSHOT_AGE_DAYS", "90")),
        max_sandbox_age_days=int(os.environ.get("MAX_SANDBOX_AGE_DAYS", "7")),
        max_access_key_age_days=int(os.environ.get("MAX_ACCESS_KEY_AGE_DAYS", "90")),
    )
