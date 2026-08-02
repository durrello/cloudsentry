"""
Lifecycle Policy Violation Checker.
Checks for resources that have exceeded their expected lifespan.
"""

import logging
from datetime import datetime, timezone

from utils.findings import create_violation

logger = logging.getLogger(__name__)


def check_lifecycle_policy(session, active_regions, config):
    """Check resources for lifecycle policy violations."""
    violations = []
    now = datetime.now(timezone.utc)

    for region in active_regions:
        violations.extend(check_old_snapshots(session, region, config, now))
        violations.extend(check_sandbox_resources(session, region, config, now))

    return violations


def check_old_snapshots(session, region, config, now):
    """Check for EBS snapshots older than max age."""
    violations = []

    try:
        ec2 = session.client("ec2", region_name=region)
        # Only get snapshots owned by this account
        snapshots = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]

        for snap in snapshots:
            snap_id = snap["SnapshotId"]
            start_time = snap["StartTime"].replace(tzinfo=timezone.utc)
            age_days = (now - start_time).days
            tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}

            if age_days > config.max_snapshot_age_days:
                # Skip if tagged with retention policy
                if tags.get("RetainUntil") or tags.get("DoNotDelete"):
                    continue

                size_gb = snap.get("VolumeSize", 0)
                monthly_cost = size_gb * 0.05  # $0.05/GB/month for snapshots

                violations.append(create_violation(
                    title=f"EBS snapshot {snap_id} is {age_days} days old (max: {config.max_snapshot_age_days})",
                    severity="low",
                    category="lifecycle",
                    resource_type="EBS Snapshot",
                    resource_id=snap_id,
                    region=region,
                    description=f"Size: {size_gb}GB, Monthly cost: ${monthly_cost:.2f}",
                    fix_commands=[
                        f"# Delete if no longer needed:",
                        f"aws ec2 delete-snapshot --snapshot-id {snap_id}",
                        f"# Or tag to keep:",
                        f"aws ec2 create-tags --resources {snap_id} --tags Key=RetainUntil,Value=2027-01-01",
                    ],
                    current_value=f"{age_days} days old",
                    expected_value=f"Max {config.max_snapshot_age_days} days or tagged with RetainUntil",
                ))

    except Exception as e:
        logger.error(f"Error checking snapshots in {region}: {e}")

    return violations


def check_sandbox_resources(session, region, config, now):
    """Check for sandbox-tagged resources that have exceeded their lifespan."""
    violations = []

    try:
        ec2 = session.client("ec2", region_name=region)

        # Find instances tagged as sandbox
        instances = ec2.describe_instances(
            Filters=[
                {"Name": "tag:Environment", "Values": ["sandbox"]},
                {"Name": "instance-state-name", "Values": ["running", "stopped"]},
            ]
        )["Reservations"]

        for res in instances:
            for instance in res["Instances"]:
                instance_id = instance["InstanceId"]
                launch_time = instance["LaunchTime"].replace(tzinfo=timezone.utc)
                age_days = (now - launch_time).days
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                name = tags.get("Name", instance_id)

                if age_days > config.max_sandbox_age_days:
                    violations.append(create_violation(
                        title=f"Sandbox instance '{name}' ({instance_id}) is {age_days} days old (max: {config.max_sandbox_age_days})",
                        severity="medium",
                        category="lifecycle",
                        resource_type="EC2 Instance",
                        resource_id=instance_id,
                        region=region,
                        description="Sandbox resources should be temporary. Terminate or promote to development.",
                        fix_commands=[
                            f"# Terminate if done:",
                            f"aws ec2 terminate-instances --instance-ids {instance_id}",
                            f"# Or promote to development:",
                            f"aws ec2 create-tags --resources {instance_id} --tags Key=Environment,Value=development",
                        ],
                        current_value=f"{age_days} days (sandbox)",
                        expected_value=f"Max {config.max_sandbox_age_days} days for sandbox",
                    ))

    except Exception as e:
        logger.error(f"Error checking sandbox resources in {region}: {e}")

    return violations
