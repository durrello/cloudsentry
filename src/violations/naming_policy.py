"""
Naming Convention Violation Checker.
Validates that resources follow naming standards.
"""

import logging
import re

from utils.findings import create_violation

logger = logging.getLogger(__name__)

# Patterns that indicate auto-generated or lazy names
LAZY_NAME_PATTERNS = [
    r"^launch-wizard-\d+$",
    r"^default$",
    r"^sg-[a-f0-9]+$",  # Just the ID, no Name tag
    r"^i-[a-f0-9]+$",
    r"^vol-[a-f0-9]+$",
]


def check_naming_policy(inventory, config):
    """Check all resources for naming convention compliance."""
    violations = []

    for region, resources in inventory.get("by_region", {}).items():
        # Security groups with launch-wizard names
        sg_data = resources.get("security_groups", {})
        for sg in sg_data.get("details", []):
            if isinstance(sg, dict):
                sg_name = sg.get("name", "")
                sg_id = sg.get("id", "unknown")

                if re.match(r"^launch-wizard-\d+$", sg_name):
                    violations.append(create_violation(
                        title=f"Security group '{sg_name}' ({sg_id}) has an auto-generated name",
                        severity="low",
                        category="naming",
                        resource_type="Security Group",
                        resource_id=sg_id,
                        region=region,
                        description="Launch-wizard security groups are created by the EC2 console wizard and often forgotten.",
                        fix_commands=[
                            f"# Rename or replace with a properly named security group:",
                            f"# Create new SG with proper name, migrate instances, delete old one",
                        ],
                        current_value=sg_name,
                        expected_value="Descriptive name like 'web-server-sg' or 'api-backend-sg'",
                    ))

        # EC2 instances without a Name tag
        ec2_data = resources.get("ec2", {})
        for instance in ec2_data.get("instances", ec2_data.get("details", [])):
            if isinstance(instance, dict):
                tags = instance.get("tags", {})
                instance_id = instance.get("id", "unknown")

                if "Name" not in tags:
                    violations.append(create_violation(
                        title=f"EC2 instance {instance_id} has no Name tag",
                        severity="low",
                        category="naming",
                        resource_type="EC2 Instance",
                        resource_id=instance_id,
                        region=region,
                        fix_commands=[
                            f"aws ec2 create-tags --resources {instance_id} --tags Key=Name,Value=<descriptive-name>",
                        ],
                        current_value="(no Name tag)",
                        expected_value="Descriptive name like 'prod-api-server' or 'staging-worker'",
                    ))

    # S3 bucket naming
    s3_data = inventory.get("global", {}).get("s3", {})
    for bucket in s3_data.get("bucket_details", []):
        if isinstance(bucket, dict):
            bucket_name = bucket.get("name", "")

            # Check for non-descriptive bucket names (very short or random-looking)
            if len(bucket_name) < 5 or re.match(r"^[a-z0-9]{8,}$", bucket_name):
                # Skip AWS-generated buckets
                if not any(prefix in bucket_name for prefix in ["aws-", "cf-", "elasticbeanstalk-"]):
                    violations.append(create_violation(
                        title=f"S3 bucket '{bucket_name}' does not follow naming convention",
                        severity="low",
                        category="naming",
                        resource_type="S3 Bucket",
                        resource_id=bucket_name,
                        description="Bucket name should follow pattern: {project}-{env}-{purpose}",
                        current_value=bucket_name,
                        expected_value="Pattern: {project}-{env}-{purpose} (e.g., myapp-prod-uploads)",
                    ))

    return violations
