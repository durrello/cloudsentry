"""
Architecture Policy Violation Checker.
Validates that resources are in approved regions and follow architectural standards.
"""

import logging

from utils.findings import create_violation

logger = logging.getLogger(__name__)


def check_architecture_policy(inventory, config):
    """Check resources against architecture policies."""
    violations = []

    approved_regions = config.approved_regions

    # Check for resources in unapproved regions
    for region, resources in inventory.get("by_region", {}).items():
        if region not in approved_regions:
            # Count resources in this unapproved region
            resource_count = 0
            resource_types = []

            for service, data in resources.items():
                if isinstance(data, dict):
                    count = data.get("count", 0)
                    if count > 0:
                        resource_count += count
                        resource_types.append(f"{service}({count})")

            if resource_count > 0:
                violations.append(create_violation(
                    title=f"Resources found in unapproved region: {region} ({resource_count} resources)",
                    severity="medium",
                    category="architecture",
                    resource_type="Region",
                    resource_id=region,
                    region=region,
                    description=f"Resources: {', '.join(resource_types)}",
                    fix_commands=[
                        f"# Either migrate resources to an approved region ({', '.join(approved_regions)})",
                        f"# Or add '{region}' to approved_regions in your configuration",
                    ],
                    current_value=f"{resource_count} resources in {region}",
                    expected_value=f"Resources only in: {', '.join(approved_regions)}",
                ))

    # Check for Lambda functions that are over-provisioned (memory > 512MB with low usage)
    for region, resources in inventory.get("by_region", {}).items():
        lambda_data = resources.get("lambda", {})
        for func in lambda_data.get("details", []):
            if isinstance(func, dict):
                memory = func.get("memory", 128)
                func_name = func.get("name", "unknown")

                if memory > 512:
                    violations.append(create_violation(
                        title=f"Lambda '{func_name}' has {memory}MB memory (may be over-provisioned)",
                        severity="low",
                        category="architecture",
                        resource_type="Lambda Function",
                        resource_id=func_name,
                        region=region,
                        description="High memory allocation increases cost. Use AWS Lambda Power Tuning to find optimal.",
                        fix_commands=[
                            f"# Check actual memory usage in CloudWatch metrics",
                            f"# Then right-size:",
                            f"aws lambda update-function-configuration --function-name {func_name} --memory-size 256",
                        ],
                        current_value=f"{memory}MB",
                        expected_value="Right-sized based on actual usage (use Lambda Power Tuning)",
                    ))

    # Check S3 buckets in unexpected regions
    s3_data = inventory.get("global", {}).get("s3", {})
    for bucket in s3_data.get("bucket_details", []):
        if isinstance(bucket, dict):
            bucket_region = bucket.get("region", "unknown")
            bucket_name = bucket.get("name", "unknown")

            if bucket_region not in approved_regions and bucket_region != "unknown":
                violations.append(create_violation(
                    title=f"S3 bucket '{bucket_name}' is in unapproved region: {bucket_region}",
                    severity="low",
                    category="architecture",
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    region=bucket_region,
                    fix_commands=[
                        "# S3 buckets cannot be moved. Options:",
                        f"# 1. Replicate to approved region and delete original",
                        f"# 2. Add '{bucket_region}' to approved_regions",
                    ],
                    current_value=f"Region: {bucket_region}",
                    expected_value=f"One of: {', '.join(approved_regions)}",
                ))

    return violations
