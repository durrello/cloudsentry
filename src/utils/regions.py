"""
Multi-region scanning utilities.
Discovers which regions have active resources.
"""

import logging
import boto3

logger = logging.getLogger(__name__)

# Regions to check for active resources
ALL_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
    "ap-south-1", "sa-east-1", "ca-central-1",
    "af-south-1", "me-south-1",
]


def get_active_regions(session):
    """
    Discover regions with active resources.
    Checks for EC2 instances, Lambda functions, and RDS instances.
    Returns list of region names that have at least one resource.
    """
    active = set()

    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        available_regions = [r["RegionName"] for r in response["Regions"]]
    except Exception as e:
        logger.warning(f"Could not list regions, using defaults: {e}")
        available_regions = ALL_REGIONS

    for region in available_regions:
        try:
            ec2_regional = session.client("ec2", region_name=region)

            # Check for any EC2 instances (running or stopped)
            instances = ec2_regional.describe_instances(
                MaxResults=5,
                Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            )
            if instances["Reservations"]:
                active.add(region)
                continue

            # Check for Lambda functions
            lam = session.client("lambda", region_name=region)
            functions = lam.list_functions(MaxItems=1)
            if functions["Functions"]:
                active.add(region)
                continue

            # Check for RDS instances
            rds = session.client("rds", region_name=region)
            db_instances = rds.describe_db_instances(MaxRecords=20)
            if db_instances["DBInstances"]:
                active.add(region)
                continue

            # Check for S3 (only from us-east-1)
            if region == "us-east-1":
                s3 = session.client("s3", region_name=region)
                buckets = s3.list_buckets()
                if buckets.get("Buckets"):
                    active.add(region)

        except Exception as e:
            logger.debug(f"Error checking region {region}: {e}")
            continue

    # Always include us-east-1 (global services like IAM, Route53 are here)
    active.add("us-east-1")

    result = sorted(active)
    logger.info(f"Active regions found: {result}")
    return result
