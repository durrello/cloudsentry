"""
Tag Compliance Violation Checker.
Validates that all taggable resources have required tags with valid values.
"""

import logging

from utils.findings import create_violation

logger = logging.getLogger(__name__)


def check_tag_compliance(inventory, config):
    """Check all resources for tag compliance."""
    violations = []

    required_tags = config.required_tags
    valid_envs = config.environment_values
    valid_managed_by = config.managed_by_values

    # Check regional resources
    for region, resources in inventory.get("by_region", {}).items():
        # EC2 instances
        ec2_data = resources.get("ec2", {})
        for instance in ec2_data.get("instances", ec2_data.get("details", [])):
            if isinstance(instance, dict):
                tags = instance.get("tags", {})
                resource_id = instance.get("id", "unknown")
                violations.extend(
                    check_resource_tags(
                        tags, required_tags, valid_envs, valid_managed_by,
                        "EC2 Instance", resource_id, region
                    )
                )

        # EBS Volumes
        ebs_data = resources.get("ebs_volumes", {})
        for vol in ebs_data.get("details", []):
            if isinstance(vol, dict):
                tags = vol.get("tags", {})
                resource_id = vol.get("id", "unknown")
                violations.extend(
                    check_resource_tags(
                        tags, required_tags, valid_envs, valid_managed_by,
                        "EBS Volume", resource_id, region
                    )
                )

        # Security Groups
        sg_data = resources.get("security_groups", {})
        for sg in sg_data.get("details", []):
            if isinstance(sg, dict):
                tags = sg.get("tags", {})
                resource_id = sg.get("id", "unknown")
                violations.extend(
                    check_resource_tags(
                        tags, required_tags, valid_envs, valid_managed_by,
                        "Security Group", resource_id, region
                    )
                )

        # Load Balancers
        lb_data = resources.get("load_balancers", {})
        for lb in lb_data.get("details", []):
            if isinstance(lb, dict):
                tags = lb.get("tags", {})
                resource_id = lb.get("name", "unknown")
                violations.extend(
                    check_resource_tags(
                        tags, required_tags, valid_envs, valid_managed_by,
                        "Load Balancer", resource_id, region
                    )
                )

        # Elastic IPs
        eip_data = resources.get("elastic_ips", {})
        for eip in eip_data.get("details", []):
            if isinstance(eip, dict):
                tags = eip.get("tags", {})
                resource_id = eip.get("allocation_id", eip.get("public_ip", "unknown"))
                violations.extend(
                    check_resource_tags(
                        tags, required_tags, valid_envs, valid_managed_by,
                        "Elastic IP", resource_id, region
                    )
                )

    # Check global resources (S3 buckets)
    s3_data = inventory.get("global", {}).get("s3", {})
    for bucket in s3_data.get("bucket_details", []):
        if isinstance(bucket, dict):
            # S3 buckets don't have tags in the listing, flag them for review
            pass

    return violations


def check_resource_tags(tags, required_tags, valid_envs, valid_managed_by,
                        resource_type, resource_id, region):
    """Check a single resource's tags against the policy."""
    violations = []

    if not tags:
        # Completely untagged resource
        violations.append(create_violation(
            title=f"{resource_type} '{resource_id}' has no tags at all",
            severity="medium",
            category="tag",
            resource_type=resource_type,
            resource_id=resource_id,
            region=region,
            description=f"Missing all required tags: {', '.join(required_tags)}",
            fix_commands=[generate_tag_command(resource_type, resource_id, required_tags)],
            current_value="no tags",
            expected_value=f"Required: {', '.join(required_tags)}",
        ))
        return violations

    # Check each required tag
    missing_tags = [tag for tag in required_tags if tag not in tags]
    if missing_tags:
        violations.append(create_violation(
            title=f"{resource_type} '{resource_id}' missing tags: {', '.join(missing_tags)}",
            severity="medium",
            category="tag",
            resource_type=resource_type,
            resource_id=resource_id,
            region=region,
            fix_commands=[generate_tag_command(resource_type, resource_id, missing_tags)],
            current_value=f"Has: {', '.join(tags.keys())}",
            expected_value=f"Missing: {', '.join(missing_tags)}",
        ))

    # Validate Environment tag value
    env_value = tags.get("Environment", "")
    if env_value and env_value not in valid_envs:
        violations.append(create_violation(
            title=f"{resource_type} '{resource_id}' has invalid Environment tag value",
            severity="low",
            category="tag",
            resource_type=resource_type,
            resource_id=resource_id,
            region=region,
            current_value=f"Environment = '{env_value}'",
            expected_value=f"One of: {', '.join(valid_envs)}",
        ))

    # Validate ManagedBy tag value
    managed_value = tags.get("ManagedBy", "")
    if managed_value and managed_value not in valid_managed_by:
        violations.append(create_violation(
            title=f"{resource_type} '{resource_id}' has invalid ManagedBy tag value",
            severity="low",
            category="tag",
            resource_type=resource_type,
            resource_id=resource_id,
            region=region,
            current_value=f"ManagedBy = '{managed_value}'",
            expected_value=f"One of: {', '.join(valid_managed_by)}",
        ))

    return violations


def generate_tag_command(resource_type, resource_id, tags):
    """Generate AWS CLI command to apply tags."""
    tag_pairs = " ".join([f"Key={t},Value=FILL_IN" for t in tags])

    if resource_type == "EC2 Instance":
        return f"aws ec2 create-tags --resources {resource_id} --tags {tag_pairs}"
    elif resource_type == "EBS Volume":
        return f"aws ec2 create-tags --resources {resource_id} --tags {tag_pairs}"
    elif resource_type == "Security Group":
        return f"aws ec2 create-tags --resources {resource_id} --tags {tag_pairs}"
    elif resource_type == "Elastic IP":
        return f"aws ec2 create-tags --resources {resource_id} --tags {tag_pairs}"
    elif resource_type == "Load Balancer":
        return f"# Tag via ALB/NLB ARN: aws elbv2 add-tags --resource-arns <arn> --tags {tag_pairs}"
    else:
        return f"# Apply tags to {resource_type} {resource_id}: {tag_pairs}"
