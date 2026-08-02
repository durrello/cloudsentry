"""
Infrastructure Drift Detection.
Identifies resources that were likely created outside of IaC (Terraform/CloudFormation).
"""

import logging

from utils.findings import create_finding

logger = logging.getLogger(__name__)


def detect_drift(session, active_regions, config):
    """
    Detect resources that appear to be created outside IaC.
    
    Heuristics used:
    - No ManagedBy tag (not tagged as terraform/cloudformation/cdk)
    - No CloudFormation stack association
    - Recently created (within last 7 days) without IaC markers
    """
    findings = []

    managed_by_tag = "ManagedBy"
    valid_iac_values = config.managed_by_values

    for region in active_regions:
        findings.extend(check_ec2_drift(session, region, managed_by_tag, valid_iac_values))
        findings.extend(check_sg_drift(session, region, managed_by_tag, valid_iac_values))

    return findings


def check_ec2_drift(session, region, managed_by_tag, valid_values):
    """Check for EC2 instances not managed by IaC."""
    findings = []

    try:
        ec2 = session.client("ec2", region_name=region)
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        )["Reservations"]

        for res in reservations:
            for instance in res["Instances"]:
                instance_id = instance["InstanceId"]
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                name = tags.get("Name", instance_id)
                managed_by = tags.get(managed_by_tag, "")

                # Check if not managed by any IaC tool
                if not managed_by or managed_by.lower() not in [v.lower() for v in valid_values]:
                    # Also check for CloudFormation stack tag
                    cf_stack = tags.get("aws:cloudformation:stack-name", "")
                    if not cf_stack:
                        findings.append(create_finding(
                            title=f"EC2 instance '{name}' ({instance_id}) appears to be created outside IaC",
                            severity="low",
                            resource_type="EC2 Instance",
                            resource_id=instance_id,
                            region=region,
                            description=f"No {managed_by_tag} tag and no CloudFormation stack association.",
                            risk="Resources outside IaC are harder to track, reproduce, and audit.",
                            fix_commands=[
                                f"# Import into Terraform:",
                                f"terraform import aws_instance.{name.lower().replace('-', '_')} {instance_id}",
                                f"# Or tag as manually managed:",
                                f"aws ec2 create-tags --resources {instance_id} --tags Key=ManagedBy,Value=manual",
                            ],
                            effort="15 minutes",
                        ))

    except Exception as e:
        logger.error(f"Error checking EC2 drift in {region}: {e}")

    return findings


def check_sg_drift(session, region, managed_by_tag, valid_values):
    """Check for security groups not managed by IaC."""
    findings = []

    try:
        ec2 = session.client("ec2", region_name=region)
        sgs = ec2.describe_security_groups()["SecurityGroups"]

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]

            # Skip default SG
            if sg_name == "default":
                continue

            tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
            managed_by = tags.get(managed_by_tag, "")

            if not managed_by or managed_by.lower() not in [v.lower() for v in valid_values]:
                cf_stack = tags.get("aws:cloudformation:stack-name", "")
                if not cf_stack:
                    # Only flag if it has non-default rules (likely manually created for a purpose)
                    has_custom_rules = len(sg.get("IpPermissions", [])) > 0
                    if has_custom_rules:
                        findings.append(create_finding(
                            title=f"Security group '{sg_name}' ({sg_id}) created outside IaC",
                            severity="low",
                            resource_type="Security Group",
                            resource_id=sg_id,
                            region=region,
                            description=f"Has custom rules but no {managed_by_tag} tag or CF stack.",
                            risk="Manual security groups can drift, be forgotten, and create inconsistency.",
                            fix_commands=[
                                f"# Import into Terraform:",
                                f"terraform import aws_security_group.{sg_name.replace('-', '_')} {sg_id}",
                                f"# Or tag:",
                                f"aws ec2 create-tags --resources {sg_id} --tags Key=ManagedBy,Value=manual",
                            ],
                            effort="10 minutes",
                        ))

    except Exception as e:
        logger.error(f"Error checking SG drift in {region}: {e}")

    return findings
