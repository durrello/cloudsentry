"""
Compute Security Audit Scanner.
Checks EC2 instances and Lambda functions for security issues.
"""

import logging
from datetime import datetime, timezone

from utils.findings import create_finding

logger = logging.getLogger(__name__)

# Deprecated Lambda runtimes
DEPRECATED_RUNTIMES = [
    "python3.7", "python3.8", "python2.7",
    "nodejs12.x", "nodejs14.x", "nodejs16.x",
    "dotnetcore3.1", "dotnet5.0", "dotnet6",
    "ruby2.7", "java8", "java8.al2",
    "go1.x",
]


def scan_compute(session, region, config):
    """Run compute security audit for a region."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    findings.extend(check_ec2_instances(ec2, session, region, config))
    findings.extend(check_lambda_functions(session, region, config))

    return findings


def check_ec2_instances(ec2, session, region, config):
    """Check EC2 instances for security issues."""
    findings = []

    try:
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        )["Reservations"]

        for res in reservations:
            for instance in res["Instances"]:
                instance_id = instance["InstanceId"]
                instance_type = instance["InstanceType"]
                state = instance["State"]["Name"]
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                name = tags.get("Name", instance_id)

                # Public IP on instances that may not need it
                if instance.get("PublicIpAddress") and state == "running":
                    # Check if it's in a private subnet (has NAT route)
                    # For now, just flag instances with public IPs for awareness
                    findings.append(create_finding(
                        title=f"EC2 instance '{name}' ({instance_id}) has a public IP",
                        severity="medium",
                        resource_type="EC2 Instance",
                        resource_id=instance_id,
                        region=region,
                        description=f"Public IP: {instance['PublicIpAddress']}",
                        risk="Instance is directly reachable from the internet. Verify this is intentional.",
                        fix_commands=[
                            "# If public access is not needed, move to private subnet:",
                            "# Or disable auto-assign public IP on the subnet:",
                            f"aws ec2 modify-subnet-attribute --subnet-id {instance.get('SubnetId')} "
                            f"--no-map-public-ip-on-launch",
                        ],
                        better_alternative="Use a load balancer or NAT gateway for outbound access",
                        effort="30 minutes",
                    ))

                # IMDSv1 check (should be v2)
                metadata_options = instance.get("MetadataOptions", {})
                if metadata_options.get("HttpTokens") != "required":
                    findings.append(create_finding(
                        title=f"EC2 instance '{name}' ({instance_id}) allows IMDSv1",
                        severity="high",
                        resource_type="EC2 Instance",
                        resource_id=instance_id,
                        region=region,
                        risk="IMDSv1 is vulnerable to SSRF attacks that can steal IAM credentials.",
                        fix_commands=[
                            f"aws ec2 modify-instance-metadata-options --instance-id {instance_id} "
                            f"--http-tokens required --http-endpoint enabled",
                        ],
                        compliance=["CIS 5.6"],
                        effort="5 minutes",
                    ))

                # No IAM role attached
                if not instance.get("IamInstanceProfile"):
                    findings.append(create_finding(
                        title=f"EC2 instance '{name}' ({instance_id}) has no IAM role",
                        severity="medium",
                        resource_type="EC2 Instance",
                        resource_id=instance_id,
                        region=region,
                        risk="Without a role, the instance may use long-lived access keys for AWS API calls.",
                        fix_commands=[
                            f"# Create and attach an instance profile:",
                            f"aws ec2 associate-iam-instance-profile "
                            f"--instance-id {instance_id} "
                            f"--iam-instance-profile Name=<your-instance-profile>",
                        ],
                        better_alternative="Always use IAM roles instead of access keys on instances",
                        effort="15 minutes",
                    ))

                # Using default security group
                sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                sg_names = [sg["GroupName"] for sg in instance.get("SecurityGroups", [])]
                if "default" in sg_names:
                    findings.append(create_finding(
                        title=f"EC2 instance '{name}' ({instance_id}) uses the default security group",
                        severity="medium",
                        resource_type="EC2 Instance",
                        resource_id=instance_id,
                        region=region,
                        risk="Default security group rules may be overly permissive. Use purpose-built SGs.",
                        fix_commands=[
                            "# Create a dedicated security group and reassign",
                        ],
                        effort="15 minutes",
                    ))

                # Unapproved instance type
                if instance_type not in config.approved_instance_types and state == "running":
                    findings.append(create_finding(
                        title=f"EC2 instance '{name}' ({instance_id}) uses unapproved type: {instance_type}",
                        severity="low",
                        resource_type="EC2 Instance",
                        resource_id=instance_id,
                        region=region,
                        description=f"Approved types: {', '.join(config.approved_instance_types)}",
                        risk="May be over-provisioned or using expensive instance types unnecessarily.",
                        fix_commands=[
                            f"# Stop and resize:",
                            f"aws ec2 stop-instances --instance-ids {instance_id}",
                            f"aws ec2 modify-instance-attribute --instance-id {instance_id} --instance-type <approved-type>",
                            f"aws ec2 start-instances --instance-ids {instance_id}",
                        ],
                        effort="15 minutes (requires downtime)",
                    ))

                # Stopped instances (still paying for EBS)
                if state == "stopped":
                    launch_time = instance.get("LaunchTime")
                    if launch_time:
                        days_stopped = (datetime.now(timezone.utc) - launch_time.replace(tzinfo=timezone.utc)).days
                        if days_stopped > 30:
                            findings.append(create_finding(
                                title=f"EC2 instance '{name}' ({instance_id}) has been stopped for {days_stopped}+ days",
                                severity="low",
                                resource_type="EC2 Instance",
                                resource_id=instance_id,
                                region=region,
                                risk="Stopped instances still incur EBS storage costs. AMI it or terminate.",
                                fix_commands=[
                                    f"# Create AMI backup then terminate:",
                                    f"aws ec2 create-image --instance-id {instance_id} --name '{name}-backup'",
                                    f"aws ec2 terminate-instances --instance-ids {instance_id}",
                                ],
                                effort="10 minutes",
                            ))

    except Exception as e:
        logger.error(f"Error checking EC2 in {region}: {e}")

    return findings


def check_lambda_functions(session, region, config):
    """Check Lambda functions for security issues."""
    findings = []

    try:
        lam = session.client("lambda", region_name=region)
        cloudwatch = session.client("cloudwatch", region_name=region)
        functions = lam.list_functions()["Functions"]

        for func in functions:
            func_name = func["FunctionName"]
            func_arn = func["FunctionArn"]
            runtime = func.get("Runtime", "unknown")

            # Deprecated runtime
            if runtime in DEPRECATED_RUNTIMES:
                findings.append(create_finding(
                    title=f"Lambda '{func_name}' uses deprecated runtime: {runtime}",
                    severity="medium",
                    resource_type="Lambda Function",
                    resource_id=func_name,
                    region=region,
                    risk="Deprecated runtimes no longer receive security patches.",
                    fix_commands=[
                        f"aws lambda update-function-configuration --function-name {func_name} "
                        f"--runtime python3.12",
                        "# Test thoroughly after updating runtime",
                    ],
                    effort="30 minutes (includes testing)",
                ))

            # Check for zero invocations in last 30 days
            try:
                now = datetime.now(timezone.utc)
                metrics = cloudwatch.get_metric_statistics(
                    Namespace="AWS/Lambda",
                    MetricName="Invocations",
                    Dimensions=[{"Name": "FunctionName", "Value": func_name}],
                    StartTime=now.replace(day=1) if now.day > 1 else now,
                    EndTime=now,
                    Period=2592000,  # 30 days
                    Statistics=["Sum"],
                )
                datapoints = metrics.get("Datapoints", [])
                total_invocations = sum(d["Sum"] for d in datapoints)

                if total_invocations == 0:
                    findings.append(create_finding(
                        title=f"Lambda '{func_name}' has zero invocations in 30+ days",
                        severity="low",
                        resource_type="Lambda Function",
                        resource_id=func_name,
                        region=region,
                        risk="Dead code. Increases attack surface without providing value.",
                        fix_commands=[
                            f"# Review if still needed, then delete:",
                            f"aws lambda delete-function --function-name {func_name}",
                        ],
                        effort="5 minutes",
                    ))
            except Exception:
                pass

            # Check environment variables for secrets
            env_vars = func.get("Environment", {}).get("Variables", {})
            secret_patterns = ["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"]
            for key, value in env_vars.items():
                if any(pattern in key.upper() for pattern in secret_patterns):
                    # Don't log the actual value
                    findings.append(create_finding(
                        title=f"Lambda '{func_name}' has potential secret in env var: {key}",
                        severity="high",
                        resource_type="Lambda Function",
                        resource_id=func_name,
                        region=region,
                        risk="Secrets in environment variables are visible in the console and API responses.",
                        fix_commands=[
                            "# Move to Secrets Manager or SSM Parameter Store:",
                            f"aws secretsmanager create-secret --name {func_name}/{key} --secret-string '<value>'",
                            "# Update function code to fetch secret at runtime",
                        ],
                        better_alternative="Use AWS Secrets Manager with IAM role-based access",
                        compliance=["AWS Well-Architected SEC-9"],
                        effort="30 minutes",
                    ))
                    break  # One finding per function is enough

    except Exception as e:
        logger.error(f"Error checking Lambda in {region}: {e}")

    return findings
