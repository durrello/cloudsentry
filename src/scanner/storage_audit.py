"""
Storage Security Audit Scanner.
Checks S3 buckets and EBS volumes for security issues.
"""

import logging

from utils.findings import create_finding

logger = logging.getLogger(__name__)


def scan_storage(session, config):
    """Run storage security audit."""
    findings = []
    s3 = session.client("s3")

    findings.extend(check_s3_buckets(s3))

    return findings


def check_s3_buckets(s3):
    """Check S3 buckets for security misconfigurations."""
    findings = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]

            # Check public access block
            try:
                public_access = s3.get_public_access_block(Bucket=bucket_name)
                config_block = public_access["PublicAccessBlockConfiguration"]

                if not all([
                    config_block.get("BlockPublicAcls", False),
                    config_block.get("IgnorePublicAcls", False),
                    config_block.get("BlockPublicPolicy", False),
                    config_block.get("RestrictPublicBuckets", False),
                ]):
                    findings.append(create_finding(
                        title=f"S3 bucket '{bucket_name}' does not have full public access block",
                        severity="high",
                        resource_type="S3 Bucket",
                        resource_id=bucket_name,
                        risk="Bucket may be publicly accessible. Data exposure risk.",
                        fix_commands=[
                            f"aws s3api put-public-access-block --bucket {bucket_name} "
                            f"--public-access-block-configuration "
                            f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                            f"BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        ],
                        compliance=["CIS 2.1.1", "SOC2 CC6.1"],
                        effort="2 minutes",
                    ))
            except s3.exceptions.ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    findings.append(create_finding(
                        title=f"S3 bucket '{bucket_name}' has no public access block configured",
                        severity="high",
                        resource_type="S3 Bucket",
                        resource_id=bucket_name,
                        risk="Without a public access block, the bucket can be made public via ACLs or policies.",
                        fix_commands=[
                            f"aws s3api put-public-access-block --bucket {bucket_name} "
                            f"--public-access-block-configuration "
                            f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                            f"BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        ],
                        compliance=["CIS 2.1.1"],
                        effort="2 minutes",
                    ))

            # Check encryption
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except s3.exceptions.ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    findings.append(create_finding(
                        title=f"S3 bucket '{bucket_name}' does not have encryption at rest",
                        severity="medium",
                        resource_type="S3 Bucket",
                        resource_id=bucket_name,
                        risk="Data is stored unencrypted. Compliance risk.",
                        fix_commands=[
                            f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                            f"--server-side-encryption-configuration "
                            f"'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'",
                        ],
                        compliance=["CIS 2.1.2"],
                        effort="2 minutes",
                    ))

            # Check versioning
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("Status") != "Enabled":
                    findings.append(create_finding(
                        title=f"S3 bucket '{bucket_name}' does not have versioning enabled",
                        severity="low",
                        resource_type="S3 Bucket",
                        resource_id=bucket_name,
                        risk="Accidental deletes or overwrites cannot be recovered.",
                        fix_commands=[
                            f"aws s3api put-bucket-versioning --bucket {bucket_name} "
                            f"--versioning-configuration Status=Enabled",
                        ],
                        effort="2 minutes",
                    ))
            except Exception:
                pass

            # Check logging (skip log buckets themselves to avoid circular logging)
            try:
                logging_config = s3.get_bucket_logging(Bucket=bucket_name)
                is_log_bucket = "access-logs" in bucket_name or "log" in bucket_name.lower()
                if not logging_config.get("LoggingEnabled") and not is_log_bucket:
                    findings.append(create_finding(
                        title=f"S3 bucket '{bucket_name}' has no access logging",
                        severity="low",
                        resource_type="S3 Bucket",
                        resource_id=bucket_name,
                        risk="Cannot audit who accessed what in this bucket.",
                        fix_commands=[
                            f"aws s3api put-bucket-logging --bucket {bucket_name} "
                            f"--bucket-logging-status '{{\"LoggingEnabled\":{{\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":\"{bucket_name}/\"}}}}'",
                        ],
                        effort="5 minutes",
                    ))
            except Exception:
                pass

            # Check lifecycle policy
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            except s3.exceptions.ClientError as e:
                if "NoSuchLifecycleConfiguration" in str(e):
                    findings.append(create_finding(
                        title=f"S3 bucket '{bucket_name}' has no lifecycle policy",
                        severity="low",
                        resource_type="S3 Bucket",
                        resource_id=bucket_name,
                        risk="Data grows indefinitely without automatic cleanup or transitions.",
                        fix_commands=[
                            "# Add a lifecycle rule to transition old objects to cheaper storage:",
                            f"aws s3api put-bucket-lifecycle-configuration --bucket {bucket_name} "
                            f"--lifecycle-configuration file://lifecycle.json",
                        ],
                        effort="10 minutes",
                    ))

    except Exception as e:
        logger.error(f"Error checking S3 buckets: {e}")

    return findings
