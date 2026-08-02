"""
Database Security Audit Scanner.
Checks RDS instances and DynamoDB tables.
"""

import logging

from utils.findings import create_finding

logger = logging.getLogger(__name__)


def scan_database(session, region, config):
    """Run database security audit for a region."""
    findings = []

    findings.extend(check_rds(session, region))
    findings.extend(check_dynamodb(session, region))

    return findings


def check_rds(session, region):
    """Check RDS instances for security issues."""
    findings = []

    try:
        rds = session.client("rds", region_name=region)
        instances = rds.describe_db_instances()["DBInstances"]

        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            db_arn = db["DBInstanceArn"]

            # Publicly accessible
            if db.get("PubliclyAccessible", False):
                findings.append(create_finding(
                    title=f"RDS instance '{db_id}' is publicly accessible",
                    severity="critical",
                    resource_type="RDS Instance",
                    resource_id=db_id,
                    region=region,
                    risk="Database is reachable from the internet. Direct target for attacks.",
                    fix_commands=[
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        f"--no-publicly-accessible --apply-immediately",
                    ],
                    better_alternative="Place RDS in private subnets, access via VPN or bastion",
                    compliance=["CIS 4.1"],
                    effort="5 minutes (may cause brief connection drop)",
                ))

            # Not encrypted
            if not db.get("StorageEncrypted", False):
                findings.append(create_finding(
                    title=f"RDS instance '{db_id}' storage is not encrypted",
                    severity="high",
                    resource_type="RDS Instance",
                    resource_id=db_id,
                    region=region,
                    risk="Data at rest is unencrypted. Cannot be changed on existing instance without migration.",
                    fix_commands=[
                        "# Cannot enable encryption on existing instance. Must:",
                        f"# 1. Create encrypted snapshot:",
                        f"aws rds create-db-snapshot --db-instance-identifier {db_id} --db-snapshot-identifier {db_id}-pre-encrypt",
                        f"# 2. Copy snapshot with encryption:",
                        f"aws rds copy-db-snapshot --source-db-snapshot-identifier {db_id}-pre-encrypt "
                        f"--target-db-snapshot-identifier {db_id}-encrypted --kms-key-id alias/aws/rds",
                        f"# 3. Restore from encrypted snapshot as new instance",
                    ],
                    compliance=["CIS 4.2"],
                    effort="1-2 hours (requires migration)",
                ))

            # No automated backups
            if db.get("BackupRetentionPeriod", 0) == 0:
                findings.append(create_finding(
                    title=f"RDS instance '{db_id}' has no automated backups",
                    severity="high",
                    resource_type="RDS Instance",
                    resource_id=db_id,
                    region=region,
                    risk="No point-in-time recovery. Data loss on failure is permanent.",
                    fix_commands=[
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        f"--backup-retention-period 7 --apply-immediately",
                    ],
                    effort="5 minutes",
                ))

            # No multi-AZ for production
            tags_response = rds.list_tags_for_resource(ResourceName=db_arn)
            tags = {t["Key"]: t["Value"] for t in tags_response.get("TagList", [])}
            env = tags.get("Environment", "").lower()

            if env == "production" and not db.get("MultiAZ", False):
                findings.append(create_finding(
                    title=f"RDS instance '{db_id}' is production but not Multi-AZ",
                    severity="medium",
                    resource_type="RDS Instance",
                    resource_id=db_id,
                    region=region,
                    risk="Single-AZ production database has no automatic failover on AZ outage.",
                    fix_commands=[
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        f"--multi-az --apply-immediately",
                    ],
                    effort="10 minutes (failover takes a few minutes)",
                ))

            # Deletion protection disabled
            if not db.get("DeletionProtection", False):
                findings.append(create_finding(
                    title=f"RDS instance '{db_id}' has deletion protection disabled",
                    severity="medium",
                    resource_type="RDS Instance",
                    resource_id=db_id,
                    region=region,
                    risk="Database can be accidentally deleted via API or console.",
                    fix_commands=[
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        f"--deletion-protection --apply-immediately",
                    ],
                    effort="2 minutes",
                ))

    except Exception as e:
        logger.error(f"Error checking RDS in {region}: {e}")

    return findings


def check_dynamodb(session, region):
    """Check DynamoDB tables for security issues."""
    findings = []

    try:
        dynamo = session.client("dynamodb", region_name=region)
        tables = dynamo.list_tables()["TableNames"]

        for table_name in tables:
            # Check point-in-time recovery
            try:
                backup_desc = dynamo.describe_continuous_backups(TableName=table_name)
                pitr = backup_desc["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
                if pitr["PointInTimeRecoveryStatus"] != "ENABLED":
                    findings.append(create_finding(
                        title=f"DynamoDB table '{table_name}' has no point-in-time recovery",
                        severity="medium",
                        resource_type="DynamoDB Table",
                        resource_id=table_name,
                        region=region,
                        risk="Cannot recover data to a specific point in time after accidental deletion.",
                        fix_commands=[
                            f"aws dynamodb update-continuous-backups --table-name {table_name} "
                            f"--point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
                        ],
                        effort="2 minutes",
                    ))
            except Exception:
                pass

    except Exception as e:
        logger.error(f"Error checking DynamoDB in {region}: {e}")

    return findings
