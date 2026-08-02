"""
Encryption and Secrets Audit Scanner.
Checks KMS keys and Secrets Manager for security issues.
"""

import logging
from datetime import datetime, timezone

from utils.findings import create_finding

logger = logging.getLogger(__name__)


def scan_encryption(session, region, config):
    """Run encryption security audit for a region."""
    findings = []

    findings.extend(check_kms_keys(session, region))
    findings.extend(check_secrets_manager(session, region, config))

    return findings


def check_kms_keys(session, region):
    """Check KMS keys for security issues."""
    findings = []

    try:
        kms = session.client("kms", region_name=region)
        keys = kms.list_keys()["Keys"]

        for key_meta in keys:
            key_id = key_meta["KeyId"]

            try:
                key_info = kms.describe_key(KeyId=key_id)["KeyMetadata"]

                # Skip AWS-managed keys
                if key_info.get("KeyManager") == "AWS":
                    continue

                # Check if key is enabled but has overly broad policy
                if key_info.get("KeyState") == "Enabled":
                    try:
                        policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")
                        policy_text = policy["Policy"]

                        # Check for wildcard principal
                        if '"Principal": "*"' in policy_text or '"Principal":"*"' in policy_text:
                            findings.append(create_finding(
                                title=f"KMS key {key_id} has wildcard principal in key policy",
                                severity="high",
                                resource_type="KMS Key",
                                resource_id=key_id,
                                region=region,
                                risk="Anyone with the right permissions can use this key. Restrict to specific accounts/roles.",
                                fix_commands=[
                                    f"aws kms get-key-policy --key-id {key_id} --policy-name default --output text > policy.json",
                                    "# Edit policy.json to restrict Principal to specific ARNs",
                                    f"aws kms put-key-policy --key-id {key_id} --policy-name default --policy file://policy.json",
                                ],
                                compliance=["AWS Well-Architected SEC-8"],
                                effort="15 minutes",
                            ))
                    except Exception:
                        pass

                # Check for pending deletion (might be accidental)
                if key_info.get("KeyState") == "PendingDeletion":
                    deletion_date = key_info.get("DeletionDate")
                    findings.append(create_finding(
                        title=f"KMS key {key_id} is pending deletion",
                        severity="medium",
                        resource_type="KMS Key",
                        resource_id=key_id,
                        region=region,
                        description=f"Deletion scheduled for: {deletion_date}",
                        risk="Any data encrypted with this key will become permanently inaccessible.",
                        fix_commands=[
                            f"# Cancel deletion if this was accidental:",
                            f"aws kms cancel-key-deletion --key-id {key_id}",
                            f"aws kms enable-key --key-id {key_id}",
                        ],
                        effort="2 minutes",
                    ))

            except Exception:
                continue

    except Exception as e:
        logger.error(f"Error checking KMS in {region}: {e}")

    return findings


def check_secrets_manager(session, region, config):
    """Check Secrets Manager for security issues."""
    findings = []
    now = datetime.now(timezone.utc)

    try:
        sm = session.client("secretsmanager", region_name=region)
        secrets = sm.list_secrets()["SecretList"]

        for secret in secrets:
            secret_name = secret["Name"]

            # Check rotation
            if not secret.get("RotationEnabled", False):
                # Calculate age of secret
                last_changed = secret.get("LastChangedDate")
                if last_changed:
                    age_days = (now - last_changed.replace(tzinfo=timezone.utc)).days
                    if age_days > 90:
                        findings.append(create_finding(
                            title=f"Secret '{secret_name}' has not been rotated in {age_days} days",
                            severity="medium",
                            resource_type="Secrets Manager",
                            resource_id=secret_name,
                            region=region,
                            risk="Long-lived secrets increase blast radius if compromised.",
                            fix_commands=[
                                f"# Enable automatic rotation:",
                                f"aws secretsmanager rotate-secret --secret-id {secret_name}",
                                "# Or configure automatic rotation with a Lambda:",
                                f"aws secretsmanager put-resource-policy --secret-id {secret_name} "
                                f"--resource-policy file://rotation-policy.json",
                            ],
                            effort="30 minutes",
                        ))

    except Exception as e:
        logger.error(f"Error checking Secrets Manager in {region}: {e}")

    return findings
