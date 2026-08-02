"""
Access Policy Violation Checker.
Checks for overly permissive access patterns.
"""

import logging

from utils.findings import create_violation

logger = logging.getLogger(__name__)


def check_access_policy(session, config):
    """Check for access policy violations."""
    violations = []

    try:
        iam = session.client("iam")
        violations.extend(check_cross_account_roles(iam))
        violations.extend(check_unused_credentials(iam, config))
    except Exception as e:
        logger.error(f"Error in access policy check: {e}")

    return violations


def check_cross_account_roles(iam):
    """Check for roles with cross-account trust to unknown accounts."""
    violations = []

    try:
        roles = iam.list_roles()["Roles"]

        for role in roles:
            role_name = role["RoleName"]

            # Skip AWS service-linked roles
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue

            # Check trust policy for external accounts
            trust_policy = role.get("AssumeRolePolicyDocument", {})
            statements = trust_policy.get("Statement", [])

            for stmt in statements:
                principal = stmt.get("Principal", {})
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]

                for p in aws_principals:
                    if ":root" in p and "arn:aws:iam::" in p:
                        # External account trust
                        account_id = p.split(":")[4]
                        violations.append(create_violation(
                            title=f"Role '{role_name}' trusts external account {account_id}",
                            severity="medium",
                            category="access",
                            resource_type="IAM Role",
                            resource_id=role_name,
                            description=f"Trust: {p}",
                            fix_commands=[
                                f"# Verify this trust is expected:",
                                f"aws iam get-role --role-name {role_name} "
                                f"--query 'Role.AssumeRolePolicyDocument'",
                                "# Add conditions (ExternalId, MFA) if not present",
                            ],
                            current_value=f"Trusts: {p}",
                            expected_value="Only known/documented cross-account trusts with conditions",
                        ))

    except Exception as e:
        logger.error(f"Error checking cross-account roles: {e}")

    return violations


def check_unused_credentials(iam, config):
    """Check for users with credentials that have never been used."""
    violations = []

    try:
        # Generate and get credential report
        try:
            iam.generate_credential_report()
        except Exception:
            pass

        try:
            report = iam.get_credential_report()
            import csv
            import io

            content = report["Content"].decode("utf-8")
            reader = csv.DictReader(io.StringIO(content))

            for row in reader:
                username = row.get("user", "")
                if username == "<root_account>":
                    continue

                # Check for password enabled but never used
                pwd_enabled = row.get("password_enabled", "false")
                pwd_last_used = row.get("password_last_used", "N/A")

                if pwd_enabled == "true" and pwd_last_used in ("N/A", "no_information"):
                    violations.append(create_violation(
                        title=f"User '{username}' has password enabled but never logged in",
                        severity="medium",
                        category="access",
                        resource_type="IAM User",
                        resource_id=username,
                        description="Console access granted but never used. Remove if not needed.",
                        fix_commands=[
                            f"aws iam delete-login-profile --user-name {username}",
                        ],
                        current_value="Password enabled, never used",
                        expected_value="Remove unused console access",
                    ))

        except Exception:
            pass

    except Exception as e:
        logger.error(f"Error checking unused credentials: {e}")

    return violations
