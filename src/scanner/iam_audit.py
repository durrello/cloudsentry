"""
IAM Security Audit Scanner.
Checks users, roles, groups, policies for security misconfigurations.
"""

import logging
from datetime import datetime, timezone

from utils.findings import create_finding

logger = logging.getLogger(__name__)


def scan_iam(session, config):
    """Run full IAM security audit."""
    findings = []
    iam = session.client("iam")

    findings.extend(check_root_account(iam))
    findings.extend(check_password_policy(iam))
    findings.extend(check_users(iam, config))
    findings.extend(check_roles(iam))
    findings.extend(check_groups(iam))
    findings.extend(check_policies(iam))

    return findings


def check_root_account(iam):
    """Check root account security."""
    findings = []

    try:
        summary = iam.get_account_summary()["SummaryMap"]

        # Root MFA
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append(create_finding(
                title="Root account has no MFA enabled",
                severity="critical",
                resource_type="IAM Root",
                resource_id="root",
                description="The root account does not have multi-factor authentication enabled.",
                risk="Full account takeover if root credentials are compromised. Root bypasses all IAM policies and can delete everything.",
                fix_commands=[
                    "# Log in as root at https://console.aws.amazon.com",
                    "# Go to IAM > Security Credentials > Assign MFA device",
                    "# Use a hardware key or authenticator app",
                ],
                compliance=["CIS 1.5", "AWS Well-Architected SEC-1"],
                effort="5 minutes",
            ))

        # Root access keys
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append(create_finding(
                title="Root account has active access keys",
                severity="critical",
                resource_type="IAM Root",
                resource_id="root",
                description="The root account has programmatic access keys. These should never exist.",
                risk="Root access keys give unrestricted API access. If leaked, the entire account is compromised.",
                fix_commands=[
                    "# Log in as root",
                    "# Go to IAM > Security Credentials",
                    "# Delete all access keys for root",
                ],
                compliance=["CIS 1.4"],
                effort="5 minutes",
            ))
    except Exception as e:
        logger.error(f"Error checking root account: {e}")

    return findings


def check_password_policy(iam):
    """Check IAM password policy."""
    findings = []

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        if policy.get("MinimumPasswordLength", 0) < 14:
            findings.append(create_finding(
                title="Password policy minimum length is less than 14 characters",
                severity="medium",
                resource_type="IAM Password Policy",
                resource_id="password-policy",
                description=f"Current minimum: {policy.get('MinimumPasswordLength', 'not set')}",
                risk="Short passwords are easier to brute-force.",
                fix_commands=[
                    "aws iam update-account-password-policy --minimum-password-length 14",
                ],
                compliance=["CIS 1.8"],
                effort="2 minutes",
            ))

        if not policy.get("RequireLowercaseCharacters", False):
            findings.append(create_finding(
                title="Password policy does not require lowercase characters",
                severity="low",
                resource_type="IAM Password Policy",
                resource_id="password-policy",
                fix_commands=[
                    "aws iam update-account-password-policy --require-lowercase-characters",
                ],
                compliance=["CIS 1.9"],
                effort="2 minutes",
            ))

    except iam.exceptions.NoSuchEntityException:
        findings.append(create_finding(
            title="No IAM password policy configured",
            severity="high",
            resource_type="IAM Password Policy",
            resource_id="password-policy",
            description="No custom password policy is set. AWS defaults allow weak passwords.",
            risk="Users can set weak, short passwords with no complexity requirements.",
            fix_commands=[
                "aws iam update-account-password-policy "
                "--minimum-password-length 14 "
                "--require-symbols "
                "--require-numbers "
                "--require-uppercase-characters "
                "--require-lowercase-characters "
                "--max-password-age 90 "
                "--password-reuse-prevention 24",
            ],
            compliance=["CIS 1.8-1.11"],
            effort="5 minutes",
        ))
    except Exception as e:
        logger.error(f"Error checking password policy: {e}")

    return findings


def check_users(iam, config):
    """Check all IAM users for security issues."""
    findings = []
    now = datetime.now(timezone.utc)
    max_key_age = config.max_access_key_age_days

    try:
        users = iam.list_users()["Users"]

        for user in users:
            username = user["UserName"]

            # Check MFA
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                # Check if user has console access
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False

                if has_console:
                    findings.append(create_finding(
                        title=f"IAM user '{username}' has console access without MFA",
                        severity="high",
                        resource_type="IAM User",
                        resource_id=username,
                        risk="Account can be compromised with just a password. MFA adds a second factor.",
                        fix_commands=[
                            f"# Notify user to enable MFA, or enforce via policy:",
                            f"aws iam put-user-policy --user-name {username} "
                            f"--policy-name ForceMFA --policy-document file://force-mfa-policy.json",
                        ],
                        better_alternative="Enforce MFA via SCP at organization level",
                        compliance=["CIS 1.10"],
                        effort="10 minutes",
                    ))

            # Check access keys age
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                if key["Status"] == "Active":
                    key_age = (now - key["CreateDate"].replace(tzinfo=timezone.utc)).days
                    if key_age > max_key_age:
                        findings.append(create_finding(
                            title=f"IAM user '{username}' access key is {key_age} days old",
                            severity="high",
                            resource_type="IAM Access Key",
                            resource_id=f"{username}/{key['AccessKeyId']}",
                            risk="Long-lived credentials increase blast radius if compromised.",
                            fix_commands=[
                                f"aws iam create-access-key --user-name {username}",
                                "# Update the key wherever it's used (CI/CD, app config)",
                                f"aws iam update-access-key --user-name {username} "
                                f"--access-key-id {key['AccessKeyId']} --status Inactive",
                                "# After confirming nothing broke:",
                                f"aws iam delete-access-key --user-name {username} "
                                f"--access-key-id {key['AccessKeyId']}",
                            ],
                            better_alternative="Migrate to IAM roles with OIDC for CI/CD (no long-lived keys needed)",
                            compliance=["CIS 1.14"],
                            effort="15 minutes",
                        ))

            # Check if user has multiple active keys
            active_keys = [k for k in keys if k["Status"] == "Active"]
            if len(active_keys) > 1:
                findings.append(create_finding(
                    title=f"IAM user '{username}' has multiple active access keys",
                    severity="medium",
                    resource_type="IAM User",
                    resource_id=username,
                    risk="Multiple keys increase attack surface and make rotation harder.",
                    fix_commands=[
                        f"aws iam list-access-keys --user-name {username}",
                        "# Deactivate the older key after confirming the newer one works",
                    ],
                    compliance=["CIS 1.13"],
                    effort="10 minutes",
                ))

            # Check if user has inline policies
            inline_policies = iam.list_user_policies(UserName=username)["PolicyNames"]
            if inline_policies:
                findings.append(create_finding(
                    title=f"IAM user '{username}' has inline policies",
                    severity="medium",
                    resource_type="IAM User",
                    resource_id=username,
                    description=f"Inline policies: {', '.join(inline_policies)}",
                    risk="Inline policies are harder to audit and manage. Use group or role-based policies.",
                    fix_commands=[
                        f"# Move inline policies to a managed policy attached via group:",
                        f"aws iam get-user-policy --user-name {username} --policy-name {inline_policies[0]}",
                        "# Create managed policy from the document, attach to group, then delete inline:",
                        f"aws iam delete-user-policy --user-name {username} --policy-name {inline_policies[0]}",
                    ],
                    effort="15 minutes",
                ))

            # Check if user is not in any group
            groups = iam.list_groups_for_user(UserName=username)["Groups"]
            if not groups:
                findings.append(create_finding(
                    title=f"IAM user '{username}' is not in any group",
                    severity="low",
                    resource_type="IAM User",
                    resource_id=username,
                    risk="Orphaned users are harder to manage. Permissions should flow through groups.",
                    fix_commands=[
                        f"aws iam add-user-to-group --user-name {username} --group-name <appropriate-group>",
                    ],
                    effort="5 minutes",
                ))

    except Exception as e:
        logger.error(f"Error checking IAM users: {e}")

    return findings


def check_roles(iam):
    """Check IAM roles for security issues."""
    findings = []

    try:
        roles = iam.list_roles()["Roles"]

        for role in roles:
            role_name = role["RoleName"]

            # Skip AWS service-linked roles
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue

            # Check for AdministratorAccess
            attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            for policy in attached:
                if policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
                    findings.append(create_finding(
                        title=f"Role '{role_name}' has AdministratorAccess attached",
                        severity="high",
                        resource_type="IAM Role",
                        resource_id=role_name,
                        risk="Full admin access. If this role is compromised, the attacker owns the account.",
                        fix_commands=[
                            f"# Review if this role needs full admin:",
                            f"aws iam detach-role-policy --role-name {role_name} "
                            f"--policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                            "# Attach least-privilege policy instead",
                        ],
                        better_alternative="Create a custom policy with only the permissions this role needs",
                        compliance=["AWS Well-Architected SEC-3"],
                        effort="30 minutes",
                    ))

            # Check for wildcard inline policies
            inline_policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
            for policy_name in inline_policies[:5]:  # Limit to avoid throttling
                try:
                    policy_doc = iam.get_role_policy(
                        RoleName=role_name, PolicyName=policy_name
                    )["PolicyDocument"]
                    statements = policy_doc.get("Statement", [])
                    for stmt in statements:
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        resources = stmt.get("Resource", [])
                        if isinstance(resources, str):
                            resources = [resources]
                        if "*" in actions and "*" in resources and stmt.get("Effect") == "Allow":
                            findings.append(create_finding(
                                title=f"Role '{role_name}' has wildcard Allow * on * in inline policy",
                                severity="high",
                                resource_type="IAM Role",
                                resource_id=role_name,
                                description=f"Policy: {policy_name}",
                                risk="Equivalent to admin access via inline policy.",
                                fix_commands=[
                                    f"aws iam get-role-policy --role-name {role_name} --policy-name {policy_name}",
                                    "# Rewrite with least-privilege permissions",
                                ],
                                compliance=["CIS 1.16"],
                                effort="30 minutes",
                            ))
                except Exception:
                    continue

    except Exception as e:
        logger.error(f"Error checking IAM roles: {e}")

    return findings


def check_groups(iam):
    """Check IAM groups for issues."""
    findings = []

    try:
        groups = iam.list_groups()["Groups"]

        for group in groups:
            group_name = group["GroupName"]

            # Check for empty groups
            members = iam.get_group(GroupName=group_name)["Users"]
            if not members:
                findings.append(create_finding(
                    title=f"IAM group '{group_name}' has no members",
                    severity="low",
                    resource_type="IAM Group",
                    resource_id=group_name,
                    risk="Empty groups are clutter. Remove if unused.",
                    fix_commands=[
                        f"aws iam delete-group --group-name {group_name}",
                    ],
                    effort="2 minutes",
                ))

            # Check for AdminAccess on groups
            attached = iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
            for policy in attached:
                if policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
                    findings.append(create_finding(
                        title=f"Group '{group_name}' has AdministratorAccess ({len(members)} members)",
                        severity="high",
                        resource_type="IAM Group",
                        resource_id=group_name,
                        risk=f"All {len(members)} members of this group have full admin access.",
                        fix_commands=[
                            f"aws iam detach-group-policy --group-name {group_name} "
                            f"--policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                            "# Attach a scoped policy instead",
                        ],
                        effort="20 minutes",
                    ))

    except Exception as e:
        logger.error(f"Error checking IAM groups: {e}")

    return findings


def check_policies(iam):
    """Check customer-managed policies."""
    findings = []

    try:
        policies = iam.list_policies(Scope="Local", OnlyAttached=False)["Policies"]

        for policy in policies:
            # Check for unattached policies
            if policy["AttachmentCount"] == 0:
                findings.append(create_finding(
                    title=f"Customer policy '{policy['PolicyName']}' is not attached to anything",
                    severity="low",
                    resource_type="IAM Policy",
                    resource_id=policy["PolicyName"],
                    risk="Unused policies are clutter and may contain stale, over-permissive rules.",
                    fix_commands=[
                        f"aws iam delete-policy --policy-arn {policy['Arn']}",
                    ],
                    effort="2 minutes",
                ))

    except Exception as e:
        logger.error(f"Error checking IAM policies: {e}")

    return findings
