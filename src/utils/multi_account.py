"""
Multi-account session management.
Handles both single-account and multi-account modes.
"""

import logging
import os
import boto3

logger = logging.getLogger(__name__)


def get_sessions(config):
    """
    Returns a list of boto3 session dicts for all accounts to scan.

    Single account mode (config.accounts is empty):
        Returns one session using Lambda's own credentials.

    Multi-account mode:
        Assumes role into each configured account.
    """
    sessions = []

    if not config.accounts:
        # Single account mode
        session = boto3.Session()
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]

        # Use configured account name or try to get account alias
        account_name = os.environ.get("ACCOUNT_NAME", "")
        if not account_name:
            try:
                iam = session.client("iam")
                aliases = iam.list_account_aliases()["AccountAliases"]
                account_name = aliases[0] if aliases else f"Account {account_id}"
            except Exception:
                account_name = f"Account {account_id}"

        logger.info(f"Single account mode: scanning {account_name} ({account_id})")
        sessions.append({
            "name": account_name,
            "account_id": account_id,
            "session": session,
        })
    else:
        # Multi-account mode
        sts = boto3.client("sts")

        # Also scan the hub account (where CloudSentry is deployed)
        hub_identity = sts.get_caller_identity()
        hub_account_id = hub_identity["Account"]
        sessions.append({
            "name": "Hub",
            "account_id": hub_account_id,
            "session": boto3.Session(),
        })

        for account in config.accounts:
            try:
                logger.info(f"Assuming role for account: {account['name']} ({account['account_id']})")
                credentials = sts.assume_role(
                    RoleArn=account["role_arn"],
                    RoleSessionName="CloudSentryAudit",
                    ExternalId="cloudsentry-audit",
                )["Credentials"]

                session = boto3.Session(
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                )

                sessions.append({
                    "name": account["name"],
                    "account_id": account["account_id"],
                    "session": session,
                })
            except Exception as e:
                logger.error(f"Failed to assume role for {account['name']}: {e}")
                sessions.append({
                    "name": account["name"],
                    "account_id": account["account_id"],
                    "session": None,
                    "error": str(e),
                })

    return sessions
