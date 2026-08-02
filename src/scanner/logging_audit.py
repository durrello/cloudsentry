"""
Logging and Monitoring Audit Scanner.
Checks CloudTrail, Config, GuardDuty, and CloudWatch.
"""

import logging

from utils.findings import create_finding

logger = logging.getLogger(__name__)


def scan_logging(session, config):
    """Run logging and monitoring security audit."""
    findings = []

    findings.extend(check_cloudtrail(session))
    findings.extend(check_guardduty(session))
    findings.extend(check_cloudwatch_alarms(session))

    return findings


def check_cloudtrail(session):
    """Check CloudTrail configuration."""
    findings = []

    try:
        cloudtrail = session.client("cloudtrail")
        trails = cloudtrail.describe_trails()["trailList"]

        if not trails:
            findings.append(create_finding(
                title="No CloudTrail trails configured",
                severity="critical",
                resource_type="CloudTrail",
                resource_id="none",
                risk="No audit logging. Cannot detect or investigate security incidents.",
                fix_commands=[
                    "aws cloudtrail create-trail --name main-trail "
                    "--s3-bucket-name <your-log-bucket> --is-multi-region-trail --enable-log-file-validation",
                    "aws cloudtrail start-logging --name main-trail",
                ],
                compliance=["CIS 3.1"],
                effort="15 minutes",
            ))
            return findings

        has_multi_region = False
        for trail in trails:
            trail_name = trail["Name"]

            # Check multi-region
            if trail.get("IsMultiRegionTrail", False):
                has_multi_region = True

            # Check log file validation
            if not trail.get("LogFileValidationEnabled", False):
                findings.append(create_finding(
                    title=f"CloudTrail '{trail_name}' has log file validation disabled",
                    severity="medium",
                    resource_type="CloudTrail",
                    resource_id=trail_name,
                    risk="Log files can be tampered with without detection.",
                    fix_commands=[
                        f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation",
                    ],
                    compliance=["CIS 3.2"],
                    effort="2 minutes",
                ))

            # Check if trail is logging
            try:
                status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
                if not status.get("IsLogging", False):
                    findings.append(create_finding(
                        title=f"CloudTrail '{trail_name}' is not currently logging",
                        severity="critical",
                        resource_type="CloudTrail",
                        resource_id=trail_name,
                        risk="Audit logging is stopped. Activity is not being recorded.",
                        fix_commands=[
                            f"aws cloudtrail start-logging --name {trail_name}",
                        ],
                        compliance=["CIS 3.1"],
                        effort="2 minutes",
                    ))
            except Exception:
                pass

        if not has_multi_region:
            findings.append(create_finding(
                title="No multi-region CloudTrail trail configured",
                severity="high",
                resource_type="CloudTrail",
                resource_id="all-trails",
                risk="Activity in non-configured regions is invisible. Attackers use unused regions.",
                fix_commands=[
                    f"aws cloudtrail update-trail --name {trails[0]['Name']} --is-multi-region-trail",
                ],
                compliance=["CIS 3.1"],
                effort="2 minutes",
            ))

    except Exception as e:
        logger.error(f"Error checking CloudTrail: {e}")

    return findings


def check_guardduty(session):
    """Check if GuardDuty is enabled."""
    findings = []

    try:
        guardduty = session.client("guardduty")
        detectors = guardduty.list_detectors()["DetectorIds"]

        if not detectors:
            findings.append(create_finding(
                title="GuardDuty is not enabled",
                severity="high",
                resource_type="GuardDuty",
                resource_id="none",
                risk="No automated threat detection. Cannot identify compromised instances or unusual API activity.",
                fix_commands=[
                    "aws guardduty create-detector --enable",
                ],
                better_alternative="Enable GuardDuty in all regions via AWS Organizations",
                compliance=["AWS Well-Architected SEC-4"],
                effort="5 minutes",
            ))

    except Exception as e:
        logger.error(f"Error checking GuardDuty: {e}")

    return findings


def check_cloudwatch_alarms(session):
    """Check CloudWatch alarms status."""
    findings = []

    try:
        cw = session.client("cloudwatch")
        alarms = cw.describe_alarms(StateValue="ALARM")["MetricAlarms"]

        for alarm in alarms:
            findings.append(create_finding(
                title=f"CloudWatch alarm '{alarm['AlarmName']}' is in ALARM state",
                severity="medium",
                resource_type="CloudWatch Alarm",
                resource_id=alarm["AlarmName"],
                description=f"Metric: {alarm.get('MetricName')} | Threshold: {alarm.get('Threshold')}",
                risk="An alarm is firing that may indicate an operational issue.",
                fix_commands=[
                    f"# Investigate the alarm:",
                    f"aws cloudwatch describe-alarm-history --alarm-name '{alarm['AlarmName']}' --max-records 5",
                    "# Fix the underlying issue, then acknowledge:",
                    f"aws cloudwatch set-alarm-state --alarm-name '{alarm['AlarmName']}' --state-value OK --state-reason 'Resolved manually'",
                ],
                effort="varies",
            ))

    except Exception as e:
        logger.error(f"Error checking CloudWatch alarms: {e}")

    return findings
