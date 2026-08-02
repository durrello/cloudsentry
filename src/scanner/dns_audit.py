"""
DNS Security Audit Scanner.
Checks Route 53 hosted zones and ACM certificates.
"""

import logging
from datetime import datetime, timezone, timedelta

from utils.findings import create_finding

logger = logging.getLogger(__name__)


def scan_dns(session, config):
    """Run DNS and certificate security audit."""
    findings = []

    findings.extend(check_route53(session))
    findings.extend(check_acm_certificates(session))

    return findings


def check_route53(session):
    """Check Route 53 for potential issues."""
    findings = []

    try:
        route53 = session.client("route53")
        zones = route53.list_hosted_zones()["HostedZones"]

        for zone in zones:
            zone_id = zone["Id"].split("/")[-1]
            zone_name = zone["Name"]

            # Get all records
            try:
                records = route53.list_resource_record_sets(HostedZoneId=zone_id)
                record_sets = records["ResourceRecordSets"]

                for record in record_sets:
                    record_name = record["Name"]
                    record_type = record["Type"]

                    # Check for dangling CNAME records (pointing to potentially claimable resources)
                    if record_type == "CNAME":
                        values = record.get("ResourceRecords", [])
                        for value in values:
                            target = value.get("Value", "")
                            # Check for common dangling patterns
                            dangling_patterns = [
                                ".s3-website",
                                ".elasticbeanstalk.com",
                                ".cloudfront.net",
                                ".herokuapp.com",
                                ".github.io",
                            ]
                            for pattern in dangling_patterns:
                                if pattern in target:
                                    findings.append(create_finding(
                                        title=f"DNS record '{record_name}' may be a dangling CNAME",
                                        severity="medium",
                                        resource_type="Route 53 Record",
                                        resource_id=f"{zone_name}/{record_name}",
                                        description=f"Points to: {target}",
                                        risk="If the target resource is deleted, an attacker can claim it and serve malicious content on your domain.",
                                        fix_commands=[
                                            "# Verify the target resource still exists",
                                            f"# If not, delete the record:",
                                            f"# Use Route 53 console or CLI to remove {record_name} from zone {zone_name}",
                                        ],
                                        compliance=["OWASP Subdomain Takeover"],
                                        effort="5 minutes",
                                    ))
                                    break

            except Exception as e:
                logger.debug(f"Error checking records for zone {zone_name}: {e}")

    except Exception as e:
        logger.error(f"Error checking Route 53: {e}")

    return findings


def check_acm_certificates(session):
    """Check ACM certificates for expiry."""
    findings = []
    now = datetime.now(timezone.utc)
    warning_threshold = timedelta(days=30)

    try:
        # Check in us-east-1 (CloudFront certs must be here) and current region
        for region in ["us-east-1"]:
            acm = session.client("acm", region_name=region)
            certs = acm.list_certificates(
                CertificateStatuses=["ISSUED"]
            )["CertificateSummaryList"]

            for cert_summary in certs:
                cert_arn = cert_summary["CertificateArn"]

                try:
                    cert_detail = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
                    domain = cert_detail["DomainName"]
                    not_after = cert_detail.get("NotAfter")

                    if not_after:
                        not_after = not_after.replace(tzinfo=timezone.utc) if not_after.tzinfo is None else not_after
                        days_until_expiry = (not_after - now).days

                        if days_until_expiry < 0:
                            findings.append(create_finding(
                                title=f"ACM certificate for '{domain}' has EXPIRED",
                                severity="critical",
                                resource_type="ACM Certificate",
                                resource_id=domain,
                                region=region,
                                description=f"Expired {abs(days_until_expiry)} days ago",
                                risk="HTTPS connections to this domain will show security warnings.",
                                fix_commands=[
                                    f"# Request a new certificate:",
                                    f"aws acm request-certificate --domain-name {domain} "
                                    f"--validation-method DNS",
                                    "# Or check if auto-renewal failed and fix validation records",
                                ],
                                effort="15 minutes",
                            ))
                        elif days_until_expiry <= 30:
                            findings.append(create_finding(
                                title=f"ACM certificate for '{domain}' expires in {days_until_expiry} days",
                                severity="high",
                                resource_type="ACM Certificate",
                                resource_id=domain,
                                region=region,
                                description=f"Expires: {not_after.strftime('%Y-%m-%d')}",
                                risk="Certificate will expire soon. If auto-renewal fails, HTTPS will break.",
                                fix_commands=[
                                    "# Check if auto-renewal is working:",
                                    f"aws acm describe-certificate --certificate-arn {cert_arn} "
                                    f"--query 'Certificate.RenewalSummary'",
                                    "# If renewal is failing, verify DNS validation records are in place",
                                ],
                                effort="10 minutes",
                            ))

                except Exception:
                    continue

    except Exception as e:
        logger.error(f"Error checking ACM certificates: {e}")

    return findings
