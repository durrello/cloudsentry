"""
Network Security Audit Scanner.
Checks VPCs, security groups, NACLs, internet gateways, NAT gateways, EIPs, load balancers.
"""

import logging

from utils.findings import create_finding

logger = logging.getLogger(__name__)

# Ports that should never be open to 0.0.0.0/0
RISKY_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    5900: "VNC",
    23: "Telnet",
    21: "FTP",
    445: "SMB",
    135: "RPC",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    9090: "Various Admin",
    2049: "NFS",
}


def scan_network(session, region, config):
    """Run network security audit for a specific region."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    findings.extend(check_security_groups(ec2, region))
    findings.extend(check_vpcs(ec2, region))
    findings.extend(check_nacls(ec2, region))
    findings.extend(check_internet_gateways(ec2, region))
    findings.extend(check_elastic_ips(ec2, region))
    findings.extend(check_load_balancers(session, region))
    findings.extend(check_vpc_peering(ec2, region))

    return findings


def check_security_groups(ec2, region):
    """Check security groups for dangerous rules."""
    findings = []

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")

                    if cidr == "0.0.0.0/0":
                        # All traffic open
                        if from_port == 0 and to_port == 65535 and rule.get("IpProtocol") == "-1":
                            findings.append(create_finding(
                                title=f"Security group '{sg_name}' ({sg_id}) allows ALL inbound traffic from internet",
                                severity="critical",
                                resource_type="Security Group",
                                resource_id=sg_id,
                                region=region,
                                risk="Every port on every protocol is accessible from the entire internet.",
                                fix_commands=[
                                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                                    f"--protocol -1 --port -1 --cidr 0.0.0.0/0",
                                ],
                                compliance=["CIS 5.1"],
                                effort="5 minutes",
                            ))
                        # Specific risky ports
                        elif from_port in RISKY_PORTS or to_port in RISKY_PORTS:
                            port = from_port if from_port in RISKY_PORTS else to_port
                            service = RISKY_PORTS[port]
                            severity = "critical" if port in (22, 3389, 3306, 5432) else "high"

                            findings.append(create_finding(
                                title=f"Security group '{sg_name}' ({sg_id}) allows 0.0.0.0/0 on port {port} ({service})",
                                severity=severity,
                                resource_type="Security Group",
                                resource_id=sg_id,
                                region=region,
                                risk=f"{service} on port {port} is exposed to the entire internet.",
                                fix_commands=[
                                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                                    f"--protocol tcp --port {port} --cidr 0.0.0.0/0",
                                    f"# Then restrict to specific IP:",
                                    f"aws ec2 authorize-security-group-ingress --group-id {sg_id} "
                                    f"--protocol tcp --port {port} --cidr YOUR_IP/32",
                                ],
                                better_alternative=f"Use SSM Session Manager instead of exposing {service} directly"
                                if port == 22 else f"Put {service} behind a private subnet with no public access",
                                compliance=["CIS 5.2" if port == 22 else "CIS 5.3"],
                                effort="5 minutes",
                            ))

            # Check for orphaned security groups (not attached to anything)
            # We check if there are no network interfaces using this SG
            if sg_name != "default":
                try:
                    enis = ec2.describe_network_interfaces(
                        Filters=[{"Name": "group-id", "Values": [sg_id]}]
                    )["NetworkInterfaces"]
                    if not enis:
                        findings.append(create_finding(
                            title=f"Security group '{sg_name}' ({sg_id}) is not attached to any resource",
                            severity="low",
                            resource_type="Security Group",
                            resource_id=sg_id,
                            region=region,
                            risk="Orphaned security groups add clutter and may be accidentally used later.",
                            fix_commands=[
                                f"aws ec2 delete-security-group --group-id {sg_id}",
                            ],
                            effort="2 minutes",
                        ))
                except Exception:
                    pass

    except Exception as e:
        logger.error(f"Error checking security groups in {region}: {e}")

    return findings


def check_vpcs(ec2, region):
    """Check VPCs for security issues."""
    findings = []

    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            is_default = vpc.get("IsDefault", False)
            tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
            vpc_name = tags.get("Name", vpc_id)

            # Check for default VPC in use
            if is_default:
                # Check if anything is running in it
                instances = ec2.describe_instances(
                    Filters=[
                        {"Name": "vpc-id", "Values": [vpc_id]},
                        {"Name": "instance-state-name", "Values": ["running", "stopped"]},
                    ]
                )["Reservations"]
                if instances:
                    findings.append(create_finding(
                        title=f"Resources running in default VPC ({vpc_id}) in {region}",
                        severity="medium",
                        resource_type="VPC",
                        resource_id=vpc_id,
                        region=region,
                        risk="Default VPCs have permissive settings. Use custom VPCs with controlled networking.",
                        fix_commands=[
                            "# Migrate resources to a custom VPC with proper subnet design",
                        ],
                        better_alternative="Create a custom VPC with public/private subnets and proper routing",
                        compliance=["AWS Well-Architected SEC-6"],
                        effort="2-4 hours (migration)",
                    ))

            # Check VPC flow logs
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )["FlowLogs"]
            if not flow_logs:
                findings.append(create_finding(
                    title=f"VPC '{vpc_name}' ({vpc_id}) has no flow logs enabled",
                    severity="medium",
                    resource_type="VPC",
                    resource_id=vpc_id,
                    region=region,
                    risk="Network traffic is not being logged. Cannot investigate incidents or detect anomalies.",
                    fix_commands=[
                        f"aws ec2 create-flow-log --resource-type VPC --resource-ids {vpc_id} "
                        f"--traffic-type ALL --log-destination-type cloud-watch-logs "
                        f"--log-group-name /aws/vpc/flow-logs/{vpc_id}",
                    ],
                    compliance=["CIS 3.9"],
                    effort="10 minutes",
                ))

    except Exception as e:
        logger.error(f"Error checking VPCs in {region}: {e}")

    return findings


def check_nacls(ec2, region):
    """Check Network ACLs for overly permissive rules."""
    findings = []

    try:
        nacls = ec2.describe_network_acls()["NetworkAcls"]

        for nacl in nacls:
            nacl_id = nacl["NetworkAclId"]

            for entry in nacl.get("Entries", []):
                # Skip default deny rules
                if entry.get("RuleAction") != "allow":
                    continue
                # Skip egress rules for this check
                if entry.get("Egress", False):
                    continue

                cidr = entry.get("CidrBlock", "")
                protocol = entry.get("Protocol", "")

                # All traffic from anywhere
                if cidr == "0.0.0.0/0" and protocol == "-1":
                    findings.append(create_finding(
                        title=f"NACL {nacl_id} allows all inbound traffic from 0.0.0.0/0",
                        severity="medium",
                        resource_type="Network ACL",
                        resource_id=nacl_id,
                        region=region,
                        risk="NACL is not providing any network-level filtering.",
                        fix_commands=[
                            f"aws ec2 replace-network-acl-entry --network-acl-id {nacl_id} "
                            f"--rule-number {entry.get('RuleNumber')} --protocol -1 "
                            f"--rule-action deny --ingress --cidr-block 0.0.0.0/0",
                        ],
                        effort="10 minutes",
                    ))

    except Exception as e:
        logger.error(f"Error checking NACLs in {region}: {e}")

    return findings


def check_internet_gateways(ec2, region):
    """Check internet gateways."""
    findings = []

    try:
        igws = ec2.describe_internet_gateways()["InternetGateways"]

        for igw in igws:
            igw_id = igw["InternetGatewayId"]
            attachments = igw.get("Attachments", [])

            # Unattached IGW
            if not attachments:
                findings.append(create_finding(
                    title=f"Internet Gateway {igw_id} is not attached to any VPC",
                    severity="low",
                    resource_type="Internet Gateway",
                    resource_id=igw_id,
                    region=region,
                    risk="Unused resource. Clean up to reduce clutter.",
                    fix_commands=[
                        f"aws ec2 delete-internet-gateway --internet-gateway-id {igw_id}",
                    ],
                    effort="2 minutes",
                ))

    except Exception as e:
        logger.error(f"Error checking IGWs in {region}: {e}")

    return findings


def check_elastic_ips(ec2, region):
    """Check Elastic IPs for waste and security."""
    findings = []

    try:
        eips = ec2.describe_addresses()["Addresses"]

        for eip in eips:
            public_ip = eip["PublicIp"]
            allocation_id = eip.get("AllocationId", "N/A")

            # Unassociated EIP (costs $3.60/month since Feb 2024)
            if not eip.get("AssociationId"):
                findings.append(create_finding(
                    title=f"Elastic IP {public_ip} is not associated with any resource",
                    severity="medium",
                    resource_type="Elastic IP",
                    resource_id=allocation_id,
                    region=region,
                    risk="Unassociated EIPs cost $3.60/month and increase attack surface.",
                    fix_commands=[
                        f"# Associate with an instance:",
                        f"aws ec2 associate-address --allocation-id {allocation_id} --instance-id <instance-id>",
                        f"# Or release if not needed:",
                        f"aws ec2 release-address --allocation-id {allocation_id}",
                    ],
                    effort="2 minutes",
                ))

    except Exception as e:
        logger.error(f"Error checking EIPs in {region}: {e}")

    return findings


def check_load_balancers(session, region):
    """Check load balancers for security and waste."""
    findings = []

    try:
        elbv2 = session.client("elbv2", region_name=region)
        lbs = elbv2.describe_load_balancers()["LoadBalancers"]

        for lb in lbs:
            lb_name = lb["LoadBalancerName"]
            lb_arn = lb["LoadBalancerArn"]

            # Check for HTTP-only listeners (no HTTPS)
            listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
            protocols = [l["Protocol"] for l in listeners]

            if "HTTP" in protocols and "HTTPS" not in protocols:
                findings.append(create_finding(
                    title=f"Load balancer '{lb_name}' uses HTTP only (no HTTPS)",
                    severity="high",
                    resource_type="Load Balancer",
                    resource_id=lb_name,
                    region=region,
                    risk="Traffic is unencrypted. Credentials and data can be intercepted.",
                    fix_commands=[
                        f"# Add HTTPS listener with ACM certificate:",
                        f"aws elbv2 create-listener --load-balancer-arn {lb_arn} "
                        f"--protocol HTTPS --port 443 --certificates CertificateArn=<cert-arn> "
                        f"--default-actions Type=forward,TargetGroupArn=<target-group-arn>",
                    ],
                    compliance=["AWS Well-Architected SEC-8"],
                    effort="15 minutes",
                ))

            # Check for unhealthy targets
            target_groups = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)["TargetGroups"]
            all_unhealthy = True
            for tg in target_groups:
                health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                healthy = [t for t in health["TargetHealthDescriptions"] if t["TargetHealth"]["State"] == "healthy"]
                if healthy:
                    all_unhealthy = False
                    break

            if all_unhealthy and target_groups:
                findings.append(create_finding(
                    title=f"Load balancer '{lb_name}' has no healthy targets",
                    severity="high",
                    resource_type="Load Balancer",
                    resource_id=lb_name,
                    region=region,
                    risk="Load balancer is serving errors to all traffic. Either fix targets or remove the LB.",
                    fix_commands=[
                        f"# Check target health:",
                        f"aws elbv2 describe-target-health --target-group-arn <tg-arn>",
                    ],
                    effort="15 minutes",
                ))

            # Check access logging
            attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
            access_logs = next(
                (a for a in attrs if a["Key"] == "access_logs.s3.enabled"), None
            )
            if access_logs and access_logs["Value"] == "false":
                findings.append(create_finding(
                    title=f"Load balancer '{lb_name}' has access logging disabled",
                    severity="medium",
                    resource_type="Load Balancer",
                    resource_id=lb_name,
                    region=region,
                    risk="Cannot audit traffic patterns or investigate incidents.",
                    fix_commands=[
                        f"aws elbv2 modify-load-balancer-attributes --load-balancer-arn {lb_arn} "
                        f"--attributes Key=access_logs.s3.enabled,Value=true "
                        f"Key=access_logs.s3.bucket,Value=<your-log-bucket>",
                    ],
                    effort="10 minutes",
                ))

    except Exception as e:
        logger.error(f"Error checking load balancers in {region}: {e}")

    return findings


def check_vpc_peering(ec2, region):
    """Check VPC peering connections."""
    findings = []

    try:
        peerings = ec2.describe_vpc_peering_connections(
            Filters=[{"Name": "status-code", "Values": ["pending-acceptance"]}]
        )["VpcPeeringConnections"]

        for peering in peerings:
            findings.append(create_finding(
                title=f"VPC peering {peering['VpcPeeringConnectionId']} is pending acceptance",
                severity="low",
                resource_type="VPC Peering",
                resource_id=peering["VpcPeeringConnectionId"],
                region=region,
                risk="Forgotten peering requests. Accept or reject to keep things clean.",
                fix_commands=[
                    f"# Accept: aws ec2 accept-vpc-peering-connection "
                    f"--vpc-peering-connection-id {peering['VpcPeeringConnectionId']}",
                    f"# Or reject: aws ec2 reject-vpc-peering-connection "
                    f"--vpc-peering-connection-id {peering['VpcPeeringConnectionId']}",
                ],
                effort="5 minutes",
            ))

    except Exception as e:
        logger.error(f"Error checking VPC peering in {region}: {e}")

    return findings
