"""
Active services inventory scanner.
Discovers all resources across all regions and builds a complete inventory.
"""

import logging

logger = logging.getLogger(__name__)


def scan_inventory(session, active_regions):
    """
    Scan all active regions and build a complete resource inventory.
    Returns a dict grouped by region with resource counts and details.
    """
    inventory = {"by_region": {}, "global": {}, "totals": {}}

    # Global services (not region-specific)
    inventory["global"] = scan_global_services(session)

    # Regional services
    for region in active_regions:
        inventory["by_region"][region] = scan_region(session, region)

    # Calculate totals
    inventory["totals"] = calculate_totals(inventory)

    return inventory


def scan_global_services(session):
    """Scan global AWS services (IAM, Route53, CloudFront)."""
    global_resources = {}

    # IAM
    try:
        iam = session.client("iam")
        users = iam.list_users()["Users"]
        roles = iam.list_roles()["Roles"]
        groups = iam.list_groups()["Groups"]
        policies = iam.list_policies(Scope="Local")["Policies"]

        global_resources["iam"] = {
            "users": len(users),
            "roles": len(roles),
            "groups": len(groups),
            "policies": len(policies),
            "user_details": [
                {"name": u["UserName"], "arn": u["Arn"], "created": str(u["CreateDate"])}
                for u in users
            ],
        }
    except Exception as e:
        logger.error(f"Error scanning IAM: {e}")
        global_resources["iam"] = {"error": str(e)}

    # Route 53
    try:
        route53 = session.client("route53")
        zones = route53.list_hosted_zones()["HostedZones"]
        global_resources["route53"] = {
            "hosted_zones": len(zones),
            "zone_details": [
                {"name": z["Name"], "id": z["Id"], "records": z["ResourceRecordSetCount"]}
                for z in zones
            ],
        }
    except Exception as e:
        logger.error(f"Error scanning Route53: {e}")
        global_resources["route53"] = {"error": str(e)}

    # CloudFront
    try:
        cf = session.client("cloudfront")
        distributions = cf.list_distributions()
        dist_list = distributions.get("DistributionList", {}).get("Items", []) or []
        global_resources["cloudfront"] = {
            "distributions": len(dist_list),
            "distribution_details": [
                {
                    "id": d["Id"],
                    "domain": d["DomainName"],
                    "status": d["Status"],
                    "enabled": d["Enabled"],
                }
                for d in dist_list
            ],
        }
    except Exception as e:
        logger.error(f"Error scanning CloudFront: {e}")
        global_resources["cloudfront"] = {"error": str(e)}

    # S3 (global listing, buckets have regions)
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        bucket_details = []
        for bucket in buckets:
            try:
                location = s3.get_bucket_location(Bucket=bucket["Name"])
                region = location.get("LocationConstraint") or "us-east-1"
            except Exception:
                region = "unknown"
            bucket_details.append({
                "name": bucket["Name"],
                "region": region,
                "created": str(bucket["CreationDate"]),
            })
        global_resources["s3"] = {
            "buckets": len(buckets),
            "bucket_details": bucket_details,
        }
    except Exception as e:
        logger.error(f"Error scanning S3: {e}")
        global_resources["s3"] = {"error": str(e)}

    return global_resources


def scan_region(session, region):
    """Scan all resources in a specific region."""
    resources = {}

    # EC2 Instances
    try:
        ec2 = session.client("ec2", region_name=region)
        reservations = ec2.describe_instances()["Reservations"]
        instances = []
        for res in reservations:
            for inst in res["Instances"]:
                instances.append({
                    "id": inst["InstanceId"],
                    "type": inst["InstanceType"],
                    "state": inst["State"]["Name"],
                    "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                    "public_ip": inst.get("PublicIpAddress"),
                    "private_ip": inst.get("PrivateIpAddress"),
                    "vpc_id": inst.get("VpcId"),
                    "subnet_id": inst.get("SubnetId"),
                    "launch_time": str(inst.get("LaunchTime")),
                })
        resources["ec2"] = {"instances": instances, "count": len(instances)}
    except Exception as e:
        logger.error(f"Error scanning EC2 in {region}: {e}")
        resources["ec2"] = {"error": str(e)}

    # VPCs
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
        resources["vpcs"] = {
            "count": len(vpcs),
            "details": [
                {
                    "id": v["VpcId"],
                    "cidr": v["CidrBlock"],
                    "is_default": v.get("IsDefault", False),
                    "tags": {t["Key"]: t["Value"] for t in v.get("Tags", [])},
                }
                for v in vpcs
            ],
        }
    except Exception as e:
        resources["vpcs"] = {"error": str(e)}

    # Security Groups
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        resources["security_groups"] = {
            "count": len(sgs),
            "details": [
                {
                    "id": sg["GroupId"],
                    "name": sg["GroupName"],
                    "vpc_id": sg.get("VpcId"),
                    "description": sg.get("Description"),
                    "tags": {t["Key"]: t["Value"] for t in sg.get("Tags", [])},
                }
                for sg in sgs
            ],
        }
    except Exception as e:
        resources["security_groups"] = {"error": str(e)}

    # EBS Volumes
    try:
        volumes = ec2.describe_volumes()["Volumes"]
        resources["ebs_volumes"] = {
            "count": len(volumes),
            "details": [
                {
                    "id": v["VolumeId"],
                    "size_gb": v["Size"],
                    "type": v["VolumeType"],
                    "state": v["State"],
                    "attached": len(v.get("Attachments", [])) > 0,
                    "encrypted": v.get("Encrypted", False),
                    "tags": {t["Key"]: t["Value"] for t in v.get("Tags", [])},
                }
                for v in volumes
            ],
        }
    except Exception as e:
        resources["ebs_volumes"] = {"error": str(e)}

    # Lambda Functions
    try:
        lam = session.client("lambda", region_name=region)
        functions = lam.list_functions()["Functions"]
        resources["lambda"] = {
            "count": len(functions),
            "details": [
                {
                    "name": f["FunctionName"],
                    "runtime": f.get("Runtime", "unknown"),
                    "memory": f["MemorySize"],
                    "timeout": f["Timeout"],
                    "last_modified": f.get("LastModified"),
                    "arn": f["FunctionArn"],
                }
                for f in functions
            ],
        }
    except Exception as e:
        resources["lambda"] = {"error": str(e)}

    # RDS
    try:
        rds = session.client("rds", region_name=region)
        db_instances = rds.describe_db_instances()["DBInstances"]
        resources["rds"] = {
            "count": len(db_instances),
            "details": [
                {
                    "id": db["DBInstanceIdentifier"],
                    "engine": db["Engine"],
                    "class": db["DBInstanceClass"],
                    "status": db["DBInstanceStatus"],
                    "multi_az": db.get("MultiAZ", False),
                    "public": db.get("PubliclyAccessible", False),
                    "encrypted": db.get("StorageEncrypted", False),
                }
                for db in db_instances
            ],
        }
    except Exception as e:
        resources["rds"] = {"error": str(e)}

    # DynamoDB
    try:
        dynamo = session.client("dynamodb", region_name=region)
        tables = dynamo.list_tables()["TableNames"]
        resources["dynamodb"] = {"count": len(tables), "tables": tables}
    except Exception as e:
        resources["dynamodb"] = {"error": str(e)}

    # Load Balancers
    try:
        elbv2 = session.client("elbv2", region_name=region)
        lbs = elbv2.describe_load_balancers()["LoadBalancers"]
        resources["load_balancers"] = {
            "count": len(lbs),
            "details": [
                {
                    "name": lb["LoadBalancerName"],
                    "arn": lb["LoadBalancerArn"],
                    "type": lb["Type"],
                    "scheme": lb["Scheme"],
                    "state": lb["State"]["Code"],
                    "dns": lb["DNSName"],
                    "vpc_id": lb.get("VpcId"),
                }
                for lb in lbs
            ],
        }
    except Exception as e:
        resources["load_balancers"] = {"error": str(e)}

    # Internet Gateways
    try:
        igws = ec2.describe_internet_gateways()["InternetGateways"]
        resources["internet_gateways"] = {
            "count": len(igws),
            "details": [
                {
                    "id": igw["InternetGatewayId"],
                    "attachments": [a["VpcId"] for a in igw.get("Attachments", [])],
                    "tags": {t["Key"]: t["Value"] for t in igw.get("Tags", [])},
                }
                for igw in igws
            ],
        }
    except Exception as e:
        resources["internet_gateways"] = {"error": str(e)}

    # NAT Gateways
    try:
        nats = ec2.describe_nat_gateways(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["NatGateways"]
        resources["nat_gateways"] = {
            "count": len(nats),
            "details": [
                {
                    "id": nat["NatGatewayId"],
                    "vpc_id": nat["VpcId"],
                    "subnet_id": nat["SubnetId"],
                    "state": nat["State"],
                }
                for nat in nats
            ],
        }
    except Exception as e:
        resources["nat_gateways"] = {"error": str(e)}

    # Elastic IPs
    try:
        eips = ec2.describe_addresses()["Addresses"]
        resources["elastic_ips"] = {
            "count": len(eips),
            "details": [
                {
                    "public_ip": eip["PublicIp"],
                    "allocation_id": eip.get("AllocationId"),
                    "associated": eip.get("AssociationId") is not None,
                    "instance_id": eip.get("InstanceId"),
                    "tags": {t["Key"]: t["Value"] for t in eip.get("Tags", [])},
                }
                for eip in eips
            ],
        }
    except Exception as e:
        resources["elastic_ips"] = {"error": str(e)}

    # ECS
    try:
        ecs = session.client("ecs", region_name=region)
        clusters = ecs.list_clusters()["clusterArns"]
        resources["ecs"] = {"clusters": len(clusters)}
    except Exception as e:
        resources["ecs"] = {"error": str(e)}

    # SNS Topics
    try:
        sns = session.client("sns", region_name=region)
        topics = sns.list_topics()["Topics"]
        resources["sns"] = {"topics": len(topics)}
    except Exception as e:
        resources["sns"] = {"error": str(e)}

    # SQS Queues
    try:
        sqs = session.client("sqs", region_name=region)
        queues = sqs.list_queues().get("QueueUrls", [])
        resources["sqs"] = {"queues": len(queues)}
    except Exception as e:
        resources["sqs"] = {"error": str(e)}

    # ACM Certificates
    try:
        acm = session.client("acm", region_name=region)
        certs = acm.list_certificates()["CertificateSummaryList"]
        resources["acm"] = {
            "count": len(certs),
            "details": [
                {
                    "domain": c["DomainName"],
                    "arn": c["CertificateArn"],
                    "status": c.get("Status"),
                }
                for c in certs
            ],
        }
    except Exception as e:
        resources["acm"] = {"error": str(e)}

    # API Gateway
    try:
        apigw = session.client("apigatewayv2", region_name=region)
        apis = apigw.get_apis()["Items"]
        resources["api_gateway"] = {
            "count": len(apis),
            "details": [
                {"name": api["Name"], "protocol": api["ProtocolType"], "id": api["ApiId"]}
                for api in apis
            ],
        }
    except Exception as e:
        resources["api_gateway"] = {"error": str(e)}

    return resources


def calculate_totals(inventory):
    """Calculate total resource counts across all regions."""
    totals = {}

    # Count from regional resources
    for region, resources in inventory["by_region"].items():
        for service, data in resources.items():
            if isinstance(data, dict) and "count" in data:
                totals[service] = totals.get(service, 0) + data["count"]
            elif isinstance(data, dict) and "instances" in data:
                totals[service] = totals.get(service, 0) + len(data["instances"])

    # Count from global services
    for service, data in inventory["global"].items():
        if isinstance(data, dict) and not data.get("error"):
            for key, value in data.items():
                if isinstance(value, int):
                    totals[f"{service}_{key}"] = value
                    break

    return totals
