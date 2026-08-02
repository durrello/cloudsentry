"""
Scoring Weights Configuration.
Maps findings to CIS Benchmark references and severity weights.
"""

# CIS AWS Foundations Benchmark v1.5 mapping
CIS_MAPPING = {
    "root_mfa": {"ref": "CIS 1.5", "weight": 10, "description": "Ensure MFA is enabled for the root account"},
    "root_access_keys": {"ref": "CIS 1.4", "weight": 10, "description": "Ensure no root access key exists"},
    "user_mfa": {"ref": "CIS 1.10", "weight": 5, "description": "Ensure MFA is enabled for all IAM users with console access"},
    "access_key_age": {"ref": "CIS 1.14", "weight": 5, "description": "Ensure access keys are rotated every 90 days"},
    "password_policy": {"ref": "CIS 1.8", "weight": 3, "description": "Ensure IAM password policy requires minimum length >= 14"},
    "s3_public": {"ref": "CIS 2.1.1", "weight": 8, "description": "Ensure S3 buckets have public access blocked"},
    "s3_encryption": {"ref": "CIS 2.1.2", "weight": 3, "description": "Ensure S3 bucket has server-side encryption enabled"},
    "cloudtrail_enabled": {"ref": "CIS 3.1", "weight": 8, "description": "Ensure CloudTrail is enabled in all regions"},
    "cloudtrail_validation": {"ref": "CIS 3.2", "weight": 3, "description": "Ensure CloudTrail log file validation is enabled"},
    "vpc_flow_logs": {"ref": "CIS 3.9", "weight": 3, "description": "Ensure VPC flow logging is enabled in all VPCs"},
    "sg_ssh_open": {"ref": "CIS 5.2", "weight": 7, "description": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"},
    "sg_rdp_open": {"ref": "CIS 5.3", "weight": 7, "description": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"},
    "rds_public": {"ref": "CIS 4.1", "weight": 8, "description": "Ensure RDS instances are not publicly accessible"},
    "rds_encryption": {"ref": "CIS 4.2", "weight": 5, "description": "Ensure RDS instances have encryption at rest enabled"},
}

# Severity to point deduction mapping
SEVERITY_POINTS = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
}

# Maximum score deduction from any single category
MAX_CATEGORY_DEDUCTION = 30

# Categories and their relative importance
CATEGORY_WEIGHTS = {
    "iam": 1.5,          # IAM issues are most impactful
    "networking": 1.3,   # Network exposure is high risk
    "encryption": 1.0,   # Encryption at rest
    "logging": 1.0,      # Audit trail
    "storage": 1.0,      # Data exposure
    "compute": 0.8,      # Instance-level issues
    "database": 1.2,     # Data tier is critical
    "dns": 0.8,          # DNS issues
    "tag": 0.5,          # Tags are hygiene, not security
    "naming": 0.3,       # Naming is low impact
    "lifecycle": 0.5,    # Lifecycle is cost, not security
    "cost": 0.5,         # Cost is financial, not security
    "architecture": 0.7, # Architecture choices
    "access": 1.2,       # Access patterns
}
