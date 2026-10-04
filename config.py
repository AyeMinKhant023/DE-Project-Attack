"""
Breach & Attack Simulation (BAS) Configuration Module
Course: 977-302 Digital Engineering Project II
Author: Aye Min Khant (6630613023)
Phase 4: Automated Breach & Attack Simulation Test Harness
"""

import os
import json
import subprocess
import boto3

# --- Target Metadata ---
STUDENT_NAME = "Aye Min Khant"
STUDENT_ID = "6630613023"
COURSE_CODE = "977-302 Digital Engineering Project II"
PROJECT_NAME = "Automated Cloud Security with Layered Perimeter Defense"
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

def discover_targets():
    """
    Dynamically discover live target endpoints:
    1. Check Environment Variables
    2. Check Terraform outputs in adjacent directory (../DE Project)
    3. Fallback to AWS SDK (boto3) API queries
    """
    alb_dns = os.getenv("TARGET_ALB_DNS")
    app_url = os.getenv("TARGET_APP_URL")
    db_endpoint = os.getenv("TARGET_DB_ENDPOINT")
    kms_arn = os.getenv("TARGET_KMS_ARN")

    # 1. Try Terraform Output if running alongside infrastructure repo
    if not (alb_dns and db_endpoint and kms_arn):
        tf_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'DE Project'))
        if os.path.exists(tf_dir):
            try:
                res = subprocess.run(
                    ['terraform', 'output', '-json'],
                    cwd=tf_dir,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if res.returncode == 0:
                    outputs = json.loads(res.stdout)
                    alb_dns = alb_dns or outputs.get('alb_dns_name', {}).get('value')
                    app_url = app_url or outputs.get('application_url', {}).get('value')
                    db_endpoint = db_endpoint or outputs.get('db_endpoint', {}).get('value')
                    kms_arn = kms_arn or outputs.get('rds_kms_key_arn', {}).get('value')
            except Exception:
                pass

    # 2. Try AWS SDK (Boto3) discovery if still missing
    if not alb_dns:
        try:
            elbv2 = boto3.client('elbv2', region_name=AWS_REGION)
            lbs = elbv2.describe_load_balancers()
            for lb in lbs.get('LoadBalancers', []):
                if 'de-project-alb' in lb.get('LoadBalancerName', ''):
                    alb_dns = lb.get('DNSName')
                    app_url = f"http://{alb_dns}"
                    break
        except Exception:
            pass

    if not db_endpoint:
        try:
            rds = boto3.client('rds', region_name=AWS_REGION)
            dbs = rds.describe_db_instances()
            for db in dbs.get('DBInstances', []):
                if 'de-project-mysql-db' in db.get('DBInstanceIdentifier', ''):
                    ep = db.get('Endpoint', {})
                    db_endpoint = f"{ep.get('Address')}:{ep.get('Port')}"
                    kms_arn = kms_arn or db.get('KmsKeyId')
                    break
        except Exception:
            pass

    return {
        "alb_dns_name": alb_dns,
        "application_url": app_url or (f"http://{alb_dns}" if alb_dns else None),
        "db_endpoint": db_endpoint,
        "rds_kms_key_arn": kms_arn,
        "aws_region": AWS_REGION
    }

TARGETS = discover_targets()
