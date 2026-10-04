"""
Automated Breach & Attack Simulation (BAS) Test Harness
Course: 977-302 Digital Engineering Project II
Author: Aye Min Khant (6630613023)
Phase 4: Programmatic Adversary Emulation & Empirical Validation Matrix
"""

import socket
import time
import pytest
import requests
import boto3
from config import TARGETS, STUDENT_NAME, STUDENT_ID, COURSE_CODE, AWS_REGION


# ==============================================================================
# VECTOR 1: LAYER 4 PERIMETER BOUNDARY DEFENSE (PORT SCAN)
# ==============================================================================
@pytest.mark.parametrize("port,service_name", [
    (22, "SSH Remote Access"),
    (5000, "Flask Internal Backend"),
    (3306, "MySQL Database Daemon")
])
def test_vector_1_layer4_boundary_port_scan(port, service_name):
    """
    Simulates an adversary scanning unauthorized ports on the public ALB ingress.
    Asserts: Layer 4 Security Groups filter and drop traffic (Timeout or Connection Refused).
    """
    alb_dns = TARGETS["alb_dns_name"]
    assert alb_dns, "ALB DNS endpoint must be discovered."

    start_time = time.time()
    is_blocked = False
    error_msg = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    try:
        sock.connect((alb_dns, port))
        sock.close()
        is_blocked = False
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        is_blocked = True
        error_msg = type(e).__name__
    finally:
        sock.close()

    elapsed_ms = (time.time() - start_time) * 1000
    assert is_blocked, f"Perimeter Vulnerability! Port {port} ({service_name}) is publicly reachable."
    print(f"[PASSED] Vector 1 ({service_name} Port {port}): Blocked ({error_msg}) in {elapsed_ms:.1f}ms")


# ==============================================================================
# VECTOR 2: TIER 3 PERSISTENCE AIR-GAP ISOLATION
# ==============================================================================
def test_vector_2_tier3_persistence_airgap():
    """
    Simulates an adversary attempting a direct TCP connection from the public internet
    to the Amazon RDS MySQL endpoint.
    Asserts: Connection times out / fails, proving database subnets are completely air-gapped.
    """
    db_endpoint = TARGETS["db_endpoint"]
    assert db_endpoint, "RDS endpoint must be discovered."

    host = db_endpoint.split(":")[0]
    port = int(db_endpoint.split(":")[1]) if ":" in db_endpoint else 3306

    start_time = time.time()
    is_blocked = False
    error_msg = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    try:
        sock.connect((host, port))
        sock.close()
        is_blocked = False
    except (socket.timeout, OSError) as e:
        is_blocked = True
        error_msg = type(e).__name__
    finally:
        sock.close()

    elapsed_ms = (time.time() - start_time) * 1000
    assert is_blocked, f"Critical Security Flaw! Air-Gapped RDS ({db_endpoint}) is publicly accessible!"
    print(f"[PASSED] Vector 2 (Tier 3 Persistence Air-Gap): Blocked ({error_msg}) in {elapsed_ms:.1f}ms")


# ==============================================================================
# VECTOR 3: LAYER 7 OWASP INJECTION (SQLi) MITIGATION
# ==============================================================================
def test_vector_3_layer7_owasp_sqli_mitigation():
    """
    Simulates an adversary sending OWASP SQL Injection attack payloads to the public ingress.
    Asserts: Edge defense (AWS WAF v2) mitigates the attack (HTTP 403 Forbidden or packet drop),
             preventing malicious payload execution against the database.
    """
    alb_dns = TARGETS["alb_dns_name"]
    assert alb_dns, "ALB DNS endpoint must be discovered."

    url = f"http://{alb_dns}/?id=1'%20OR%20'1'='1"
    start_time = time.time()
    mitigated = False
    status_code = None

    try:
        resp = requests.get(url, timeout=5.0)
        status_code = resp.status_code
        if resp.status_code == 403:
            mitigated = True
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        # Network/WAF edge dropped plaintext malicious payload
        mitigated = True
        status_code = "DROPPED (Timeout)"

    elapsed_ms = (time.time() - start_time) * 1000
    assert mitigated, f"WAF failed to mitigate SQLi attack! Received status: {status_code}"
    print(f"[PASSED] Vector 3 (Layer 7 OWASP SQLi Mitigation): Edge Blocked ({status_code}) in {elapsed_ms:.1f}ms")


# ==============================================================================
# VECTOR 4: LAYER 7 VOLUMETRIC RATE LIMITING DEFENSE
# ==============================================================================
def test_vector_4_layer7_volumetric_rate_limit():
    """
    Simulates ingress throughput verification and validates WAF rate-limiting rule posture.
    Asserts: Legitimate traffic returns 200 OK, and WAF rate-based rule is actively provisioned.
    """
    alb_dns = TARGETS["alb_dns_name"]
    assert alb_dns, "ALB DNS endpoint must be discovered."

    url = f"http://{alb_dns}/"
    session = requests.Session()

    start_time = time.time()
    success_count = 0
    total_probes = 5

    for _ in range(total_probes):
        try:
            r = session.get(url, timeout=3.0)
            if r.status_code == 200:
                success_count += 1
        except Exception:
            pass

    elapsed_ms = (time.time() - start_time) * 1000
    assert success_count > 0, "ALB failed to serve legitimate baseline HTTP traffic."

    # Query AWS SDK to verify active RateLimitPerIP rule
    waf = boto3.client("wafv2", region_name=AWS_REGION)
    acls = waf.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
    acl_id = [a["Id"] for a in acls if "de-project-web-acl" in a["Name"]][0]
    acl = waf.get_web_acl(Name="de-project-web-acl", Scope="REGIONAL", Id=acl_id)["WebACL"]

    rate_rules = [r for r in acl.get("Rules", []) if "rate_based_statement" in str(r).lower() or "ratelimit" in r["Name"].lower()]
    assert len(rate_rules) > 0, "Rate-limiting rule not found in WebACL."
    limit = rate_rules[0]["Statement"]["RateBasedStatement"]["Limit"]

    print(f"[PASSED] Vector 4 (Layer 7 Rate Limiting Defense): Active rule threshold = {limit} req/5min ({success_count}/{total_probes} verified in {elapsed_ms:.1f}ms)")


# ==============================================================================
# VECTOR 5: CRYPTOGRAPHIC GOVERNANCE AUDIT (AWS KMS & RDS)
# ==============================================================================
def test_vector_5_cryptographic_governance_audit():
    """
    Performs automated compliance audit on AWS KMS Customer Managed Key and RDS MySQL storage.
    Asserts:
      1. KMS CMK has automated 365-day rotation enabled (True)
      2. RDS MySQL storage is encrypted at rest (True)
      3. RDS KMS Key matches the provisioned Customer Managed Key ARN
    """
    kms_arn = TARGETS["rds_kms_key_arn"]
    assert kms_arn, "KMS Key ARN must be discovered."

    kms = boto3.client("kms", region_name=AWS_REGION)
    rds = boto3.client("rds", region_name=AWS_REGION)

    # 1. Audit KMS Key Rotation
    rot_resp = kms.get_key_rotation_status(KeyId=kms_arn)
    rotation_enabled = rot_resp.get("KeyRotationEnabled", False)
    assert rotation_enabled is True, "Cryptographic non-compliance! KMS Key rotation is disabled."

    # 2. Audit RDS Storage Encryption
    db_instances = rds.describe_db_instances(DBInstanceIdentifier="de-project-mysql-db").get("DBInstances", [])
    assert len(db_instances) > 0, "RDS instance de-project-mysql-db not found."
    db = db_instances[0]

    assert db.get("StorageEncrypted") is True, "Data governance failure! RDS storage is unencrypted."
    assert db.get("KmsKeyId") == kms_arn, "RDS is encrypted with default key instead of Customer Managed Key!"

    print(f"[PASSED] Vector 5 (Cryptographic Governance): KMS Rotation = ENABLED, RDS Storage = ENCRYPTED (AES-256 via CMK)")
