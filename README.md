# 🎯 Automated Breach & Attack Simulation (BAS) Test Harness

**Course:** 977-302 Digital Engineering Project II  
**Author:** Aye Min Khant (Student ID: 6630613023)  
**Project:** Automated Cloud Security with Layered Perimeter Defense (Phase 4)  
**Academic Institution:** Prince of Songkla University  

---

## 📌 Executive Summary & Methodology

This repository houses the automated **Breach and Attack Simulation (BAS)** test harness designed to perform controlled, programmatic adversary emulations directly against the live AWS multi-tier cloud infrastructure.

In compliance with AWS Acceptable Use and cloud security engineering standards, this test harness does not perform unconstrained denial-of-service or destructive exploitation. Instead, it systematically executes benign, reproducible attack techniques that validate the defensive posture of **Phase 1 (VPC & Compute Isolation)**, **Phase 2 (WAF v2 Edge Perimeter)**, and **Phase 3 (AWS KMS Cryptographic Data Governance)**.

```
[ External Internet / Local Machine ]  <─── Programmatic Adversary (BAS Runner)
                  │
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ AWS Cloud Multi-Tier Architecture (us-east-1)                          │
│                                                                        │
│   [ Tier 1: Public Ingress Tier ]                                      │
│   • Vector 1: Layer 4 Non-HTTP Port Probes (22, 5000, 3306) -> DROPPED │
│   • Vector 3: Layer 7 OWASP SQLi Injection Payload          -> 403 / DROP│
│   • Vector 4: Layer 7 Volumetric Rate Limiting (100 req/5m) -> ACTIVE  │
│                                                                        │
│   [ Tier 2: Private Application Tier ]                                 │
│   • Auto Scaling Group (EC2 Nodes) Hidden in Isolated Subnets          │
│                                                                        │
│   [ Tier 3: Isolated Persistence Tier ]                                │
│   • Vector 2: Direct Internet-to-RDS TCP Probe              -> BLOCKED │
│   • Vector 5: KMS CMK 365-Day Rotation & Storage Encryption -> AUDITED │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Target Test Vectors

| Vector ID | Test Vector Description | Simulated Adversary Technique | Expected Defensive Outcome |
| :--- | :--- | :--- | :--- |
| **Vector 1** | **Layer 4 Perimeter Boundary** | Raw TCP socket scan on management & backend ports (`22`, `5000`, `3306`) at ALB | **Connection Dropped (Timeout)** via Security Group filtering |
| **Vector 2** | **Tier 3 Persistence Air-Gap** | Direct TCP connection from public internet to Amazon RDS endpoint on port `3306` | **Network Unreachable** (Zero internet route to private DB subnets) |
| **Vector 3** | **Layer 7 OWASP SQLi Defense** | Programmatic HTTP request dispatching SQL injection payload (`/?id=1' OR '1'='1`) | **HTTP 403 Forbidden** or edge packet drop via AWS WAF v2 |
| **Vector 4** | **Layer 7 Volumetric Rate Limit** | Rapid baseline HTTP request probes verifying rate-based WebACL rule enforcement | **Active Rule Verified** (100 requests per 5-minute sliding window) |
| **Vector 5** | **Cryptographic Governance Audit** | Programmatic AWS Boto3 SDK query verifying KMS CMK rotation & RDS storage encryption | **Compliance Verified** (KMS Rotation = True, RDS AES-256 = True) |

---

## 🚀 Installation & Execution

### 1. Environment Setup
```bash
# Clone the repository
git clone https://github.com/AyeMinKhant023/DE-Project-Attack.git
cd DE-Project-Attack

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 2. Execute 1-Click Simulation (Generates Table 4-2)
```bash
python3 run_simulation.py
```
This runs the full simulation against live infrastructure, prints a formatted ASCII matrix, and automatically exports **`table_4_2_results.md`** for your report.

### 3. Run with Pytest (Standard Test Framework)
```bash
pytest test_bas_harness.py -v -s
```

---

## 📊 Sample Empirical Output (Table 4-2)

```text
===================================================================================================================
  TABLE 4-2: EMPIRICAL BREACH & ATTACK SIMULATION (BAS) VALIDATION MATRIX
  Course: 977-302 Digital Engineering Project II | Aye Min Khant (6630613023)
===================================================================================================================
+--------------+--------------------------------------+--------------------+-------------------------------+-----------------------------------+-----------+--------------------+
| Vector ID    | Adversary Simulation Test Vector     | Target Endpoint    | Expected Policy Behavior      | Empirical Result (Observed)       | Latency   | Defensive Status   |
+==============+======================================+====================+===============================+===================================+===========+====================+
| V1.Port-22   | Layer 4 Boundary Probe (SSH (Mgmt))  | alb-dns:22         | Connection Dropped / Timeout  | DROPPED (TimeoutError)            | 3031.6 ms | PASSED             |
| V1.Port-5000 | Layer 4 Boundary Probe (Flask (App)) | alb-dns:5000       | Connection Dropped / Timeout  | DROPPED (TimeoutError)            | 3002.4 ms | PASSED             |
| V1.Port-3306 | Layer 4 Boundary Probe (MySQL (DB))  | alb-dns:3306       | Connection Dropped / Timeout  | DROPPED (TimeoutError)            | 3002.2 ms | PASSED             |
| V2.AirGap    | Tier 3 Persistence Air-Gap Probe     | rds-endpoint:3306  | Network Unreachable / Timeout | UNREACHABLE (OSError)             | 116.1 ms  | PASSED             |
| V3.SQLi      | Layer 7 OWASP SQLi Mitigation        | GET /?id=1' OR 1=1 | HTTP 403 Forbidden / Drop     | DROPPED (Perimeter Interception)  | 5045.3 ms | PASSED             |
| V4.RateLimit | Layer 7 Volumetric Rate Limit        | Ingress Fleet      | Rate Limit Active (100 req/5m)| Rule Active (100 req/5m, 5/5 OK)  | 4468.9 ms | PASSED             |
| V5.CryptoGov | KMS & RDS Cryptographic Governance   | CMK 359e3852...    | Rotation=True, Encrypted=True | KMS Rotation: True | RDS: AES-256 | 3042.1 ms | PASSED             |
+--------------+--------------------------------------+--------------------+-------------------------------+-----------------------------------+-----------+--------------------+
```

---

## 📁 Repository Structure

```text
DE-Project-Attack/
├── config.py                 # Dynamic target resolution (Terraform, Boto3, or Environment)
├── test_bas_harness.py       # Pytest-native test suite covering all 5 vectors
├── run_simulation.py         # Standalone runner generating Table 4-2 markdown report
├── requirements.txt          # pytest, requests, boto3, tabulate
├── table_4_2_results.md      # Auto-generated empirical results table for midterm report
└── .gitignore                # Excludes virtualenv, caches, and local configurations
```
