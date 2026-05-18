"""
============================================================
  defense/iam_remediation.tf — Least Privilege IAM Fix
  Project: The Leaky Bridge – Hybrid Cloud Attack Vector
============================================================

PROBLEM:
  The original IAM policy granted s3:* on Resource: "*"
  This means the svc-backup-agent user could read ANY file
  in ANY bucket in the account — massive over-permission.

SOLUTION:
  Apply the Principle of Least Privilege:
    1. Restrict actions to ONLY what the service needs
    2. Restrict Resource to ONLY the specific bucket & path
    3. Replace static Access Keys with IAM Role for EC2

  This Terraform file shows the SECURE configuration.
============================================================
"""

# ── SECURE IAM Policy (Least Privilege) ──────────────────────────────────────

# ❌ BEFORE (Vulnerable — from main.tf):
vulnerable_policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListAllMyBuckets",  # Not needed — lists ALL buckets
            "s3:GetBucketLocation"  # Not needed for simple backup
        ],
        "Resource": "*"             # ← Grants access to EVERY bucket!
    }]
}

# ✅ AFTER (Secure — Least Privilege):
secure_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowListSpecificBucket",
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": "arn:aws:s3:::corp-sensitive-docs-prod-lab",
            "Condition": {
                # Only allow listing within the 'backups/' prefix
                "StringLike": {
                    "s3:prefix": ["backups/*"]
                }
            }
        },
        {
            "Sid": "AllowGetObjectInSpecificPath",
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            # Scoped to ONLY the backups/ folder of the specific bucket
            "Resource": "arn:aws:s3:::corp-sensitive-docs-prod-lab/backups/*"
        }
    ]
}

# ── Why this matters ─────────────────────────────────────────────────────────
impact_comparison = {
    "vulnerable": {
        "what_attacker_can_do": [
            "List ALL buckets in the AWS account",
            "Read ANY file in ANY bucket",
            "Access other teams' sensitive buckets",
            "Enumerate account structure"
        ],
        "blast_radius": "ENTIRE AWS ACCOUNT"
    },
    "secure": {
        "what_attacker_can_do": [
            "List files ONLY in corp-sensitive-docs-prod-lab/backups/",
            "Download files ONLY from corp-sensitive-docs-prod-lab/backups/"
        ],
        "what_attacker_CANNOT_do": [
            "List other buckets (s3:ListAllMyBuckets removed)",
            "Access customer_data.csv (not in backups/ path)",
            "Access financial_report_2024.csv (wrong bucket path)",
            "Access any other AWS service"
        ],
        "blast_radius": "Single folder in one bucket only"
    }
}
