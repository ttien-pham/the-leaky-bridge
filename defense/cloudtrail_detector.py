#!/usr/bin/env python3
"""
============================================================
  defense/cloudtrail_detector.py — Threat Detection
  Project: The Leaky Bridge – Hybrid Cloud Attack Vector
============================================================

PURPOSE:
  Query AWS CloudTrail logs to detect:
    1. Suspicious ListBuckets calls (attacker enumeration)
    2. Unexpected GetObject calls (data exfiltration)
    3. API calls from unusual IP addresses
    4. Calls made outside business hours (timezone-aware)
    5. Access from unrecognized regions

  This simulates a basic SIEM rule / threat detection script.

USAGE:
  # Query last 24 hours
  python cloudtrail_detector.py --hours 24

  # Query specific time range
  python cloudtrail_detector.py --start "2024-12-01" --end "2024-12-02"

  # Specify target user to monitor
  python cloudtrail_detector.py --user svc-backup-agent

REQUIRES:
  pip install boto3 pytz

  *** FOR EDUCATIONAL USE — Demonstrates defensive monitoring ***
============================================================
"""

import boto3
import json
import argparse
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import pytz

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  CLOUDTRAIL THREAT DETECTOR                             ║
║  The Leaky Bridge — Defense & Monitoring                ║
╚══════════════════════════════════════════════════════════╝
"""

# ── Detection Configuration ──────────────────────────────────
REGION         = "ap-southeast-1"
MONITORED_USER = "svc-backup-agent"
BUSINESS_TZ    = pytz.timezone("Asia/Ho_Chi_Minh")
BUSINESS_HOURS = (8, 18)          # 08:00 – 18:00 local time

# Thresholds
THRESHOLD_LIST_BUCKETS   = 1     # Any ListBuckets outside expected = alert
THRESHOLD_GET_OBJECTS    = 10    # >10 GetObject in 1 hour = suspicious
KNOWN_GOOD_IPS           = [     # Replace with your office/VPN CIDRs
    "203.0.113.10",   # Office NAT gateway
    "198.51.100.25",  # VPN endpoint
]

# ── Suspicious S3 event names ────────────────────────────────
ENUMERATION_EVENTS = {
    "ListBuckets",
    "ListObjects",
    "ListObjectsV2",
    "ListAllMyBuckets",
    "GetBucketAcl",
    "GetBucketPolicy",
    "GetBucketLocation",
}
EXFILTRATION_EVENTS = {
    "GetObject",
    "GetObjectAcl",
    "CopyObject",
    "RestoreObject",
}


def get_cloudtrail_events(session: boto3.Session, username: str,
                           hours: int = 24) -> list:
    """Fetch CloudTrail events for the specified user."""
    ct = session.client('cloudtrail', region_name=REGION)

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)

    print(f"[*] Querying CloudTrail: {start_time.strftime('%Y-%m-%d %H:%M')} UTC"
          f" → {end_time.strftime('%Y-%m-%d %H:%M')} UTC")
    print(f"[*] Filtering for user: {username}\n")

    events = []
    paginator = ct.get_paginator('lookup_events')

    for page in paginator.paginate(
        LookupAttributes=[{
            'AttributeKey': 'Username',
            'AttributeValue': username
        }],
        StartTime=start_time,
        EndTime=end_time
    ):
        events.extend(page.get('Events', []))

    return events


def analyze_events(events: list) -> dict:
    """
    Analyze events and generate threat detections.
    Returns a dict of findings, each with severity and evidence.
    """
    findings = []
    hourly_buckets = defaultdict(list)  # bucket events per hour

    for event in events:
        event_name = event.get('EventName', '')
        event_time = event.get('EventTime')
        source_ip  = event.get('SourceIPAddress', '')
        resources  = event.get('Resources', [])
        cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))

        # ── Parse timestamp ───────────────────────────────────
        if isinstance(event_time, str):
            event_time = datetime.fromisoformat(event_time)
        local_time = event_time.astimezone(BUSINESS_TZ)
        hour_bucket = event_time.strftime('%Y-%m-%d %H')

        # ── Detection Rule 1: ListBuckets Enumeration ─────────
        if event_name == "ListBuckets":
            findings.append({
                "rule":     "ENUM-001: S3 Bucket Enumeration",
                "severity": "HIGH",
                "event":    event_name,
                "time":     local_time.strftime('%Y-%m-%d %H:%M:%S %Z'),
                "source_ip": source_ip,
                "detail":   "svc-backup-agent should NEVER call ListBuckets — "
                            "it only needs access to one specific bucket. "
                            "This indicates credential theft and attacker enumeration."
            })

        # ── Detection Rule 2: After-hours Access ──────────────
        hour = local_time.hour
        if event_name in EXFILTRATION_EVENTS | ENUMERATION_EVENTS:
            if not (BUSINESS_HOURS[0] <= hour < BUSINESS_HOURS[1]):
                findings.append({
                    "rule":     "TEMPORAL-001: After-Hours S3 Access",
                    "severity": "MEDIUM",
                    "event":    event_name,
                    "time":     local_time.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    "source_ip": source_ip,
                    "detail":   f"API call at {local_time.strftime('%H:%M')} local time. "
                                f"Expected window: {BUSINESS_HOURS[0]}:00–{BUSINESS_HOURS[1]}:00. "
                                "Investigate immediately."
                })

        # ── Detection Rule 3: Unknown IP ──────────────────────
        if source_ip and source_ip not in KNOWN_GOOD_IPS:
            # Ignore AWS internal IPs (e.g., from EC2 without public IP)
            if not source_ip.startswith("10.") and \
               not source_ip.startswith("172.") and \
               not source_ip.startswith("192.168."):
                findings.append({
                    "rule":     "GEO-001: Unrecognized Source IP",
                    "severity": "HIGH",
                    "event":    event_name,
                    "time":     local_time.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    "source_ip": source_ip,
                    "detail":   f"API call from IP {source_ip} which is not in the "
                                "known-good list. Could be attacker's machine. "
                                "Cross-reference with IP geolocation."
                })

        # Track hourly volumes for rate analysis
        if event_name in EXFILTRATION_EVENTS:
            hourly_buckets[hour_bucket].append(event_name)

    # ── Detection Rule 4: High-Volume GetObject (Exfil) ───────
    for hour, evts in hourly_buckets.items():
        if len(evts) >= THRESHOLD_GET_OBJECTS:
            findings.append({
                "rule":     "EXFIL-001: High-Volume S3 Data Exfiltration",
                "severity": "CRITICAL",
                "event":    f"GetObject x{len(evts)}",
                "time":     hour,
                "source_ip": "Various",
                "detail":   f"{len(evts)} GetObject calls in 1 hour (threshold: "
                            f"{THRESHOLD_GET_OBJECTS}). Possible mass data download. "
                            "Check which files were accessed in this window."
            })

    return {
        "total_events": len(events),
        "findings":     findings,
        "summary":      {
            "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "HIGH":     sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
        }
    }


def print_report(analysis: dict):
    """Print the threat detection report."""
    findings = analysis["findings"]
    summary  = analysis["summary"]

    severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    print(f"\n{'═'*60}")
    print(f"  CLOUDTRAIL THREAT DETECTION REPORT")
    print(f"{'═'*60}")
    print(f"  Total API Events Analyzed : {analysis['total_events']}")
    print(f"  Findings:")
    print(f"    🔴 CRITICAL : {summary['CRITICAL']}")
    print(f"    🟠 HIGH     : {summary['HIGH']}")
    print(f"    🟡 MEDIUM   : {summary['MEDIUM']}")
    print(f"{'─'*60}\n")

    if not findings:
        print("  ✅ No suspicious activity detected in this time window.\n")
        return

    for i, finding in enumerate(findings, 1):
        icon = severity_icon.get(finding["severity"], "⚪")
        print(f"  [{i}] {icon} {finding['severity']} — {finding['rule']}")
        print(f"       Event   : {finding['event']}")
        print(f"       Time    : {finding['time']}")
        print(f"       From IP : {finding['source_ip']}")
        print(f"       Detail  : {finding['detail']}")
        print()

    print(f"{'═'*60}")
    print(f"  ⚠  RECOMMENDED ACTIONS:")
    print(f"  1. Immediately revoke Access Key: aws iam delete-access-key ...")
    print(f"  2. Rotate all credentials in the affected account")
    print(f"  3. Check CloudTrail for full scope of data accessed")
    print(f"  4. Notify Data Protection Officer (GDPR/PDPA compliance)")
    print(f"  5. Investigate the web server for the LFI vulnerability")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    print(BANNER)
    parser = argparse.ArgumentParser(description="CloudTrail Threat Detector")
    parser.add_argument('--user',   default=MONITORED_USER, help='IAM username to monitor')
    parser.add_argument('--hours',  default=24, type=int,   help='Look-back window in hours')
    parser.add_argument('--region', default=REGION,         help='AWS region for CloudTrail')
    parser.add_argument('--output', help='Save JSON report to file')
    args = parser.parse_args()

    session  = boto3.Session(region_name=args.region)
    events   = get_cloudtrail_events(session, args.user, args.hours)
    analysis = analyze_events(events)
    print_report(analysis)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        print(f"[+] Report saved to: {args.output}")
