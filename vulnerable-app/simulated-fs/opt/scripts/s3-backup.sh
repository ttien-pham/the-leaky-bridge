#!/bin/bash
# ============================================================
#  s3-backup.sh — Automated S3 Backup Script
#  Author : sysadmin@corp-internal.local
#  Created: 2024-07-01
#
#  WARNING: This script is INTENTIONALLY INSECURE (Lab Demo)
#  Real-world best practice: Use IAM Roles, not static keys.
# ============================================================

# ❌ BAD PRACTICE: Hardcoded credentials in script
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="ap-southeast-1"

BUCKET="corp-sensitive-docs-prod"
SOURCE_DIR="/var/www/html"
LOG_FILE="/var/log/s3-backup.log"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting S3 sync..." >> "$LOG_FILE"

aws s3 sync "$SOURCE_DIR" "s3://$BUCKET/backups/" \
    --exclude "*.php" \
    --exclude "*.env" \
    --quiet

if [ $? -eq 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sync completed successfully." >> "$LOG_FILE"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Sync failed. Check AWS credentials." >> "$LOG_FILE"
fi
