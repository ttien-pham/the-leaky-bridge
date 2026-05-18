# terraform/main.tf
# ============================================================
#  The Leaky Bridge — Terraform IaC (Optional / Reference)
#  Defines the AWS resources in code for reproducibility.
# ============================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ───────────────────────────────────────────────
variable "aws_region"   { default = "ap-southeast-1" }
variable "bucket_name"  { default = "corp-sensitive-docs-prod-lab" }
variable "iam_username" { default = "svc-backup-agent" }

# ── S3 Bucket (Private) ─────────────────────────────────────
resource "aws_s3_bucket" "sensitive_data" {
  bucket        = var.bucket_name
  force_destroy = true

  tags = {
    Name        = "Corp Sensitive Docs"
    Environment = "Lab"
    Project     = "TheLeakyBridge"
  }
}

resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.sensitive_data.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Upload sensitive files to bucket
resource "aws_s3_object" "customer_data" {
  bucket = aws_s3_bucket.sensitive_data.id
  key    = "customer_data.csv"
  source = "${path.module}/../aws-setup/s3-bucket-contents/customer_data.csv"
  etag   = filemd5("${path.module}/../aws-setup/s3-bucket-contents/customer_data.csv")
}

resource "aws_s3_object" "financial_report" {
  bucket = aws_s3_bucket.sensitive_data.id
  key    = "financial_report_2024.csv"
  source = "${path.module}/../aws-setup/s3-bucket-contents/financial_report_2024.csv"
  etag   = filemd5("${path.module}/../aws-setup/s3-bucket-contents/financial_report_2024.csv")
}

# ── IAM User (Service Account — Overly Permissive) ──────────
resource "aws_iam_user" "svc_backup" {
  name = var.iam_username
  tags = { Project = "TheLeakyBridge" }
}

# ❌ MISCONFIGURATION: Resource = "*" violates Least Privilege
resource "aws_iam_user_policy" "svc_backup_s3" {
  name = "SvcBackupAgentS3Policy"
  user = aws_iam_user.svc_backup.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3ReadAll"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation"
        ]
        Resource = "*"   # ← TOO BROAD — Lab intentional misconfiguration
      }
    ]
  })
}

# Create Access Key (the "leaked" credential)
resource "aws_iam_access_key" "svc_backup_key" {
  user = aws_iam_user.svc_backup.name
}

# ── Outputs ─────────────────────────────────────────────────
output "s3_bucket_name" {
  value = aws_s3_bucket.sensitive_data.bucket
}

output "iam_user_name" {
  value = aws_iam_user.svc_backup.name
}

output "access_key_id" {
  value     = aws_iam_access_key.svc_backup_key.id
  sensitive = false
}

output "secret_access_key" {
  value     = aws_iam_access_key.svc_backup_key.secret
  sensitive = true
}
