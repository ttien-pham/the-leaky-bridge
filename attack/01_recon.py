#!/usr/bin/env python3
"""
============================================================
  attack/01_recon.py — Step 1: Reconnaissance
  Project: The Leaky Bridge – Hybrid Cloud Attack Vector
============================================================

PURPOSE:
  Simulates the attacker's initial reconnaissance phase.
  This script wraps Nmap to:
    1. Discover the target host
    2. Enumerate open ports and running services
    3. Detect OS fingerprint
    4. Output structured JSON results

USAGE:
  python 01_recon.py --target 192.168.56.101
  python 01_recon.py --target 192.168.56.0/24 --discover

REQUIRES:
  sudo apt install nmap python3-nmap
  pip install python-nmap

  *** FOR LAB / EDUCATIONAL USE ONLY ***
============================================================
"""

import nmap
import json
import argparse
import sys
from datetime import datetime

TARGET = "192.168.56.101"   # Replace with your VM's IP

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  STEP 1: RECONNAISSANCE                                  ║
║  The Leaky Bridge — Attack Simulation                    ║
╚══════════════════════════════════════════════════════════╝
"""


def run_port_scan(target: str) -> dict:
    """Full port scan with service and OS detection."""
    print(f"[*] Initializing Nmap scanner...")
    nm = nmap.PortScanner()

    print(f"[*] Running service scan on: {target}")
    print(f"    Command: nmap -sV -sC -O -T4 {target}\n")

    # -sV : Version detection
    # -sC : Default scripts (equivalent to --script=default)
    # -O  : OS detection
    # -T4 : Aggressive timing
    nm.scan(hosts=target, arguments='-sV -sC -O -T4')

    results = {}
    for host in nm.all_hosts():
        results[host] = {
            "state":    nm[host].state(),
            "hostname": nm[host].hostname(),
            "os":       nm[host].get('osmatch', [{}])[0].get('name', 'Unknown') if nm[host].get('osmatch') else 'Unknown',
            "ports":    {}
        }

        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]
                results[host]["ports"][port] = {
                    "protocol": proto,
                    "state":    service['state'],
                    "service":  service['name'],
                    "version":  f"{service['product']} {service['version']}".strip(),
                    "extra":    service.get('extrainfo', '')
                }

    return results


def print_results(results: dict):
    """Pretty-print scan results."""
    for host, data in results.items():
        print(f"\n{'═'*55}")
        print(f"  HOST: {host} ({data['hostname'] or 'no hostname'})")
        print(f"  STATUS: {data['state'].upper()}")
        print(f"  OS: {data['os']}")
        print(f"{'─'*55}")
        print(f"  {'PORT':<8} {'SERVICE':<15} {'VERSION':<25} STATE")
        print(f"{'─'*55}")

        for port, info in sorted(data['ports'].items()):
            state_color = "✓" if info['state'] == 'open' else "✗"
            print(f"  {state_color} {info['protocol'].upper()}/{port:<5} "
                  f"{info['service']:<15} {info['version']:<25} {info['state']}")

        print(f"\n  [!] INTERESTING FINDINGS:")
        for port, info in data['ports'].items():
            if info['state'] == 'open':
                if port == 80 or port == 8080:
                    print(f"      → Port {port} OPEN: HTTP web server detected!")
                    print(f"         Next step: Navigate to http://{host}:{port}")
                    print(f"         Try: gobuster dir -u http://{host}:{port} -w /usr/share/wordlists/dirb/common.txt")
                if port == 22:
                    print(f"      → Port 22 OPEN: SSH accessible")
                    print(f"         Try: ssh ubuntu@{host} (if creds found)")
                if port == 443:
                    print(f"      → Port 443 OPEN: HTTPS — check SSL cert for hostname clues")

    print(f"\n{'═'*55}")


def discover_hosts(network: str) -> list:
    """Ping sweep to find live hosts."""
    print(f"[*] Performing host discovery on: {network}")
    print(f"    Command: nmap -sn {network}\n")
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    live = [h for h in nm.all_hosts() if nm[h].state() == 'up']
    print(f"[+] Found {len(live)} live hosts:")
    for h in live:
        print(f"    → {h}")
    return live


if __name__ == "__main__":
    print(BANNER)

    parser = argparse.ArgumentParser(description="The Leaky Bridge — Step 1: Recon")
    parser.add_argument('--target',   default=TARGET, help='Target IP or range')
    parser.add_argument('--discover', action='store_true', help='Run host discovery first')
    parser.add_argument('--output',   help='Save results to JSON file')
    args = parser.parse_args()

    print(f"[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Target   : {args.target}\n")

    if args.discover:
        live_hosts = discover_hosts(args.target)
        if not live_hosts:
            print("[-] No live hosts found. Check your network settings.")
            sys.exit(1)
        target = live_hosts[0]
    else:
        target = args.target

    results = run_port_scan(target)
    print_results(results)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to: {args.output}")

    print("\n[*] NEXT STEP: Exploit the HTTP web application")
    print(f"    Navigate to http://{target}/ and probe for LFI vulnerabilities")
    print(f"    Proceed to: python 02_lfi_exploit.py --target {target}\n")
