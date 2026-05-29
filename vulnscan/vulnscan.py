#!/usr/bin/env python3
"""
VulnScan - Beginner-Friendly Penetration Testing Framework
=============================================================
LEGAL NOTICE: Only use against systems you own or have explicit
written permission to test. Unauthorized testing is illegal.
=============================================================
"""

import sys
import os
import argparse
import json
from datetime import datetime
from utils.banner import print_banner
from utils.report import ReportGenerator
from utils.helpers import validate_target, color

# Module imports
from modules.xss import XSSScanner
from modules.sqli import SQLiScanner
from modules.ssrf import SSRFScanner
from modules.csrf import CSRFScanner
from modules.idor import IDORScanner
from modules.lfi import LFIScanner
from modules.open_redirect import OpenRedirectScanner
from modules.host_header import HostHeaderScanner
from modules.crlf import CRLFScanner
from modules.log4j import Log4jScanner
from modules.file_upload import FileUploadScanner
from modules.oauth import OAuthScanner
from modules.account_takeover import AccountTakeoverScanner
from modules.twofa_bypass import TwoFABypassScanner
from modules.info_disclosure import InfoDisclosureScanner
from modules.cache_poison import CachePoisonScanner
from modules.clickjacking import ClickjackingScanner
from modules.prototype_pollution import PrototypePollutionScanner
from modules.subdomain_takeover import SubdomainTakeoverScanner
from modules.github_exposure import GithubExposureScanner
from modules.email_spoofing import EmailSpoofingScanner
from modules.ddos import DDoSChecks
from modules.cloud_rce import CloudRCEScanner
from modules.api_exposure import APIExposureScanner
from modules.business_logic import BusinessLogicScanner

MODULES = {
    "xss":          ("XSS (Stored & Reflected)",           XSSScanner),
    "sqli":         ("SQL Injection",                       SQLiScanner),
    "ssrf":         ("SSRF",                                SSRFScanner),
    "csrf":         ("CSRF",                                CSRFScanner),
    "idor":         ("IDOR",                                IDORScanner),
    "lfi":          ("Local File Inclusion",                LFIScanner),
    "open_redirect":("Open Redirect",                       OpenRedirectScanner),
    "host_header":  ("Host Header Injection",               HostHeaderScanner),
    "crlf":         ("CRLF Injection",                      CRLFScanner),
    "log4j":        ("Log4j / Log4Shell",                   Log4jScanner),
    "file_upload":  ("File Upload Vulnerability",           FileUploadScanner),
    "oauth":        ("OAuth Exploitation",                  OAuthScanner),
    "account_takeover": ("Account Takeover",                AccountTakeoverScanner),
    "2fa_bypass":   ("2FA Bypass",                          TwoFABypassScanner),
    "info_disclosure": ("Information Disclosure",           InfoDisclosureScanner),
    "cache_poison": ("Cache Poisoning",                     CachePoisonScanner),
    "clickjacking": ("Clickjacking",                        ClickjackingScanner),
    "proto_pollution": ("Prototype Pollution",              PrototypePollutionScanner),
    "subdomain_takeover": ("Subdomain Takeover",            SubdomainTakeoverScanner),
    "github_exposure": ("GitHub Exposure",                  GithubExposureScanner),
    "email_spoofing": ("Email Spoofing",                    EmailSpoofingScanner),
    "ddos":         ("DDoS Surface Checks",                 DDoSChecks),
    "cloud_rce":    ("Cloud RCE (AWS/GCP/Azure/Oracle/Huawei)", CloudRCEScanner),
    "api_exposure": ("API Exposure",                        APIExposureScanner),
    "business_logic": ("Business Logic Vulnerabilities",   BusinessLogicScanner),
}

def list_modules():
    print(color("\n  Available Scan Modules:", "cyan"))
    print(color("  " + "─" * 55, "dim"))
    for i, (key, (name, _)) in enumerate(MODULES.items(), 1):
        print(f"  {color(str(i).rjust(2), 'yellow')}. {color(key.ljust(22), 'green')} {name}")
    print()

def run_scan(target, modules_to_run, args):
    report = ReportGenerator(target)
    results = []

    for key in modules_to_run:
        if key not in MODULES:
            print(color(f"  [!] Unknown module: {key}", "red"))
            continue

        name, ScannerClass = MODULES[key]
        print(color(f"\n  ┌─ [{key.upper()}] {name}", "cyan"))
        print(color(f"  │  Target: {target}", "dim"))
        print(color(f"  └─ Running...", "dim"))

        try:
            scanner = ScannerClass(target, args)
            result = scanner.run()
            results.append({"module": key, "name": name, "result": result})

            if result.get("vulnerable"):
                print(color(f"  ✗ VULNERABLE: {result.get('summary', '')}", "red"))
                for finding in result.get("findings", []):
                    print(color(f"    → {finding}", "yellow"))
            else:
                print(color(f"  ✓ No issues found: {result.get('summary', 'Clean')}", "green"))

        except Exception as e:
            print(color(f"  ✗ Module error: {e}", "red"))
            results.append({"module": key, "name": name, "result": {"error": str(e)}})

    report.generate(results)
    return results

def interactive_menu(args):
    print_banner()
    target = input(color("\n  Enter target URL or domain: ", "cyan")).strip()
    if not target:
        print(color("  [!] No target provided.", "red"))
        sys.exit(1)

    if not validate_target(target):
        print(color("  [!] Invalid target. Use http://... or domain.com", "red"))
        sys.exit(1)

    print(color("\n  Select scan mode:", "cyan"))
    print(f"  {color('1', 'yellow')}. Full scan (all {len(MODULES)} modules)")
    print(f"  {color('2', 'yellow')}. Choose specific modules")
    print(f"  {color('3', 'yellow')}. Category scan")
    print(f"  {color('4', 'yellow')}. List all modules")

    choice = input(color("\n  Choice [1-4]: ", "cyan")).strip()

    if choice == "1":
        modules_to_run = list(MODULES.keys())
    elif choice == "2":
        list_modules()
        selected = input(color("  Enter module keys (comma-separated): ", "cyan")).strip()
        modules_to_run = [m.strip() for m in selected.split(",")]
    elif choice == "3":
        print(color("\n  Categories:", "cyan"))
        print(f"  {color('a', 'yellow')}. Web Vulnerabilities")
        print(f"  {color('b', 'yellow')}. Authentication & Authorization")
        print(f"  {color('c', 'yellow')}. Cloud & Infrastructure")
        print(f"  {color('d', 'yellow')}. Reconnaissance")
        cat = input(color("\n  Category [a-d]: ", "cyan")).strip().lower()
        categories = {
            "a": ["xss", "sqli", "ssrf", "csrf", "idor", "lfi", "open_redirect",
                  "host_header", "crlf", "file_upload", "cache_poison",
                  "clickjacking", "proto_pollution", "business_logic"],
            "b": ["oauth", "account_takeover", "2fa_bypass", "api_exposure"],
            "c": ["log4j", "cloud_rce", "ddos"],
            "d": ["info_disclosure", "subdomain_takeover", "github_exposure",
                  "email_spoofing"],
        }
        modules_to_run = categories.get(cat, list(MODULES.keys()))
    elif choice == "4":
        list_modules()
        return interactive_menu(args)
    else:
        modules_to_run = list(MODULES.keys())

    print(color(f"\n  [*] Starting scan on {target} with {len(modules_to_run)} module(s)...", "cyan"))
    print(color(f"  [*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "dim"))
    run_scan(target, modules_to_run, args)

def main():
    parser = argparse.ArgumentParser(
        description="VulnScan - Beginner-Friendly Pentest Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", nargs="?", help="Target URL or domain")
    parser.add_argument("-m", "--modules", help="Comma-separated module keys to run")
    parser.add_argument("--list", action="store_true", help="List all available modules")
    parser.add_argument("--full", action="store_true", help="Run all modules")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout seconds (default: 10)")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookies", help="Cookies string for authenticated scans")
    parser.add_argument("--headers", help="Extra headers as JSON string")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.list:
        print_banner()
        list_modules()
        return

    if not args.target:
        interactive_menu(args)
        return

    print_banner()
    if not validate_target(args.target):
        print(color("  [!] Invalid target.", "red"))
        sys.exit(1)

    if args.modules:
        modules_to_run = [m.strip() for m in args.modules.split(",")]
    elif args.full:
        modules_to_run = list(MODULES.keys())
    else:
        modules_to_run = list(MODULES.keys())

    run_scan(args.target, modules_to_run, args)

if __name__ == "__main__":
    main()
