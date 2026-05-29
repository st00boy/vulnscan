#!/usr/bin/env python3
"""
VulnScan - Terminal Report Viewer
===================================
Author : st00boy
GitHub : https://github.com/st00boy
---
Usage:
  python3 view_report.py                  # picks latest report automatically
  python3 view_report.py reports/scan.json
"""

import os
import sys
import json
from datetime import datetime

COLORS = {
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "blue":   "\033[94m",
    "dim":    "\033[2m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def c(text, col):
    return f"{COLORS.get(col,'')}{text}{COLORS['reset']}"

def pick_report():
    folder = "reports"
    if not os.path.exists(folder):
        print(c("  [!] No reports/ folder found. Run a scan first.", "red"))
        sys.exit(1)
    files = sorted(
        [f for f in os.listdir(folder) if f.endswith(".json")],
        reverse=True
    )
    if not files:
        print(c("  [!] No JSON reports found in reports/", "red"))
        sys.exit(1)
    if len(files) == 1:
        return os.path.join(folder, files[0])
    print(c("\n  Available Reports:\n", "cyan"))
    for i, f in enumerate(files, 1):
        print(f"  {c(str(i), 'yellow')}. {f}")
    choice = input(c("\n  Select report number: ", "cyan")).strip()
    try:
        return os.path.join(folder, files[int(choice) - 1])
    except Exception:
        return os.path.join(folder, files[0])

def render(path):
    with open(path) as f:
        data = json.load(f)

    results = data.get("results", [])
    vulns   = [r for r in results if r["result"].get("vulnerable")]
    errors  = [r for r in results if r["result"].get("error")]
    clean   = [r for r in results if not r["result"].get("vulnerable") and not r["result"].get("error")]

    print(c("\n  " + "═"*62, "dim"))
    print(c("  VULNSCAN REPORT VIEWER", "bold"))
    print(c("  " + "═"*62, "dim"))
    print(f"  {c('Target :', 'dim')}  {c(data.get('target','—'), 'cyan')}")
    print(f"  {c('Scanned:', 'dim')}  {data.get('scan_time','—')}")
    print(f"  {c('Modules:', 'dim')}  {len(results)}")
    print(c("  " + "─"*62, "dim"))
    print(f"  {c('VULNERABLE', 'red')}   {c(str(len(vulns)), 'red')}   "
          f"{c('CLEAN', 'green')}   {c(str(len(clean)), 'green')}   "
          f"{c('ERRORS', 'yellow')}   {c(str(len(errors)), 'yellow')}")
    print(c("  " + "═"*62, "dim"))

    if vulns:
        print(c("\n  ⚠  VULNERABILITIES FOUND\n", "red"))
        for r in vulns:
            print(f"  {c('✗', 'red')} {c(r['name'], 'bold')}"
                  f"  {c('['+r['module']+']', 'blue')}")
            print(f"    {c('→', 'dim')} {r['result'].get('summary','')}")
            for finding in r['result'].get('findings', []):
                print(f"    {c('•', 'yellow')} {c(finding, 'yellow')}")
            print()

    if clean:
        print(c("  ✓  CLEAN MODULES\n", "green"))
        for r in clean:
            print(f"  {c('✓', 'green')} {r['name'].ljust(36)}"
                  f"  {c(r['result'].get('summary',''), 'dim')}")
        print()

    if errors:
        print(c("\n  ! ERRORS\n", "yellow"))
        for r in errors:
            print(f"  {c('!', 'yellow')} {r['name']}  "
                  f"{c(r['result'].get('error',''), 'dim')}")
        print()

    print(c("  " + "═"*62, "dim"))
    print(f"  {c('Report:', 'dim')} {path}")
    print(c("  " + "═"*62 + "\n", "dim"))

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else pick_report()
    if not os.path.exists(path):
        print(c(f"  [!] File not found: {path}", "red"))
        sys.exit(1)
    render(path)
