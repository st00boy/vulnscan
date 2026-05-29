<div align="center">

```
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**Beginner-Friendly Penetration Testing Framework**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Modules](https://img.shields.io/badge/Modules-26%2B-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Author](https://img.shields.io/badge/Author-st00boy-red?style=for-the-badge)

> A modular, CLI-based web vulnerability scanner covering 26+ vulnerability classes.  
> Built for beginners — every module includes plain-English explanations of what the vulnerability is, why it's dangerous, and how to fix it.

</div>

---

## ⚠️ Legal Disclaimer

> **This tool is for educational purposes and authorized security testing ONLY.**  
> Never run VulnScan against systems you do not own or do not have **explicit written permission** to test.  
> Unauthorized use is illegal and unethical. The author is not responsible for any misuse.

---

## 📋 Table of Contents

- [Features](#-features)
- [Vulnerability Modules](#-vulnerability-modules)
- [Installation](#-installation)
- [Usage](#-usage)
- [Live Dashboard](#-live-dashboard)
- [Output & Reports](#-output--reports)
- [Project Structure](#-project-structure)
- [Adding a Custom Module](#-adding-a-custom-module)
- [Learning Resources](#-learning-resources)
- [Author](#-author)

---

## ✨ Features

- 🔍 **26+ vulnerability modules** covering all major web attack classes
- 🧠 **Beginner-friendly** — every module explains the vulnerability in plain English
- 🖥️ **Interactive CLI menu** — no flags needed to get started
- 📄 **Auto-generates reports** in both JSON and HTML formats
- 🌐 **Live web dashboard** — drag & drop JSON reports into a visual browser UI
- 📊 **Terminal report viewer** — pretty-print scan results directly in the terminal
- ⚙️ **Auto setup script** — one command installs everything automatically
- 🔌 **Modular design** — easily add your own custom modules
- 🛡️ **Proxy support** — route traffic through Burp Suite or any HTTP proxy
- 🍪 **Cookie/Header support** — test authenticated sessions
- ⚡ **Multithreaded** — configurable thread count for faster scans

---

## 🛡️ Vulnerability Modules

| # | Module | Vulnerability |
|---|--------|---------------|
| 1 | `xss` | XSS — Stored & Reflected |
| 2 | `sqli` | SQL Injection (Error-based & Boolean) |
| 3 | `ssrf` | Server-Side Request Forgery |
| 4 | `csrf` | Cross-Site Request Forgery |
| 5 | `idor` | Insecure Direct Object Reference |
| 6 | `lfi` | Local File Inclusion |
| 7 | `open_redirect` | Open Redirect |
| 8 | `host_header` | Host Header Injection |
| 9 | `crlf` | CRLF Injection |
| 10 | `log4j` | Log4Shell / Log4j (CVE-2021-44228) |
| 11 | `file_upload` | File Upload Vulnerability |
| 12 | `oauth` | OAuth Exploitation |
| 13 | `account_takeover` | Account Takeover |
| 14 | `2fa_bypass` | 2FA Bypass |
| 15 | `info_disclosure` | Information Disclosure |
| 16 | `cache_poison` | Cache Poisoning |
| 17 | `clickjacking` | Clickjacking |
| 18 | `proto_pollution` | Prototype Pollution |
| 19 | `subdomain_takeover` | Subdomain Takeover |
| 20 | `github_exposure` | GitHub / Source Code Exposure |
| 21 | `email_spoofing` | Email Spoofing (SPF/DKIM/DMARC) |
| 22 | `ddos` | DDoS Surface Checks |
| 23 | `cloud_rce` | Cloud RCE — AWS, GCP, Azure, Oracle, Huawei |
| 24 | `api_exposure` | API Exposure |
| 25 | `business_logic` | Business Logic Vulnerabilities |

---

## 📦 Installation

**Requirements:** Python 3.8+

```bash
# 1. Clone the repository
git clone https://github.com/st00boy/vulnscan.git
cd vulnscan

# 2. Run the auto setup script (installs everything automatically)
bash setup.sh
```

Or manually:

```bash
pip install -r requirements.txt
chmod +x vulnscan.py
```

---

## 🚀 Usage

### Interactive Mode (Recommended for Beginners)
```bash
python3 vulnscan.py
```
You'll be prompted to enter a target and choose a scan mode from a menu.

---

### Command-Line Mode

```bash
# Full scan — all 26 modules
python3 vulnscan.py http://target.com --full

# Scan with specific modules only
python3 vulnscan.py http://target.com -m xss,sqli,ssrf

# Verbose output
python3 vulnscan.py http://target.com --full -v

# Use a proxy (e.g. Burp Suite)
python3 vulnscan.py http://target.com --proxy http://127.0.0.1:8080

# Authenticated scan with cookies
python3 vulnscan.py http://target.com --cookies "session=abc123; token=xyz"

# Custom timeout and threads
python3 vulnscan.py http://target.com --timeout 15 --threads 10

# List all available modules
python3 vulnscan.py --list
```

---

### View Reports in Terminal

After a scan, use the report viewer to pretty-print results directly in the terminal:

```bash
# Auto-picks the latest report
python3 view_report.py

# Or load a specific report
python3 view_report.py reports/vulnscan_20250527_120000.json
```

---

### Category Scans

When using the interactive menu, you can choose to scan by category:

| Category | Modules Included |
|----------|-----------------|
| **Web Vulnerabilities** | XSS, SQLi, SSRF, CSRF, IDOR, LFI, Open Redirect, Host Header, CRLF, File Upload, Cache Poison, Clickjacking, Prototype Pollution, Business Logic |
| **Authentication & Authorization** | OAuth, Account Takeover, 2FA Bypass, API Exposure |
| **Cloud & Infrastructure** | Log4j, Cloud RCE, DDoS |
| **Reconnaissance** | Info Disclosure, Subdomain Takeover, GitHub Exposure, Email Spoofing |

---

## 🌐 Live Dashboard

VulnScan includes a browser-based live dashboard (`dashboard.html`) to visualize your scan reports.

**Open locally — just double-click `dashboard.html`**, or run:

```bash
# Linux
xdg-open dashboard.html

# macOS
open dashboard.html

# Windows
start dashboard.html
```

**Load your scan results:**
1. Run a scan — a JSON file is saved in `reports/`
2. Open `dashboard.html` in your browser
3. Click **Load Report** and select the JSON file
4. Results appear instantly with color-coded status, findings, and stats

**Host it online for free via GitHub Pages:**
1. Push your repo to GitHub
2. Go to **Settings → Pages → Source → main branch → Save**
3. Dashboard live at: `https://st00boy.github.io/vulnscan/dashboard.html`

**Dashboard features:**
- 🔴🟢🟡 Color-coded vulnerability status per module
- 📊 Result distribution bar (Vulnerable / Clean / Errors)
- 🔍 Filter by status + search by module name
- 📋 Full findings list per vulnerability
- 🖥️ Loads demo data on first open so you can preview it instantly

---

## 📊 Output & Reports

After every scan, VulnScan automatically saves two report files to the `reports/` folder:

```
reports/
├── vulnscan_20250527_120000.json   ← Machine-readable results
└── vulnscan_20250527_120000.html   ← Visual HTML report
```

The HTML report includes a color-coded summary dashboard:

- 🔴 **VULNERABLE** — issue confirmed
- 🟢 **CLEAN** — no issues found
- 🟡 **ERROR** — module could not connect or crashed

---

## 📁 Project Structure

```
vulnscan/
│
├── vulnscan.py              ← Main entry point
├── requirements.txt
│
├── modules/                 ← One file per vulnerability
│   ├── base.py              ← BaseScanner (all modules inherit this)
│   ├── xss.py
│   ├── sqli.py
│   ├── ssrf.py
│   └── ... (26 total)
│
├── utils/
│   ├── banner.py            ← ASCII banner + color output
│   ├── helpers.py           ← HTTP session, URL utils
│   └── report.py            ← JSON + HTML report generator
│
├── wordlists/               ← Add custom payloads here
└── reports/                 ← Scan output saved here (auto-created)
```

---

## 🔧 Adding a Custom Module

1. Create a new file in `modules/`, e.g. `modules/my_check.py`
2. Inherit from `BaseScanner` and implement `run()`:

```python
from modules.base import BaseScanner
from utils.helpers import safe_get

class MyCheckScanner(BaseScanner):
    NAME = "My Custom Check"

    def run(self):
        resp = safe_get(self.session, self.base_url, self.timeout)
        if resp and "secret" in resp.text:
            self.add_finding("Secret keyword found in response!")
            return self.result(True, "Custom issue found")
        return self.result(False, "Nothing found")
```

3. Register it in `vulnscan.py` inside the `MODULES` dict:

```python
"my_check": ("My Custom Check", MyCheckScanner),
```

---

## 📚 Learning Resources

| Topic | Link |
|-------|------|
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ |
| PortSwigger Web Academy | https://portswigger.net/web-security |
| HackTheBox | https://www.hackthebox.com |
| TryHackMe | https://tryhackme.com |
| CVE Database | https://cve.mitre.org |

---

## 👤 Author

**st00boy**

- GitHub: [@st00boy](https://github.com/st00boy)

---

## 📄 License

This project is licensed under the MIT License.

```
MIT License — feel free to use, modify, and distribute with attribution.
```

---

<div align="center">

**⭐ Star this repo if you find it useful!**

Made with ❤️ by [st00boy](https://github.com/st00boy)

</div>
