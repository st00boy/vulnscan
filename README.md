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

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Modules](https://img.shields.io/badge/Modules-25%2B-brightgreen?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Mac%20%7C%20Windows-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Author](https://img.shields.io/badge/Author-st00boy-red?style=for-the-badge)

<br>

> A modular CLI-based web vulnerability scanner covering **25+ vulnerability classes**.
> Built for beginners — every module includes plain-English explanations of what the
> vulnerability is, why it's dangerous, and how to fix it.

<br>

[📦 Download](#-installation) • [🚀 Usage](#-usage) • [🛡️ Modules](#-vulnerability-modules) • [📊 Reports](#-reports) • [👤 Author](#-author)

</div>

---

## ⚠️ Legal Disclaimer

> **This tool is for educational purposes and authorized security testing ONLY.**
> Never run VulnScan against systems you do not own or do not have **explicit written
> permission** to test. Unauthorized use is illegal and unethical.
> The author is **not responsible** for any misuse or damage caused by this tool.

---

## 📋 Table of Contents

- [Features](#-features)
- [Vulnerability Modules](#-vulnerability-modules)
- [Installation](#-installation)
- [Usage](#-usage)
- [Reports](#-reports)
- [Dashboard](#-dashboard)
- [Project Structure](#-project-structure)
- [Adding a Custom Module](#-adding-a-custom-module)
- [Learning Resources](#-learning-resources)
- [Author](#-author)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **25+ Modules** | Covers all major web vulnerability classes |
| 🧠 **Beginner Friendly** | Every module explains the vuln in plain English |
| 🖥️ **Interactive CLI** | Menu-driven interface — no complex flags needed |
| 📄 **Auto Reports** | Generates JSON + HTML reports after every scan |
| 🌐 **Dashboard** | Visual HTML dashboard showing demo scan results |
| 📊 **Terminal Viewer** | Pretty-print scan results directly in terminal |
| ⚙️ **Auto Setup** | One script installs and configures everything |
| 🔌 **Modular Design** | Easily plug in your own custom modules |
| 🛡️ **Proxy Support** | Route traffic through Burp Suite or any proxy |
| 🍪 **Auth Support** | Test authenticated sessions via cookies/headers |
| ⚡ **Multithreaded** | Configurable threads for faster scanning |

---

## 🛡️ Vulnerability Modules

<details>
<summary><strong>🌐 Web Vulnerabilities</strong></summary>

| Module | Vulnerability | Description |
|--------|--------------|-------------|
| `xss` | XSS — Stored & Reflected | Inject malicious scripts into web pages |
| `sqli` | SQL Injection | Manipulate database queries |
| `ssrf` | Server-Side Request Forgery | Trick server into making internal requests |
| `csrf` | Cross-Site Request Forgery | Force authenticated actions without consent |
| `idor` | Insecure Direct Object Reference | Access unauthorized objects via ID manipulation |
| `lfi` | Local File Inclusion | Read server files via path traversal |
| `open_redirect` | Open Redirect | Redirect users to malicious sites |
| `host_header` | Host Header Injection | Poison password resets and cache via Host header |
| `crlf` | CRLF Injection | Inject fake HTTP headers via newline characters |
| `file_upload` | File Upload Vulnerability | Upload malicious files like webshells |
| `cache_poison` | Cache Poisoning | Poison CDN/proxy cache to serve malicious content |
| `clickjacking` | Clickjacking | Trick users into clicking hidden elements |
| `proto_pollution` | Prototype Pollution | Corrupt JavaScript object prototypes |
| `business_logic` | Business Logic Flaws | Exploit broken application workflows |

</details>

<details>
<summary><strong>🔐 Authentication & Authorization</strong></summary>

| Module | Vulnerability | Description |
|--------|--------------|-------------|
| `oauth` | OAuth Exploitation | Exploit OAuth misconfigurations |
| `account_takeover` | Account Takeover | Gain control of other user accounts |
| `2fa_bypass` | 2FA Bypass | Circumvent two-factor authentication |
| `api_exposure` | API Exposure | Find exposed API keys and endpoints |

</details>

<details>
<summary><strong>☁️ Cloud & Infrastructure</strong></summary>

| Module | Vulnerability | Description |
|--------|--------------|-------------|
| `log4j` | Log4Shell (CVE-2021-44228) | Critical Java logging RCE vulnerability |
| `cloud_rce` | Cloud RCE | AWS, GCP, Azure, Oracle, Huawei metadata exposure |
| `ddos` | DDoS Surface Checks | Identify rate-limiting and amplification weaknesses |

</details>

<details>
<summary><strong>🔎 Reconnaissance</strong></summary>

| Module | Vulnerability | Description |
|--------|--------------|-------------|
| `info_disclosure` | Information Disclosure | Exposed .env, .git, backup files, API keys |
| `subdomain_takeover` | Subdomain Takeover | Claim dangling DNS records |
| `github_exposure` | GitHub Exposure | Exposed source code and credentials |
| `email_spoofing` | Email Spoofing | Missing SPF, DKIM, DMARC records |

</details>

---

## 📦 Installation

**Requirements:** Python 3.8+

```bash
# 1. Clone the repo
git clone https://github.com/st00boy/vulnscan.git
cd vulnscan

# 2. Run auto setup (installs everything)
bash setup.sh
```

**Or manually:**
```bash
pip install -r requirements.txt
chmod +x vulnscan.py
```

---

## 🚀 Usage

### ▶ Interactive Mode — Recommended for Beginners

```bash
python3 vulnscan.py
```

A menu will guide you through entering a target and choosing a scan mode.

---

### ⚡ Command-Line Mode

```bash
# Full scan — all 25 modules
python3 vulnscan.py http://target.com --full

# Specific modules only
python3 vulnscan.py http://target.com -m xss,sqli,ssrf

# Verbose output
python3 vulnscan.py http://target.com --full -v

# With Burp Suite proxy
python3 vulnscan.py http://target.com --proxy http://127.0.0.1:8080

# Authenticated scan
python3 vulnscan.py http://target.com --cookies "session=abc123"

# Custom timeout & threads
python3 vulnscan.py http://target.com --timeout 15 --threads 10

# List all modules
python3 vulnscan.py --list
```

---

### 📋 Terminal Report Viewer

```bash
# Auto-loads the latest report
python3 view_report.py

# Load a specific report
python3 view_report.py reports/vulnscan_20250527_120000.json
```

---

### 🗂 Scan Categories

| Category | Included Modules |
|----------|-----------------|
| **Web** | xss, sqli, ssrf, csrf, idor, lfi, open_redirect, host_header, crlf, file_upload, cache_poison, clickjacking, proto_pollution, business_logic |
| **Auth** | oauth, account_takeover, 2fa_bypass, api_exposure |
| **Cloud** | log4j, cloud_rce, ddos |
| **Recon** | info_disclosure, subdomain_takeover, github_exposure, email_spoofing |

---

## 📊 Reports

Every scan auto-generates two report files in the `reports/` folder:

```
reports/
├── vulnscan_20250527_120000.json   ← machine-readable
└── vulnscan_20250527_120000.html   ← visual HTML report
```

Open the **HTML report** directly in your browser for a color-coded view of all results.

---

## 🌐 Dashboard

VulnScan includes `dashboard.html` — a visual demo dashboard showing what scan results look like.

**Open it:**
```bash
# Just double-click dashboard.html
# Or from terminal:

# Linux
xdg-open dashboard.html

# macOS
open dashboard.html

# Windows
start dashboard.html
```

> The dashboard displays demo data. For real results, open the HTML report
> generated in the `reports/` folder after running a scan.

---

## 📁 Project Structure

```
vulnscan/
│
├── vulnscan.py          ← main scanner entry point
├── dashboard.html       ← visual results dashboard
├── view_report.py       ← terminal report viewer
├── setup.sh             ← auto install & setup script
├── requirements.txt
├── README.md
│
├── modules/             ← one file per vulnerability (25 total)
│   ├── base.py          ← BaseScanner (all modules inherit this)
│   ├── xss.py
│   ├── sqli.py
│   └── ...
│
├── utils/
│   ├── banner.py        ← ASCII banner + colors
│   ├── helpers.py       ← HTTP session, URL utilities
│   └── report.py        ← JSON + HTML report generator
│
├── wordlists/           ← add custom payloads here
└── reports/             ← scan output (auto-created)
```

---

## 🔧 Adding a Custom Module

1. Create `modules/my_check.py`:

```python
from modules.base import BaseScanner
from utils.helpers import safe_get

class MyCheckScanner(BaseScanner):
    NAME = "My Custom Check"

    def run(self):
        resp = safe_get(self.session, self.base_url, self.timeout)
        if resp and "secret" in resp.text:
            self.add_finding("Secret keyword found!")
            return self.result(True, "Custom issue found")
        return self.result(False, "Nothing found")
```

2. Register it in `vulnscan.py`:

```python
"my_check": ("My Custom Check", MyCheckScanner),
```

---

## 📚 Learning Resources

| Resource | Link |
|----------|------|
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

MIT License — free to use, modify, and distribute with attribution.

---

<div align="center">

⭐ **Star this repo if you find it useful!**

Made with ❤️ by [st00boy](https://github.com/st00boy)

</div>
