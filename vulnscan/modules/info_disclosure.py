"""
Information Disclosure
=======================
WHAT IS IT?
  The app accidentally exposes sensitive info: API keys, passwords, stack traces,
  server versions, internal paths, .git folders, backup files, etc.

FIX: Disable debug mode in production, remove .git from webroot, sanitize error messages.
"""
from modules.base import BaseScanner
from utils.helpers import safe_get

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.backup",
    "/config.php", "/config.yml", "/config.json", "/settings.py",
    "/wp-config.php", "/database.yml", "/secrets.yml",
    "/backup.zip", "/backup.sql", "/dump.sql", "/db.sql",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config",
    "/api/swagger.json", "/swagger.json", "/openapi.json",
    "/api-docs", "/swagger-ui.html", "/.well-known/security.txt",
    "/server-status", "/server-info", "/_profiler",
    "/trace", "/actuator", "/actuator/env", "/actuator/dump",
    "/console", "/admin/config", "/.DS_Store",
]

SENSITIVE_PATTERNS = [
    ("AWS key", r"AKIA[0-9A-Z]{16}"),
    ("Private key", r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
    ("DB password", r"(DB_PASS|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*[=:]\s*\S+"),
    ("API key", r"(api_key|apikey|api_secret)\s*[=:]\s*['\"]?\w{16,}"),
    ("JWT token", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ("Git config", r"\[core\]"),
]


class InfoDisclosureScanner(BaseScanner):
    NAME = "Information Disclosure Scanner"

    def run(self):
        import re
        self.log("Checking for sensitive file/path exposures...")
        for path in SENSITIVE_PATHS:
            url = f"{self.base_url}{path}"
            resp = safe_get(self.session, url, self.timeout)
            if not resp or resp.status_code not in (200, 206):
                continue
            if len(resp.text) < 5:
                continue
            # Check for sensitive patterns
            for name, pattern in SENSITIVE_PATTERNS:
                if re.search(pattern, resp.text, re.I):
                    self.add_finding(f"{name} found at {path}!")
                    self.log(f"{name} exposed at {path}", "vuln")
                    break
            else:
                # Path accessible but no specific pattern — still interesting
                if path in ["/.git/HEAD", "/.env", "/phpinfo.php", "/actuator/env"]:
                    self.add_finding(f"Sensitive path accessible: {path} (HTTP {resp.status_code})")
                    self.log(f"Sensitive path: {path}", "vuln")

        if self.vulnerable:
            return self.result(True, f"Information disclosure: {len(self.findings)} finding(s)")
        return self.result(False, "No sensitive files exposed")
