"""
XSS (Cross-Site Scripting) Scanner
====================================
WHAT IS XSS?
  XSS allows attackers to inject malicious JavaScript into web pages viewed by
  other users. There are two main types:
  - Reflected XSS: The payload comes from the URL/request and is immediately shown
  - Stored XSS: The payload is saved in the database and shown to all visitors

WHY IS IT DANGEROUS?
  Attackers can steal session cookies, redirect users, deface sites, or run
  keyloggers in the victim's browser.

HOW TO FIX IT?
  - Encode all user input before displaying it (HTML entity encoding)
  - Use Content-Security-Policy (CSP) headers
  - Validate and sanitize all inputs server-side

REFERENCE: https://owasp.org/www-community/attacks/xss/
"""

from modules.base import BaseScanner
from utils.helpers import safe_get, safe_post, extract_params, inject_param

PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",  # URL encoded
]

STORED_ENDPOINTS = ["/comment", "/post", "/feedback", "/contact", "/review", "/message"]
STORED_FIELDS = ["name", "comment", "message", "body", "content", "text", "description"]


class XSSScanner(BaseScanner):
    NAME = "XSS Scanner"

    def run(self):
        self.log("Testing for Reflected XSS via URL parameters...")
        self._test_reflected()

        self.log("Testing for Stored XSS via common form fields...")
        self._test_stored()

        if self.vulnerable:
            return self.result(True, f"XSS found! {len(self.findings)} injection point(s)")
        return self.result(False, "No XSS indicators found")

    def _test_reflected(self):
        params = extract_params(self.target)
        if not params:
            # If no params in URL, try common ones
            params = ["q", "search", "id", "page", "name", "query", "s", "input"]

        for payload in PAYLOADS[:5]:
            for param in params:
                test_url = inject_param(self.target, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if resp and payload in (resp.text or ""):
                    self.add_finding(
                        f"Reflected XSS in param '{param}': {test_url[:80]}"
                    )
                    self.log(f"REFLECTED XSS: param={param}", "vuln")
                    return  # Stop after first confirmed finding

    def _test_stored(self):
        for endpoint in STORED_ENDPOINTS:
            url = f"{self.base_url}{endpoint}"
            resp = safe_get(self.session, url, self.timeout)
            if not resp or resp.status_code == 404:
                continue

            for payload in PAYLOADS[:3]:
                data = {field: payload for field in STORED_FIELDS}
                data["email"] = "test@test.com"
                post_resp = safe_post(self.session, url, data=data, timeout=self.timeout)
                if post_resp and payload in (post_resp.text or ""):
                    self.add_finding(
                        f"Possible Stored XSS at {endpoint} - payload reflected in response"
                    )
                    self.log(f"Possible STORED XSS at {endpoint}", "vuln")
                    break
