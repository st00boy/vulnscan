"""
Clickjacking Scanner
=====================
WHAT IS IT?
  The site can be embedded in an iframe on an attacker's page. The attacker
  overlays invisible buttons over the real page, tricking users into clicking
  things they didn't mean to (e.g. "confirm transfer").

FIX: Set X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'
"""
from modules.base import BaseScanner
from utils.helpers import safe_get

class ClickjackingScanner(BaseScanner):
    NAME = "Clickjacking Scanner"
    def run(self):
        self.log("Checking for clickjacking protections...")
        resp = safe_get(self.session, self.base_url, self.timeout)
        if not resp:
            return self.result(False, "Could not connect to target")

        headers = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")

        if not xfo and "frame-ancestors" not in csp:
            self.add_finding(
                "Missing X-Frame-Options AND no frame-ancestors in CSP. "
                "Site can be embedded in an iframe — clickjacking possible."
            )
            self.log("No clickjacking protection", "vuln")
            return self.result(True, "No clickjacking protection headers found")

        if xfo.lower() not in ("deny", "sameorigin"):
            self.add_finding(f"Weak X-Frame-Options value: '{xfo}'")

        return self.result(False, f"Clickjacking protection present: X-Frame-Options={xfo or 'via CSP'}")
