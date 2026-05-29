"""
CSRF - Cross-Site Request Forgery
===================================
WHAT IS CSRF?
  CSRF tricks an authenticated user's browser into making unwanted requests
  to a site where they're logged in. E.g., submitting a "change email" form
  from a malicious page you control.

WHY DANGEROUS?
  Can change account settings, make purchases, transfer money — all without
  the victim knowing.

FIX: Use CSRF tokens on all state-changing requests, SameSite cookies.
REFERENCE: https://owasp.org/www-community/attacks/csrf
"""

from modules.base import BaseScanner
from utils.helpers import safe_get

FORM_ENDPOINTS = [
    "/login", "/register", "/account", "/profile", "/settings",
    "/password", "/email", "/transfer", "/payment", "/checkout",
    "/admin", "/update", "/delete", "/upload",
]


class CSRFScanner(BaseScanner):
    NAME = "CSRF Scanner"

    def run(self):
        self.log("Checking for missing CSRF protections...")
        self._check_csrf_tokens()
        self._check_samesite_cookies()

        if self.vulnerable:
            return self.result(True, f"CSRF issues found: {len(self.findings)}")
        return self.result(False, "CSRF tokens appear present or no forms found")

    def _check_csrf_tokens(self):
        import re
        for endpoint in FORM_ENDPOINTS:
            url = f"{self.base_url}{endpoint}"
            resp = safe_get(self.session, url, self.timeout)
            if not resp or resp.status_code == 404:
                continue

            # Check for CSRF tokens in forms
            has_form = bool(re.search(r'<form', resp.text, re.I))
            if not has_form:
                continue

            has_csrf = bool(re.search(
                r'(csrf|_token|authenticity_token|__RequestVerificationToken)',
                resp.text, re.I
            ))

            if has_form and not has_csrf:
                self.add_finding(
                    f"No CSRF token found in form at {endpoint}. "
                    f"State-changing form without protection."
                )
                self.log(f"Missing CSRF token at {endpoint}", "vuln")

    def _check_samesite_cookies(self):
        resp = safe_get(self.session, self.base_url, self.timeout)
        if not resp:
            return
        for cookie in resp.cookies:
            samesite = cookie._rest.get("SameSite", "").lower()
            if not samesite or samesite == "none":
                self.add_finding(
                    f"Cookie '{cookie.name}' missing SameSite attribute — CSRF risk"
                )
