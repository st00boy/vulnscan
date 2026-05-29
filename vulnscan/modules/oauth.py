"""OAuth Exploitation Scanner"""
from modules.base import BaseScanner
from utils.helpers import safe_get
import re

OAUTH_ENDPOINTS = [
    "/oauth/authorize", "/oauth/token", "/auth/callback",
    "/.well-known/openid-configuration", "/connect/authorize",
    "/oauth2/authorize", "/api/oauth/token",
]

class OAuthScanner(BaseScanner):
    NAME = "OAuth Scanner"
    def run(self):
        self.log("Checking for OAuth misconfigurations...")
        for ep in OAUTH_ENDPOINTS:
            url = f"{self.base_url}{ep}"
            resp = safe_get(self.session, url, self.timeout)
            if not resp or resp.status_code == 404:
                continue
            # Test open redirect_uri
            test_url = f"{url}?redirect_uri=https://evil.com&response_type=token&client_id=test"
            r = safe_get(self.session, test_url, self.timeout)
            if r and "evil.com" in r.url:
                self.add_finding(f"OAuth open redirect_uri at {ep} — token could be stolen")
                self.log(f"OAuth redirect_uri open at {ep}", "vuln")
            # Check for state parameter (CSRF protection)
            if r and "state" not in (r.url + (r.text or "")):
                self.add_finding(f"OAuth endpoint {ep} may lack 'state' param — CSRF risk")

        if self.vulnerable:
            return self.result(True, f"OAuth issues: {len(self.findings)}")
        return self.result(False, "No obvious OAuth misconfigurations found")
