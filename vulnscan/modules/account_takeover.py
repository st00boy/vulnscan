"""
Account Takeover
=================
WHAT IS IT?
  A class of vulnerabilities that allow an attacker to gain access to
  another user's account. Common vectors: weak password reset, JWT flaws,
  username enumeration, default credentials.
"""
from modules.base import BaseScanner
from utils.helpers import safe_get, safe_post

RESET_ENDPOINTS = ["/forgot-password", "/reset-password", "/account/recover",
                   "/auth/forgot", "/password/reset", "/api/password-reset"]
ADMIN_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("administrator", "administrator"),
]


class AccountTakeoverScanner(BaseScanner):
    NAME = "Account Takeover Scanner"

    def run(self):
        self.log("Checking account takeover vectors...")
        self._check_password_reset()
        self._check_user_enumeration()
        self._check_default_creds()

        if self.vulnerable:
            return self.result(True, f"Account takeover risks: {len(self.findings)}")
        return self.result(False, "No obvious account takeover issues found")

    def _check_password_reset(self):
        for ep in RESET_ENDPOINTS:
            url = f"{self.base_url}{ep}"
            r = safe_get(self.session, url, self.timeout)
            if not r or r.status_code == 404:
                continue
            # Check if token is in URL (insecure)
            import re
            if re.search(r'token=[a-zA-Z0-9]{4,}', r.url):
                self.add_finding(f"Password reset token visible in URL at {ep}")
                self.log(f"Reset token in URL at {ep}", "vuln")

    def _check_user_enumeration(self):
        login_endpoints = ["/login", "/signin", "/api/login", "/auth/login"]
        for ep in login_endpoints:
            url = f"{self.base_url}{ep}"
            r1 = safe_post(self.session, url, data={"username": "admin@admin.com", "password": "wrongpass"}, timeout=self.timeout)
            r2 = safe_post(self.session, url, data={"username": "notexist_xyz@fake.com", "password": "wrongpass"}, timeout=self.timeout)
            if r1 and r2 and r1.text != r2.text:
                self.add_finding(f"User enumeration possible at {ep} — different responses for valid vs invalid usernames")
                self.log(f"User enumeration at {ep}", "vuln")

    def _check_default_creds(self):
        admin_panels = ["/admin", "/admin/login", "/administrator", "/wp-admin", "/manager"]
        for panel in admin_panels:
            url = f"{self.base_url}{panel}"
            r = safe_get(self.session, url, self.timeout)
            if not r or r.status_code == 404:
                continue
            for user, pwd in ADMIN_CREDS:
                resp = safe_post(self.session, url, data={"username": user, "password": pwd}, timeout=self.timeout)
                if resp and resp.status_code in (200, 302):
                    if "dashboard" in resp.url or "logout" in resp.text.lower():
                        self.add_finding(f"Default credentials work at {panel}: {user}/{pwd}")
                        self.log(f"Default creds work: {user}/{pwd}", "vuln")
