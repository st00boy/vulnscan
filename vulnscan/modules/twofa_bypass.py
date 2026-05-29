"""2FA Bypass Scanner"""
from modules.base import BaseScanner
from utils.helpers import safe_get, safe_post

class TwoFABypassScanner(BaseScanner):
    NAME = "2FA Bypass Scanner"
    def run(self):
        self.log("Checking for 2FA bypass vectors...")
        endpoints = ["/2fa", "/verify", "/otp", "/auth/2fa", "/mfa"]
        for ep in endpoints:
            url = f"{self.base_url}{ep}"
            r = safe_get(self.session, url, self.timeout)
            if not r or r.status_code == 404:
                continue
            # Test: response manipulation — try code=000000
            for code in ["000000", "123456", "111111", "999999"]:
                resp = safe_post(self.session, url, data={"code": code, "otp": code, "token": code}, timeout=self.timeout)
                if resp and resp.status_code in (200, 302):
                    if any(w in resp.text.lower() for w in ["dashboard", "welcome", "success", "home"]):
                        self.add_finding(f"2FA bypass possible at {ep} with code {code}")
                        self.log(f"2FA bypass at {ep}", "vuln")
                        return self.result(True, f"2FA bypassed at {ep}")
            # Check if 2FA can be skipped entirely
            skip = safe_get(self.session, f"{self.base_url}/dashboard", self.timeout)
            if skip and skip.status_code == 200 and "login" not in skip.url.lower():
                self.add_finding(f"2FA may be skippable — /dashboard accessible without completing 2FA")
        if self.vulnerable:
            return self.result(True, f"2FA bypass issues: {len(self.findings)}")
        return self.result(False, "No 2FA bypass vectors found")
