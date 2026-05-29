"""
Host Header Injection
======================
WHAT IS IT?
  The server trusts the Host header from the request without validating it.
  Attackers can manipulate it to poison password reset links, cache poisoning,
  or bypass access controls.

FIX: Always hardcode the trusted domain. Never build URLs from the Host header.
"""
from modules.base import BaseScanner
from utils.helpers import safe_get

EVIL_HOSTS = [
    "evil.com",
    "attacker.com",
    "localhost",
    "127.0.0.1",
]


class HostHeaderScanner(BaseScanner):
    NAME = "Host Header Injection Scanner"

    def run(self):
        self.log("Testing Host Header Injection...")
        for evil_host in EVIL_HOSTS:
            resp = safe_get(
                self.session, self.base_url, self.timeout,
                headers={"Host": evil_host}
            )
            if not resp:
                continue
            body = resp.text
            if evil_host in body:
                self.add_finding(
                    f"Host header reflected in response! Injected: {evil_host} — "
                    f"Possible password-reset poisoning or cache poisoning."
                )
                self.log(f"Host header reflected: {evil_host}", "vuln")
                return self.result(True, f"Host header '{evil_host}' reflected in page body")

        # Check if X-Forwarded-Host is also trusted
        resp = safe_get(
            self.session, self.base_url, self.timeout,
            headers={"X-Forwarded-Host": "evil.com"}
        )
        if resp and "evil.com" in resp.text:
            self.add_finding("X-Forwarded-Host reflected in response — server trusts this header")
            return self.result(True, "X-Forwarded-Host injection works")

        return self.result(False, "Host header does not appear reflected")
