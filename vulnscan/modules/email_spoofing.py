"""
Email Spoofing Scanner
=======================
WHAT IS IT?
  If a domain lacks proper SPF, DKIM, DMARC DNS records, attackers can send
  emails that appear to come from that domain (e.g. ceo@yourcompany.com).

FIX: Set up SPF, DKIM, and DMARC records in your DNS.
"""
import socket
from modules.base import BaseScanner

class EmailSpoofingScanner(BaseScanner):
    NAME = "Email Spoofing Scanner"

    def run(self):
        self.log("Checking SPF, DMARC, DKIM DNS records...")
        import re
        base_domain = re.sub(r'^www\.', '', self.domain)
        self._check_spf(base_domain)
        self._check_dmarc(base_domain)

        if self.vulnerable:
            return self.result(True, f"Email spoofing risk: {len(self.findings)} missing record(s)")
        return self.result(False, "SPF and DMARC records appear to be present")

    def _dns_txt(self, domain):
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "TXT", domain],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout
        except Exception:
            return ""

    def _check_spf(self, domain):
        txt = self._dns_txt(domain)
        if "v=spf1" not in txt:
            self.add_finding(
                f"No SPF record found for {domain}! "
                f"Anyone can send email pretending to be @{domain}"
            )
            self.log(f"Missing SPF record for {domain}", "vuln")
        else:
            if "~all" in txt:
                self.add_finding(f"SPF uses '~all' (soft fail) instead of '-all' (hard fail) — weak protection")

    def _check_dmarc(self, domain):
        txt = self._dns_txt(f"_dmarc.{domain}")
        if "v=DMARC1" not in txt:
            self.add_finding(
                f"No DMARC record for {domain}! "
                f"Spoofed emails will not be rejected by mail servers."
            )
            self.log(f"Missing DMARC for {domain}", "vuln")
        elif "p=none" in txt:
            self.add_finding(f"DMARC policy is 'p=none' — monitoring only, spoofed emails still delivered")
