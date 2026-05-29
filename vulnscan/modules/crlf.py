"""
CRLF Injection
===============
WHAT IS IT?
  CRLF = Carriage Return (\r) + Line Feed (\n). These characters mark the end of
  HTTP headers. If user input containing \r\n is placed in a response header,
  attackers can inject fake headers or split the HTTP response.

WHY DANGEROUS?
  Can lead to XSS, cache poisoning, session fixation, or phishing via fake pages.

FIX: Strip or encode \r and \n from all user input used in HTTP headers.
"""
from modules.base import BaseScanner
from utils.helpers import safe_get, extract_params, inject_param

PAYLOADS = [
    "%0d%0aX-Injected: crlf-test",
    "%0aX-Injected: crlf-test",
    "\r\nX-Injected: crlf-test",
    "%0d%0aSet-Cookie: crlf=injected",
    "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK",
]


class CRLFScanner(BaseScanner):
    NAME = "CRLF Injection Scanner"

    def run(self):
        self.log("Testing for CRLF Injection...")
        params = extract_params(self.target) or ["url", "redirect", "next", "lang", "ref"]

        for param in params:
            for payload in PAYLOADS:
                test_url = inject_param(self.target, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                # Check if our injected header appears in the response headers
                if "x-injected" in str(resp.headers).lower() or "crlf-test" in str(resp.headers):
                    self.add_finding(
                        f"CRLF Injection via param '{param}'! "
                        f"Injected header appeared in response."
                    )
                    self.log(f"CRLF injection via {param}", "vuln")
                    return self.result(True, f"CRLF injection via param '{param}'")
                if "crlf=injected" in str(resp.cookies):
                    self.add_finding(f"CRLF cookie injection via '{param}'")
                    return self.result(True, "CRLF injection set arbitrary cookie")

        return self.result(False, "No CRLF injection found")
