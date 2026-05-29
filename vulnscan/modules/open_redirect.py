"""
Open Redirect
==============
WHAT IS IT?
  The app redirects users to a URL supplied in a parameter without validating it.
  Attackers use this to redirect victims to phishing sites while the URL looks
  legitimate (e.g. bank.com/redirect?url=evil.com)

FIX: Whitelist allowed redirect destinations. Never redirect to user input directly.
"""
from modules.base import BaseScanner
from utils.helpers import safe_get, extract_params, inject_param

PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2F..",
    "https://evil.com?",
    "https:evil.com",
    "/\\evil.com",
    "https://evil%E3%80%82com",
]

REDIRECT_PARAMS = ["url", "redirect", "return", "next", "continue", "goto",
                   "dest", "destination", "redir", "redirect_uri", "return_url",
                   "callback", "forward", "location", "target"]


class OpenRedirectScanner(BaseScanner):
    NAME = "Open Redirect Scanner"

    def run(self):
        self.log("Testing for Open Redirect...")
        params = extract_params(self.target)
        candidates = [p for p in params if p.lower() in REDIRECT_PARAMS] or REDIRECT_PARAMS[:8]

        for param in candidates:
            for payload in PAYLOADS[:4]:
                test_url = inject_param(self.target, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                # Check if we ended up at evil.com or got a redirect header pointing there
                final_url = resp.url
                if "evil.com" in final_url:
                    self.add_finding(f"Open Redirect via param '{param}' → redirected to {final_url}")
                    self.log(f"Open Redirect via {param}", "vuln")
                    return self.result(True, f"Open redirect via param '{param}'")
                # Check Location header in history
                for r in resp.history:
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc:
                        self.add_finding(f"Open Redirect in Location header via '{param}': {loc}")
                        return self.result(True, f"Open redirect in Location header")

        return self.result(False, "No open redirect found")
