"""
DDoS Surface Checks
====================
WHAT IS IT?
  Checks for application-layer weaknesses that can amplify denial-of-service
  attacks: missing rate limiting, large unauthenticated endpoints, etc.
  (Does NOT perform actual DDoS attacks — only surface analysis.)
"""
from modules.base import BaseScanner
from utils.helpers import safe_get
import time

class DDoSChecks(BaseScanner):
    NAME = "DDoS Surface Checks"

    def run(self):
        self.log("Checking DDoS attack surface (passive checks only)...")
        self._check_rate_limiting()
        self._check_large_responses()
        self._check_missing_security_headers()

        if self.vulnerable:
            return self.result(True, f"DDoS surface issues: {len(self.findings)}")
        return self.result(False, "No obvious DDoS surface issues found")

    def _check_rate_limiting(self):
        # Send 5 rapid requests and see if any rate limiting kicks in
        times = []
        statuses = []
        for _ in range(5):
            start = time.time()
            resp = safe_get(self.session, self.base_url, self.timeout)
            times.append(time.time() - start)
            statuses.append(resp.status_code if resp else 0)

        if 429 not in statuses and all(s == 200 for s in statuses if s):
            self.add_finding(
                "No rate limiting detected after 5 rapid requests. "
                "Endpoints may be vulnerable to brute force or request flooding."
            )
            self.log("No rate limiting found", "warn")

    def _check_large_responses(self):
        heavy_paths = ["/search?q=*", "/api/users", "/api/products", "/export", "/download"]
        for path in heavy_paths:
            resp = safe_get(self.session, f"{self.base_url}{path}", self.timeout)
            if resp and len(resp.content) > 1_000_000:  # >1MB
                self.add_finding(
                    f"Large unauthenticated response ({len(resp.content)//1024}KB) at {path} "
                    f"— can amplify bandwidth exhaustion attacks"
                )
                self.log(f"Large response at {path}", "warn")

    def _check_missing_security_headers(self):
        resp = safe_get(self.session, self.base_url, self.timeout)
        if not resp:
            return
        headers = {k.lower() for k in resp.headers}
        missing = []
        for h in ["x-ratelimit-limit", "retry-after"]:
            if h not in headers:
                missing.append(h)
        if missing:
            self.add_finding(f"Missing rate-limit headers: {', '.join(missing)}")
