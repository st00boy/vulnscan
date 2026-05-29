"""Cache Poisoning Scanner"""
from modules.base import BaseScanner
from utils.helpers import safe_get

class CachePoisonScanner(BaseScanner):
    NAME = "Cache Poisoning Scanner"
    def run(self):
        self.log("Testing for web cache poisoning...")
        POISON_HEADERS = [
            ("X-Forwarded-Host",  "evil.com"),
            ("X-Forwarded-Scheme","nothttps"),
            ("X-Original-URL",    "/admin"),
            ("X-Rewrite-URL",     "/admin"),
        ]
        for header, value in POISON_HEADERS:
            resp = safe_get(self.session, self.base_url, self.timeout, headers={header: value})
            if not resp:
                continue
            if value in resp.text:
                self.add_finding(
                    f"Cache poisoning vector: header '{header}: {value}' reflected in response. "
                    f"If cached, all users see poisoned content."
                )
                self.log(f"Cache poisoning via {header}", "vuln")

        if self.vulnerable:
            return self.result(True, f"Cache poisoning vectors: {len(self.findings)}")
        return self.result(False, "No cache poisoning indicators found")
