"""Prototype Pollution Scanner"""
from modules.base import BaseScanner
from utils.helpers import safe_get, safe_post

class PrototypePollutionScanner(BaseScanner):
    NAME = "Prototype Pollution Scanner"
    def run(self):
        self.log("Testing for prototype pollution in JSON endpoints...")
        PAYLOADS = [
            {"__proto__": {"polluted": "yes"}},
            {"constructor": {"prototype": {"polluted": "yes"}}},
        ]
        api_paths = ["/api", "/api/v1", "/api/v2", "/graphql", "/data"]
        for path in api_paths:
            url = f"{self.base_url}{path}"
            for payload in PAYLOADS:
                resp = safe_post(self.session, url, json=payload, timeout=self.timeout)
                if resp and "polluted" in (resp.text or ""):
                    self.add_finding(f"Prototype pollution at {path} — 'polluted' key reflected in response")
                    self.log(f"Prototype pollution at {path}", "vuln")
                    return self.result(True, f"Prototype pollution at {path}")
        return self.result(False, "No prototype pollution detected")
