"""API Exposure Scanner"""
from modules.base import BaseScanner
from utils.helpers import safe_get

class APIExposureScanner(BaseScanner):
    NAME = "API Exposure Scanner"
    def run(self):
        self.log("Checking for exposed API docs and keys...")
        API_PATHS = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
            "/openapi.json", "/api-docs", "/redoc",
            "/graphql", "/graphiql", "/__graphql",
            "/api/users", "/api/admin", "/api/keys",
            "/api/config", "/api/debug", "/api/test",
            "/v1/keys", "/v2/keys",
        ]
        for path in API_PATHS:
            url = f"{self.base_url}{path}"
            resp = safe_get(self.session, url, self.timeout)
            if not resp or resp.status_code not in (200, 201):
                continue
            # Check for sensitive content
            suspicious = any(kw in resp.text.lower() for kw in [
                "password", "secret", "api_key", "token", "private",
                "swagger", "openapi", "graphql", "introspection"
            ])
            if suspicious:
                self.add_finding(f"Sensitive API endpoint exposed: {path}")
                self.log(f"API exposed: {path}", "vuln")
            # Unauthenticated access to user/admin data
            if path in ["/api/users", "/api/admin"] and resp.status_code == 200:
                self.add_finding(f"Unauthenticated access to {path}!")
                self.log(f"Unauth API: {path}", "vuln")

        if self.vulnerable:
            return self.result(True, f"API exposure: {len(self.findings)}")
        return self.result(False, "No dangerous API exposure found")
