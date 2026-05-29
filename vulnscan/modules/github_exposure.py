"""GitHub Exposure Scanner"""
from modules.base import BaseScanner
from utils.helpers import safe_get

class GithubExposureScanner(BaseScanner):
    NAME = "GitHub Exposure Scanner"
    def run(self):
        self.log("Checking for GitHub/source code exposure...")
        # Check for .git directory
        git_url = f"{self.base_url}/.git/HEAD"
        resp = safe_get(self.session, git_url, self.timeout)
        if resp and resp.status_code == 200 and "ref:" in resp.text:
            self.add_finding(
                f"Git repository exposed at /.git/HEAD! "
                f"Attacker can download your entire source code using git-dumper."
            )
            self.log(".git/ exposed!", "vuln")

        # Check for common source code files
        source_paths = [
            "/package.json", "/composer.json", "/Gemfile",
            "/requirements.txt", "/Dockerfile", "/docker-compose.yml",
            "/.travis.yml", "/.github/workflows/", "/Makefile",
        ]
        for path in source_paths:
            r = safe_get(self.session, f"{self.base_url}{path}", self.timeout)
            if r and r.status_code == 200 and len(r.text) > 10:
                self.add_finding(f"Source/config file exposed: {path}")
                self.log(f"Source file exposed: {path}", "warn")

        if self.vulnerable:
            return self.result(True, f"GitHub/source exposure: {len(self.findings)}")
        return self.result(False, "No Git/source code exposure found")
