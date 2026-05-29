"""
Subdomain Takeover
===================
WHAT IS IT?
  A DNS record points to a service (Heroku, GitHub Pages, S3 etc.) that no
  longer exists. An attacker registers that service and now controls the subdomain.

WHY DANGEROUS?
  Can be used to serve phishing pages, steal cookies scoped to parent domain.

FIX: Remove dangling DNS records for decommissioned services.
"""
import socket
from modules.base import BaseScanner
from utils.helpers import safe_get

TAKEOVER_SIGNATURES = {
    "GitHub":       "There isn't a GitHub Pages site here",
    "Heroku":       "No such app",
    "Shopify":      "Sorry, this shop is currently unavailable",
    "Fastly":       "Fastly error: unknown domain",
    "Pantheon":     "The gods are wise",
    "Tumblr":       "Whatever you were looking for doesn't currently exist",
    "WordPress":    "Do you want to register",
    "Ghost":        "The thing you were looking for is no longer here",
    "Surge.sh":     "project not found",
    "AWS S3":       "NoSuchBucket",
    "Azure":        "404 Web Site not found",
    "Bitbucket":    "Repository not found",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "staging", "dev", "test", "api", "blog",
    "shop", "store", "app", "admin", "beta", "demo", "old", "new",
    "static", "cdn", "assets", "media", "images", "help", "support",
]


class SubdomainTakeoverScanner(BaseScanner):
    NAME = "Subdomain Takeover Scanner"

    def run(self):
        self.log("Checking for subdomain takeover opportunities...")
        import re
        base_domain = re.sub(r'^www\.', '', self.domain)

        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{base_domain}"
            try:
                socket.gethostbyname(fqdn)
            except socket.gaierror:
                continue  # Subdomain doesn't resolve — skip

            for scheme in ["https", "http"]:
                url = f"{scheme}://{fqdn}"
                resp = safe_get(self.session, url, self.timeout)
                if not resp:
                    continue
                for service, sig in TAKEOVER_SIGNATURES.items():
                    if sig.lower() in resp.text.lower():
                        self.add_finding(
                            f"Subdomain takeover possible! {fqdn} → {service} "
                            f"(dangling DNS record, service not claimed)"
                        )
                        self.log(f"Takeover: {fqdn} via {service}", "vuln")
                        break

        if self.vulnerable:
            return self.result(True, f"Subdomain takeover opportunities: {len(self.findings)}")
        return self.result(False, "No subdomain takeover indicators found")
