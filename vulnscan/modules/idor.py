"""
IDOR - Insecure Direct Object Reference
=========================================
WHAT IS IDOR?
  IDOR occurs when an app uses user-controlled input (like an ID number) to
  access objects (files, records) without verifying the user's permissions.
  E.g.: /profile?id=1234 — change to id=1235 and see someone else's profile.

WHY DANGEROUS?
  Exposes private data, allows unauthorized actions (delete, modify records).

FIX: Always verify ownership server-side. Never trust client-supplied IDs alone.
REFERENCE: https://portswigger.net/web-security/access-control/idor
"""

from modules.base import BaseScanner
from utils.helpers import safe_get, extract_params, inject_param

IDOR_PARAMS = ["id", "user_id", "account", "order", "invoice", "doc", "file",
               "record", "profile", "uid", "pid", "tid", "oid", "num"]


class IDORScanner(BaseScanner):
    NAME = "IDOR Scanner"

    def run(self):
        self.log("Testing for IDOR via numeric ID parameters...")
        params = extract_params(self.target)
        idor_candidates = [p for p in params if p.lower() in IDOR_PARAMS or
                           p.lower().endswith("_id") or p.lower().endswith("id")]

        if not idor_candidates:
            idor_candidates = IDOR_PARAMS[:5]

        for param in idor_candidates:
            self._test_idor_param(param)

        if self.vulnerable:
            return self.result(True, f"Possible IDOR: {len(self.findings)} point(s)")
        return self.result(False, "No obvious IDOR indicators found (manual verification recommended)")

    def _test_idor_param(self, param):
        # Get baseline with ID=1
        base = inject_param(self.target, param, "1")
        resp1 = safe_get(self.session, base, self.timeout)
        if not resp1 or resp1.status_code not in (200, 201, 302):
            return

        # Try sequential IDs
        for i in [2, 3, 100, 1337]:
            test_url = inject_param(self.target, param, str(i))
            resp2 = safe_get(self.session, test_url, self.timeout)
            if not resp2:
                continue

            # Different content = different object served = possible IDOR
            if (resp2.status_code == 200 and
                resp1.status_code == 200 and
                abs(len(resp2.text) - len(resp1.text)) > 100 and
                resp2.text != resp1.text):
                self.add_finding(
                    f"Possible IDOR: param '{param}' returns different content for "
                    f"id=1 vs id={i}. Verify manually if it exposes other users' data."
                )
                self.log(f"Possible IDOR via param '{param}'", "vuln")
                return
