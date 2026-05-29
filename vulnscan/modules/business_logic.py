"""
Business Logic Vulnerabilities
================================
WHAT IS IT?
  Flaws in how the application's rules are enforced. E.g. buying an item with
  negative quantity to get a refund, applying the same coupon twice, bypassing
  payment, or accessing a paid feature for free.

FIX: Test every user flow for edge cases. Apply server-side validation for all
     business rules. Never trust client-supplied prices or quantities.
"""
from modules.base import BaseScanner
from utils.helpers import safe_get, safe_post

class BusinessLogicScanner(BaseScanner):
    NAME = "Business Logic Scanner"

    def run(self):
        self.log("Checking for business logic flaws...")
        self._check_negative_values()
        self._check_price_manipulation()
        self._check_coupon_reuse()
        self._check_privilege_escalation()

        if self.vulnerable:
            return self.result(True, f"Business logic issues: {len(self.findings)}")
        return self.result(False, "No automated business logic flaws found (manual testing recommended)")

    def _check_negative_values(self):
        cart_endpoints = ["/cart", "/api/cart", "/checkout", "/order"]
        for ep in cart_endpoints:
            url = f"{self.base_url}{ep}"
            resp = safe_post(self.session, url,
                data={"quantity": "-1", "amount": "-100", "price": "-1"},
                timeout=self.timeout)
            if resp and resp.status_code in (200, 201):
                if any(w in resp.text.lower() for w in ["success", "added", "cart", "total"]):
                    self.add_finding(
                        f"Negative quantity/amount accepted at {ep}! "
                        f"Could allow getting items for free or gaining credits."
                    )
                    self.log(f"Negative value accepted at {ep}", "vuln")

    def _check_price_manipulation(self):
        checkout_endpoints = ["/checkout", "/api/checkout", "/order/create", "/payment"]
        for ep in checkout_endpoints:
            url = f"{self.base_url}{ep}"
            resp = safe_post(self.session, url,
                data={"price": "0.01", "total": "0.01", "amount": "0.01"},
                timeout=self.timeout)
            if resp and resp.status_code in (200, 201):
                if any(w in resp.text.lower() for w in ["order", "payment", "success", "confirm"]):
                    self.add_finding(
                        f"Price parameter accepted client-side at {ep}! "
                        f"Price manipulation may be possible."
                    )

    def _check_coupon_reuse(self):
        coupon_endpoints = ["/coupon", "/promo", "/discount", "/voucher"]
        for ep in coupon_endpoints:
            url = f"{self.base_url}{ep}"
            for _ in range(2):
                resp = safe_post(self.session, url,
                    data={"code": "SAVE10", "coupon": "SAVE10"},
                    timeout=self.timeout)
            if resp and resp.status_code == 200:
                if "discount" in resp.text.lower() or "applied" in resp.text.lower():
                    self.add_finding(f"Coupon may be reusable at {ep} — no single-use enforcement detected")

    def _check_privilege_escalation(self):
        privileged = ["/admin", "/admin/users", "/api/admin", "/superuser",
                      "/internal", "/staff", "/moderator"]
        for ep in privileged:
            resp = safe_get(self.session, f"{self.base_url}{ep}", self.timeout)
            if resp and resp.status_code == 200:
                if any(w in resp.text.lower() for w in ["admin", "user list", "manage", "dashboard"]):
                    self.add_finding(
                        f"Privileged endpoint accessible without elevated auth: {ep}"
                    )
                    self.log(f"Privilege escalation: {ep}", "vuln")
