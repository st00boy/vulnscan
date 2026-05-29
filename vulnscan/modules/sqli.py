"""
SQL Injection Scanner
======================
WHAT IS SQL INJECTION?
  SQL injection occurs when user-supplied input is inserted into SQL queries
  without proper sanitization, allowing attackers to manipulate the database.

WHY IS IT DANGEROUS?
  Attackers can read sensitive data (passwords, credit cards), modify/delete
  data, bypass authentication, and in some cases execute OS commands.

HOW TO FIX IT?
  - Use parameterized queries / prepared statements (NEVER concatenate user input)
  - Use an ORM (e.g., SQLAlchemy, Hibernate)
  - Apply least privilege to DB users

REFERENCE: https://owasp.org/www-community/attacks/SQL_Injection
"""

from modules.base import BaseScanner
from utils.helpers import safe_get, extract_params, inject_param

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query(): query failed",
    "supplied argument is not a valid mysql",
    "ORA-01756",
    "SQLite3::query",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "syntax error at or near",
    "invalid query",
    "sql syntax",
    "database error",
]

PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    ") OR ('1'='1",
    "' AND SLEEP(3)--",  # Time-based blind
    "1; SELECT SLEEP(3)--",
]

BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),   # True vs False pair
]


class SQLiScanner(BaseScanner):
    NAME = "SQL Injection Scanner"

    def run(self):
        self.log("Testing for SQL injection via URL parameters...")
        self._test_error_based()
        self._test_boolean_based()

        if self.vulnerable:
            return self.result(True, f"SQL injection indicators found: {len(self.findings)} point(s)")
        return self.result(False, "No SQL injection indicators found")

    def _test_error_based(self):
        params = extract_params(self.target) or ["id", "page", "search", "q", "cat", "user"]
        for param in params:
            for payload in PAYLOADS[:7]:
                test_url = inject_param(self.target, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                body = resp.text.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in body:
                        self.add_finding(
                            f"Error-based SQLi in param '{param}' | Sig: '{sig}' | Payload: {payload}"
                        )
                        self.log(f"SQLi error-based: param={param}", "vuln")
                        return

    def _test_boolean_based(self):
        params = extract_params(self.target) or ["id", "page"]
        base_resp = safe_get(self.session, self.target, self.timeout)
        if not base_resp:
            return

        for param in params:
            for true_pay, false_pay in BOOLEAN_PAYLOADS:
                true_url  = inject_param(self.target, param, true_pay)
                false_url = inject_param(self.target, param, false_pay)
                true_resp  = safe_get(self.session, true_url, self.timeout)
                false_resp = safe_get(self.session, false_url, self.timeout)
                if not true_resp or not false_resp:
                    continue
                # Significant content length difference = boolean-based SQLi
                diff = abs(len(true_resp.text) - len(false_resp.text))
                if diff > 50:
                    self.add_finding(
                        f"Boolean-based SQLi possible in param '{param}' | "
                        f"Response size diff: {diff} bytes"
                    )
                    self.log(f"SQLi boolean-based: param={param}", "vuln")
