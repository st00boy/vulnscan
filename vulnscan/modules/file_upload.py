"""
File Upload Vulnerability
==========================
WHAT IS IT?
  When a web app allows file uploads without properly restricting file types,
  attackers can upload malicious files like PHP/ASP webshells to execute
  commands on the server.

WHY DANGEROUS?
  A successful upload of a webshell = full server compromise (RCE).

FIX: Whitelist allowed extensions, validate MIME type server-side, store uploads
     outside webroot, rename uploaded files, use antivirus scanning.
"""
from modules.base import BaseScanner
from utils.helpers import safe_get, safe_post

UPLOAD_ENDPOINTS = [
    "/upload", "/file/upload", "/api/upload", "/media/upload",
    "/avatar", "/profile/photo", "/image/upload", "/files",
    "/admin/upload", "/attachments",
]

# Harmless test files with dangerous extensions
TEST_FILES = [
    ("shell.php",   "<?php echo 'vulnscan_test'; ?>",                "text/plain"),
    ("shell.php5",  "<?php echo 'vulnscan_test'; ?>",                "text/plain"),
    ("shell.phtml", "<?php echo 'vulnscan_test'; ?>",                "text/plain"),
    ("shell.asp",   "<% Response.Write('vulnscan_test') %>",         "text/plain"),
    ("shell.aspx",  "<%@ Page Language='C#' %><%= 'vulnscan_test'%>","text/plain"),
    ("test.jpg.php","<?php echo 'vulnscan_test'; ?>",                "image/jpeg"),
    ("test.svg",    '<svg><script>alert(1)</script></svg>',           "image/svg+xml"),
]


class FileUploadScanner(BaseScanner):
    NAME = "File Upload Scanner"

    def run(self):
        self.log("Checking for file upload endpoints and misconfigurations...")
        for endpoint in UPLOAD_ENDPOINTS:
            url = f"{self.base_url}{endpoint}"
            resp = safe_get(self.session, url, self.timeout)
            if not resp or resp.status_code == 404:
                continue

            self.log(f"Upload endpoint found: {endpoint}", "warn")
            self._test_upload(url, endpoint)

        if self.vulnerable:
            return self.result(True, f"File upload issues found: {len(self.findings)}")
        return self.result(False, "No accessible upload endpoints found")

    def _test_upload(self, url, endpoint):
        for filename, content, mime in TEST_FILES:
            files = {"file": (filename, content.encode(), mime)}
            # Also try common field names
            for field in ["file", "upload", "image", "attachment", "document"]:
                files_payload = {field: (filename, content.encode(), mime)}
                resp = safe_post(self.session, url, timeout=self.timeout, files=files_payload)
                if not resp:
                    continue
                # Success indicators
                if resp.status_code in (200, 201) and any(
                    sig in resp.text.lower() for sig in
                    ["success", "uploaded", "url", "path", filename.split(".")[0]]
                ):
                    self.add_finding(
                        f"Upload endpoint '{endpoint}' accepted file '{filename}' — "
                        f"Verify if file is accessible/executable on server."
                    )
                    self.log(f"File upload accepted: {filename} at {endpoint}", "vuln")
                    return
