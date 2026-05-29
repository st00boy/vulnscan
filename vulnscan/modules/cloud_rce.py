"""
Cloud RCE - Remote Code Execution in Cloud Services
=====================================================
Checks for exposed cloud metadata endpoints, misconfigured cloud storage,
and common cloud-specific RCE vectors across AWS, GCP, Azure, Oracle, Huawei.
"""
from modules.base import BaseScanner
from utils.helpers import safe_get

CLOUD_METADATA = [
    # AWS
    ("AWS",    "http://169.254.169.254/latest/meta-data/",             ["ami-id", "instance-id"]),
    ("AWS",    "http://169.254.169.254/latest/user-data",              ["#!/bin", "cloud-init"]),
    ("AWS",    "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["RoleArn", "Type"]),
    # GCP
    ("GCP",    "http://metadata.google.internal/computeMetadata/v1/",  ["project", "instance"]),
    # Azure
    ("Azure",  "http://169.254.169.254/metadata/v1/",                  ["compute", "network"]),
    ("Azure",  "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["azEnvironment"]),
    # Oracle Cloud
    ("Oracle", "http://169.254.169.254/opc/v1/instance/",              ["compartmentId", "shape"]),
    # Huawei Cloud
    ("Huawei", "http://169.254.169.254/openstack/latest/meta_data.json",["uuid", "availability_zone"]),
]

EXPOSED_SERVICES = [
    ("/actuator/heapdump",         "Java heap dump — may contain credentials"),
    ("/actuator/env",              "Spring Boot env — exposes all config/secrets"),
    ("/.aws/credentials",          "AWS credentials file exposed"),
    ("/app/.env",                  "Environment variables exposed"),
    ("/api/v1/namespaces",         "Kubernetes API exposed (unauthenticated)"),
    (":8080/manager/html",         "Tomcat manager exposed"),
    (":9200/_cat/indices",         "Elasticsearch exposed"),
    (":27017",                     "MongoDB exposed"),
    (":6379",                      "Redis exposed"),
]


class CloudRCEScanner(BaseScanner):
    NAME = "Cloud RCE Scanner"

    def run(self):
        self.log("Checking for cloud metadata and exposed services...")
        self._check_metadata()
        self._check_exposed_services()

        if self.vulnerable:
            return self.result(True, f"Cloud exposure issues: {len(self.findings)}")
        return self.result(False, "No cloud metadata or service exposure found")

    def _check_metadata(self):
        for provider, url, indicators in CLOUD_METADATA:
            headers = {}
            if provider == "GCP":
                headers["Metadata-Flavor"] = "Google"
            elif provider == "Azure":
                headers["Metadata"] = "true"

            resp = safe_get(self.session, url, timeout=3, headers=headers)
            if not resp:
                continue
            if resp.status_code == 200:
                for indicator in indicators:
                    if indicator.lower() in resp.text.lower():
                        self.add_finding(
                            f"{provider} cloud metadata accessible at {url}! "
                            f"Could expose credentials and instance details."
                        )
                        self.log(f"{provider} metadata exposed", "vuln")
                        break

    def _check_exposed_services(self):
        for path, desc in EXPOSED_SERVICES:
            url = f"{self.base_url}{path}"
            resp = safe_get(self.session, url, timeout=3)
            if resp and resp.status_code == 200 and len(resp.text) > 20:
                self.add_finding(f"Exposed service at {path}: {desc}")
                self.log(f"Exposed: {path}", "vuln")
