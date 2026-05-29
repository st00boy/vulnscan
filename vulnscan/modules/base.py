from utils.helpers import build_session, normalize_url, get_base_url, get_domain
from utils.banner import color


class BaseScanner:
    """
    Base class for all VulnScan modules.
    Every module inherits from this and implements run().
    """
    NAME = "Base Scanner"
    EXPLANATION = "No description provided."
    REFERENCES = []

    def __init__(self, target, args):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.domain = get_domain(self.target)
        self.args = args
        self.session = build_session(args)
        self.timeout = getattr(args, 'timeout', 10)
        self.verbose = getattr(args, 'verbose', False)
        self.findings = []
        self.vulnerable = False

    def run(self):
        """Override this in each module. Must return a dict."""
        raise NotImplementedError

    def result(self, vulnerable, summary, findings=None):
        return {
            "vulnerable": vulnerable,
            "summary": summary,
            "findings": findings or self.findings,
        }

    def log(self, msg, level="info"):
        if self.verbose or level in ("warn", "vuln"):
            icons = {"info": "·", "warn": "!", "vuln": "✗", "ok": "✓"}
            clrs = {"info": "dim", "warn": "yellow", "vuln": "red", "ok": "green"}
            print(f"  {color(icons.get(level,'·'), clrs.get(level,'dim'))} {msg}")

    def add_finding(self, finding):
        self.findings.append(finding)
        self.vulnerable = True
