import re
import requests
import urllib.parse
from utils.banner import color


def validate_target(target):
    """Validate and normalize target URL."""
    if not target:
        return False
    if re.match(r'^https?://', target):
        return True
    if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', target):
        return True
    return False


def normalize_url(target):
    """Ensure target has a scheme."""
    if not re.match(r'^https?://', target):
        return f"http://{target}"
    return target


def build_session(args):
    """Build a requests session with proxy, cookies, headers from args."""
    session = requests.Session()
    session.verify = False  # Allow self-signed certs in pentest environments

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if hasattr(args, 'proxy') and args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    if hasattr(args, 'cookies') and args.cookies:
        for cookie in args.cookies.split(";"):
            if "=" in cookie:
                k, v = cookie.strip().split("=", 1)
                session.cookies.set(k.strip(), v.strip())

    if hasattr(args, 'headers') and args.headers:
        import json
        try:
            extra = json.loads(args.headers)
            session.headers.update(extra)
        except Exception:
            pass

    session.headers.update({
        "User-Agent": "Mozilla/5.0 (VulnScan/1.0 PentestFramework)"
    })

    return session


def safe_get(session, url, timeout=10, **kwargs):
    """Safe GET request with timeout and error handling."""
    try:
        return session.get(url, timeout=timeout, allow_redirects=True, **kwargs)
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


def safe_post(session, url, data=None, json=None, timeout=10, **kwargs):
    """Safe POST request with timeout and error handling."""
    try:
        return session.post(url, data=data, json=json, timeout=timeout, **kwargs)
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


def inject_param(url, param, payload):
    """Inject a payload into a URL parameter."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def extract_params(url):
    """Extract query parameters from a URL."""
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query).keys())


def get_domain(url):
    """Get just the domain from a URL."""
    return urllib.parse.urlparse(normalize_url(url)).netloc


def get_base_url(url):
    """Get scheme + domain."""
    p = urllib.parse.urlparse(normalize_url(url))
    return f"{p.scheme}://{p.netloc}"


def explain(title, description, references=None):
    """Print a beginner-friendly explanation of a vulnerability."""
    print(color(f"\n  📚 WHAT IS {title.upper()}?", "yellow"))
    print(f"  {description}")
    if references:
        print(color("  📖 Learn more:", "dim"))
        for ref in references:
            print(color(f"     → {ref}", "dim"))
