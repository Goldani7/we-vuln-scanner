"""Anti-SSRF validation for the API.

Vulnerability: SSRF (Server-Side Request Forgery) — if the service makes requests to any URL
the user sends, an attacker uses it to reach the internal network or cloud metadata.
Example: url=http://169.254.169.254/latest/meta-data/ exposes IAM credentials on AWS.
Ref.: OWASP A10:2021 (SSRF); CWE-918.

This validates the URL the user typed (fast, friendly 422). The real enforcement happens in the HTTP
client (`ScanConfig.public_only`), which re-checks every request and every redirect hop. See
scanner/netguard.py for the remaining DNS-rebinding limitation.
"""
from urllib.parse import urlparse

from scanner.netguard import resolve_blocked


def validate_public_url(url: str) -> str:
    """Returns the URL if it's http(s) pointing to a public host; raises ValueError otherwise."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("The URL must be http:// or https:// with a valid host")
    host = parsed.hostname.lower().rstrip(".")
    if resolve_blocked(host):
        raise ValueError("Local, private or internal targets are not allowed")
    return url
