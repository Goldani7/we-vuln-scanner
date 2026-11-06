"""Anti-SSRF validation.

Vulnerability: SSRF (Server-Side Request Forgery) — if the service makes requests to any URL
the user sends, an attacker uses it to reach the internal network or cloud metadata.
Example: url=http://169.254.169.254/latest/meta-data/ exposes IAM credentials on AWS.
Ref.: OWASP A10:2021 (SSRF); CWE-918.
Limitation: the check resolves DNS at validation time; DNS rebinding is still possible.
"""
import ipaddress
import socket
from urllib.parse import urlparse


def _is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def validate_public_url(url: str) -> str:
    """Returns the URL if it's http(s) pointing to a public host; raises ValueError otherwise."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("The URL must be http:// or https:// with a valid host")
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Local targets are not allowed")

    try:
        ips = [host] if ipaddress.ip_address(host) else []
    except ValueError:
        try:
            ips = [i[4][0] for i in socket.getaddrinfo(host, None)]
        except socket.gaierror:
            ips = []  # doesn't resolve: the scan will fail to connect

    if any(_is_blocked(ip) for ip in ips):
        raise ValueError("Targets on private/internal IPs are not allowed")
    return url
