"""Network guard: refuse to talk to private/internal addresses (anti-SSRF).

Used by the HTTP client (`ScanConfig.public_only`) on EVERY request, including each redirect hop,
and by the API's URL validation. Checking only the URL the user typed is not enough: a public host
can answer `302 -> http://169.254.169.254/...` and the client would happily follow it.

Limitation: the hostname is resolved here and again by the HTTP stack when it connects, so a
malicious DNS server could still flip the answer in between (DNS rebinding). Run the API behind an
egress firewall that blocks internal ranges if you need that closed completely.
"""
import asyncio
import ipaddress
import socket


def is_blocked_ip(ip: str) -> bool:
    """True for addresses a public scanner has no business reaching."""
    addr = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped  # ::ffff:127.0.0.1 is still loopback
    return (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
            or addr.is_multicast or addr.is_unspecified or not addr.is_global)


def is_local_name(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host == "localhost" or host.endswith(".localhost")


def _literal_ip(host: str):
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


def resolve_blocked(host: str):
    """Sync check. Returns the offending IP/name if `host` is internal, else None.
    Hosts that don't resolve return None (the request will simply fail to connect)."""
    if is_local_name(host):
        return host
    ip = _literal_ip(host)
    ips = [ip] if ip else _resolve(host)
    return next((i for i in ips if is_blocked_ip(i)), None)


def _resolve(host: str) -> list:
    try:
        return [i[4][0] for i in socket.getaddrinfo(host, None)]
    except socket.gaierror:
        return []


async def resolve_blocked_async(host: str):
    if is_local_name(host):
        return host
    ip = _literal_ip(host)
    if ip:
        return ip if is_blocked_ip(ip) else None
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except socket.gaierror:
        return None
    return next((i[4][0] for i in infos if is_blocked_ip(i[4][0])), None)
