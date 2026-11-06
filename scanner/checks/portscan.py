"""TCP-connect port scan (ACTIVE check: only runs with --allow-active and inside --scope).

Method: a simple TCP connect() across a short list of common service ports — no SYN scan, no full
65535-port sweep, and no payload sent at all; at most it reads (never writes) the first bytes the
service itself sends first (its banner), the same way SSH, FTP and SMTP already do with any TCP
client. No data is ever sent to the services found.
Why: a database, RDP or VNC port directly reachable from the internet is, on its own, a high-risk
finding — nothing needs to be exploited for that to matter.
Default limits: ~25 ports, rate and concurrency controlled by --rate/--concurrency (like the rest
of the scan), a short per-port timeout. Use --ports to narrow it further.
Ref.: CWE-668 (Exposure of Resource to Wrong Sphere); OWASP WSTG-INFO-02.
"""
import asyncio
import re

from ..finding import Finding, Severity
from ..http import RateLimiter

CHECK = "portscan"
BANNER_READ_TIMEOUT = 0.6
BANNER_MAX_BYTES = 160
MAX_CONCURRENCY = 20
DEFAULT_CONNECT_TIMEOUT = 2.5

# Short, deliberate list: common services whose direct exposure already matters on its own.
# (port, description, severity if found open, reason)
PORT_TABLE = {
    21: ("FTP", Severity.MEDIUM, "Transmits credentials in plain text."),
    22: ("SSH", Severity.INFO, "Remote access; normal if well administered (keys, fail2ban)."),
    23: ("Telnet", Severity.HIGH, "Unencrypted protocol; credentials in plain text."),
    25: ("SMTP", Severity.INFO, "Mail server; see also --mode email."),
    53: ("DNS", Severity.INFO, "DNS server; an open resolver can be abused for amplification attacks."),
    80: ("HTTP", Severity.INFO, "Expected on a web server."),
    110: ("POP3", Severity.LOW, "Prefer POP3S (995) with TLS."),
    111: ("RPCbind", Severity.MEDIUM, "Tends to expose other internal RPC services."),
    139: ("NetBIOS", Severity.MEDIUM, "Legacy file sharing, a known attack surface."),
    143: ("IMAP", Severity.LOW, "Prefer IMAPS (993) with TLS."),
    389: ("LDAP", Severity.MEDIUM, "Corporate directory; confirm it needs to be on the internet."),
    443: ("HTTPS", Severity.INFO, "Expected on a web server."),
    445: ("SMB", Severity.HIGH, "Historical target of worms and network exploits (e.g. EternalBlue)."),
    1433: ("Microsoft SQL Server", Severity.HIGH, "Database directly reachable from the internet."),
    1521: ("Oracle Database", Severity.HIGH, "Database directly reachable from the internet."),
    2375: ("Docker (no TLS)", Severity.CRITICAL, "An unauthenticated Docker API is equivalent to remote code execution."),
    3000: ("Generic app (dev)", Severity.LOW, "Common development-server port; confirm it isn't production."),
    3306: ("MySQL/MariaDB", Severity.HIGH, "Database directly reachable from the internet."),
    3389: ("RDP", Severity.MEDIUM, "Windows remote access; a common target for brute force and exploits."),
    5000: ("Generic app (dev)", Severity.LOW, "Common development-server port; confirm it isn't production."),
    5432: ("PostgreSQL", Severity.HIGH, "Database directly reachable from the internet."),
    5900: ("VNC", Severity.HIGH, "Remote access, often without a strong password."),
    6379: ("Redis", Severity.HIGH, "Often unauthenticated by default."),
    8080: ("Alternate HTTP", Severity.INFO, "Common on proxies/apps; confirm it should be public."),
    8443: ("Alternate HTTPS", Severity.INFO, "Common on admin panels; confirm it should be public."),
    9200: ("Elasticsearch", Severity.HIGH, "Often unauthenticated; exposes the indexed data."),
    27017: ("MongoDB", Severity.HIGH, "Often unauthenticated by default."),
}
DEFAULT_PORTS = sorted(PORT_TABLE)
REFERENCES = ["https://owasp.org/www-project-web-security-testing-guide/"]
_PRINTABLE = re.compile(rb"[^\x09\x0a\x0d\x20-\x7e]")


def _clean_banner(raw: bytes) -> str:
    return _PRINTABLE.sub(b"?", raw[:BANNER_MAX_BYTES]).decode("ascii", "replace").strip()


async def _probe_port(host: str, port: int, timeout: float) -> str:
    """None if closed/filtered; a string (banner, possibly empty) if connect() succeeded."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        try:
            data = await asyncio.wait_for(reader.read(BANNER_MAX_BYTES), timeout=BANNER_READ_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            data = b""
        return _clean_banner(data)
    finally:
        writer.close()


async def scan_ports(host: str, ports, rate: float, concurrency: int, timeout: float) -> dict:
    """{port: banner} of the open ports, honoring rate/concurrency."""
    limiter = RateLimiter(rate)
    sem = asyncio.Semaphore(max(1, min(concurrency, MAX_CONCURRENCY)))

    async def one(port):
        async with sem:
            await limiter.wait()
            banner = await _probe_port(host, port, timeout)
            return port, banner

    results = await asyncio.gather(*(one(p) for p in ports))
    return {port: banner for port, banner in results if banner is not None}


async def check_portscan(ctx) -> list:
    host = ctx.domain
    if not host:
        return [Finding(CHECK, Severity.INFO, "Port scan not run: target has no resolvable hostname",
                        rule_id="portscan.skipped")]
    # Defense in depth: the HTTP client already enforces --scope on every request; this check
    # uses raw sockets, so the check is repeated explicitly before opening any connection.
    scope = ctx.config.scope
    if scope is not None and not scope.allows(host):
        return [Finding(
            CHECK, Severity.INFO, "Port scan blocked: target is out of scope", f"host: {host}",
            "Add the host to the scope file to authorize the port scan.",
            rule_id="portscan.out_of_scope", confidence="high")]

    ports = getattr(ctx.config, "ports", None) or DEFAULT_PORTS
    timeout = min(ctx.config.timeout, DEFAULT_CONNECT_TIMEOUT)
    try:
        open_ports = await scan_ports(host, ports, ctx.config.rate, ctx.config.concurrency, timeout)
    except OSError as e:
        return [Finding(CHECK, Severity.INFO, "Port scan failed: could not resolve/reach the host",
                        f"{type(e).__name__}: {e}", rule_id="portscan.error")]

    if not open_ports:
        return [Finding(
            CHECK, Severity.INFO, "No common port found open",
            f"{len(ports)} ports tested (TCP connect): {', '.join(map(str, ports))}.",
            rule_id="portscan.none")]

    findings = []
    for port, banner in sorted(open_ports.items()):
        name, severity, reason = PORT_TABLE.get(port, ("unknown", Severity.INFO, ""))
        evidence = f"{host}:{port}/tcp open (TCP connect succeeded)"
        if banner:
            evidence += f"\nBanner: {banner}"
        findings.append(Finding(
            CHECK, severity, f"Port {port}/tcp open ({name})", reason, _remediation(port, name),
            {"port": port, "service": name, "banner": banner or None},
            evidence=evidence, cwe="CWE-668", references=REFERENCES,
            confidence="high" if banner else "medium", rule_id=f"portscan.port-{port}"))

    findings.append(Finding(
        CHECK, Severity.INFO, f"{len(open_ports)} of {len(ports)} common ports open",
        "TCP-connect scan summary.",
        metadata={"open_ports": sorted(open_ports)},
        evidence=", ".join(f"{p}/tcp" for p in sorted(open_ports)),
        confidence="high", rule_id="portscan.summary"))
    return findings


def _remediation(port: int, name: str) -> str:
    if port in (3306, 5432, 1433, 1521, 6379, 9200, 27017, 2375):
        return (f"Restrict {name} to an internal network/VPN or to specific IPs via a firewall; "
               "never expose a database or admin API directly to the internet.")
    if port in (23, 445, 139, 111):
        return f"Disable {name} if not needed, or restrict access via firewall/VPN."
    if port in (3389, 5900):
        return f"Restrict {name} by VPN/IP and require strong authentication (MFA); avoid exposing it directly to the internet."
    return f"Confirm whether {name} needs to be publicly reachable; otherwise restrict it via a firewall."
