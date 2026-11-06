"""TLS/SSL: protocol version and certificate validity.

Vulnerability: old TLS 1.0/1.1 and SSL have known flaws; an expired or invalid certificate
trains users to ignore warnings.
Example: POODLE (SSLv3) and BEAST (TLS 1.0) let a network attacker decrypt parts of the traffic.
Ref.: OWASP A02:2021 (Cryptographic Failures); CWE-326, CWE-295.
"""
import socket
import ssl
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..finding import Finding, Severity

CHECK = "ssl_tls"
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)  # TLSv1/1.1 are deprecated, but that's what we probe
    PROBE_VERSIONS = {
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }


def supported_protocols(host: str, port: int, timeout: int = 8) -> list:
    """TLS versions the server accepts, tested one at a time (best effort).

    Versions the local OpenSSL can't offer are omitted: absence from the list means "not
    supported or not testable", never a guarantee.
    """
    supported = []
    for name, version in PROBE_VERSIONS.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # only probing the handshake; the certificate is checked below
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ctx.maximum_version = version
            if version < ssl.TLSVersion.TLSv1_2:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    if tls.version() == name:  # only counts if the negotiated version is the one probed
                        supported.append(name)
        except (OSError, ssl.SSLError, ValueError):
            continue
    return supported


def check_ssl_tls(url: str, timeout: int = 8) -> list:
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    if parsed.scheme != "https":
        return [Finding(
            CHECK, Severity.INFO, "Target does not use HTTPS",
            "The TLS check was skipped because the URL is not https://.",
        )]

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as e:
        return [Finding(
            CHECK, Severity.HIGH, "Invalid TLS certificate",
            str(e),
            "Use a valid certificate issued by a trusted CA.",
        )]
    except (OSError, ssl.SSLError) as e:
        return [Finding(
            CHECK, Severity.INFO, "Could not verify TLS",
            f"Connection failure to {host}:{port}: {e}",
        )]

    findings = []
    if version in WEAK_PROTOCOLS:
        findings.append(Finding(
            CHECK, Severity.HIGH, f"Weak protocol negotiated: {version}",
            f"The server negotiated {version}.",
            "Disable old protocols and require TLS 1.2 or higher.",
            {"protocol": version},
        ))
    else:
        findings.append(Finding(
            CHECK, Severity.INFO, f"TLS protocol: {version}",
            metadata={"protocol": version},
        ))

    supported = supported_protocols(host, port, timeout)
    weak = [p for p in supported if p in WEAK_PROTOCOLS]
    if weak:
        findings.append(Finding(
            CHECK, Severity.MEDIUM, f"Server accepts obsolete protocols: {', '.join(weak)}",
            f"Versions accepted during the handshake: {', '.join(supported)}.",
            "Disable TLS 1.0 and 1.1 on the server/load balancer.",
            {"supported": supported},
        ))
    elif supported:
        findings.append(Finding(
            CHECK, Severity.INFO, f"TLS versions accepted: {', '.join(supported)}",
            metadata={"supported": supported},
        ))

    not_after = cert.get("notAfter") if cert else None
    if not_after:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        meta = {"expires": expires.isoformat(), "days_left": days}
        if days < 0:
            findings.append(Finding(
                CHECK, Severity.HIGH, "Expired certificate",
                f"Expired on {expires:%Y-%m-%d}.",
                "Renew the certificate immediately.", meta,
            ))
        elif days < 15:
            findings.append(Finding(
                CHECK, Severity.MEDIUM, "Certificate expiring soon",
                f"Expires in {days} day(s) ({expires:%Y-%m-%d}).",
                "Renew the certificate and consider automatic renewal.", meta,
            ))
        else:
            findings.append(Finding(
                CHECK, Severity.INFO, "Valid certificate",
                f"Expires in {days} day(s) ({expires:%Y-%m-%d}).", metadata=meta,
            ))
    return findings
