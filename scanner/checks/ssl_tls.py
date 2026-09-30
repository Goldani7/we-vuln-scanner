"""TLS/SSL: versão do protocolo e validade do certificado.

Vulnerabilidade: TLS 1.0/1.1 e SSL antigos têm falhas conhecidas; certificado expirado ou
inválido treina usuários a ignorar avisos.
Exemplo: POODLE (SSLv3) e BEAST (TLS 1.0) permitem a um atacante na rede decifrar trechos do tráfego.
Ref.: OWASP A02:2021 (Cryptographic Failures); CWE-326, CWE-295.
"""
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..finding import Finding, Severity

CHECK = "ssl_tls"
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_ssl_tls(url: str, timeout: int = 8) -> list:
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    if parsed.scheme != "https":
        return [Finding(
            CHECK, Severity.INFO, "Alvo não usa HTTPS",
            "A verificação TLS foi ignorada porque a URL não é https://.",
        )]

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as e:
        return [Finding(
            CHECK, Severity.HIGH, "Certificado TLS inválido",
            str(e),
            "Use um certificado válido emitido por uma CA confiável.",
        )]
    except (OSError, ssl.SSLError) as e:
        return [Finding(
            CHECK, Severity.INFO, "Não foi possível verificar TLS",
            f"Falha de conexão em {host}:{port}: {e}",
        )]

    findings = []
    if version in WEAK_PROTOCOLS:
        findings.append(Finding(
            CHECK, Severity.HIGH, f"Protocolo fraco negociado: {version}",
            f"O servidor negociou {version}.",
            "Desabilite protocolos antigos e exija TLS 1.2 ou superior.",
            {"protocol": version},
        ))
    else:
        findings.append(Finding(
            CHECK, Severity.INFO, f"Protocolo TLS: {version}",
            metadata={"protocol": version},
        ))

    not_after = cert.get("notAfter") if cert else None
    if not_after:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        meta = {"expires": expires.isoformat(), "days_left": days}
        if days < 0:
            findings.append(Finding(
                CHECK, Severity.HIGH, "Certificado expirado",
                f"Expirou em {expires:%Y-%m-%d}.",
                "Renove o certificado imediatamente.", meta,
            ))
        elif days < 15:
            findings.append(Finding(
                CHECK, Severity.MEDIUM, "Certificado expira em breve",
                f"Expira em {days} dia(s) ({expires:%Y-%m-%d}).",
                "Renove o certificado e considere renovação automática.", meta,
            ))
        else:
            findings.append(Finding(
                CHECK, Severity.INFO, "Certificado válido",
                f"Expira em {days} dia(s) ({expires:%Y-%m-%d}).", metadata=meta,
            ))
    return findings
