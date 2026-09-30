"""Validação anti-SSRF.

Vulnerabilidade: SSRF (Server-Side Request Forgery) — se o serviço faz requisições para qualquer URL
enviada pelo usuário, o atacante o usa para alcançar rede interna ou metadados de cloud.
Exemplo: url=http://169.254.169.254/latest/meta-data/ expõe credenciais IAM na AWS.
Ref.: OWASP A10:2021 (SSRF); CWE-918.
Limitação: a checagem resolve o DNS no momento da validação; DNS rebinding ainda é possível.
"""
import ipaddress
import socket
from urllib.parse import urlparse


def _is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def validate_public_url(url: str) -> str:
    """Retorna a URL se for http(s) apontando para host público; levanta ValueError caso contrário."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("A URL deve ser http:// ou https:// com um host válido")
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Alvos locais não são permitidos")

    try:
        ips = [host] if ipaddress.ip_address(host) else []
    except ValueError:
        try:
            ips = [i[4][0] for i in socket.getaddrinfo(host, None)]
        except socket.gaierror:
            ips = []  # não resolve: o scan falhará ao conectar

    if any(_is_blocked(ip) for ip in ips):
        raise ValueError("Alvos em IPs privados/internos não são permitidos")
    return url
