"""Arquivo de escopo (--scope): o que o scanner tem permissão de tocar.

Formato, uma entrada por linha (`#` começa comentário):

    exemplo.com          # apenas este host
    *.exemplo.com        # qualquer subdomínio (não inclui exemplo.com)
    10.0.0.0/24          # faixa de IPs (casa com alvos dados como IP)
    203.0.113.7          # IP único
    !admin.exemplo.com   # exclusão explícita (vence qualquer inclusão)

Regras: o que não está listado está FORA do escopo, e exclusões sempre vencem. O escopo é imposto no
cliente HTTP a cada requisição, inclusive nos redirecionamentos, então um 302 para um host não autorizado é
bloqueado em vez de seguido. Hosts de serviços públicos passivos usados pela ferramenta (crt.sh) não são o
alvo e ficam fora desta checagem.
Limitação: entradas CIDR só casam com alvos informados como IP; um nome de domínio não é resolvido para
verificar se cai numa faixa.
"""
import ipaddress
import re
from dataclasses import dataclass, field

_HOST = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


class ScopeError(Exception):
    """Arquivo de escopo ilegível ou com entrada inválida."""


@dataclass
class Scope:
    hosts: set = field(default_factory=set)
    wildcards: set = field(default_factory=set)        # sufixos de "*.dominio"
    networks: list = field(default_factory=list)
    ex_hosts: set = field(default_factory=set)
    ex_wildcards: set = field(default_factory=set)
    ex_networks: list = field(default_factory=list)
    source: str = ""

    def __bool__(self) -> bool:
        return bool(self.hosts or self.wildcards or self.networks)

    @staticmethod
    def _match(host: str, hosts, wildcards, networks) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host in hosts or any(host.endswith("." + w) for w in wildcards)
        return str(ip) in hosts or any(ip in n for n in networks)

    def allows(self, host: str) -> bool:
        host = (host or "").strip().lower().rstrip(".").strip("[]")
        if not host:
            return False
        if self._match(host, self.ex_hosts, self.ex_wildcards, self.ex_networks):
            return False
        return self._match(host, self.hosts, self.wildcards, self.networks)


def parse_scope(text: str, source: str = "") -> Scope:
    scope = Scope(source=source)
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        exclude = line.startswith("!")
        entry = line[1:].strip() if exclude else line
        hosts, wildcards, networks = ((scope.ex_hosts, scope.ex_wildcards, scope.ex_networks) if exclude
                                      else (scope.hosts, scope.wildcards, scope.networks))
        try:
            if "/" in entry:
                networks.append(ipaddress.ip_network(entry, strict=False))
            else:
                try:
                    hosts.add(str(ipaddress.ip_address(entry)))
                except ValueError:
                    if not _HOST.match(entry):
                        raise ValueError("host inválido")
                    if entry.startswith("*."):
                        wildcards.add(entry[2:])
                    else:
                        hosts.add(entry)
        except ValueError as e:
            raise ScopeError(f"{source or 'escopo'}:{lineno}: entrada inválida {raw.strip()!r} ({e})") from e
    if not scope:
        raise ScopeError(f"{source or 'escopo'}: nenhuma entrada de inclusão; o escopo está vazio")
    return scope


def load_scope(path: str) -> Scope:
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_scope(fh.read(), path)
    except OSError as e:
        raise ScopeError(f"não foi possível ler o escopo '{path}': {e.strerror or e}") from e
