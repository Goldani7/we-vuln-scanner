"""Scope file (--scope): what the scanner is allowed to touch.

Format, one entry per line (`#` starts a comment):

    example.com          # this host only
    *.example.com        # any subdomain (does not include example.com)
    10.0.0.0/24          # IP range (matches targets given as an IP)
    203.0.113.7          # single IP
    !admin.example.com   # explicit exclusion (always wins over any inclusion)

Rules: anything not listed is OUT of scope, and exclusions always win. The scope is enforced on
the HTTP client for every request, including redirects, so a 302 to an unauthorized host is
blocked instead of followed. Hosts of passive public services used by the tool (crt.sh) are not
the target and are exempt from this check.
Limitation: CIDR entries only match targets given as an IP; a domain name is never resolved to
check whether it falls inside a range.
"""
import ipaddress
import re
from dataclasses import dataclass, field

_HOST = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


class ScopeError(Exception):
    """Scope file unreadable or with an invalid entry."""


@dataclass
class Scope:
    hosts: set = field(default_factory=set)
    wildcards: set = field(default_factory=set)        # suffixes of "*.domain"
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
                        raise ValueError("invalid host") from None
                    if entry.startswith("*."):
                        wildcards.add(entry[2:])
                    else:
                        hosts.add(entry)
        except ValueError as e:
            raise ScopeError(f"{source or 'scope'}:{lineno}: invalid entry {raw.strip()!r} ({e})") from e
    if not scope:
        raise ScopeError(f"{source or 'scope'}: no inclusion entry found; the scope is empty")
    return scope


def load_scope(path: str) -> Scope:
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_scope(fh.read(), path)
    except OSError as e:
        raise ScopeError(f"could not read scope file '{path}': {e.strerror or e}") from e
