"""Port scan TCP connect (check ATIVO: só roda com --allow-active e dentro do --scope).

Método: connect() TCP simples numa lista curta de portas de serviços comuns, sem SYN scan, sem
varredura completa de 65535 portas e sem enviar payload nenhum — no máximo lê (nunca escreve) os
primeiros bytes que o próprio serviço envia primeiro (banner), como SSH, FTP e SMTP já fazem com
qualquer cliente TCP. Nenhum dado é enviado aos serviços encontrados.
Por quê: uma porta de banco de dados, RDP ou VNC alcançável diretamente da internet é, sozinha, um
achado de alto risco — não é preciso explorar nada para isso importar.
Limites por padrão: ~25 portas, taxa e concorrência controladas por --rate/--concurrency (como o
resto do scan), timeout curto por porta. Use --ports para restringir ainda mais.
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

# Lista curta e intencional: serviços comuns cuja exposição direta já é relevante por si só.
# (porta, descrição, severidade se encontrada aberta, razão)
PORT_TABLE = {
    21: ("FTP", Severity.MEDIUM, "Transmite credenciais em texto claro."),
    22: ("SSH", Severity.INFO, "Acesso remoto; normal se bem administrado (chaves, fail2ban)."),
    23: ("Telnet", Severity.HIGH, "Protocolo sem criptografia; credenciais em texto claro."),
    25: ("SMTP", Severity.INFO, "Servidor de e-mail; veja também o modo --mode email."),
    53: ("DNS", Severity.INFO, "Servidor DNS; um resolver aberto pode ser abusado em ataques de amplificação."),
    80: ("HTTP", Severity.INFO, "Esperado num servidor web."),
    110: ("POP3", Severity.LOW, "Prefira POP3S (995) com TLS."),
    111: ("RPCbind", Severity.MEDIUM, "Costuma expor outros serviços RPC internos."),
    139: ("NetBIOS", Severity.MEDIUM, "Compartilhamento de arquivos legado, superfície de ataque conhecida."),
    143: ("IMAP", Severity.LOW, "Prefira IMAPS (993) com TLS."),
    389: ("LDAP", Severity.MEDIUM, "Diretório corporativo; confirme se precisa estar na internet."),
    443: ("HTTPS", Severity.INFO, "Esperado num servidor web."),
    445: ("SMB", Severity.HIGH, "Alvo histórico de worms e exploits de rede (ex.: EternalBlue)."),
    1433: ("Microsoft SQL Server", Severity.HIGH, "Banco de dados alcançável diretamente da internet."),
    1521: ("Oracle Database", Severity.HIGH, "Banco de dados alcançável diretamente da internet."),
    2375: ("Docker (sem TLS)", Severity.CRITICAL, "API do Docker sem autenticação equivale a execução remota de comandos."),
    3000: ("App genérica (dev)", Severity.LOW, "Porta comum de servidor de desenvolvimento; confirme se é produção."),
    3306: ("MySQL/MariaDB", Severity.HIGH, "Banco de dados alcançável diretamente da internet."),
    3389: ("RDP", Severity.MEDIUM, "Acesso remoto Windows; alvo comum de força bruta e exploits."),
    5000: ("App genérica (dev)", Severity.LOW, "Porta comum de servidor de desenvolvimento; confirme se é produção."),
    5432: ("PostgreSQL", Severity.HIGH, "Banco de dados alcançável diretamente da internet."),
    5900: ("VNC", Severity.HIGH, "Acesso remoto frequentemente sem senha forte."),
    6379: ("Redis", Severity.HIGH, "Frequentemente sem autenticação por padrão."),
    8080: ("HTTP alternativo", Severity.INFO, "Comum em proxies/apps; confirme se deveria ser público."),
    8443: ("HTTPS alternativo", Severity.INFO, "Comum em painéis administrativos; confirme se deveria ser público."),
    9200: ("Elasticsearch", Severity.HIGH, "Frequentemente sem autenticação; expõe os dados indexados."),
    27017: ("MongoDB", Severity.HIGH, "Frequentemente sem autenticação por padrão."),
}
DEFAULT_PORTS = sorted(PORT_TABLE)
REFERENCES = ["https://owasp.org/www-project-web-security-testing-guide/"]
_PRINTABLE = re.compile(rb"[^\x09\x0a\x0d\x20-\x7e]")


def _clean_banner(raw: bytes) -> str:
    return _PRINTABLE.sub(b"?", raw[:BANNER_MAX_BYTES]).decode("ascii", "replace").strip()


async def _probe_port(host: str, port: int, timeout: float) -> str:
    """None se fechada/filtrada; string (banner, possivelmente vazia) se o connect() teve sucesso."""
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
    """{porta: banner} das portas abertas, respeitando rate/concorrência."""
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
        return [Finding(CHECK, Severity.INFO, "Port scan não executado: alvo sem hostname resolvível",
                        rule_id="portscan.skipped")]
    # Defesa em profundidade: o cliente HTTP já impõe o --scope a cada requisição; aqui usamos
    # sockets crus, então a checagem é repetida explicitamente antes de abrir qualquer conexão.
    scope = ctx.config.scope
    if scope is not None and not scope.allows(host):
        return [Finding(
            CHECK, Severity.INFO, "Port scan bloqueado: alvo fora do escopo", f"host: {host}",
            "Adicione o host ao arquivo de escopo para autorizar o port scan.",
            rule_id="portscan.out_of_scope", confidence="high")]

    ports = getattr(ctx.config, "ports", None) or DEFAULT_PORTS
    timeout = min(ctx.config.timeout, DEFAULT_CONNECT_TIMEOUT)
    try:
        open_ports = await scan_ports(host, ports, ctx.config.rate, ctx.config.concurrency, timeout)
    except OSError as e:
        return [Finding(CHECK, Severity.INFO, "Port scan falhou: não foi possível resolver/alcançar o host",
                        f"{type(e).__name__}: {e}", rule_id="portscan.error")]

    if not open_ports:
        return [Finding(
            CHECK, Severity.INFO, "Nenhuma porta comum aberta encontrada",
            f"{len(ports)} portas testadas (TCP connect): {', '.join(map(str, ports))}.",
            rule_id="portscan.none")]

    findings = []
    for port, banner in sorted(open_ports.items()):
        name, severity, reason = PORT_TABLE.get(port, ("desconhecido", Severity.INFO, ""))
        evidence = f"{host}:{port}/tcp aberto (TCP connect bem-sucedido)"
        if banner:
            evidence += f"\nBanner: {banner}"
        findings.append(Finding(
            CHECK, severity, f"Porta {port}/tcp aberta ({name})", reason, _remediation(port, name),
            {"port": port, "service": name, "banner": banner or None},
            evidence=evidence, cwe="CWE-668", references=REFERENCES,
            confidence="high" if banner else "medium", rule_id=f"portscan.port-{port}"))

    findings.append(Finding(
        CHECK, Severity.INFO, f"{len(open_ports)} de {len(ports)} portas comuns abertas",
        "Resumo da varredura TCP connect.",
        metadata={"open_ports": sorted(open_ports)},
        evidence=", ".join(f"{p}/tcp" for p in sorted(open_ports)),
        confidence="high", rule_id="portscan.summary"))
    return findings


def _remediation(port: int, name: str) -> str:
    if port in (3306, 5432, 1433, 1521, 6379, 9200, 27017, 2375):
        return (f"Restrinja {name} a uma rede interna/VPN ou a IPs específicos via firewall; "
               "nunca exponha um banco de dados ou API de administração direto à internet.")
    if port in (23, 445, 139, 111):
        return f"Desabilite {name} se não for necessário, ou restrinja o acesso por firewall/VPN."
    if port in (3389, 5900):
        return f"Restrinja {name} por VPN/IP e exija autenticação forte (MFA); evite expor diretamente à internet."
    return f"Confirme se {name} precisa estar acessível publicamente; caso contrário, restrinja por firewall."
