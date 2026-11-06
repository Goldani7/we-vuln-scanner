import argparse
import logging
import os
import sys

from .baseline import BaselineError, annotate, compare, load_baseline
from .core import MODES, REGISTRY, extract_domain, scan_target
from .http import DEFAULT_USER_AGENT, ScanConfig
from .scope import ScopeError, load_scope
from .report import to_html, to_json, to_markdown, to_sarif, to_text

EXTENSION_FORMATS = {".json": "json", ".html": "html", ".htm": "html", ".md": "md",
                     ".markdown": "md", ".sarif": "sarif"}
FAIL_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": None}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web-vuln-scanner",
        description="Scanner passivo de vulnerabilidades web e de e-mail/DNS. "
                    "Use apenas em alvos autorizados.",
    )
    p.add_argument("target_pos", nargs="?", metavar="target",
                   help="alvo (URL ou domínio); alternativa posicional a --target")
    p.add_argument("-t", "--target", help="URL ou domínio alvo (ex.: https://exemplo.com ou exemplo.com)")
    p.add_argument("-m", "--mode", choices=MODES, default="full",
                   help="web = checks HTTP/TLS; email = SPF/DKIM/DMARC/DNSBL; "
                        "recon = subdomínios (crt.sh); full = todos (default)")
    p.add_argument("-o", "--output",
                   help="salva o relatório neste arquivo; o formato vem da extensão "
                        "(.json, .md, .sarif, .html)")
    p.add_argument("-f", "--format", choices=["text", "json", "md", "sarif", "html"],
                   help="formato do relatório (default: text no console, ou pela extensão de --output)")
    p.add_argument("-v", "--verbose", action="store_true", help="mostra logs de depuração")
    p.add_argument("--checks", help="checks web separados por vírgula (default: todos; veja --list-checks)")
    p.add_argument("--list-checks", action="store_true", help="lista os checks disponíveis (inclui plugins) e sai")
    p.add_argument("--scope", metavar="ESCOPO.txt",
                   help="arquivo com os alvos autorizados; toda requisição fora dele é bloqueada, "
                        "inclusive redirecionamentos")
    p.add_argument("--allow-active", action="store_true",
                   help="permite checks ativos/intrusivos; exige --scope e autorização expressa do dono do alvo")
    p.add_argument("--ports", metavar="22,80,443",
                   help="portas para o check 'portscan' (default: ~25 portas de serviços comuns)")
    p.add_argument("--baseline", metavar="RELATORIO.json",
                   help="compara com um relatório JSON anterior e marca achados novos/resolvidos")
    p.add_argument("--new-only", action="store_true",
                   help="com --baseline: mostra e avalia --fail-on apenas nos achados novos")
    p.add_argument("--no-info", action="store_true", help="oculta findings informativos")
    p.add_argument("--timeout", type=float, default=10, help="timeout por requisição, em segundos")

    net = p.add_argument_group("rede e desempenho")
    net.add_argument("--rate", type=float, default=10,
                     help="máximo de requisições por segundo no total; 0 = sem limite (default: 10)")
    net.add_argument("--concurrency", type=int, default=10, help="requisições simultâneas (default: 10)")
    net.add_argument("--retries", type=int, default=2,
                     help="retentativas em timeout/429/5xx, respeitando Retry-After (default: 2)")
    net.add_argument("--proxy", help="proxy http://host:porta ou socks5://host:porta (ex.: Burp)")
    net.add_argument("-H", "--header", action="append", default=[], metavar="'Nome: valor'",
                     help="header extra em todas as requisições (repetível)")
    net.add_argument("--user-agent", default=DEFAULT_USER_AGENT,
                     help="User-Agent (default identifica a ferramenta)")
    net.add_argument("--insecure", action="store_true",
                     help="não valida o certificado TLS do alvo (só para diagnóstico)")
    p.add_argument("--fail-on", choices=list(FAIL_LEVELS), default="high",
                   help="exit code 2 se houver achado desta severidade ou maior (default: high)")
    return p


def _format_check_list() -> str:
    rows = [f"{'CHECK':<16}{'CATEGORIA':<10}{'ATIVO':<7}{'ORIGEM':<22}DESCRIÇÃO"]
    for name in REGISTRY.names(include_active=True):
        s = REGISTRY.get(name)
        rows.append(f"{s.name:<16}{s.category:<10}{'sim' if s.active else 'não':<7}{s.source:<22}"
                    f"{s.description[:70]}")
    return "\n".join(rows)


def _parse_ports(raw):
    try:
        ports = [int(p.strip()) for p in raw.split(",") if p.strip()]
    except ValueError:
        raise ValueError(f"--ports deve ser uma lista de números separados por vírgula, não {raw!r}")
    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid:
        raise ValueError(f"--ports fora do intervalo 1-65535: {invalid}")
    return ports


def _parse_headers(raw):
    headers = {}
    for item in raw:
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"header inválido (use 'Nome: valor'): {item!r}")
        headers[name.strip()] = value.strip()
    return headers


def _resolve_format(args):
    """Formato do relatório a partir de --format ou da extensão de --output."""
    if args.format:
        return args.format
    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext not in EXTENSION_FORMATS:
            return None
        return EXTENSION_FORMATS[ext]
    return "text"


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr,
    )
    for noisy in ("httpx", "httpcore", "asyncio"):  # logs de transporte escondem o que importa
        logging.getLogger(noisy).setLevel(logging.WARNING)

    if args.list_checks:
        print(_format_check_list())
        return 0
    target = args.target or args.target_pos
    if not target:
        parser.error("informe o alvo com --target/-t")
    if args.new_only and not args.baseline:
        parser.error("--new-only exige --baseline")
    if args.allow_active and not args.scope:
        parser.error("--allow-active exige --scope: checks intrusivos só rodam contra alvos "
                     "explicitamente listados no arquivo de escopo")

    scope = None
    if args.scope:
        try:
            scope = load_scope(args.scope)
        except ScopeError as e:
            print(f"Erro: {e}", file=sys.stderr)
            return 2
        host = extract_domain(target)
        if not scope.allows(host):
            print(f"Erro: o alvo '{host}' está FORA do escopo definido em {args.scope}. "
                  "Nenhuma requisição foi enviada.", file=sys.stderr)
            return 2

    fmt = _resolve_format(args)
    if fmt is None:
        print("Erro: use uma extensão .json ou .html em --output (ou informe --format).",
              file=sys.stderr)
        return 2

    checks = None
    if args.checks:
        checks = [c.strip() for c in args.checks.split(",") if c.strip()]
        valid = REGISTRY.names("web", include_active=True)
        invalid = [c for c in checks if c not in valid]
        if invalid:
            print(f"Erro: checks inválidos: {', '.join(invalid)}. Válidos: {', '.join(valid)}",
                  file=sys.stderr)
            return 2
        active = [c for c in checks if REGISTRY.get(c).active]
        if active and not args.allow_active:
            print(f"Erro: os checks {', '.join(active)} são ativos/intrusivos e exigem --allow-active "
                  "(use apenas com autorização expressa do dono do alvo).", file=sys.stderr)
            return 2

    baseline = None
    if args.baseline:  # valida antes de gastar um scan inteiro
        try:
            baseline = load_baseline(args.baseline)
        except BaselineError as e:
            print(f"Erro: {e}", file=sys.stderr)
            return 2

    try:
        config = ScanConfig(
            timeout=args.timeout, rate=args.rate, concurrency=args.concurrency, retries=args.retries,
            proxy=args.proxy, headers=_parse_headers(args.header), user_agent=args.user_agent,
            verify=not args.insecure, allow_active=args.allow_active,
            scope=scope, ports=_parse_ports(args.ports) if args.ports else None)
    except ValueError as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 2

    findings = scan_target(target, mode=args.mode, web_checks=checks, config=config)
    meta = {"target": target, "mode": args.mode}
    if scope:
        meta["scope"] = args.scope
    if baseline is not None:
        comparison = compare(findings, baseline, args.baseline)
        findings = annotate(findings, comparison)
        meta["baseline"] = comparison.summary()
        if args.new_only:
            findings = [f for f in findings if f.status == "new"]
    text = to_text(findings, show_info=not args.no_info, meta=meta)
    renderers = {
        "text": lambda: text,
        "json": lambda: to_json(findings, meta),
        "md": lambda: to_markdown(findings, meta, show_info=not args.no_info),
        "sarif": lambda: to_sarif(findings, meta),
        "html": lambda: to_html(findings, meta, show_info=not args.no_info),
    }
    report = renderers[fmt]()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(text)
        print(f"\nRelatório {fmt} salvo em {args.output}", file=sys.stderr)
    else:
        print(report)

    threshold = FAIL_LEVELS[args.fail_on]
    if threshold is not None and any(f.severity.rank >= threshold for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
