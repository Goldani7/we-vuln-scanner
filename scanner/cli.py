import argparse
import logging
import os
import sys

from .core import ALL_CHECKS, MODES, scan_target
from .http import DEFAULT_USER_AGENT, ScanConfig
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
    p.add_argument("--checks", default=",".join(ALL_CHECKS),
                   help="checks web separados por vírgula (default: todos)")
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

    target = args.target or args.target_pos
    if not target:
        parser.error("informe o alvo com --target/-t")

    fmt = _resolve_format(args)
    if fmt is None:
        print("Erro: use uma extensão .json ou .html em --output (ou informe --format).",
              file=sys.stderr)
        return 2

    checks = [c.strip() for c in args.checks.split(",") if c.strip()]
    invalid = [c for c in checks if c not in ALL_CHECKS]
    if invalid:
        print(f"Erro: checks inválidos: {', '.join(invalid)}. Válidos: {', '.join(ALL_CHECKS)}",
              file=sys.stderr)
        return 2

    try:
        config = ScanConfig(
            timeout=args.timeout, rate=args.rate, concurrency=args.concurrency, retries=args.retries,
            proxy=args.proxy, headers=_parse_headers(args.header), user_agent=args.user_agent,
            verify=not args.insecure)
    except ValueError as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 2

    findings = scan_target(target, mode=args.mode, web_checks=checks, config=config)
    meta = {"target": target, "mode": args.mode}
    text = to_text(findings, show_info=not args.no_info)
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
