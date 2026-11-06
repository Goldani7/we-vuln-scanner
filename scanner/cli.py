import argparse
import logging
import os
import sys

from .core import ALL_CHECKS, MODES, scan_target
from .finding import Severity
from .report import to_html, to_json, to_text

EXTENSION_FORMATS = {".json": "json", ".html": "html", ".htm": "html"}


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
                   help="web = checks HTTP/TLS; email = SPF/DKIM/DMARC/DNSBL; full = ambos (default)")
    p.add_argument("-o", "--output",
                   help="salva o relatório neste arquivo; o formato (json|html) vem da extensão")
    p.add_argument("-f", "--format", choices=["text", "json", "html"],
                   help="formato do relatório (default: text no console, ou pela extensão de --output)")
    p.add_argument("-v", "--verbose", action="store_true", help="mostra logs de depuração")
    p.add_argument("--checks", default=",".join(ALL_CHECKS),
                   help="checks web separados por vírgula (default: todos)")
    p.add_argument("--no-info", action="store_true", help="oculta findings informativos")
    p.add_argument("--timeout", type=int, default=8)
    return p


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

    findings = scan_target(target, mode=args.mode, web_checks=checks, timeout=args.timeout)
    meta = {"target": target, "mode": args.mode}
    text = to_text(findings, show_info=not args.no_info)
    renderers = {
        "text": lambda: text,
        "json": lambda: to_json(findings, meta),
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

    return 2 if any(f.severity is Severity.HIGH for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
