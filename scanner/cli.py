import argparse
import sys

from .core import ALL_CHECKS, scan
from .finding import Severity
from .report import to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web-vuln-scanner",
        description="Scanner passivo de vulnerabilidades web. Use apenas em alvos autorizados.",
    )
    p.add_argument("url", help="URL alvo (http:// ou https://)")
    p.add_argument("--checks", default=",".join(ALL_CHECKS),
                   help="lista de checks separada por vírgula (default: todos)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--output", help="arquivo de saída (default: stdout)")
    p.add_argument("--no-info", action="store_true", help="oculta findings informativos")
    p.add_argument("--timeout", type=int, default=8)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.url.startswith(("http://", "https://")):
        print("Erro: a URL deve começar com http:// ou https://", file=sys.stderr)
        return 2

    checks = [c.strip() for c in args.checks.split(",") if c.strip()]
    invalid = [c for c in checks if c not in ALL_CHECKS]
    if invalid:
        print(f"Erro: checks inválidos: {', '.join(invalid)}. Válidos: {', '.join(ALL_CHECKS)}",
              file=sys.stderr)
        return 2

    findings = scan(args.url, checks=checks, timeout=args.timeout)
    if args.format == "json":
        out = to_json(findings)
    else:
        out = to_text(findings, show_info=not args.no_info)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    else:
        print(out)

    return 2 if any(f.severity is Severity.HIGH for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
