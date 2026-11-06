import argparse
import logging
import os
import sys

from .baseline import BaselineError, annotate, compare, load_baseline
from .core import MODES, REGISTRY, extract_domain, planned_checks, scan_target
from .http import DEFAULT_USER_AGENT, ScanConfig
from .scope import ScopeError, load_scope
from .report import to_html, to_json, to_markdown, to_sarif, to_text

EXTENSION_FORMATS = {".json": "json", ".html": "html", ".htm": "html", ".md": "md",
                     ".markdown": "md", ".sarif": "sarif"}
FAIL_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": None}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web-vuln-scanner",
        description="Passive web and email/DNS vulnerability scanner. "
                    "Use only against authorized targets.",
    )
    p.add_argument("target_pos", nargs="?", metavar="target",
                   help="target (URL or domain); positional alternative to --target")
    p.add_argument("-t", "--target", help="target URL or domain (e.g. https://example.com or example.com)")
    p.add_argument("-m", "--mode", choices=MODES, default="full",
                   help="web = HTTP/TLS checks; email = SPF/DKIM/DMARC/DNSBL; "
                        "recon = subdomains (crt.sh); full = everything (default)")
    p.add_argument("-o", "--output",
                   help="save the report to this file; the format comes from the extension "
                        "(.json, .md, .sarif, .html)")
    p.add_argument("-f", "--format", choices=["text", "json", "md", "sarif", "html"],
                   help="report format (default: text on the console, or the --output extension)")
    p.add_argument("-v", "--verbose", action="store_true", help="show debug logs")
    p.add_argument("--rich", action="store_true",
                   help="banner, per-check progress bar and colorized table in the terminal "
                        "(requires the 'rich' library; does not affect -o/--format)")
    p.add_argument("--no-color", action="store_true", help="with --rich: turn off colors (e.g. unsupported terminal)")
    p.add_argument("--checks", help="comma-separated web checks (default: all; see --list-checks)")
    p.add_argument("--list-checks", action="store_true", help="list the available checks (plugins included) and exit")
    p.add_argument("--scope", metavar="SCOPE.txt",
                   help="file with the authorized targets; every request outside it is blocked, "
                        "including redirects")
    p.add_argument("--allow-active", action="store_true",
                   help="allow active/intrusive checks; requires --scope and explicit authorization from the target owner")
    p.add_argument("--ports", metavar="22,80,443",
                   help="ports for the 'portscan' check (default: ~25 common service ports)")
    p.add_argument("--baseline", metavar="REPORT.json",
                   help="compare against a previous JSON report and mark new/resolved findings")
    p.add_argument("--new-only", action="store_true",
                   help="with --baseline: only show findings and evaluate --fail-on on new findings")
    p.add_argument("--no-info", action="store_true", help="hide informational findings")
    p.add_argument("--timeout", type=float, default=10, help="per-request timeout, in seconds")

    net = p.add_argument_group("network and performance")
    net.add_argument("--rate", type=float, default=10,
                     help="maximum total requests per second; 0 = unlimited (default: 10)")
    net.add_argument("--concurrency", type=int, default=10, help="simultaneous requests (default: 10)")
    net.add_argument("--retries", type=int, default=2,
                     help="retries on timeout/429/5xx, honoring Retry-After (default: 2)")
    net.add_argument("--proxy", help="proxy http://host:port or socks5://host:port (e.g. Burp)")
    net.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                     help="extra header on every request (repeatable)")
    net.add_argument("--user-agent", default=DEFAULT_USER_AGENT,
                     help="User-Agent (default identifies the tool)")
    net.add_argument("--insecure", action="store_true",
                     help="do not validate the target's TLS certificate (diagnostics only)")
    p.add_argument("--fail-on", choices=list(FAIL_LEVELS), default="high",
                   help="exit code 2 if a finding of this severity or higher exists (default: high)")
    return p


def _format_check_list() -> str:
    rows = [f"{'CHECK':<16}{'CATEGORY':<10}{'ACTIVE':<8}{'SOURCE':<22}DESCRIPTION"]
    for name in REGISTRY.names(include_active=True):
        s = REGISTRY.get(name)
        rows.append(f"{s.name:<16}{s.category:<10}{'yes' if s.active else 'no':<8}{s.source:<22}"
                    f"{s.description[:70]}")
    return "\n".join(rows)


def _parse_ports(raw):
    try:
        ports = [int(p.strip()) for p in raw.split(",") if p.strip()]
    except ValueError:
        raise ValueError(f"--ports must be a comma-separated list of numbers, not {raw!r}")
    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid:
        raise ValueError(f"--ports out of the 1-65535 range: {invalid}")
    return ports


def _parse_headers(raw):
    headers = {}
    for item in raw:
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"invalid header (use 'Name: value'): {item!r}")
        headers[name.strip()] = value.strip()
    return headers


def _resolve_format(args):
    """Report format from --format, or from the --output extension."""
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
    for noisy in ("httpx", "httpcore", "asyncio"):  # transport logs drown out what matters
        logging.getLogger(noisy).setLevel(logging.WARNING)

    if args.list_checks:
        print(_format_check_list())
        return 0
    target = args.target or args.target_pos
    if not target:
        parser.error("provide the target with --target/-t")
    if args.new_only and not args.baseline:
        parser.error("--new-only requires --baseline")
    if args.allow_active and not args.scope:
        parser.error("--allow-active requires --scope: intrusive checks only run against targets "
                     "explicitly listed in the scope file")

    scope = None
    if args.scope:
        try:
            scope = load_scope(args.scope)
        except ScopeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
        host = extract_domain(target)
        if not scope.allows(host):
            print(f"Error: target '{host}' is OUT of the scope defined in {args.scope}. "
                  "No request was sent.", file=sys.stderr)
            return 2

    fmt = _resolve_format(args)
    if fmt is None:
        print("Error: use a .json, .md, .sarif or .html extension on --output (or pass --format).",
              file=sys.stderr)
        return 2

    checks = None
    if args.checks:
        checks = [c.strip() for c in args.checks.split(",") if c.strip()]
        valid = REGISTRY.names("web", include_active=True)
        invalid = [c for c in checks if c not in valid]
        if invalid:
            print(f"Error: invalid checks: {', '.join(invalid)}. Valid: {', '.join(valid)}",
                  file=sys.stderr)
            return 2
        active = [c for c in checks if REGISTRY.get(c).active]
        if active and not args.allow_active:
            print(f"Error: checks {', '.join(active)} are active/intrusive and require --allow-active "
                  "(use only with explicit authorization from the target owner).", file=sys.stderr)
            return 2

    baseline = None
    if args.baseline:  # validate before spending a whole scan
        try:
            baseline = load_baseline(args.baseline)
        except BaselineError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2

    console = progress_cb = None
    if args.rich:
        from . import ui
        if not ui.RICH_AVAILABLE:
            print("Error: --rich requires the 'rich' library (pip install rich).", file=sys.stderr)
            return 2
        console = ui.make_console(no_color=args.no_color)
        ui.print_banner(console, target, args.mode)

    try:
        config = ScanConfig(
            timeout=args.timeout, rate=args.rate, concurrency=args.concurrency, retries=args.retries,
            proxy=args.proxy, headers=_parse_headers(args.header), user_agent=args.user_agent,
            verify=not args.insecure, allow_active=args.allow_active,
            scope=scope, ports=_parse_ports(args.ports) if args.ports else None)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if console is not None:
        from . import ui
        with ui.make_progress(console) as progress:
            reporter = ui.ProgressReporter(progress, planned_checks(args.mode, checks, config))
            findings = scan_target(target, mode=args.mode, web_checks=checks, config=config,
                                   progress_cb=reporter.on_event)
    else:
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

    if console is not None:
        from . import ui
        ui.print_results(console, findings, meta)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
            console.print(f"\n[dim]{fmt} report saved to {args.output}[/]")
    elif args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(text)
        print(f"\n{fmt} report saved to {args.output}", file=sys.stderr)
    else:
        print(report)

    threshold = FAIL_LEVELS[args.fail_on]
    if threshold is not None and any(f.severity.rank >= threshold for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
