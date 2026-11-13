import asyncio
import dataclasses
import logging
from urllib.parse import urlparse

from .builtin_checks import BUILTIN_SPECS
from .finding import Finding, Severity
from .http import HttpClient, RequestFailed, ScanConfig, ScanContext
from .registry import Registry

log = logging.getLogger(__name__)

REGISTRY = Registry()
for _spec in BUILTIN_SPECS:
    REGISTRY.register(_spec)
REGISTRY.load_plugins()  # third-party checks via the "wvs.checks" entry point

ALL_CHECKS = REGISTRY.names("web")
EMAIL_CHECKS = REGISTRY.names("email")
RECON_CHECKS = REGISTRY.names("recon")
MODES = ("web", "email", "recon", "full")

# Views by signature kind (derived from the registry).
RESPONSE_CHECKS = REGISTRY.by_kind("response")  # over the homepage response (runs in a thread)
ASYNC_CHECKS = REGISTRY.by_kind("async")        # receive the ScanContext
URL_CHECKS = REGISTRY.by_kind("url")            # blocking (socket): in a thread
DOMAIN_CHECKS = REGISTRY.by_kind("domain")      # blocking (DNS): in a thread


def _failure(name: str, e: Exception) -> list:
    if isinstance(e, RequestFailed):
        return [Finding(name, Severity.INFO, f"Check '{name}' got no response from the target", e.describe(),
                        "Check availability and lower --rate/--concurrency if you're being blocked.",
                        rule_id=f"{name}.unreachable")]
    return [Finding(name, Severity.INFO, f"Check '{name}' failed", f"{type(e).__name__}: {e}",
                    "Run with -v to see the traceback.", rule_id=f"{name}.error")]


async def _safe(name, awaitable, progress_cb=None) -> list:
    """Isolates a check: no exception (timeout, TLS, bug) ever takes down the whole scan.

    `progress_cb(event, name, *rest)` is optional and UI-only (e.g. scanner.ui.ProgressReporter);
    it never affects the scan's result. "start" before running, "done" with the finding count after.
    """
    log.debug("running check %s", name)
    if progress_cb:
        progress_cb("start", name)
    try:
        result = await awaitable
    except Exception as e:  # noqa: BLE001
        log.debug("check %s failed", name, exc_info=True)
        result = _failure(name, e)
    if progress_cb:
        progress_cb("done", name, len(result))
    return result


def _tag(findings: list, target: str) -> list:
    return [dataclasses.replace(f, target=f.target or target) for f in findings]


def _looks_blocked(s: dict) -> bool:
    """A high ratio of 403/406 suggests active blocking (WAF/rate limit), not just protected files."""
    return s["forbidden"] >= 10 and s["forbidden"] >= 0.5 * s["requests"]


def _scope_notice(client: HttpClient) -> list:
    n = client.stats["out_of_scope"]
    if not n:
        return []
    return [Finding(
        "core", Severity.INFO, f"{n} request(s) blocked for being out of scope",
        "The target redirected to (or a check tried to reach) a host that isn't in the scope file; "
        "the request was NOT sent.", "If that host is also authorized, add it to the scope file.",
        dict(client.stats), rule_id="core.out-of-scope", confidence="high")]


def _rate_limit_notice(client: HttpClient) -> list:
    s = client.stats
    if not s["throttled"] and not s["failures"] and not _looks_blocked(s):
        return []
    return [Finding(
        "core", Severity.INFO, "Target rate-limited or refused requests; results may be incomplete",
        f"{s['throttled']} 429 response(s), {s['forbidden']} 403/406 response(s), {s['failures']} network "
        f"failure(s), {s['retries']} retry(ies) out of {s['requests']} request(s).",
        "Lower --rate and --concurrency, or arrange an allowlist for your IP with the client.",
        dict(s), rule_id="core.throttled", confidence="high")]


async def _gather_with_deadline(jobs, max_duration) -> list:
    """Runs the jobs concurrently. With a deadline, whatever finished is kept and the rest is
    cancelled (and reported), so a slow target can't hold the scan (or an API worker) forever."""
    if not max_duration:
        return [f for group in await asyncio.gather(*jobs) for f in group]
    tasks = [asyncio.ensure_future(j) for j in jobs]
    done, pending = await asyncio.wait(tasks, timeout=max_duration)
    for t in pending:
        t.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    findings = [f for t in done for f in t.result()]
    if pending:
        findings.append(Finding(
            "core", Severity.INFO, "Scan deadline reached; results are incomplete",
            f"{len(pending)} group(s) of checks were cancelled after {max_duration:g}s.",
            "Raise the deadline, narrow --checks, or lower the target's latency impact.",
            rule_id="core.deadline", confidence="high"))
    return findings


def default_web_checks(config: ScanConfig) -> list:
    """Default web checks; active ones only join in when allow_active is set."""
    return REGISTRY.names("web", include_active=config.allow_active)


async def scan_web_async(ctx: ScanContext, checks, progress_cb=None) -> list:
    checks = checks or default_web_checks(ctx.config)
    try:
        response = await ctx.index() if any(c in RESPONSE_CHECKS for c in checks) else None
    except RequestFailed as e:
        if e.kind == "out_of_scope":  # a scan restriction, not a vulnerability of the target
            return [Finding("core", Severity.INFO, "Redirect to an out-of-scope host blocked", str(e),
                            "If the destination host is also authorized, add it to the scope file; "
                            "otherwise point the scan at the final URL that is within scope.",
                            evidence=f"GET {ctx.url} → {e.describe()}", rule_id="core.connect-out_of_scope",
                            confidence="high")]
        return [Finding("core", Severity.HIGH, f"Failed to connect to the target ({e.kind})", str(e),
                        "Check the URL, the certificate (use --insecure only to diagnose), and availability.",
                        evidence=f"GET {ctx.url} → {e.describe()}", rule_id=f"core.connect-{e.kind}",
                        confidence="high")]
    jobs = []
    for name in checks:
        if name in RESPONSE_CHECKS:
            jobs.append(_safe(name, asyncio.to_thread(RESPONSE_CHECKS[name], response), progress_cb))
        elif name in ASYNC_CHECKS:
            jobs.append(_safe(name, ASYNC_CHECKS[name](ctx), progress_cb))
        elif name in URL_CHECKS:
            jobs.append(_safe(name, asyncio.to_thread(URL_CHECKS[name], ctx.url, timeout=ctx.config.timeout),
                              progress_cb))
    return [f for group in await asyncio.gather(*jobs) for f in group]


async def scan_email_async(domain: str, config: ScanConfig, checks=None, progress_cb=None) -> list:
    checks = checks or EMAIL_CHECKS
    jobs = [_safe(c, asyncio.to_thread(DOMAIN_CHECKS[c], domain, timeout=config.timeout), progress_cb)
           for c in checks]
    return [f for group in await asyncio.gather(*jobs) for f in group]


def extract_domain(target: str) -> str:
    """Hostname of a URL or a plain domain ('https://a.com:8443/x' -> 'a.com')."""
    host = urlparse(target if "://" in target else f"//{target}").hostname
    return (host or "").rstrip(".").lower()


def planned_checks(mode: str, web_checks=None, config: ScanConfig = None) -> list:
    """Names of the checks `scan_target(_async)` will run for this mode (for the progress UI)."""
    config = config or ScanConfig()
    names = []
    if mode in ("web", "full"):
        names += web_checks or default_web_checks(config)
    if mode in ("recon", "full"):
        names += RECON_CHECKS
    if mode in ("email", "full"):
        names += EMAIL_CHECKS
    return names


async def scan_target_async(target: str, mode: str = "full", web_checks=None,
                            config: ScanConfig = None, transport=None, progress_cb=None) -> list:
    if mode not in MODES:
        raise ValueError(f"invalid mode: {mode}")
    config = config or ScanConfig()
    url = target if "://" in target else f"https://{target}"
    findings = []
    async with HttpClient(config, transport=transport) as client:
        ctx = ScanContext(url, client, config)
        jobs = []
        if mode in ("web", "full"):
            jobs.append(scan_web_async(ctx, web_checks, progress_cb))
        if mode in ("recon", "full"):
            jobs.extend(_safe(name, ASYNC_CHECKS[name](ctx), progress_cb) for name in RECON_CHECKS)
        if mode in ("email", "full"):
            jobs.append(scan_email_async(extract_domain(target), config, progress_cb=progress_cb))
        findings.extend(await _gather_with_deadline(jobs, config.max_duration))
        findings.extend(_rate_limit_notice(client))
        findings.extend(_scope_notice(client))
    return _tag(findings, url)


def scan_target(target: str, mode: str = "full", web_checks=None, timeout: float = 10,
                config: ScanConfig = None, progress_cb=None) -> list:
    """Synchronous entry point for the CLI: accepts a URL or a domain."""
    config = config or ScanConfig(timeout=timeout)
    return asyncio.run(scan_target_async(target, mode, web_checks, config, progress_cb=progress_cb))


def scan(url: str, checks=None, timeout: int = 8, config: ScanConfig = None) -> list:
    """Synchronous web scan (used by the API). Safe to call from a thread with no event loop."""
    return scan_target(url, mode="web", web_checks=checks, timeout=timeout, config=config)
