# Contributing

Thanks for wanting to improve web-vuln-scanner. Two rules apply to everything: **only modules that
respect the project's ethical scope** (passive by default; intrusive ones require `active=True` and
`--allow-active`) and **no test may depend on the network** (use `httpx.MockTransport`, see
`tests/conftest.py`).

## Environment

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests -q
```

## Modules and severity

| Module | What it checks |
|---|---|
| `headers` | CSP, HSTS, X-Frame-Options, Referrer-Policy, COOP/CORP, and more — evaluates the *value*, not just presence |
| `cookies` | Secure, HttpOnly, SameSite flags, prioritizing session-looking cookie names |
| `tech_detection` | Server/X-Powered-By exposure and known CVEs (NVD), prioritized by EPSS and CISA KEV |
| `waf` / `waf_active` | Passive WAF/CDN fingerprinting; `waf_active` is an active probe (see below) |
| `ssl_tls` | TLS versions accepted and certificate validity |
| `cors` | Reflected-origin / credentials misconfigurations |
| `exposed_files` | `.env`, `.git`, backups, keys... validated by content signature to avoid false positives |
| `misconfig` | HTTP→HTTPS redirect, TRACE, directory listing, debug/error pages, security.txt |
| `subdomains` | Passive enumeration via Certificate Transparency (crt.sh) |
| `spf` / `dkim` / `dmarc` / `dnsbl` | Email authentication and sender reputation |
| `portscan` / `waf_active` | **Active** checks — see below |

Severity criteria: **critical** = a secret or sensitive data is confirmed reachable; **high** =
direct exploitation is likely; **medium** = weakens defenses or leaks useful information; **low**
= hardening; **info** = confirmations and context.

## Writing a check

A check is a function returning `list[Finding]` plus a `CheckSpec` describing it.

| `kind` | Signature | When to use it |
|---|---|---|
| `response` | `fn(response) -> list` | Analyze the homepage response (headers, cookies, body). Runs in a thread |
| `async` | `async fn(ctx) -> list` | Make extra requests via `ctx.client` (inherits rate limit, retry, proxy) |
| `url` | `fn(url, timeout=) -> list` | Blocking code over the URL (sockets) |
| `domain` | `fn(domain, timeout=) -> list` | Blocking code over the domain (DNS) |

`category` sets the mode it runs in: `web`, `email` or `recon` (recon only accepts `async`).

### Finding best practices

- `evidence`: what was **observed**. **Never** include secrets: mask values (`DB_PASSWORD=****`).
- `remediation`: one concrete step, not "improve security".
- `confidence`: `high` only if the finding was validated (content signature, confirmed echo).
  Heuristics are `low`/`medium`.
- Stable `rule_id` (`mycheck.rule`): becomes the SARIF `ruleId`. Add `cwe` and `references` when there's one.
- Avoid false positives: a 200 status proves nothing on its own; validate the content.
- Use `ctx.client.request(...)` instead of opening your own connections, and handle `RequestFailed`.

## External plugins (no changes to this repo needed)

A plugin is a package that exposes a `CheckSpec` via the `wvs.checks` entry point. Full, installable
example at [`examples/wvs-plugin-cache-control`](examples/wvs-plugin-cache-control).

```python
# my_plugin/__init__.py
from scanner.finding import Finding, Severity
from scanner.registry import CheckSpec

def check_my_header(response):
    if "x-my-header" in response.headers:
        return []
    return [Finding("my_header", Severity.LOW, "X-My-Header missing",
                    remediation="Add the header.", rule_id="my_header.missing")]

SPEC = CheckSpec(name="my_header", kind="response", func=check_my_header,
                 category="web", description="Requires the X-My-Header header.")
```

```toml
# the plugin's pyproject.toml
[project.entry-points."wvs.checks"]
my_header = "my_plugin:SPEC"
```

After `pip install`, confirm with `wvs --list-checks` (the SOURCE column shows `plugin:<name>`).
An entry point can also point to a **list** of `CheckSpec`. Plugins that fail to load, repeat a
name, or don't point to a `CheckSpec` are **skipped with a warning**: they never take down the scan.

## Active checks

Any check that sends traffic outside normal browsing patterns (test payloads, port scanning) must
declare `active=True` in its `CheckSpec`. Examples already in the project: `portscan` (TCP connect)
and `waf_active` (a test-pattern probe). They're excluded from the defaults and only run with
`--allow-active` **and** `--scope` together — the CLI refuses `--allow-active` without a scope.
Use only against targets with explicit authorization; if the check uses sockets outside the HTTP
client (like `portscan`), check the scope manually inside the check too, as defense in depth.

### Scope file format

```text
example.com            # this host only
*.api.example.com      # any subdomain (does not include api.example.com)
203.0.113.0/24         # an IP range (matches targets given as an IP)
!internal.example.com  # exclusion (always wins over any inclusion)
```

## Rich UI (`scanner/ui.py`)

The `--rich` layer is presentation only: it never decides severity or filters findings (that's
always `scanner.report`/`scanner.core`). When adding a new check, there's no need to touch
`ui.py`: the progress bar picks up the check's name automatically via `core.planned_checks()`.

## Pull requests

Commits in [Conventional Commits](https://www.conventionalcommits.org/) style (`feat(waf): ...`),
tests for new behavior, and an updated README when the CLI or output changes.
