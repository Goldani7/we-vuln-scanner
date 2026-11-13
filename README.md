# Goldani Scanner (web-vuln-scanner)

A passive-by-default web and email/DNS vulnerability scanner, built as a portfolio project by Goldani. It scans a target, reports real, actionable findings with evidence and severity, and stays safe to point at any site because it never attacks anything unless you explicitly opt in.

## ⚠️ Ethical notice

Use this tool **only against systems you own or are explicitly authorized to test**. Unauthorized access to computer systems is a crime in most jurisdictions.

## How it works

The scan runs as an async pipeline (`httpx` + `asyncio`) across three modes you can combine:

| Mode | What it checks |
|---|---|
| `web` | Security headers, cookie flags, exposed tech/CVEs (matched by CPE, prioritized by EPSS/CISA KEV), TLS versions, CORS, exposed files (`.env`, `.git`, API docs, heap dumps...; extensible via `--probes-file`), misconfigurations (TRACE, directory listing, debug pages), mixed content / missing SRI / insecure login forms, vulnerable JS libraries (jQuery, Bootstrap, Lodash...), CAA and DNSSEC, GraphQL introspection, passive WAF/CDN detection |
| `email` | SPF, DKIM, DMARC, DNSBL |
| `recon` | Passive subdomain enumeration via Certificate Transparency (crt.sh) and dangling-CNAME (subdomain takeover) detection |

Every finding carries `severity` (critical/high/medium/low/info), `evidence` (secrets are masked), `remediation`, a confidence level, and an exploitability tag — so you know what to fix first.

Three checks — **port scanning**, **active WAF probing** and **open-redirect testing** — send traffic outside normal browsing. They're off by default and only run with `--allow-active` **and** a `--scope` file listing the hosts you're authorized to test; every request (including redirects) is checked against that scope before it's sent.

Reports can be printed to the terminal (plain, or with `--rich` for a colorized banner/table/progress UI) or saved as Markdown, JSON, SARIF, or HTML.

## Installation

```bash
git clone https://github.com/Goldani7/we-vuln-scanner.git
cd we-vuln-scanner
bash install.sh
```

This creates a virtualenv, installs the `wvs` and `goldani` commands, and offers to open the interactive menu right away. Prefer to do it by hand?

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
goldani                                    # interactive menu — no flags to remember
wvs -t https://example.com --rich          # full scan, colorized terminal output
wvs -t https://example.com -m web          # web checks only
wvs -t https://example.com -o report.md    # save a Markdown report
wvs -T targets.txt --config wvs.toml       # many targets, defaults from a TOML file
wvs --list-checks                          # see every available check
wvs --help                                 # full option list
```

Run `pip install -e ".[dev]"`, then `ruff check .` and `pytest tests -q --cov` (fully offline, no network required).

### Docker, CI and the API

```bash
docker build -t wvs . && docker run --rm wvs -t https://example.com
docker run --rm -p 8000:8000 -e WVS_API_KEY=changeme --entrypoint uvicorn wvs api.main:app --host 0.0.0.0
```

GitHub Actions (SARIF into Code Scanning, fails the job on `--fail-on`):

```yaml
- uses: Goldani7/we-vuln-scanner@main
  with: { target: "https://staging.example.com", upload-sarif: "true", fail-on: high }
```

The API is hardened for untrusted callers: every request **and redirect hop** is refused if it resolves to a private/loopback/link-local address (anti-SSRF), active checks are never available, scans have a hard deadline (`WVS_API_DEADLINE`, default 120s), and setting `WVS_API_KEY` requires an `X-API-Key` header on `/scan`. Residual DNS-rebinding risk is documented in `scanner/netguard.py`; deploy behind an egress firewall for full coverage.

More detail — architecture, writing a plugin, the scope-file format — lives in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
