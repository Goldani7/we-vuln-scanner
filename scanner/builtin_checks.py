"""Built-in checks: one CheckSpec per check. Third-party checks plug in through the
`wvs.checks` entry point instead (see registry.py)."""
from .checks.api_exposure import check_api_exposure
from .checks.cookies import check_cookies
from .checks.cors import check_cors
from .checks.dns_security import check_dns_security
from .checks.email_dns import check_dkim, check_dmarc, check_dnsbl, check_spf
from .checks.exposed_files import check_exposed_files
from .checks.headers import check_headers
from .checks.html_security import check_html_security
from .checks.js_libs import check_js_libs
from .checks.misconfig import check_misconfig
from .checks.open_redirect import check_open_redirect
from .checks.portscan import check_portscan
from .checks.ssl_tls import check_ssl_tls
from .checks.subdomains import check_subdomains
from .checks.takeover import check_subdomain_takeover
from .checks.tech_detection import check_tech_detection
from .checks.waf import check_waf
from .checks.waf_active import check_waf_active
from .registry import CheckSpec

BUILTIN_SPECS = (
    CheckSpec("headers", "response", check_headers, "web",
              "Checks security headers (CSP, HSTS, X-Frame-Options...). They tell the browser to "
              "block XSS, clickjacking and HTTP downgrade."),
    CheckSpec("cookies", "response", check_cookies, "web",
              "Checks the Secure, HttpOnly and SameSite cookie flags. Without them, session cookies "
              "can be stolen via XSS, an insecure network, or CSRF."),
    CheckSpec("tech_detection", "response", check_tech_detection, "web",
              "Detects software/version exposed in Server/X-Powered-By and looks up CVEs in the NVD, "
              "prioritized by EPSS and CISA KEV."),  # queries the NVD (sync HTTP): runs in a thread
    CheckSpec("waf", "response", check_waf, "web",
              "Passively identifies WAF/CDN (Cloudflare, Akamai, CloudFront...) from headers, cookies "
              "and block pages. The edge masks the origin and may filter findings."),
    CheckSpec("ssl_tls", "url", check_ssl_tls, "web",
              "Checks the TLS versions accepted and the certificate's validity. Old protocols and "
              "expired certificates allow interception and break trust."),
    CheckSpec("cors", "async", check_cors, "web",
              "Tests whether CORS accepts arbitrary origins. A permissive policy lets malicious sites "
              "read the user's authenticated responses."),
    CheckSpec("exposed_files", "async", check_exposed_files, "web",
              "Looks for common sensitive files (.env, .git, backups) and validates the content to "
              "avoid false positives. They tend to leak credentials and source code."),
    CheckSpec("misconfig", "async", check_misconfig, "web",
              "Checks HTTP->HTTPS redirection, the TRACE method, directory listing, and error pages "
              "with a stack trace, which leak information about the server."),
    CheckSpec("html_security", "response", check_html_security, "web",
              "Mixed content (http resources on https pages), third-party scripts without "
              "Subresource Integrity, and password forms posting over plain http."),
    CheckSpec("js_libs", "response", check_js_libs, "web",
              "Detects known-vulnerable front-end libraries (jQuery, Bootstrap, Lodash, "
              "AngularJS...) from the script URLs in the homepage."),
    CheckSpec("dns_security", "async", check_dns_security, "web",
              "DNS hardening: CAA (who may issue certificates) and DNSSEC (signed DNS answers)."),
    CheckSpec("api_exposure", "async", check_api_exposure, "web",
              "Detects GraphQL introspection enabled on common endpoints (read-only query)."),
    CheckSpec("open_redirect", "async", check_open_redirect, "web",
              "Tests redirect-style parameters (next, url, redirect...) for open redirects. "
              "ACTIVE: requires --allow-active and --scope.", active=True),
    CheckSpec("subdomains", "async", check_subdomains, "recon",
              "Passive subdomain enumeration via Certificate Transparency (crt.sh)."),
    CheckSpec("subdomain_takeover", "async", check_subdomain_takeover, "recon",
              "Finds dangling CNAMEs among the CT subdomains (takeover candidates), DNS only."),
    CheckSpec("portscan", "async", check_portscan, "web",
              "TCP-connect port scan over a short list of common ports. ACTIVE: requires "
              "--allow-active and --scope.", active=True),
    CheckSpec("waf_active", "async", check_waf_active, "web",
              "Active WAF probe using a known, non-functional test pattern. "
              "ACTIVE: requires --allow-active and --scope.", active=True),
    CheckSpec("spf", "domain", check_spf, "email", "SPF: which servers are authorized to send email for the domain."),
    CheckSpec("dkim", "domain", check_dkim, "email", "DKIM: cryptographic signature of outgoing email."),
    CheckSpec("dmarc", "domain", check_dmarc, "email", "DMARC: policy against spoofed email."),
    CheckSpec("dnsbl", "domain", check_dnsbl, "email", "Reputation of the mail servers on DNSBL lists."),
)
