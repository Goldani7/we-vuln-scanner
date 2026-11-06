"""Permissive CORS.

Vulnerability: if the server reflects any Origin with credentials allowed, a malicious site can
read the victim's authenticated responses.
Example: evil.com does fetch(api, {credentials:"include"}) and reads the logged-in user's private data.
Ref.: OWASP WSTG-CLNT-07 (Testing CORS); CWE-942.
"""
from ..finding import Finding, Severity
from ..http import RequestFailed

CHECK = "cors"
TEST_ORIGIN = "https://evil-example-probe.test"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"
FIX = "Validate the origin against an explicit allowlist instead of reflecting it, and only send Allow-Credentials for trusted origins."


def _finding(severity, title, detail, evidence, meta, remediation=FIX, confidence="high", rule="cors.misconfig"):
    return Finding(CHECK, severity, title, detail, remediation, meta, evidence=evidence,
                   cwe="CWE-942", references=[REFERENCE], confidence=confidence, rule_id=rule)


async def check_cors(ctx) -> list:
    findings = []
    for origin in (TEST_ORIGIN, "null"):
        try:
            r = await ctx.client.request("GET", ctx.url, headers={"Origin": origin}, follow_redirects=True)
        except RequestFailed as e:
            return [Finding(CHECK, Severity.INFO, "Could not test CORS", e.describe(),
                            rule_id="cors.unreachable")]
        acao = r.headers.get("Access-Control-Allow-Origin")
        creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        meta = {"origin_sent": origin, "allow_origin": acao, "allow_credentials": creds}
        evidence = f"Origin: {origin} → Access-Control-Allow-Origin: {acao}; Allow-Credentials: {creds}"
        reflected = acao == origin

        if reflected and creds:
            findings.append(_finding(
                Severity.HIGH, "CORS reflects an arbitrary origin with credentials" if origin != "null"
                else "CORS accepts Origin 'null' with credentials",
                "Any site (or a sandboxed iframe, in the 'null' case) can read the victim's "
                "authenticated responses.", evidence, meta))
        elif reflected and origin != "null":
            findings.append(_finding(
                Severity.LOW, "CORS reflects an arbitrary origin (no credentials)",
                "Without credentials only public data is readable, but the policy is still loose.",
                evidence, meta))
        elif acao == "*" and creds and origin != "null":
            findings.append(_finding(
                Severity.MEDIUM, "CORS combines * with Allow-Credentials",
                "Browsers reject this combination, but it signals a misconfiguration.",
                evidence, meta))
        elif acao == "*" and origin != "null":
            findings.append(_finding(
                Severity.LOW, "CORS allows any origin",
                "Access-Control-Allow-Origin: * (no credentials).", evidence, meta,
                "Restrict the origins if the API isn't meant to be public.", rule="cors.wildcard"))
    return findings or [Finding(CHECK, Severity.INFO, "CORS has no permissive configuration",
                                rule_id="cors.ok")]
