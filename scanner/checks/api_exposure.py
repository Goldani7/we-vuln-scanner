"""Exposed API surface: GraphQL introspection.

Vulnerability: with introspection enabled, anyone can download the full GraphQL schema (every type,
query, mutation and field, including internal/admin ones) and map the API like documentation.
Method: one read-only POST of the standard introspection query to a few conventional endpoints.
It only READS schema metadata; no data is queried and nothing is mutated.
(Swagger/OpenAPI documents are covered by `exposed_files`.)
Ref.: OWASP API Security API9:2023 (Improper Inventory Management); CWE-200.
"""
import json
from urllib.parse import urljoin

from ..finding import Finding, Severity
from ..http import RequestFailed

CHECK = "api_exposure"
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query")
INTROSPECTION = json.dumps({"query": "query{__schema{queryType{name} types{name}}}"}).encode()


def parse_introspection(response):
    """Type names if the response is a real introspection result, else None."""
    if response.status_code != 200:
        return None
    try:
        data = response.json()["data"]["__schema"]
        return [t["name"] for t in data["types"]]
    except (ValueError, KeyError, TypeError):
        return None


async def check_api_exposure(ctx) -> list:
    findings = []
    for path in GRAPHQL_PATHS:
        url = urljoin(ctx.url, path)
        try:
            r = await ctx.client.request("POST", url, headers={"Content-Type": "application/json"},
                                         content=INTROSPECTION, follow_redirects=False)
        except RequestFailed:
            continue
        types = parse_introspection(r)
        if types is None:
            continue
        custom = [t for t in types if not t.startswith("__")]
        findings.append(Finding(
            CHECK, Severity.MEDIUM, f"GraphQL introspection enabled at {path}",
            f"The endpoint returned its full schema ({len(custom)} types). Attackers use it to find "
            "hidden queries, mutations and admin fields.",
            "Disable introspection in production (and field suggestions), or require authentication "
            "for it.",
            {"url": url, "types": custom[:50]},
            evidence=f"POST {url} {{__schema}} → HTTP 200, types: {', '.join(custom[:8])}",
            cwe="CWE-200", confidence="high", rule_id="api.graphql-introspection",
            references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"]))
        break  # one exposed endpoint is enough; avoid probing the rest
    return findings or [Finding(CHECK, Severity.INFO, "No GraphQL introspection found",
                                rule_id="api.none")]
