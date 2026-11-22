"""GraphQL-specific checks: introspection, aliases, batching, depth."""

from __future__ import annotations

import json

from ..crawling import Endpoint
from ..findings import Finding, Severity
from . import Context
from .spa import is_spa_fallback

KIND = "active"

_CANDIDATES = ("/graphql", "/api/graphql", "/graphql/v1", "/gql")


def _graphql_urls(ctx: Context) -> list[str]:
    urls: list[str] = []
    for candidate in _CANDIDATES:
        url = ctx.origin.rstrip("/") + candidate
        if url not in urls:
            urls.append(url)
    for page in ctx.pages:
        for link in page.links + page.script_paths:
            lowered = link.lower()
            if "graphql" in lowered or lowered.endswith("/gql"):
                if link not in urls:
                    urls.append(link)
    return urls[:8]


def check_graphql(ctx: Context, _endpoints: list[Endpoint]) -> None:
    if not ctx.config.enabled("graphql"):
        return
    if not ctx.config.allow_post:
        return

    for url in _graphql_urls(ctx):
        if ctx.stop():
            return

        introspection = _post(ctx, url, {
            "query": "query { __schema { queryType { name } } }",
        })
        if introspection is None or introspection.error:
            continue
        body = introspection.text.lower()
        if "__schema" in body or '"data"' in body and "querytype" in body:
            ctx.emit(Finding(
                title="GraphQL-introspeksioon on lubatud", severity=Severity.MEDIUM,
                category="API", url=url,
                detail="Introspeksioonipäring tagastas skeemi. Ründaja saab täieliku väljade nimekirja.",
                evidence=introspection.text[:260], check="graphql", tags=("info",),
                request={"method": "POST", "url": url,
                         "payload": "query { __schema { queryType { name } } }"},
                remediation="Lülita introspeksioon tootmises välja või nõua autentimist.",
            ))

        alias = _post(ctx, url, {
            "query": "{ a: __typename b: __typename c: __typename d: __typename e: __typename }",
        })
        if alias and not alias.error and is_spa_fallback(alias):
            continue
        if alias and not alias.error and "a" in alias.text and "b" in alias.text:
            ctx.emit(Finding(
                title="GraphQL-i aliase ei piirata", severity=Severity.LOW,
                category="API", url=url,
                detail="Viie aliasiga päring läbi. Piiramata aliased võimaldavad kulutõhusat DoS-i.",
                evidence=alias.text[:260], check="graphql", tags=(),
                request={"method": "POST", "url": url, "payload": "alias x5"},
                remediation="Sea aliasLimit ja depthLimit (nt 10 / 7).",
            ))

        batch = ctx.client.request(
            "POST", url,
            data=json.dumps([
                {"query": "{ __typename }"}, {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        if not batch.error and batch.text.strip().startswith("["):
            ctx.emit(Finding(
                title="GraphQL-batch on lubatud", severity=Severity.LOW,
                category="API", url=url,
                detail="Server aktsepteerib päringute partii — võimalik brute-force'i kiirendus.",
                evidence=batch.text[:260], check="graphql",
                request={"method": "POST", "url": url, "payload": "batch x3"},
                remediation="Lülita batching välja või piira partii suurust.",
            ))


def _post(ctx: Context, url: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    return ctx.client.request("POST", url, data=data, headers={"Content-Type": "application/json"})


CHECKS = [{"name": "graphql", "kind": KIND, "run": check_graphql}]
