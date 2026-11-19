"""Bounded IDOR / authorization-differential checks for authenticated scans."""

from __future__ import annotations

import re
import urllib.parse

from .crawling import Endpoint
from .findings import Finding, Severity
from .http import Client, Response, with_params

_ID_PARAM = re.compile(r"^(id|uid|user|user_id|account|order|doc|file|invoice|item|record|pk|key|ref)$", re.I)
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def check_idor(client: Client, endpoints: list[Endpoint], origin: str) -> list[Finding]:
    """Compare an authenticated response with an unauthenticated/altered one.

    Only runs on object-looking parameters. A differential means one identity
    can read data another cannot — a classic broken-access-control signal.
    """
    findings: list[Finding] = []
    unauth = Client(
        user_agent=client.user_agent,
        timeout=client.timeout,
        rate_limit=0,
        max_body=client.max_body,
        headers={k: v for k, v in client.extra_headers.items() if k.lower() != "authorization"},
    )

    tested = 0
    for endpoint in endpoints[:40]:
        if tested >= 15:
            break
        for name, value in endpoint.params.items():
            if not _ID_PARAM.match(name):
                continue
            if not (value.isdigit() or _UUID.match(value)):
                continue
            tested += 1

            authed = _fetch(client, endpoint)
            if authed.error or authed.status >= 400:
                continue
            anonymous = _fetch(unauth, endpoint)
            if anonymous.error:
                continue

            different = (
                authed.status != anonymous.status
                or abs(len(authed.body) - len(anonymous.body)) > 80
            )
            if not different:
                continue

            findings.append(Finding(
                title=f"Võimalik IDOR parameetris `{name}`",
                severity=Severity.HIGH,
                category="Juurdepääsukontroll",
                url=endpoint.url,
                detail="Autenditud ja autentimata vastus erinevad oluliselt. Objekti ID-d "
                       "võib olla võimalik teise kasutaja andmete lugemiseks muuta.",
                evidence=f"authed: HTTP {authed.status}, {len(authed.body)} baiti; "
                         f"anonymous: HTTP {anonymous.status}, {len(anonymous.body)} baiti",
                check="idor",
                confidence="tentative",
                tags=("auth",),
                request={"method": endpoint.method, "url": endpoint.url, "parameter": name},
                remediation="Kontrolli iga päringus ligipääsuõigusi objekti tasemel. "
                            "Ära eelda, et autentimine tähendab autoriseerimist.",
            ))
            break
    return findings


def check_id_sequences(client: Client, endpoints: list[Endpoint], origin: str) -> list[Finding]:
    """Probe adjacent numeric IDs under the same authenticated session."""
    findings: list[Finding] = []
    tested = 0
    for endpoint in endpoints[:40]:
        if tested >= 10:
            break
        for name, value in endpoint.params.items():
            if not value.isdigit() or not _ID_PARAM.match(name):
                continue
            tested += 1
            base = _fetch(client, endpoint)
            if base.error or base.status >= 400:
                continue
            neighbor_value = str(int(value) + 1)
            params = dict(endpoint.params)
            params[name] = neighbor_value
            if endpoint.method == "POST":
                neighbor = client.post(endpoint.url, params)
            else:
                neighbor = client.get(with_params(endpoint.url, params))
            if neighbor.error or neighbor.status >= 400:
                continue
            if abs(len(neighbor.body) - len(base.body)) < 80:
                continue
            if neighbor.body == base.body:
                continue
            findings.append(Finding(
                title=f"Naabrus-ID loetav parameetris `{name}`",
                severity=Severity.MEDIUM,
                category="Juurdepääsukontroll",
                url=endpoint.url,
                detail=f"ID {value} asemel õnnestus lugeda ID {neighbor_value} ja vastus erineb. "
                       "Võimalik ennustatav objektiviitlus.",
                evidence=f"ID {value}: {len(base.body)} baiti; ID {neighbor_value}: "
                         f"{len(neighbor.body)} baiti",
                check="idor",
                confidence="tentative",
                tags=("auth",),
                request={"method": endpoint.method, "url": endpoint.url,
                         "parameter": name, "payload": neighbor_value},
                remediation="Kasuta ligipääsuõiguse kontrolli enne objekti tagastamist.",
            ))
            break
    return findings


def _fetch(client: Client, endpoint: Endpoint) -> Response:
    if endpoint.method == "POST":
        return client.post(endpoint.url, endpoint.params)
    return client.get(with_params(endpoint.url, endpoint.params))


__all__ = ["check_idor", "check_id_sequences"]
