"""Active injection checks with unique tokens, differentials and bounded targets."""

from __future__ import annotations

import hashlib
import random
import re
import string
import urllib.parse

from .. import http
from ..crawling import Endpoint
from ..findings import Finding, Severity
from . import Context

KIND = "active"
MAX_PARAMS = 40

SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark after the character string", "quoted string not properly terminated",
    "pg_query()", "postgresql error", "ora-00933", "ora-01756",
    "sqlite3.operationalerror", "sqlitedatabaseerror", "microsoft odbc sql server driver",
    "odbc sql server driver", "sequelizedatabaseerror", "sqlstate[",
    "doctrine\\dbal\\exception", "mysqli_sql_exception", "syntax error at or near",
    "org.postgresql.util.psqlexception",
]

TRAVERSAL_MARKERS = [
    "root:x:0:0", "root:*:0:0", "daemon:x:1:1", "[extensions]",
    "for 16-bit app support", "<configuration>", "mysql",
]

REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "return", "return_to", "returnurl",
    "next", "url", "target", "dest", "destination", "continue", "callback",
    "goto", "r", "u", "link", "out", "forward", "redir", "ref", "page",
}


def _token(length: int = 10) -> str:
    return "ol" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _excerpt(text: str, needle: str, radius: int = 80) -> str:
    index = text.find(needle)
    if index < 0:
        return " ".join(text[:radius].split())
    start, end = max(0, index - radius), min(len(text), index + len(needle) + radius)
    return " ".join(text[start:end].split())[:260]


def _request(ctx: Context, endpoint: Endpoint, name: str, payload: str, follow: bool = False):
    params = dict(endpoint.params)
    params[name] = payload
    if endpoint.method == "POST":
        return ctx.client.post(endpoint.url, params)
    return ctx.client.get(http.with_params(endpoint.url, params), follow=follow)


def _repro(endpoint: Endpoint, name: str, payload: str) -> dict[str, str]:
    return {
        "method": endpoint.method,
        "url": endpoint.url,
        "parameter": name,
        "payload": payload[:200],
    }


def check_xss(ctx: Context, endpoints: list[Endpoint]) -> None:
    if not ctx.config.enabled("xss"):
        return
    token = _token()
    payloads = [
        f"<oli{token}>",
        f'oli{token}"><svg/onload=alert(1)>',
        f"'><oli{token}>",
        f'"><img src=x onerror=alert(1)>oli{token}',
        f"<!--oli{token}--><!-->",
    ]
    seen: set[tuple[str, str]] = set()
    tested = 0
    for endpoint in endpoints:
        if tested >= MAX_PARAMS or ctx.stop():
            return
        for name in endpoint.params:
            if tested >= MAX_PARAMS or ctx.stop():
                return
            key = (urllib.parse.urlsplit(endpoint.url).path, name)
            if key in seen:
                continue
            seen.add(key)
            tested += 1
            for payload in payloads:
                response = _request(ctx, endpoint, name, payload)
                if response.error:
                    continue
                body = response.text
                raw_tag = f"<oli{token}>" in body
                svg = ("<svg/onload=alert(1)>" in body
                       or bool(re.search(r"<img[^>]+onerror\s*=", body, re.IGNORECASE)))
                script = bool(re.search(r"<script[^>]*>[^<]*oli" + token, body, re.IGNORECASE))
                if not (raw_tag or svg or script):
                    continue
                ctx.emit(Finding(
                    title=f"Reflekteeruv XSS parameetris `{name}`", severity=Severity.HIGH,
                    category="Süst", url=endpoint.url,
                    detail="Kasutaja sisend jõuab HTML-i muutmata kujul. Suvaline JavaScript "
                           "käivitub ohvri sessioonis.",
                    evidence=f"payload: {payload}\n" + _excerpt(body, payload[:20]),
                    check="xss", tags=("xss",), request=_repro(endpoint, name, payload),
                    remediation="Kodeeri väljund konteksti järgi ja lisa CSP `script-src 'self'`.",
                ))
                break


def check_sqli(ctx: Context, endpoints: list[Endpoint]) -> None:
    if not ctx.config.enabled("sqli"):
        return
    seen: set[tuple[str, str]] = set()
    tested = 0
    for endpoint in endpoints:
        if tested >= MAX_PARAMS or ctx.stop():
            return
        for name in endpoint.params:
            if tested >= MAX_PARAMS or ctx.stop():
                return
            key = (urllib.parse.urlsplit(endpoint.url).path, name)
            if key in seen:
                continue
            seen.add(key)
            tested += 1
            baseline = _request(ctx, endpoint, name, endpoint.params[name])
            if baseline.error:
                continue

            for payload in ("'", '"', "')", "';", "\\", "1' OR '1'='1"):
                response = _request(ctx, endpoint, name, endpoint.params[name] + payload)
                if response.error:
                    continue
                lowered = response.text.lower()
                hit = next((error for error in SQL_ERRORS if error in lowered), None)
                if not hit:
                    continue
                ctx.emit(Finding(
                    title=f"SQL-süst parameetris `{name}` (veapõhine)", severity=Severity.CRITICAL,
                    category="Süst", url=endpoint.url,
                    detail="Sisend jõuab SQL-päringusse ja andmebaasi viga jõuab vastusesse.",
                    evidence=f"payload: {payload!r}\n" + _excerpt(lowered, hit),
                    check="sqli", tags=("sqli",), request=_repro(endpoint, name, payload),
                    remediation="Kasuta parametriseeritud päringuid ja lülita veateated välja.",
                ))
                break
            else:
                _boolean_probe(ctx, endpoint, name, baseline)


def _boolean_probe(ctx: Context, endpoint: Endpoint, name: str, baseline) -> None:
    original = endpoint.params[name]
    if not original.strip().isdigit():
        return
    true_response = _request(ctx, endpoint, name, original + " AND 1=1")
    false_response = _request(ctx, endpoint, name, original + " AND 1=0")
    if true_response.error or false_response.error:
        return
    if true_response.status != false_response.status:
        suspicious = True
    else:
        size_delta = abs(len(true_response.body) - len(false_response.body))
        suspicious = size_delta > max(64, len(baseline.body) * 0.15)
    if not suspicious:
        return
    payload = original + " AND 1=0"
    ctx.emit(Finding(
        title=f"Võimalik boole’i-SQL-süst parameetris `{name}`", severity=Severity.HIGH,
        category="Süst", url=endpoint.url,
        detail="`AND 1=1` ja `AND 1=0` annavad erineva vastuse. See on tüüpiline märk "
               "sisendi jõudmisest SQL-i loogikasse.",
        evidence=f"true: HTTP {true_response.status}, {len(true_response.body)} baiti; "
                 f"false: HTTP {false_response.status}, {len(false_response.body)} baiti",
        check="sqli", confidence="tentative", tags=("sqli",),
        request=_repro(endpoint, name, payload),
        remediation="Kontrolli käsitsi `sqlmap`-iga ja paranda parametriseeritud päringutega.",
    ))


def check_traversal(ctx: Context, endpoints: list[Endpoint]) -> None:
    if not ctx.config.enabled("traversal"):
        return
    payloads = [
        "../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//etc/passwd",
        "..\\..\\..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    seen: set[tuple[str, str]] = set()
    tested = 0
    for endpoint in endpoints:
        if tested >= MAX_PARAMS or ctx.stop():
            return
        for name in endpoint.params:
            if tested >= MAX_PARAMS or ctx.stop():
                return
            key = (urllib.parse.urlsplit(endpoint.url).path, name)
            if key in seen:
                continue
            seen.add(key)
            tested += 1
            for payload in payloads:
                response = _request(ctx, endpoint, name, payload)
                if response.error:
                    continue
                hit = next((marker for marker in TRAVERSAL_MARKERS if marker in response.text.lower()), None)
                if not hit:
                    continue
                ctx.emit(Finding(
                    title=f"Path traversal parameetris `{name}`", severity=Severity.CRITICAL,
                    category="Failisüsteem", url=endpoint.url,
                    detail="Parameeter jõuab failiteena ilma normaliseerimata.",
                    evidence=f"payload: {payload}\n" + _excerpt(response.text, hit),
                    check="traversal", tags=("source",),
                    request=_repro(endpoint, name, payload),
                    remediation="Normaliseeri tee ja piira lubatud baaskaustaga.",
                ))
                break


def check_redirect(ctx: Context, endpoints: list[Endpoint]) -> None:
    if not ctx.config.enabled("redirect"):
        return
    canary = "nutiscan-redirect.invalid"
    for endpoint in endpoints:
        if ctx.stop():
            return
        for name in endpoint.params:
            if name.lower() not in REDIRECT_PARAMS:
                continue
            for payload in (f"//{canary}/x", f"https://{canary}/x", f"/\\{canary}/x"):
                response = _request(ctx, endpoint, name, payload, follow=False)
                if response.error:
                    continue
                location = response.header("location")
                if not location or canary not in location:
                    continue
                ctx.emit(Finding(
                    title=f"Avatud ümbersuunamine parameetris `{name}`", severity=Severity.MEDIUM,
                    category="Ümbersuunamine", url=endpoint.url,
                    detail="Rakendus suunab kasutaja ründaja valitud aadressile.",
                    evidence=f"payload: {payload}\nLocation: {location}",
                    check="redirect", tags=("redirect",),
                    request=_repro(endpoint, name, payload),
                    remediation="Luba ainult suhtelised teed või valideeri siht nimekirja vastu.",
                ))
                break


def check_command(ctx: Context, endpoints: list[Endpoint]) -> None:
    if not ctx.config.enabled("command"):
        return
    token = _token(8)
    payloads = [f"; echo {token}", f"| echo {token}", f"$(echo {token})", f"`echo {token}`"]
    seen: set[tuple[str, str]] = set()
    tested = 0
    for endpoint in endpoints:
        if tested >= MAX_PARAMS or ctx.stop():
            return
        for name in endpoint.params:
            if tested >= MAX_PARAMS or ctx.stop():
                return
            key = (urllib.parse.urlsplit(endpoint.url).path, name)
            if key in seen:
                continue
            seen.add(key)
            tested += 1
            for payload in payloads:
                response = _request(ctx, endpoint, name, payload)
                if response.error or token not in response.text:
                    continue
                # An echoed payload is not execution: a real command returns the
                # marker alone, without the shell syntax that produced it.
                if payload in response.text:
                    continue
                ctx.emit(Finding(
                    title=f"Käsu süüst parameetris `{name}`", severity=Severity.CRITICAL,
                    category="Süst", url=endpoint.url,
                    detail="Süsteemikäsu väljund ilmub vastusesse — sisend jõuab kesta.",
                    evidence=f"payload: {payload}\n" + _excerpt(response.text, token),
                    check="command", tags=("rce",),
                    request=_repro(endpoint, name, payload),
                    remediation="Ära kunagi edasta kasutaja sisendit kestale; kasuta fikseeritud "
                                "argumente ja `exec`-perekonna funktsioone.",
                ))
                break


def check_ssti(ctx: Context, endpoints: list[Endpoint]) -> None:
    if not ctx.config.enabled("ssti"):
        return
    payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}"]
    seen: set[tuple[str, str]] = set()
    tested = 0
    for endpoint in endpoints:
        if tested >= MAX_PARAMS or ctx.stop():
            return
        for name in endpoint.params:
            if tested >= MAX_PARAMS or ctx.stop():
                return
            key = (urllib.parse.urlsplit(endpoint.url).path, name)
            if key in seen:
                continue
            seen.add(key)
            tested += 1
            for payload in payloads:
                response = _request(ctx, endpoint, name, payload)
                if response.error:
                    continue
                body = response.text
                if "49" not in body or payload not in body:
                    continue
                ctx.emit(Finding(
                    title=f"Serveripoolne mallisüst (SSTI) parameetris `{name}`",
                    severity=Severity.CRITICAL, category="Süst", url=endpoint.url,
                    detail="Mallimootor hindas sisendi avaldisena (`7*7` → `49`).",
                    evidence=f"payload: {payload}\n" + _excerpt(body, "49"),
                    check="ssti", tags=("rce",),
                    request=_repro(endpoint, name, payload),
                    remediation="Ära anna kasutaja sisendit malliks; kasuta turvalisi "
                                "kontekstipõhiseid asendusi.",
                ))
                break


def check_crlf(ctx: Context, endpoints: list[Endpoint]) -> None:
    if not ctx.config.enabled("crlf"):
        return
    token = _token(8)
    header = f"X-Nutiscan-{token}"
    raw = "%0d%0a" + header + "%3a+1"
    for endpoint in endpoints:
        if ctx.stop():
            return
        for name in endpoint.params:
            if endpoint.method != "GET":
                continue
            params = dict(endpoint.params)
            params[name] = raw
            parts = urllib.parse.urlsplit(endpoint.url)
            query = urllib.parse.urlencode(params, doseq=True, safe="%")
            response = ctx.client.get(
                urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))
            )
            if response.error:
                continue
            if header.lower() not in {key.lower() for key in response.headers}:
                continue
            ctx.emit(Finding(
                title=f"CRLF-päisesüst parameetris `{name}`", severity=Severity.HIGH,
                category="Süst", url=endpoint.url,
                detail="Rünnaja saab sisestada vastusse uue päise.",
                evidence=f"payload: {raw}\nLeitud päis: {header}",
                check="crlf", tags=("xss",),
                request=_repro(endpoint, name, raw),
                remediation="Keeldu kontrollemärkidest päistes ja URL-i parameetrites.",
            ))
            return


CHECKS = [
    {"name": "xss", "kind": KIND, "run": check_xss},
    {"name": "sqli", "kind": KIND, "run": check_sqli},
    {"name": "traversal", "kind": KIND, "run": check_traversal},
    {"name": "redirect", "kind": KIND, "run": check_redirect},
    {"name": "command", "kind": KIND, "run": check_command},
    {"name": "ssti", "kind": KIND, "run": check_ssti},
    {"name": "crlf", "kind": KIND, "run": check_crlf},
]
