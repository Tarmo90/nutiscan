"""Passive checks: headers, cookies, CORS, cache, banners, TLS, HTTP methods."""

from __future__ import annotations

import datetime
import email.utils
import socket
import ssl
import urllib.parse

from .. import http
from ..crawling import Endpoint
from ..findings import Finding, Severity
from . import Context

KIND = "passive"

EVIL_ORIGIN = "https://evil.nutiscan.invalid"

HEADER_RULES: list[tuple[str, Severity, str, str, str]] = [
    ("strict-transport-security", Severity.MEDIUM, "HSTS puudub", "Turvapeadised",
     "Lisa `Strict-Transport-Security: max-age=31536000; includeSubDomains`."),
    ("content-security-policy", Severity.MEDIUM, "CSP puudub", "Turvapeadised",
     "Lisa `Content-Security-Policy: default-src 'self'; script-src 'self'`."),
    ("x-content-type-options", Severity.LOW, "X-Content-Type-Options puudub", "Turvapeadised",
     "Lisa `X-Content-Type-Options: nosniff`."),
    ("referrer-policy", Severity.LOW, "Referrer-Policy puudub", "Turvapeadised",
     "Lisa `Referrer-Policy: strict-origin-when-cross-origin`."),
    ("permissions-policy", Severity.LOW, "Permissions-Policy puudub", "Turvapeadised",
     "Lisa `Permissions-Policy: camera=(), microphone=(), geolocation=()`."),
    ("cross-origin-opener-policy", Severity.LOW, "COOP puudub", "Turvapeadised",
     "Lisa `Cross-Origin-Opener-Policy: same-origin`, et piirata `window.opener` ligipääsu."),
    ("cross-origin-resource-policy", Severity.LOW, "CORP puudub", "Turvapeadised",
     "Lisa `Cross-Origin-Resource-Policy: same-origin`."),
    ("x-permitted-cross-domain-policies", Severity.INFO, "X-Permitted-Cross-Domain-Policies puudub",
     "Turvapeadised", "Lisa `X-Permitted-Cross-Domain-Policies: none`."),
]

BANNER_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-litespeed-cache",
]


def check_headers(ctx: Context, _endpoints: list[Endpoint]) -> None:
    response = ctx.root
    if response.error:
        return
    for name, severity, title, category, fix in HEADER_RULES:
        if name == "strict-transport-security" and not ctx.origin.startswith("https"):
            continue
        if response.header(name):
            continue
        ctx.emit(Finding(
            title=title, severity=severity, category=category, url=ctx.origin,
            detail=f"Vastus ei sisalda `{name}` päist.",
            check="headers", remediation=fix, tags=["hardening"],
        ))

    csp = response.header("content-security-policy", "").lower()
    if not (response.header("x-frame-options") or "frame-ancestors" in csp):
        ctx.emit(Finding(
            title="Raamimise kaitse puudub", severity=Severity.MEDIUM,
            category="Turvapeadised", url=ctx.origin,
            detail="Ei `X-Frame-Options` ega CSP `frame-ancestors` ei keela lehe raamimist.",
            check="headers", remediation="Lisa `X-Frame-Options: DENY` või CSP `frame-ancestors 'none'`.",
            tags=["clickjacking"],
        ))


def check_cookies(ctx: Context, _endpoints: list[Endpoint]) -> None:
    for raw in ctx.root.all_headers("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        if not name:
            continue
        lower = raw.lower()
        issues: list[str] = []
        if "secure" not in lower:
            issues.append("Secure")
        if "httponly" not in lower:
            issues.append("HttpOnly")
        if "samesite" not in lower:
            issues.append("SameSite")
        if name.startswith("__Host-") and ("domain=" in lower or "path=/" not in lower):
            issues.append("__Host- eesliite reeglid")
        if "domain=" in lower:
            domain = lower.split("domain=", 1)[1].split(";", 1)[0].strip()
            host = urllib.parse.urlsplit(ctx.origin).hostname or ""
            if domain and domain.lstrip(".") not in host:
                issues.append("Domain ei ühti hostiga")
        if not issues:
            continue
        ctx.emit(Finding(
            title=f"Küpsis `{name}`: " + ", ".join(issues),
            severity=Severity.MEDIUM if "HttpOnly" in issues or "Secure" in issues else Severity.LOW,
            category="Sessioonihaldus", url=ctx.origin,
            detail="Küpsise turvareeglid on puudulikud: " + ", ".join(issues) + ".",
            evidence=raw[:240], check="cookies", tags=["auth"],
            remediation="Lisa `Secure; HttpOnly; SameSite=Lax` ning eemalda tarbetu Domain.",
        ))


def check_cors(ctx: Context, _endpoints: list[Endpoint]) -> None:
    for probe_origin in (EVIL_ORIGIN, "null"):
        response = ctx.client.get(ctx.origin, headers={"Origin": probe_origin})
        if response.error:
            continue
        allow = response.header("access-control-allow-origin")
        creds = response.header("access-control-allow-credentials", "").lower() == "true"
        if not allow:
            continue
        if allow == "*" and creds:
            severity, title = Severity.HIGH, "CORS: `*` koos credentials-iga"
        elif allow in (EVIL_ORIGIN, "null"):
            severity = Severity.HIGH if creds else Severity.MEDIUM
            title = f"CORS: Origin `{probe_origin}` peegeldatakse tagasi"
        else:
            continue
        ctx.emit(Finding(
            title=title, severity=severity, category="CORS", url=ctx.origin,
            detail="Server lubab võõra origini lugeda autenditud vastuseid.",
            evidence=f"Origin: {probe_origin} -> ACAO: {allow}, ACAC: {creds}",
            check="cors", tags=["auth"],
            remediation="Valideeri Origin lubatud nimekirja vastu ja tagasta staatiline väärtus.",
        ))
        break


def check_cache(ctx: Context, _endpoints: list[Endpoint]) -> None:
    response = ctx.root
    if response.error or not response.all_headers("set-cookie"):
        return
    control = response.header("cache-control", "").lower()
    if "no-store" in control or "no-cache" in control:
        return
    ctx.emit(Finding(
        title="Sessiooniküpsis ilma vahemälukaitsega", severity=Severity.MEDIUM,
        category="Sessioonihaldus", url=ctx.origin,
        detail="Vastus seab küpsise, aga `Cache-Control: no-store` puudub.",
        evidence=f"Cache-Control: {response.header('cache-control', 'puudub')}",
        check="cache", tags=["auth"],
        remediation="Lisa `Cache-Control: no-store, private` ja `Pragma: no-cache`.",
    ))


def check_banner(ctx: Context, _endpoints: list[Endpoint]) -> None:
    response = ctx.root
    if response.error:
        return
    for header in BANNER_HEADERS:
        value = response.header(header)
        if not value:
            continue
        if header in ("server", "x-powered-by") and not any(ch.isdigit() for ch in value):
            continue
        ctx.emit(Finding(
            title=f"Versioonileke päises `{header}`", severity=Severity.LOW,
            category="Info leke", url=ctx.origin,
            detail=f"Vastus paljastab tarkvara ja versiooni: `{value}`.",
            evidence=f"{header}: {value}", check="banner", tags=["fingerprint"],
            remediation="Eemalda versioon päisest (nt nginx `server_tokens off`).",
        ))
    generator = next((p.generator for p in ctx.pages if p.generator), "")
    if generator and any(ch.isdigit() for ch in generator):
        ctx.emit(Finding(
            title=f"Generatori leke: {generator}", severity=Severity.LOW,
            category="Info leke", url=ctx.origin,
            detail="HTML-i meta generator paljastab CMS-i ja versiooni.",
            evidence=generator[:200], check="banner", tags=["fingerprint"],
            remediation="Eemalda `<meta name=generator>` või maski versioon.",
        ))


def check_tls(ctx: Context, _endpoints: list[Endpoint]) -> None:
    parts = urllib.parse.urlsplit(ctx.origin)
    if parts.scheme != "https":
        ctx.emit(Finding(
            title="HTTP ilma TLS-ita", severity=Severity.HIGH, category="Transport",
            url=ctx.origin, detail="Kogu liiklus on krüpteerimata.",
            check="tls", tags=["transport"],
            remediation="Võta kasutusele TLS 1.2+ ja suuna HTTP 301-ga ümber.",
        ))
        return

    host, port = parts.hostname or "", parts.port or 443
    protocol = "unknown"
    cert: dict = {}
    verify_error = ""

    loose = ssl.create_default_context()
    loose.check_hostname = False
    loose.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=ctx.config.timeout) as raw:
            with loose.wrap_socket(raw, server_hostname=host) as tls:
                protocol = tls.version() or "unknown"
    except (OSError, ssl.SSLError) as exc:
        ctx.emit(Finding(
            title="TLS-kätlus ebaõnnestus", severity=Severity.MEDIUM, category="Transport",
            url=ctx.origin, detail=f"Ühendust ei saanud luua: {exc}",
            check="tls", tags=["transport"],
            remediation="Kontrolli TLS-i konfiguratsiooni ja porti.",
        ))
        return

    try:
        verified = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=ctx.config.timeout) as raw:
            with verified.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
    except (OSError, ssl.SSLError) as exc:
        verify_error = f"{type(exc).__name__}: {exc}"

    if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        ctx.emit(Finding(
            title=f"Aegunud TLS: {protocol}", severity=Severity.HIGH, category="Transport",
            url=ctx.origin, detail=f"Server lubab murdunud versiooni {protocol}.",
            check="tls", tags=["transport"], remediation="Luba ainult TLS 1.2 / 1.3.",
        ))
    if verify_error:
        ctx.emit(Finding(
            title="TLS-sertifikaat ei läbi kontrolli", severity=Severity.HIGH,
            category="Transport", url=ctx.origin,
            detail=f"Brauseri kontroll ebaõnnestub: {verify_error}",
            evidence=verify_error[:300], check="tls", tags=["transport"],
            remediation="Paigalda hosti katav kehtiv sertifikaat koos kettaga.",
        ))

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = email.utils.parsedate_to_datetime(not_after)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=datetime.timezone.utc)
            days = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
            if days < 0:
                ctx.emit(Finding(
                    title="TLS-sertifikaat on aegunud", severity=Severity.HIGH,
                    category="Transport", url=ctx.origin,
                    detail=f"Sertifikaat aegus {not_after}.", evidence=not_after,
                    check="tls", tags=["transport"], remediation="Uuenda sertifikaat kohe.",
                ))
            elif days < 14:
                ctx.emit(Finding(
                    title=f"TLS-sertifikaat aegub {days} päeva pärast",
                    severity=Severity.MEDIUM, category="Transport", url=ctx.origin,
                    detail=f"Kehtivus lõppeb {not_after}.", evidence=not_after,
                    check="tls", tags=["transport"], remediation="Uuenda sertifikaat.",
                ))
        except (TypeError, ValueError, IndexError):
            pass


def check_methods(ctx: Context, _endpoints: list[Endpoint]) -> None:
    response = ctx.client.request("OPTIONS", ctx.origin)
    allow = response.header("allow", "")
    dangerous = [m for m in ("TRACE", "PUT", "DELETE", "PATCH", "CONNECT")
                 if m in allow.upper()]
    if dangerous:
        ctx.emit(Finding(
            title=f"Ohtlikud HTTP-meetodid lubatud: {', '.join(dangerous)}",
            severity=Severity.MEDIUM, category="Konfiguratsioon", url=ctx.origin,
            detail=f"OPTIONS vastus lubab meetodeid: {allow}", evidence=allow[:200],
            check="methods", tags=["config"],
            remediation="Piira lubatud meetodid (GET, POST, HEAD) veebiserveri tasemel.",
        ))

    token = "nutiscan-trace-check"
    traced = ctx.client.request("TRACE", ctx.origin, headers={"X-Nutiscan": token})
    if traced.status == 200 and (token in traced.text or "TRACE" in traced.text[:200]):
        ctx.emit(Finding(
            title="TRACE on lubatud", severity=Severity.MEDIUM, category="Konfiguratsioon",
            url=ctx.origin, detail="TRACE peegeldab päised tagasi ja võib lekitada credentials-e.",
            evidence=traced.text[:200], check="methods", tags=["config"],
            remediation="Lülita TRACE välja: `TraceEnable off` (Apache) või `ignore_invalid_headers`.",
        ))


CHECKS = [
    {"name": "headers", "kind": KIND, "run": check_headers},
    {"name": "cookies", "kind": KIND, "run": check_cookies},
    {"name": "cors", "kind": KIND, "run": check_cors},
    {"name": "cache", "kind": KIND, "run": check_cache},
    {"name": "banner", "kind": KIND, "run": check_banner},
    {"name": "tls", "kind": KIND, "run": check_tls},
    {"name": "methods", "kind": KIND, "run": check_methods},
]
