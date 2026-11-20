"""Scan orchestration: target guard, transport, crawl, checks, triage."""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
import traceback
import urllib.parse
import uuid
from dataclasses import dataclass, field

from . import auth as auth_module
from . import domxss, idor, intel, oob, triage
from .checks import Context, load_checks
from .config import Config
from .crawling import Crawler, Endpoint
from .findings import Finding, counts, sort_findings
from .http import Client, origin


@dataclass
class ScanJob:
    id: str
    url: str
    config: Config
    status: str = "queued"
    progress: int = 0
    stage: str = "ootab"
    logs: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    pages: int = 0
    endpoints: int = 0
    error: str = ""
    started: float = 0.0
    finished: float = 0.0
    triage: str = ""
    triage_summary: dict = field(default_factory=dict)
    _stop: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _keys: set = field(default_factory=set)

    def log(self, message: str) -> None:
        with self._lock:
            self.logs.append(f"[{time.strftime('%H:%M:%S')}] {message}")
            if len(self.logs) > 1000:
                del self.logs[:200]

    def emit(self, finding: Finding) -> None:
        key = (finding.check, finding.url, finding.title)
        with self._lock:
            if key in self._keys:
                return
            self._keys.add(key)
            self.findings.append(finding)
        self.log(f"+ [{finding.severity.value.upper()}] {finding.title}")

    def stop(self) -> bool:
        with self._lock:
            return self._stop

    def request_stop(self) -> None:
        with self._lock:
            self._stop = True

    def snapshot(self) -> dict:
        with self._lock:
            findings = [item.to_dict() for item in sort_findings(self.findings)]
            logs = list(self.logs)
        return {
            "id": self.id,
            "tool": "Nutiscan",
            "version": "2.2.0",
            "url": self.url,
            "status": self.status,
            "stage": self.stage,
            "progress": self.progress,
            "logs": logs,
            "findings": findings,
            "counts": counts(self.findings),
            "pages": self.pages,
            "endpoints": self.endpoints,
            "error": self.error,
            "duration": round((self.finished or time.time()) - self.started, 2) if self.started else 0,
            "triage": self.triage,
            "triageSummary": self.triage_summary,
            "options": {
                "maxPages": self.config.max_pages,
                "maxDepth": self.config.max_depth,
                "rateLimit": self.config.rate_limit,
                "allowPost": self.config.allow_post,
                "checks": self.config.checks,
            },
        }


class Engine:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.checks = load_checks()

    def run(self, job: ScanJob) -> None:
        job.status = "running"
        job.started = time.time()
        job.progress = 2
        job.stage = "algatus"
        try:
            self._execute(job)
        except Exception as exc:  # noqa: BLE001 - surface any failure in the snapshot
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.log("KRIITILINE: " + job.error)
            job.log(traceback.format_exc(limit=5))
        finally:
            if job.status == "running":
                job.status = "done"
            job.finished = time.time()
            job.progress = 100
            job.stage = "valmis"
            job.log(f"Lõpetatud: {len(job.findings)} leidu, "
                    f"{round(job.finished - job.started, 1)} s")

    def _execute(self, job: ScanJob) -> None:
        config = job.config
        candidates = _target_candidates(job.url)
        if not config.allow_private:
            for candidate in candidates:
                _guard_target(candidate)

        client = Client(
            user_agent=config.user_agent,
            timeout=config.timeout,
            verify_tls=config.verify_tls,
            rate_limit=config.rate_limit,
            max_body=config.max_body,
            retries=config.retries,
            headers=config.headers,
        )

        auth_detail = ""
        if config.auth:
            auth_cfg = auth_module.AuthConfig.from_dict(config.auth)
            ok, auth_detail = auth_module.apply_auth(client, auth_cfg, candidates[0])
            job.log(f"Autentimine: {auth_detail}")
            if not ok:
                raise RuntimeError(f"Autentimine ebaõnnestus: {auth_detail}")

        target, root = _first_reachable(client, candidates, job.stop)
        if target is None or root is None:
            raise RuntimeError(f"Sihtmärk ei vasta: {job.url}")
        if target != candidates[0]:
            job.log(f"Esimene kandidaat ebaõnnestus, kasutan: {target}")

        # CVE correlation from observed banners (offline, no external calls).
        for banner in (root.header("server", ""), root.header("x-powered-by", "")):
            if not banner:
                continue
            for match in intel.correlate_banner(banner):
                job.emit(Finding(
                    title=f"Teadaolev haavatavus: {match.cve}",
                    severity=_severity_from_text(match.severity),
                    category="Teadaolevad haavatavused",
                    url=origin(target),
                    detail=match.detail,
                    evidence=match.banner,
                    check="cve",
                    tags=("fingerprint",),
                    remediation="Uuenda tarkvara viimasele turvaversioonile.",
                ))

        job.progress = 5
        job.stage = "avaleht"
        job.log(f"Sihtmärk: {origin(target)}")
        job.log(f"HTTP {root.status}, {len(root.body)} baiti, {int(root.elapsed * 1000)} ms")

        ctx = Context(
            client=client, config=config, origin=origin(target), root=root,
            pages=[], endpoints=[], log=job.log, emit=job.emit, stop=job.stop,
        )

        job.progress = 8
        job.stage = "passiivsed kontrollid"
        self._run_kind(job, ctx, "passive", [])

        job.progress = 15
        job.stage = "kaardistamine"
        crawler = Crawler(client, target, config.max_pages, config.max_depth)

        def on_page(page) -> None:
            job.pages += 1
            job.progress = min(45, 15 + int(30 * job.pages / max(1, config.max_pages)))
            job.log(f"leht {job.pages}: {page.status} {page.url}")

        pages, endpoints = crawler.crawl(on_page)
        if not config.allow_post:
            endpoints = [item for item in endpoints if item.method != "POST"]
        job.endpoints = len(endpoints)
        ctx.pages = pages
        ctx.endpoints = endpoints
        job.log(f"Kaardistatud {len(pages)} lehte, {len(endpoints)} sisendit")

        if config.enabled("domxss"):
            job.stage = "DOM-XSS"
            dom_findings = domxss.check_dom_xss(pages, origin(target))
            for finding in dom_findings:
                job.emit(finding)
            if dom_findings:
                job.log(f"DOM-XSS: {len(dom_findings)} kahtlast voolu")

        job.progress = 50
        job.stage = "avalikud failid"
        self._run_kind(job, ctx, "exposed", [])

        job.progress = 60
        job.stage = "aktiivsed kontrollid"
        active_endpoints = endpoints[:config.max_endpoints]
        active_checks = [item for item in self.checks if item["kind"] == "active"]
        for index, check in enumerate(active_checks):
            if job.stop():
                return
            if not config.enabled(check["name"]):
                continue
            job.stage = f"kontroll: {check['name']}"
            job.progress = 60 + int(30 * index / max(1, len(active_checks)))
            job.log(f"Kontroll {check['name']}: {len(active_endpoints)} sihtmärki")
            _safe_run(job, check, ctx, active_endpoints)

        if config.enable_oob:
            job.progress = 90
            job.stage = "OOB-kontroll"
            job.log("Pime süüst: käivitan kohaliku callback-kuulaja")
            try:
                with oob.CallbackListener(host=config.oob_host) as listener:
                    for finding in oob.check_oob(
                        client, active_endpoints, listener,
                        wait_seconds=config.oob_wait,
                    ):
                        job.emit(finding)
            except OSError as exc:
                job.log(f"OOB-kuulaja ei käivitunud: {exc}")

        if config.enable_idor and config.auth:
            job.progress = 92
            job.stage = "juurdepääsukontroll"
            job.log("IDOR-i diferentsiaalkontroll (autenditud)")
            for probe in (
                idor.check_idor(client, active_endpoints, origin(target)),
                idor.check_id_sequences(client, active_endpoints, origin(target)),
            ):
                for finding in probe:
                    job.emit(finding)

        # Attach CVSS-style estimates to every finding.
        for finding in job.findings:
            finding.score = intel.cvss_estimate(finding)

        job.findings = sort_findings(job.findings)
        job.progress = 95
        job.stage = "triaaž"
        stats = {
            "pages": len(pages),
            "endpoints": len(endpoints),
            "duration": round(time.time() - job.started, 1),
        }
        job.triage, job.triage_summary = triage.analyze(job.url, job.findings, stats)
        job.log(f"Valmis: {len(job.findings)} leidu, riskiskoor {job.triage_summary['riskScore']}/100")

    def _run_kind(self, job: ScanJob, ctx: Context, kind: str, endpoints: list[Endpoint]) -> None:
        for check in self.checks:
            if check["kind"] != kind or not job.config.enabled(check["name"]):
                continue
            if job.stop():
                return
            _safe_run(job, check, ctx, endpoints)


def _severity_from_text(value: str):
    from .findings import Severity
    return {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW,
    }.get(value, Severity.INFO)


def _safe_run(job: ScanJob, check: dict, ctx: Context, endpoints: list[Endpoint]) -> None:
    try:
        check["run"](ctx, endpoints)
    except Exception as exc:  # noqa: BLE001 - one broken check must not kill the scan
        job.log(f"! kontroll '{check['name']}' ebaõnnestus: {type(exc).__name__}: {exc}")


def _target_candidates(raw: str) -> list[str]:
    url = raw.strip()
    if not url:
        raise ValueError("URL on tühi")
    if not url.startswith(("http://", "https://")):
        return ["https://" + url, "http://" + url]
    return [url]


def _first_reachable(client: Client, candidates: list[str], stop):
    for url in candidates:
        if stop():
            return None, None
        response = client.get(url, follow=True)
        if not response.error:
            return url, response
    return None, None


def _guard_target(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    if not host:
        raise RuntimeError("Sihtmärgil puudub host")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise RuntimeError(f"Sihtmärgi lahendamine ebaõnnestus: {exc}") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast or address.is_unspecified):
            raise RuntimeError(
                f"Era-/lokaalaadress {address} on vaikimisi keelatud. "
                "Oma testserveri jaoks kasuta --allow-private."
            )


def new_job(url: str, config: Config | None = None) -> ScanJob:
    return ScanJob(id=uuid.uuid4().hex[:12], url=url, config=config or Config())
