"""Out-of-band interaction detection using a local HTTP callback listener.

Blind SQLi / blind SSRF / blind command injection do not reflect into the
response. We inject a unique URL and watch our own listener for a hit.
The listener binds only to 127.0.0.1 by default; set host for LAN targets.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .crawling import Endpoint
from .findings import Finding, Severity
from .http import Client, with_params

_TOKEN_LEN = 12


def _token() -> str:
    import random
    import string
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=_TOKEN_LEN))


class _Collector(BaseHTTPRequestHandler):
    hits: list[tuple[str, str, float]] = []

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):  # noqa: N802
        _Collector.hits.append((self.path, self.headers.get("User-Agent", ""), time.time()))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_HEAD = do_GET


class CallbackListener:
    """Context manager: starts a local HTTP collector and exposes its base URL."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, path_prefix: str = "/ Nutiscan".replace(" ", "")) -> None:
        self.host = host
        self.port = port
        self.prefix = path_prefix
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        _Collector.hits = []

    def __enter__(self) -> "CallbackListener":
        self.httpd = ThreadingHTTPServer((self.host, self.port), _Collector)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *args) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=3)

    @property
    def base_url(self) -> str:
        if not self.httpd:
            raise RuntimeError("listener not started")
        return f"http://{self.host}:{self.httpd.server_address[1]}{self.prefix}"

    def hits_for(self, token: str) -> list[tuple[str, str, float]]:
        return [hit for hit in _Collector.hits if token in hit[0]]


def check_oob(
    client: Client,
    endpoints: list[Endpoint],
    listener: CallbackListener,
    wait_seconds: float = 3.0,
    max_params: int = 12,
) -> list[Finding]:
    """Inject callback URLs into parameters and wait for interaction."""
    findings: list[Finding] = []
    tested = 0
    base = listener.base_url
    pending: dict[str, tuple[str, str, Endpoint, str]] = {}

    for endpoint in endpoints[:max_params]:
        if tested >= max_params:
            break
        for name in endpoint.params:
            if tested >= max_params:
                break
            token = _token()
            payload = f"{base}?id={token}"
            pending[token] = (name, endpoint.url, endpoint, payload)
            tested += 1
            if endpoint.method == "POST":
                params = dict(endpoint.params)
                params[name] = payload
                client.post(endpoint.url, params)
            else:
                client.get(with_params(endpoint.url, {**endpoint.params, name: payload}))

    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        for token, (name, url, endpoint, payload) in list(pending.items()):
            hits = listener.hits_for(token)
            if not hits:
                continue
            findings.append(Finding(
                title=f"Pime süüst (OOB) parameetris `{name}`",
                severity=Severity.CRITICAL,
                category="Süst",
                url=url,
                detail="Süstitud callback sai serverilt päringu — kasutaja sisend vallandab "
                       "võrgupäringu või käsuaheluse ka siis, kui vastus seda ei näita.",
                evidence=f"payload: {payload}\ncallback: {hits[0][0]} @ {hits[0][2]:.2f}",
                check="oob",
                tags=("sqli", "rce", "ssrf"),
                request={"method": endpoint.method, "url": url,
                         "parameter": name, "payload": payload},
                remediation="Kasuta parametriseeritud päringuid, range sisendivalidatsiooni "
                            "ja väljuva liikluse piiranguid (egress filtering).",
            ))
            del pending[token]
        if not pending:
            break
        time.sleep(0.2)

    return findings


__all__ = ["CallbackListener", "check_oob"]
