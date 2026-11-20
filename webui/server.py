"""Web UI backend: scan API, history, fix-library, SARIF/JSON export."""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    from .fixes import FIXES, get_fix
except ImportError:
    from fixes import FIXES, get_fix

from nutiscan import __version__, export
from nutiscan.config import Config
from nutiscan.engine import Engine, ScanJob, new_job

ROOT = Path(__file__).resolve().parent
HISTORY = Path(os.environ.get("NUTISCAN_HISTORY", str(ROOT.parent / "webui-history")))


class App:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.jobs: dict[str, ScanJob] = {}
        self.engine = Engine()
        HISTORY.mkdir(parents=True, exist_ok=True)

    def start(self, payload: dict) -> ScanJob:
        url = str(payload.get("url", "")).strip()
        config = Config(
            max_pages=_int(payload.get("maxPages"), 60, 5, 300),
            max_depth=_int(payload.get("maxDepth"), 2, 0, 5),
            rate_limit=_float(payload.get("rateLimit"), 8.0, 0.5, 50.0),
            timeout=_float(payload.get("timeout"), 10.0, 2.0, 60.0),
            max_endpoints=_int(payload.get("maxEndpoints"), 120, 1, 500),
            allow_private=bool(payload.get("allowPrivate")),
            allow_post=bool(payload.get("allowPost", True)),
            verify_tls=bool(payload.get("verifyTls")),
            headers=_headers(payload.get("headers")),
            checks=_checks(payload.get("checks")),
            auth=_auth(payload.get("auth")),
            enable_idor=bool(payload.get("idor")),
        )
        job = new_job(url, config)
        with self.lock:
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _run(self, job: ScanJob) -> None:
        self.engine.run(job)
        snapshot = job.snapshot()
        try:
            (HISTORY / f"{job.id}.json").write_bytes(export.to_json(snapshot))
        except OSError:
            pass

    def get(self, job_id: str) -> ScanJob | None:
        with self.lock:
            return self.jobs.get(job_id)

    def history(self) -> list[dict]:
        items: list[dict] = []
        for path in sorted(HISTORY.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:40]:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            items.append({
                "id": data.get("id", path.stem),
                "url": data.get("url", ""),
                "status": data.get("status", ""),
                "findings": len(data.get("findings") or []),
                "counts": data.get("counts", {}),
                "risk": (data.get("triageSummary") or {}).get("riskScore", 0),
                "duration": data.get("duration", 0),
            })
        return items


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    app: App

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/health":
            self._json({"ok": True, "version": __version__, "tool": "Nutiscan"})
            return
        if path == "/api/history":
            self._json({"items": self.app.history()})
            return
        if path == "/api/fixes":
            self._json({"fixes": FIXES})
            return
        if path.startswith("/api/scan/"):
            parts = path.split("/")
            if len(parts) >= 5 and parts[4] == "export":
                job_id = parts[3]
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                fmt = str((query.get("format") or ["json"])[0]).lower()
                snapshot = self._snapshot(job_id)
                if snapshot is None:
                    self._json({"error": "tundmatu skann"}, HTTPStatus.NOT_FOUND)
                    return
                if fmt not in export.FORMATS:
                    self._json({"error": "tundmatu formaat"}, HTTPStatus.BAD_REQUEST)
                    return
                content_type, extension, render = export.FORMATS[fmt]
                self._download(f"nutiscan-{job_id}.{extension}", content_type, render(snapshot))
                return
            job_id = path.rsplit("/", 1)[-1]
            job = self.app.get(job_id)
            if job:
                self._json(job.snapshot())
                return
            snapshot = self._disk_snapshot(job_id)
            if snapshot is None:
                self._json({"error": "tundmatu skann"}, HTTPStatus.NOT_FOUND)
            else:
                self._json(snapshot)
            return
        if path in ("/", "/index.html"):
            self._file(ROOT / "index.html", "text/html; charset=utf-8")
            return
        if path == "/app.js":
            self._file(ROOT / "app.js", "application/javascript; charset=utf-8")
            return
        if path == "/style.css":
            self._file(ROOT / "style.css", "text/css; charset=utf-8")
            return
        if path == "/favicon.ico":
            self._file(ROOT.parent / "Nutiscan.ico", "image/x-icon")
            return
        self._json({"error": "ei leitud"}, HTTPStatus.NOT_FOUND)

    def do_POST(self):  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/scan":
            payload = self._body()
            if not str(payload.get("url", "")).strip():
                self._json({"error": "URL on kohustuslik"}, HTTPStatus.BAD_REQUEST)
                return
            job = self.app.start(payload)
            self._json({"id": job.id, "status": job.status}, HTTPStatus.ACCEPTED)
            return
        if path.startswith("/api/scan/") and path.endswith("/stop"):
            job_id = path.split("/")[3]
            job = self.app.get(job_id)
            if not job:
                self._json({"error": "tundmatu skann"}, HTTPStatus.NOT_FOUND)
                return
            job.request_stop()
            self._json({"id": job.id, "status": "stopping"})
            return
        self._json({"error": "ei leitud"}, HTTPStatus.NOT_FOUND)

    def _snapshot(self, job_id: str) -> dict | None:
        job = self.app.get(job_id)
        if job:
            return job.snapshot()
        return self._disk_snapshot(job_id)

    def _disk_snapshot(self, job_id: str) -> dict | None:
        path = HISTORY / f"{job_id}.json"
        if not path.is_file() or "/" in job_id or "\\" in job_id:
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > 1_000_000:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def _json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, content_type: str) -> None:
        try:
            body = path.read_bytes()
        except OSError:
            self._json({"error": "fail puudub"}, HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _download(self, filename: str, content_type: str, body: bytes) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def _int(value, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


def _float(value, default: float, low: float, high: float) -> float:
    try:
        return max(low, min(high, float(value)))
    except (TypeError, ValueError):
        return default


def _headers(value) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    blocked = {"host", "content-length", "connection", "transfer-encoding"}
    return {
        str(k): str(v) for k, v in list(value.items())[:20]
        if str(k).lower() not in blocked and len(str(k)) < 128 and len(str(v)) < 1024
    }


def _auth(value) -> dict | None:
    if not isinstance(value, dict) or not value:
        return None
    clean: dict = {}
    for key in ("bearer", "cookieFile"):
        if value.get(key):
            clean[key] = str(value[key])[:2000]
    for key in ("cookies", "headers"):
        if isinstance(value.get(key), dict):
            clean[key] = {
                str(k)[:128]: str(v)[:1024] for k, v in list(value[key].items())[:20]
            }
    if isinstance(value.get("credentials"), list):
        clean["credentials"] = [
            {
                "loginUrl": str(item.get("loginUrl", ""))[:1000],
                "fields": {str(k)[:128]: str(v)[:512] for k, v in
                           list((item.get("fields") or {}).items())[:20]},
                "method": str(item.get("method", "POST"))[:10],
                "successMarker": str(item.get("successMarker", ""))[:200],
                "failureMarker": str(item.get("failureMarker", ""))[:200],
            }
            for item in value["credentials"][:5] if isinstance(item, dict)
        ]
    return clean or None


def _checks(value) -> list[str]:
    if not isinstance(value, list):
        return []
    allowed = {
        "headers", "cookies", "cors", "cache", "banner", "tls", "methods", "exposed",
        "xss", "sqli", "traversal", "redirect", "command", "ssti", "crlf", "domxss",
    }
    return [str(item) for item in value[:20] if str(item) in allowed]


def serve(host: str = "127.0.0.1", port: int = 8822, open_browser: bool = True) -> None:
    app = App()
    handler = type("Bound", (Handler,), {"app": app})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    url = f"http://{host}:{port}/"
    print(f"Nutiscan Web UI: {url}")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    serve()
