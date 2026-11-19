"""End-to-end checks for the Web UI backend and assets."""

from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from webui import server
from webui.server import App, Handler

ROOT = Path(__file__).resolve().parents[1]


class WebUITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = App()
        cls.handler = type("Bound", (Handler,), {"app": cls.app})
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), cls.handler)
        cls.httpd.daemon_threads = True
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def call(self, path, payload=None, method=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.base + path, data=data,
            method=method or ("POST" if data else "GET"),
            headers={"Content-Type": "application/json"} if data else {},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "")

    def test_assets(self):
        for path, marker in (("/", "<title>Nutiscan"), ("/app.js", "renderFindings"),
                             ("/style.css", ".fix-box")):
            status, body, content_type = self.call(path)
            self.assertEqual(status, 200)
            self.assertIn(marker, body.decode("utf-8"))

    def test_fixes_api(self):
        status, body, _ = self.call("/api/fixes")
        self.assertEqual(status, 200)
        fixes = json.loads(body)["fixes"]
        for name in ("headers", "xss", "sqli", "exposed", "tls", "cookies"):
            self.assertIn(name, fixes)
            self.assertTrue(fixes[name]["steps"])
            self.assertTrue(fixes[name]["code"])

    def test_scan_and_exports(self):
        status, body, _ = self.call("/api/scan", {
            "url": "example.com", "maxPages": 5, "rateLimit": 60,
            "checks": ["headers", "exposed"], "allowPrivate": False,
        })
        self.assertEqual(status, 202)
        job_id = json.loads(body)["id"]

        deadline = time.time() + 60
        while time.time() < deadline:
            _, body, _ = self.call(f"/api/scan/{job_id}")
            snapshot = json.loads(body)
            if snapshot["status"] in ("done", "error"):
                break
            time.sleep(0.3)
        self.assertEqual(snapshot["status"], "done", snapshot.get("error"))
        self.assertTrue(snapshot["findings"])

        for fmt in ("json", "md", "html", "csv", "sarif"):
            status, body, content_type = self.call(f"/api/scan/{job_id}/export?format={fmt}")
            self.assertEqual(status, 200)
            self.assertGreater(len(body), 100)

        status, body, _ = self.call("/api/history")
        self.assertIn(job_id, body.decode("utf-8"))

    def test_history_and_reload_snapshot(self):
        status, body, _ = self.call("/api/history")
        items = json.loads(body)["items"]
        self.assertIsInstance(items, list)
        if items:
            status, body, _ = self.call(f"/api/scan/{items[0]['id']}")
            self.assertEqual(json.loads(body)["id"], items[0]["id"])


if __name__ == "__main__":
    unittest.main()
