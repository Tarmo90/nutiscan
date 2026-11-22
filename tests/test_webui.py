"""End-to-end checks for the Web UI backend and assets."""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from nutiscan import license as lic
from webui import server
from webui.server import App, Handler
from test_nutiscan import STAAR_LICENSE, TEST_LICENSE

ROOT = Path(__file__).resolve().parents[1]


class WebUITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.history_patch = mock.patch.object(server, "HISTORY", Path(cls.temp.name))
        cls.history_patch.start()
        cls.app = App()
        cls.app.license = lic.load(TEST_LICENSE)
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
        cls.history_patch.stop()
        cls.temp.cleanup()

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

    def test_license_api(self):
        status, body, _ = self.call("/api/license")
        info = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(info["tier"], "too")
        self.assertTrue(info["signed"])
        self.assertEqual(info["sites"], 5)

        req = urllib.request.Request(
            self.base + "/api/license", data=b'{"key":"garbage"}',
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            exc.close()
        else:
            self.fail("Vigane võti aktsepteeriti")
        _, body, _ = self.call("/api/license")
        self.assertEqual(json.loads(body)["tier"], "too")

    def test_api_v1(self):
        original = self.app.license
        try:
            def api_get(path, key="testkey123"):
                headers = {"X-API-Key": key} if key is not None else {}
                request = urllib.request.Request(self.base + path, headers=headers)
                try:
                    with urllib.request.urlopen(request, timeout=10) as response:
                        return response.status, json.loads(response.read())
                except urllib.error.HTTPError as exc:
                    code, body = exc.code, json.loads(exc.read())
                    exc.close()
                    return code, body

            status, data = api_get("/api/v1/license")
            self.assertEqual(status, 403, data)
            self.app.license = lic.load(STAAR_LICENSE)
            with mock.patch.dict("os.environ", {"NUTISCAN_API_KEYS": "testkey123"}):
                status, data = api_get("/api/v1/license")
                self.assertEqual(status, 200, data)
                self.assertEqual(data["tier"], "staar")
                self.assertTrue(data["apiAccess"])
                status, data = api_get("/api/v1/license", key="wrong")
                self.assertEqual(status, 401, data)
                status, data = api_get("/api/v1/license", key=None)
                self.assertEqual(status, 401, data)
                status, data = api_get("/api/v1/history")
                self.assertEqual(status, 200, data)
                self.assertIsInstance(data["items"], list)
                status, data = api_get("/api/v1/scan/does-not-exist")
                self.assertEqual(status, 404, data)
        finally:
            self.app.license = original

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
