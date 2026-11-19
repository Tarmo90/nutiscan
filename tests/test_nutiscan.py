"""End-to-end tests for Nutiscan against the bundled demo application."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_target import DemoApp  # noqa: E402
from nutiscan import export  # noqa: E402
from nutiscan.config import Config  # noqa: E402
from nutiscan.engine import Engine, new_job  # noqa: E402


class NutiscanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), DemoApp)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = f"http://127.0.0.1:{cls.port}/"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def run_scan(self, **overrides):
        values = {
            "max_pages": 10, "max_depth": 2, "rate_limit": 80,
            "allow_private": True, "timeout": 5, "retries": 0,
        }
        values.update(overrides)
        config = Config(**values)
        job = new_job(self.target, config)
        Engine(config).run(job)
        return job

    def test_full_scan_checks(self):
        job = self.run_scan()
        self.assertEqual(job.status, "done", job.error)
        by_check: dict[str, list[str]] = {}
        for finding in job.findings:
            by_check.setdefault(finding.check, []).append(finding.title)

        for name in ("headers", "cookies", "cors", "cache", "banner", "tls", "methods",
                     "exposed", "xss", "sqli", "traversal", "redirect", "command", "ssti"):
            self.assertIn(name, by_check, f"missing {name}: {list(by_check)}")
        self.assertTrue(any(".env" in title for title in by_check["exposed"]))
        self.assertTrue(any("security.txt" in title for title in by_check["exposed"]))
        self.assertGreaterEqual(job.pages, 3)
        self.assertGreaterEqual(job.endpoints, 4)
        self.assertTrue(job.triage)
        self.assertGreater(job.triage_summary["riskScore"], 0)

    def test_check_filter(self):
        job = self.run_scan(checks=["headers"])
        self.assertEqual(job.status, "done")
        self.assertTrue(all(item.check in ("headers",) for item in job.findings))

    def test_header_and_cookie_transport(self):
        job = self.run_scan(checks=["headers"], headers={"X-Test-Header": "yes"})
        self.assertEqual(job.status, "done")
        from nutiscan.http import Client
        client = Client("test", headers={"X-Test-Header": "yes"})
        client.get(self.target)
        body = client.get(self.target + "headers").text
        self.assertIn("X-Test-Header: yes", body)
        self.assertIn("Cookie: sid=demo123", body)

    def test_exports(self):
        job = self.run_scan()
        snapshot = job.snapshot()
        self.assertEqual(len(json.loads(export.to_json(snapshot))["findings"]), len(job.findings))
        self.assertIn("# Nutiscan", export.to_markdown(snapshot).decode("utf-8"))
        html = export.to_html(snapshot).decode("utf-8")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertNotIn("<script", html)
        csv = export.to_csv(snapshot).decode("utf-8")
        self.assertIn("severity,score", csv)
        sarif = json.loads(export.to_sarif(snapshot))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])

    def test_target_guard(self):
        from nutiscan.engine import _guard_target
        with self.assertRaises(RuntimeError):
            _guard_target("http://127.0.0.1/")
        with mock.patch("nutiscan.engine.socket.getaddrinfo",
                        return_value=[(2, 1, 6, "", ("93.184.216.34", 80))]):
            _guard_target("https://example.com/")

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scan.py"), "scan", "--target", self.target,
                 "--allow-private", "--rate-limit", "80", "--max-pages", "10",
                 "--formats", "md,html,csv,sarif,json", "--out", temp],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            files = list(Path(temp).glob("*"))
            suffixes = {path.suffix for path in files}
            self.assertTrue({".json", ".md", ".html", ".csv", ".sarif"}.issubset(suffixes))
            self.assertTrue(any(path.name.startswith("summary-") for path in files))


if __name__ == "__main__":
    unittest.main()
