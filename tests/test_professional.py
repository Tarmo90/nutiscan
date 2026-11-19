"""Tests for auth, IDOR differentials and CVE correlation."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nutiscan.auth import AuthConfig, apply_auth  # noqa: E402
from nutiscan.http import Client  # noqa: E402
from nutiscan.intel import correlate_banner, cvss_estimate  # noqa: E402
from nutiscan.findings import Finding, Severity  # noqa: E402


class ProfessionalTest(unittest.TestCase):
    def test_auth_config_from_dict(self):
        cfg = AuthConfig.from_dict({
            "bearer": "abc",
            "cookies": {"sid": "123"},
            "credentials": [{
                "loginUrl": "https://example.com/login",
                "fields": {"u": "a", "p": "b"},
                "successMarker": "welcome",
            }],
        })
        self.assertEqual(cfg.bearer, "abc")
        self.assertEqual(cfg.cookies["sid"], "123")
        self.assertEqual(cfg.credentials[0].success_marker, "welcome")

    def test_apply_bearer_and_cookies(self):
        client = Client("test", headers={})
        cfg = AuthConfig(bearer="tok", cookies={"sid": "xyz"})
        ok, detail = apply_auth(client, cfg, "https://example.com")
        self.assertTrue(ok)
        self.assertIn("bearer", detail)
        self.assertEqual(client.extra_headers["Authorization"], "Bearer tok")

    def test_cve_correlation(self):
        hits = correlate_banner("Apache/2.4.49")
        self.assertTrue(any(m.cve == "CVE-2021-41773" for m in hits))
        self.assertEqual(correlate_banner("nginx/1.24.0"), [])

    def test_cvss_estimate(self):
        finding = Finding(
            title="t", severity=Severity.CRITICAL, category="c", url="u",
            detail="d", check="x", tags=["rce"],
        )
        self.assertGreaterEqual(finding.score, 9.0)
        self.assertLessEqual(cvss_estimate(finding), 10.0)

    def test_no_secrets_in_snapshot(self):
        from nutiscan.engine import new_job
        from nutiscan.config import Config
        cfg = Config()
        job = new_job("https://example.com", cfg)
        data = json.dumps(job.snapshot())
        self.assertNotIn("bearer", data.lower())


if __name__ == "__main__":
    unittest.main()
