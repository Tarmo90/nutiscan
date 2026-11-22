"""License key verification and tier enforcement tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import license_tool  # noqa: E402
from nutiscan import license as lic  # noqa: E402


class LicenseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ephemeral key keeps tests independent of the vendor private key.
        p = license_tool._gen_prime(512)
        q = license_tool._gen_prime(512)
        while p == q:
            q = license_tool._gen_prime(512)
        cls.n = p * q
        cls.d = pow(license_tool.E, -1, (p - 1) * (q - 1))
        cls.patch_n = mock.patch.object(lic, "N", cls.n)
        cls.patch_e = mock.patch.object(lic, "E", license_tool.E)
        cls.patch_n.start()
        cls.patch_e.start()

    @classmethod
    def tearDownClass(cls):
        cls.patch_e.stop()
        cls.patch_n.stop()

    def issue(self, tier: str = "too", **overrides) -> str:
        base = license_tool.TIERS[tier]
        payload = {
            "v": 1, "t": tier, "n": "Test", "e": "2035-12-31",
            "s": base["sites"], "f": base["findings"], "c": None,
            "x": base["exports"], "r": base["fixes"], "i": "abcd1234",
        }
        payload.update(overrides)
        body = license_tool._encode(payload)
        signature = license_tool._sign(body.encode("ascii"), self.d, self.n)
        return body + "." + license_tool._b64(signature)

    def test_free_tier(self):
        free = lic.load("")
        self.assertEqual(free.tier, "proov")
        self.assertEqual(free.sites, 1)
        self.assertEqual(free.findings, 5)
        self.assertEqual(free.exports, ("md",))
        self.assertFalse(free.fixes)

    def test_valid_key(self):
        key = self.issue()
        obj = lic.load(key)
        self.assertEqual(obj.tier, "too")
        self.assertEqual(obj.sites, 5)
        self.assertIsNone(obj.findings)
        self.assertTrue(obj.fixes)
        self.assertTrue(obj.signed)
        with self.assertRaises(lic.LicenseError):
            obj.require_sites(6)
        obj.require_sites(5)

    def test_tampered_key_rejected(self):
        body, signature = self.issue().rsplit(".", 1)
        replacement = "A" if signature[0] != "A" else "B"
        with self.assertRaises(lic.LicenseError):
            lic.load(body + "." + replacement + signature[1:])

    def test_garbage_key_rejected(self):
        for token in ("garbage", "XX1.abc.def", "NS1.!!!.@@@", "NS1." + "A" * 9000):
            with self.subTest(token=token[:24]), self.assertRaises(lic.LicenseError):
                lic.load(token)

    def test_expired_key_rejected(self):
        with self.assertRaises(lic.LicenseError):
            lic.load(self.issue(e="2020-01-01"))

    def test_unknown_tier_rejected(self):
        with self.assertRaises(lic.LicenseError):
            lic.load(self.issue(t="nope"))

    def test_format_and_check_gating(self):
        free = lic.load("")
        self.assertEqual(free.filter_formats(["md", "html", "csv"]), ["md"])
        obj = lic.load(self.issue(c=["headers", "cookies"]))
        self.assertEqual(obj.filter_checks(["headers", "xss"]), ["headers"])
        self.assertTrue(obj.allows_check("headers"))
        self.assertFalse(obj.allows_check("xss"))

    def test_snapshot_cap(self):
        severities = ["high", "low", "medium", "info", "critical", "high"]
        snapshot = {
            "findings": [{"severity": value} for value in severities],
            "counts": {"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 1},
        }
        capped = lic.load("").cap_snapshot(dict(snapshot))
        self.assertEqual(len(capped["findings"]), 5)
        self.assertEqual(capped["counts"]["high"], 2)
        self.assertEqual(sum(capped["counts"].values()), 5)
        self.assertTrue(capped["licenseLimited"])
        self.assertEqual(capped["licenseTier"], "Proov")
        self.assertIs(lic.load(self.issue()).cap_snapshot(snapshot), snapshot)

    def test_active_from_environment(self):
        key = self.issue()
        with mock.patch.dict("os.environ", {"NUTISCAN_LICENSE": key}):
            self.assertEqual(lic.active().tier, "too")
        with mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch.object(lic, "read_stored", return_value=""):
            self.assertEqual(lic.active().tier, "proov")


if __name__ == "__main__":
    unittest.main()
