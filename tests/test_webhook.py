"""Tests for the Stripe license delivery webhook."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import license_tool  # noqa: E402
import license_webhook as webhook  # noqa: E402
from nutiscan import license as lic  # noqa: E402

KEY_PATTERN = re.compile(r"NS1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


class WebhookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = license_tool._gen_prime(512)
        q = license_tool._gen_prime(512)
        while p == q:
            q = license_tool._gen_prime(512)
        cls.n = p * q
        cls.d = pow(license_tool.E, -1, (p - 1) * (q - 1))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patch_private = mock.patch.object(
            license_tool, "_private", return_value=(self.d, self.n))
        self.patch_n = mock.patch.object(lic, "N", self.n)
        self.patch_e = mock.patch.object(lic, "E", license_tool.E)
        self.patch_private.start()
        self.patch_n.start()
        self.patch_e.start()
        self.cfg = webhook.Config(
            secret="whsec_test", smtp_host="smtp.example.com", smtp_port=587,
            smtp_user="user", smtp_pass="pass", from_email="nuti@example.com",
            host="127.0.0.1", port=8833, state_dir=Path(self.temp.name),
        )
        self.state = webhook.State(Path(self.temp.name) / "state")

    def tearDown(self):
        self.patch_e.stop()
        self.patch_n.stop()
        self.patch_private.stop()
        self.temp.cleanup()

    def signed(self, body: bytes, secret: str = "whsec_test", offset: int = 0) -> str:
        stamp = str(int(time.time()) + offset)
        digest = hmac.new(secret.encode(), stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        return f"t={stamp},v1={digest}"

    def checkout_event(self, plan="too", cycle="m", email="client@example.com",
                       event_id="evt_1", sub="sub_1", status="paid"):
        return {
            "id": event_id, "type": "checkout.session.completed",
            "data": {"object": {
                "id": "cs_1", "subscription": sub, "payment_status": status,
                "metadata": {"plan": plan, "cycle": cycle},
                "customer_details": {"email": email},
            }},
        }

    def test_signature_valid_and_tampered(self):
        body = b'{"id":"evt_1"}'
        self.assertTrue(webhook.verify_signature("whsec_test", self.signed(body), body))
        self.assertFalse(webhook.verify_signature("whsec_test", self.signed(body), body + b" "))
        self.assertFalse(webhook.verify_signature("wrong", self.signed(body), body))
        self.assertFalse(webhook.verify_signature("whsec_test", self.signed(body, offset=-1000), body))
        self.assertFalse(webhook.verify_signature("whsec_test", "", body))

    def test_plan_and_dates(self):
        self.assertEqual(webhook.plan_key("too"), "too")
        self.assertEqual(webhook.plan_key("Nutiscan Staar · month"), "staar")
        self.assertEqual(webhook.plan_key("Nutiscan Töö · year"), "too")
        self.assertEqual(webhook.plan_key("Nutiscan Ettevõte"), "ettevotte")
        self.assertEqual(webhook.plan_key(""), "")
        self.assertEqual(webhook.plus_months(dt.date(2026, 1, 31), 1), dt.date(2026, 2, 28))
        self.assertEqual(webhook.plus_months(dt.date(2026, 11, 15), 12), dt.date(2027, 11, 15))

    def test_checkout_issues_key_and_deduplicates(self):
        with mock.patch.object(webhook, "send_email") as send:
            result = webhook.process_event(self.checkout_event(), self.state, self.cfg)
            self.assertTrue(result.startswith("sent too"), result)
            message = send.call_args[0][1]
            self.assertEqual(message["To"], "client@example.com")
            key = KEY_PATTERN.search(message.get_content()).group(0)
            self.assertEqual(lic.load(key).tier, "too")
            self.assertEqual(webhook.process_event(self.checkout_event(), self.state, self.cfg), "duplicate")
            self.assertEqual(send.call_count, 1)

    def test_renewal_uses_remembered_subscription(self):
        renewal = {
            "id": "evt_2", "type": "invoice.paid",
            "data": {"object": {
                "id": "in_1", "subscription": "sub_1", "customer_email": "",
                "lines": {"data": []},
            }},
        }
        with mock.patch.object(webhook, "send_email") as send:
            webhook.process_event(self.checkout_event(), self.state, self.cfg)
            result = webhook.process_event(renewal, self.state, self.cfg)
            self.assertTrue(result.startswith("sent too"), result)
            self.assertEqual(send.call_count, 2)
            key = KEY_PATTERN.search(send.call_args[0][1].get_content()).group(0)
            self.assertEqual(lic.load(key).tier, "too")

    def test_unpaid_and_unknown_events_are_skipped(self):
        unpaid = self.checkout_event(status="unpaid", event_id="evt_3")
        self.assertTrue(webhook.process_event(unpaid, self.state, self.cfg).startswith("skip"))
        unknown = {"id": "evt_4", "type": "customer.created", "data": {"object": {}}}
        self.assertTrue(webhook.process_event(unknown, self.state, self.cfg).startswith("skip"))

    def test_http_endpoint(self):
        handler = type("Bound", (webhook.Handler,), {"cfg": self.cfg, "state": self.state})
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        httpd.daemon_threads = True
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            with urllib.request.urlopen(base + "/health", timeout=5) as response:
                self.assertEqual(response.status, 200)
            body = json.dumps(self.checkout_event()).encode("utf-8")
            request = urllib.request.Request(
                base + "/stripe", data=body, method="POST",
                headers={"Stripe-Signature": self.signed(body),
                         "Content-Type": "application/json"},
            )
            with mock.patch.object(webhook, "send_email"):
                with urllib.request.urlopen(request, timeout=5) as response:
                    self.assertTrue(json.loads(response.read())["received"])
            bad = urllib.request.Request(
                base + "/stripe", data=body, method="POST",
                headers={"Stripe-Signature": "t=1,v1=bad", "Content-Type": "application/json"},
            )
            try:
                urllib.request.urlopen(bad, timeout=5)
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 401)
                exc.close()
            else:
                self.fail("Vigase allkirjaga päring aktsepteeriti")
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    def test_missing_email_fails(self):
        event = self.checkout_event(email="", event_id="evt_5")
        with self.assertRaises(ValueError):
            webhook.process_event(event, self.state, self.cfg)
        self.assertFalse(self.state.seen("evt_5"))


if __name__ == "__main__":
    unittest.main()
