"""Tests for SMTP report delivery."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nutiscan import mailer  # noqa: E402


SNAPSHOT = {
    "url": "https://example.com",
    "status": "done",
    "findings": [{"title": "Test", "severity": "high", "score": 7.9}],
    "triageSummary": {"riskScore": 42},
}


class MailerTest(unittest.TestCase):
    def setUp(self):
        self.config = mailer.MailConfig(
            host="smtp.example.com", port=587,
            user="user", password="pass", sender="nuti@example.com",
        )

    def test_config_from_env(self):
        env = {
            "SMTP_HOST": "smtp.example.com", "SMTP_USER": "user",
            "SMTP_PASS": "pass", "NUTISCAN_FROM_EMAIL": "nuti@example.com",
            "SMTP_PORT": "2525",
        }
        with mock.patch.dict("os.environ", env, clear=True):
            config = mailer.MailConfig.from_env()
        self.assertEqual(config.host, "smtp.example.com")
        self.assertEqual(config.port, 2525)
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                mailer.MailConfig.from_env()

    def test_message_contents(self):
        message = mailer.build_message(self.config, "client@example.com", SNAPSHOT, "html")
        self.assertEqual(message["To"], "client@example.com")
        self.assertIn("example.com", message["Subject"])
        self.assertIn("42/100", message.get_body(preferencelist=("plain",)).get_content())
        attachment = list(message.iter_attachments())[0]
        self.assertEqual(attachment.get_filename(), "nutiscan-report.html")
        self.assertIn(b"<!DOCTYPE html>", attachment.get_payload(decode=True))

    def test_unknown_format_rejected(self):
        with self.assertRaises(ValueError):
            mailer.build_message(self.config, "client@example.com", SNAPSHOT, "pdf")

    def test_send_report(self):
        with mock.patch.object(mailer.smtplib, "SMTP") as smtp:
            mailer.send_report(self.config, "client@example.com", SNAPSHOT)
        smtp.assert_called_once_with("smtp.example.com", 587, timeout=25)
        instance = smtp.return_value.__enter__.return_value
        instance.starttls.assert_called_once_with()
        instance.login.assert_called_once_with("user", "pass")
        instance.send_message.assert_called_once()

    def test_bad_recipient_rejected(self):
        with self.assertRaises(ValueError):
            mailer.send_report(self.config, "not-an-email", SNAPSHOT)


if __name__ == "__main__":
    unittest.main()
