"""SMTP report delivery. Configuration comes from the environment only."""

from __future__ import annotations

import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

from . import export


@dataclass(frozen=True)
class MailConfig:
    host: str
    port: int
    user: str
    password: str
    sender: str

    @classmethod
    def from_env(cls) -> "MailConfig":
        host = os.environ.get("SMTP_HOST", "").strip()
        user = os.environ.get("SMTP_USER", "").strip()
        password = os.environ.get("SMTP_PASS", "").strip()
        sender = os.environ.get("NUTISCAN_FROM_EMAIL", "").strip()
        missing = [
            name for name, value in (
                ("SMTP_HOST", host), ("SMTP_USER", user),
                ("SMTP_PASS", password), ("NUTISCAN_FROM_EMAIL", sender),
            ) if not value
        ]
        if missing:
            raise ValueError("Puuduvad e-posti seaded: " + ", ".join(missing))
        try:
            port = int(os.environ.get("SMTP_PORT", "587"))
        except ValueError as exc:
            raise ValueError("SMTP_PORT peab olema number") from exc
        return cls(host=host, port=port, user=user, password=password, sender=sender)


_MIME = {
    "json": ("application", "json"),
    "md": ("text", "markdown"),
    "html": ("text", "html"),
    "csv": ("text", "csv"),
    "sarif": ("application", "sarif+json"),
}


def build_message(config: MailConfig, to: str, snapshot: dict, fmt: str = "html") -> EmailMessage:
    if fmt not in export.FORMATS:
        raise ValueError(f"Tundmatu formaat: {fmt}")
    _, extension, render = export.FORMATS[fmt]
    maintype, subtype = _MIME[fmt]
    message = EmailMessage()
    message["Subject"] = "Nutiscan — raport: " + str(snapshot.get("url", ""))
    message["From"] = config.sender
    message["To"] = to
    score = (snapshot.get("triageSummary") or {}).get("riskScore", "—")
    message.set_content(
        f"Tere,\n\n"
        f"Lisatud on Nutiscani raport aadressile {snapshot.get('url', '')}.\n"
        f"Leide: {len(snapshot.get('findings') or [])}, riskiskoor: {score}/100.\n\n"
        f"Raport on ka asjakohaste parandusjuhenditega.",
        charset="utf-8",
    )
    message.add_attachment(
        render(snapshot), maintype=maintype, subtype=subtype,
        filename=f"nutiscan-report.{extension}",
    )
    return message


def send_report(config: MailConfig, to: str, snapshot: dict, fmt: str = "html") -> None:
    if "@" not in to or len(to) > 254:
        raise ValueError("Vigane e-posti aadress")
    with smtplib.SMTP(config.host, config.port, timeout=25) as server:
        server.ehlo()
        server.starttls()
        server.login(config.user, config.password)
        server.send_message(build_message(config, to, snapshot, fmt))
