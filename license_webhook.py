#!/usr/bin/env python3
"""Stripe webhook -> signed Nutiscan license key -> email.

Standard library only. Verifies the Stripe-Signature HMAC before touching the
payload, deduplicates by event id, and issues keys with the vendor private key.
Run it behind a TLS reverse proxy (or a tunnel); it binds to loopback by default.

Environment:
    NUTISCAN_WEBHOOK_SECRET   whsec_... from Stripe > Developers > Webhooks
    NUTISCAN_LICENSE_PRIVATE  private key (or leave unset to use license_private.key)
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
    NUTISCAN_FROM_EMAIL       sender address
    NUTISCAN_WEBHOOK_PORT     default 8833
    NUTISCAN_WEBHOOK_STATE    default ./webhook-state
    NUTISCAN_WEBHOOK_HOST     default 127.0.0.1
"""

from __future__ import annotations

import calendar
import datetime as dt
import hashlib
import hmac
import json
import os
import smtplib
import sys
import time
from dataclasses import dataclass
from email.message import EmailMessage
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import license_tool

ROOT = Path(__file__).resolve().parent
MAX_BODY = 1_000_000
TOLERANCE_SECONDS = 300


@dataclass(frozen=True)
class Config:
    secret: str
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_pass: str
    from_email: str
    host: str
    port: int
    state_dir: Path

    @classmethod
    def from_env(cls) -> "Config":
        secret = os.environ.get("NUTISCAN_WEBHOOK_SECRET", "").strip()
        host = os.environ.get("SMTP_HOST", "").strip()
        user = os.environ.get("SMTP_USER", "").strip()
        password = os.environ.get("SMTP_PASS", "").strip()
        sender = os.environ.get("NUTISCAN_FROM_EMAIL", "").strip()
        missing = [
            name for name, value in (
                ("NUTISCAN_WEBHOOK_SECRET", secret), ("SMTP_HOST", host),
                ("SMTP_USER", user), ("SMTP_PASS", password),
                ("NUTISCAN_FROM_EMAIL", sender),
            ) if not value
        ]
        if missing:
            raise SystemExit("Puuduvad keskkonnamuutujad: " + ", ".join(missing))
        try:
            port = int(os.environ.get("SMTP_PORT", "587"))
        except ValueError as exc:
            raise SystemExit("SMTP_PORT peab olema number") from exc
        try:
            listen_port = int(os.environ.get("NUTISCAN_WEBHOOK_PORT", "8833"))
        except ValueError as exc:
            raise SystemExit("NUTISCAN_WEBHOOK_PORT peab olema number") from exc
        return cls(
            secret=secret, smtp_host=host, smtp_port=port, smtp_user=user,
            smtp_pass=password, from_email=sender,
            host=os.environ.get("NUTISCAN_WEBHOOK_HOST", "127.0.0.1"),
            port=listen_port,
            state_dir=Path(os.environ.get("NUTISCAN_WEBHOOK_STATE", str(ROOT / "webhook-state"))),
        )


class State:
    """Small file-backed dedupe log and subscription -> plan map."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.events_path = directory / "events.log"
        self.subs_path = directory / "subscriptions.json"
        self.events: set[str] = set()
        if self.events_path.is_file():
            try:
                self.events = set(line.strip() for line in
                                  self.events_path.read_text(encoding="utf-8").splitlines() if line.strip())
            except OSError:
                pass
        self.subs: dict[str, dict] = {}
        if self.subs_path.is_file():
            try:
                loaded = json.loads(self.subs_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.subs = loaded
            except (OSError, ValueError):
                pass

    def seen(self, event_id: str) -> bool:
        return event_id in self.events

    def mark(self, event_id: str) -> None:
        self.events.add(event_id)
        if len(self.events) > 5000:
            kept = list(self.events)[-2500:]
            self.events_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        else:
            with self.events_path.open("a", encoding="utf-8") as handle:
                handle.write(event_id + "\n")

    def remember(self, subscription_id: str, plan: str, email: str, cycle: str) -> None:
        if not subscription_id:
            return
        self.subs[subscription_id] = {"plan": plan, "email": email, "cycle": cycle}
        self._write_subs()

    def lookup(self, subscription_id: str) -> dict | None:
        return self.subs.get(subscription_id)

    def _write_subs(self) -> None:
        kept = dict(list(self.subs.items())[-2000:])
        self.subs_path.write_text(json.dumps(kept, ensure_ascii=False, indent=2), encoding="utf-8")


def verify_signature(secret: str, header: str, body: bytes) -> bool:
    """Constant-time check of Stripe's t=...,v1=... signature header."""
    fields: dict[str, list[str]] = {}
    for item in header.split(","):
        key, separator, value = item.strip().partition("=")
        if separator and key:
            fields.setdefault(key, []).append(value)
    timestamps = fields.get("t", [])
    signatures = fields.get("v1", [])
    if len(timestamps) != 1 or not signatures:
        return False
    try:
        timestamp = int(timestamps[0])
    except ValueError:
        return False
    if abs(time.time() - timestamp) > TOLERANCE_SECONDS:
        return False
    expected = hmac.new(secret.encode("utf-8"), timestamps[0].encode("ascii") + b"." + body,
                        hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, value) for value in signatures)


def plan_key(value: str) -> str:
    """Resolve a Stripe metadata value or price nickname to a tier key."""
    text = (value or "").strip().lower()
    if text in ("proov", "too", "staar", "ettevotte"):
        return text
    if "ettev" in text:
        return "ettevotte"
    if "staar" in text or "star" in text:
        return "staar"
    if "töö" in text or "too" in text:
        return "too"
    return ""


def customer_email(obj: dict) -> str:
    details = obj.get("customer_details") or {}
    email = str(details.get("email") or obj.get("customer_email") or "").strip()
    return email[:254] if "@" in email else ""


def plus_months(day: dt.date, months: int) -> dt.date:
    total = day.month - 1 + months
    year, month = day.year + total // 12, total % 12 + 1
    return dt.date(year, month, min(day.day, calendar.monthrange(year, month)[1]))


def issue_for(plan: str, email: str, cycle: str) -> tuple[str, dt.date]:
    """Return (license key, expiry date) for one paid subscription."""
    if plan not in license_tool.TIERS:
        raise ValueError(f"Pakett ei ole litsentsitase: {plan!r}")
    if not email:
        raise ValueError("Stripe'i sündmusel puudub kliendi e-post")
    months = 12 if cycle == "y" else 1
    grace = 10 if cycle == "y" else 5
    expires = plus_months(dt.date.today(), months) + dt.timedelta(days=grace)
    name = email.split("@", 1)[0][:80] or "Klient"
    return license_tool.issue_key(plan, name, expires.isoformat()), expires


def build_email(cfg: Config, to: str, plan: str, key: str, expires: dt.date) -> EmailMessage:
    label = license_tool.TIERS[plan]["label"]
    message = EmailMessage()
    message["Subject"] = f"Nutiscan {label} — sinu litsentsivõti"
    message["From"] = cfg.from_email
    message["To"] = to
    message.set_content(
        f"Tere,\n\n"
        f"Tänu tellimuse eest! Sinu Nutiscan {label} litsentsivõti:\n\n"
        f"{key}\n\n"
        f"Kehtib kuni {expires.isoformat()}.\n\n"
        f"Kasutamine:\n"
        f"  Käsurea:  python scan.py scan --target sinu-sait.ee --license \"NS1...\"\n"
        f"  Veebiliides: ava Nutiscan-Web.bat, kleebi võti väljale \"Rakenda võti\".\n"
        f"  Või sea keskkonnamuutuja NUTISCAN_LICENSE.\n\n"
        f"Võti töötab ilma internetiühenduseta. Küsimuste korral vasta sellele kirjale.\n",
        charset="utf-8",
    )
    return message


def send_email(cfg: Config, message: EmailMessage) -> None:
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=25) as server:
        server.ehlo()
        server.starttls()
        server.login(cfg.smtp_user, cfg.smtp_pass)
        server.send_message(message)


def process_event(event: dict, state: State, cfg: Config) -> str:
    """Fulfil one Stripe event. Returns a short status string."""
    event_id = str(event.get("id", ""))
    if not event_id:
        raise ValueError("Sündmusel puudub id")
    if state.seen(event_id):
        return "duplicate"

    event_type = str(event.get("type", ""))
    obj = event.get("data", {}).get("object") or {}
    metadata = obj.get("metadata") or {}
    plan = plan_key(str(metadata.get("plan", "")))
    cycle = str(metadata.get("cycle", "m"))
    email = customer_email(obj)
    subscription_id = str(obj.get("subscription") or "")

    if event_type == "checkout.session.completed":
        status = str(obj.get("payment_status", ""))
        if status not in ("", "paid", "no_payment_required"):
            return f"skip: payment_status={status}"
    elif event_type == "invoice.paid":
        previous = state.lookup(subscription_id)
        if previous:
            plan = plan or previous["plan"]
            email = email or previous["email"]
            cycle = previous.get("cycle", cycle)
        else:
            for line in ((obj.get("lines") or {}).get("data") or [])[:10]:
                nickname = str((line.get("price") or {}).get("nickname", ""))
                plan = plan or plan_key(nickname)
                line_meta = line.get("metadata") or {}
                plan = plan or plan_key(str(line_meta.get("plan", "")))
            email = email or ""
    else:
        return f"skip: {event_type}"

    key, expires = issue_for(plan, email, cycle)
    send_email(cfg, build_email(cfg, email, plan, key, expires))
    if subscription_id:
        state.remember(subscription_id, plan, email, cycle)
    state.mark(event_id)
    return f"sent {plan} to {email} until {expires.isoformat()}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    cfg: Config
    state: State

    def log_message(self, fmt, *args):
        pass

    def _reply(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/health":
            self._reply(HTTPStatus.OK, {"ok": True, "service": "nutiscan-license-webhook"})
        else:
            self._reply(HTTPStatus.NOT_FOUND, {"error": "ei leitud"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/stripe", "/webhook"):
            self._reply(HTTPStatus.NOT_FOUND, {"error": "ei leitud"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._reply(HTTPStatus.BAD_REQUEST, {"error": "vigane keha"})
            return
        body = self.rfile.read(length)
        signature = self.headers.get("Stripe-Signature", "")
        if not verify_signature(self.cfg.secret, signature, body):
            self._reply(HTTPStatus.UNAUTHORIZED, {"error": "allkiri ei kehti"})
            return
        try:
            event = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._reply(HTTPStatus.BAD_REQUEST, {"error": "vigane JSON"})
            return
        if not isinstance(event, dict):
            self._reply(HTTPStatus.BAD_REQUEST, {"error": "vigane JSON"})
            return
        try:
            result = process_event(event, self.state, self.cfg)
        except (ValueError, KeyError, smtplib.SMTPException, OSError) as exc:
            # 500 tells Stripe to retry; the event is not marked as done.
            print(f"Viga sündmusel {event.get('id', '?')}: {exc}", file=sys.stderr)
            self._reply(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
            return
        print(f"OK {event.get('id', '?')}: {result}", flush=True)
        self._reply(HTTPStatus.OK, {"received": True, "result": result})


def serve(cfg: Config) -> None:
    state = State(cfg.state_dir)
    handler = type("Bound", (Handler,), {"cfg": cfg, "state": state})
    server = ThreadingHTTPServer((cfg.host, cfg.port), handler)
    server.daemon_threads = True
    print(f"License webhook: http://{cfg.host}:{cfg.port}/stripe", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    cfg = Config.from_env()
    serve(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
