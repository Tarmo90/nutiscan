#!/usr/bin/env python3
"""Patched version of the demo app: every fixable Nutiscan finding closed.

Run: python demo_fixed.py --port 8899
Then: python scan.py scan --target http://127.0.0.1:8899/ --allow-private
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_plus

ALLOWED_ORIGINS = {"https://trusted.example"}


class FixedApp(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def send_body(self, body: str, status: int = 200, headers: dict | None = None) -> None:
        raw = body.encode("utf-8", "replace")
        self.send_response(status)
        # FIX headers: full hardening set on every response.
        extra = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Cache-Control": "no-store, private",
            "Pragma": "no-cache",
            "Server": "FixedDemo",  # no version digits -> no banner finding
        }
        extra.update(headers or {})
        for key, value in extra.items():
            self.send_header(key, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):  # noqa: N802
        # FIX: only safe methods advertised.
        self.send_body("", 204, {"Allow": "GET, POST, HEAD, OPTIONS"})

    def do_TRACE(self):  # noqa: N802
        # FIX: TRACE disabled.
        self.send_body("", 405, {"Allow": "GET, POST, HEAD, OPTIONS"})

    def do_GET(self):  # noqa: N802
        path, _, query = self.path.partition("?")

        # FIX: sensitive files no longer served.
        if path in ("/.env", "/.git/HEAD", "/backup.zip", "/uploads/"):
            self.send_body("not found", 404)
            return
        if path == "/.well-known/security.txt":
            # FIX: security.txt now present.
            self.send_body("Contact: mailto:security@example.test\nExpires: 2030-01-01T00:00:00Z\n")
            return
        if path == "/headers":
            self.send_body("\n".join(f"{k}: {v}" for k, v in self.headers.items()))
            return
        if path == "/go":
            target = parse_qs(query).get("redirect", [""])[0]
            # FIX: only same-origin relative paths allowed.
            if target.startswith("/") and not target.startswith("//") and "\\" not in target:
                self.send_body("", 302, {"Location": target})
            else:
                self.send_body("", 400)
            return
        if path == "/echo":
            value = unquote_plus(parse_qs(query).get("q", [""])[0])
            # FIX: output is HTML-escaped, no raw reflection.
            from html import escape
            self.send_body("<html><body>echo: " + escape(value, quote=True) + "</body></html>")
            return

        origin = self.headers.get("Origin", "")
        headers: dict[str, str] = {
            # FIX: Secure + HttpOnly + SameSite on the session cookie.
            "Set-Cookie": "sid=demo123; HttpOnly; Secure; SameSite=Lax; Path=/",
        }
        # FIX: CORS allowlist, no credential reflection for arbitrary origins.
        if origin in ALLOWED_ORIGINS:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Vary"] = "Origin"

        self.send_body(
            "<html><head><title>Fixed</title></head><body>"  # FIX: no generator meta
            "<a href='/echo?q=1'>echo</a><a href='/go?redirect=%2Fsafe'>go</a>"
            "<form action='/echo' method='GET'><input name='q' value='1'></form>"
            "</body></html>",
            headers=headers,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8899)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), FixedApp)
    print(f"Nutiscan fixed demo on http://127.0.0.1:{args.port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
