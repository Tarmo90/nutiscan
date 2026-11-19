#!/usr/bin/env python3
"""Local demo application with known, harmless weaknesses for Nutiscan."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_plus


class DemoApp(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def send_body(self, body: str, status: int = 200, headers: dict | None = None) -> None:
        raw = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):  # noqa: N802
        self.send_body("", 204, {"Allow": "GET, POST, OPTIONS, TRACE, PUT"})

    def do_TRACE(self):  # noqa: N802
        echoed = self.headers.get("X-Nutiscan", "")
        self.send_body(f"TRACE {self.path}\nX-Nutiscan: {echoed}")

    def do_GET(self):  # noqa: N802
        path, _, query = self.path.partition("?")

        if path == "/.env":
            self.send_body("APP_KEY=demo123\nDB_PASSWORD=demo123\n")
            return
        if path == "/.git/HEAD":
            self.send_body("ref: refs/heads/main\n")
            return
        if path == "/backup.zip":
            raw = b"PK\x03\x04" + b"demo archive" * 8
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if path == "/.well-known/security.txt":
            self.send_body("missing", 404)
            return
        if path == "/headers":
            self.send_body("\n".join(f"{k}: {v}" for k, v in self.headers.items()))
            return
        if path == "/uploads/":
            self.send_body("<html><title>Index of /uploads/</title>"
                           "<a href='secret.txt'>secret.txt</a></html>")
            return
        if path == "/go":
            target = parse_qs(query).get("redirect", [""])[0]
            if target:
                self.send_body("", 302, {"Location": unquote_plus(target)})
            else:
                self.send_body("<html>go</html>")
            return
        if path == "/echo":
            value = unquote_plus(parse_qs(query).get("q", [""])[0])
            # Emulate a real command result: only the marker is returned,
            # not the shell syntax that produced it.
            import re
            match = re.search(r"echo\s+(ol[a-z0-9]+)", value)
            if match and any(s in value for s in (";", "|", "$(", "`")):
                self.send_body("<html>" + match.group(1) + "</html>")
                return
            if "'" in value or '"' in value:
                self.send_body("You have an error in your SQL syntax near ''")
                return
            if "../" in value or "%2f" in value.lower():
                self.send_body("root:x:0:0:root:/root:/bin/bash")
                return
            if "1=1" in value:
                self.send_body("<html>echo: " + value + " " + "A" * 320 + "</html>")
                return
            if "1=0" in value:
                self.send_body("<html>false</html>")
                return
            if "7*7" in value:
                self.send_body("<html>" + value + " result 49</html>")
                return
            self.send_body("<html><body>echo: " + value + "</body></html>")
            return

        origin = self.headers.get("Origin", "")
        extra = {"Set-Cookie": "sid=demo123", "Server": "DemoServer/1.0"}
        if origin:
            extra["Access-Control-Allow-Origin"] = origin
            extra["Access-Control-Allow-Credentials"] = "true"
        self.send_body(
            "<html><head><title>Demo</title>"
            "<meta name='generator' content='DemoCMS 2.1'></head><body>"
            "<a href='/echo?q=1'>echo</a><a href='/echo?q=2'>echo2</a>"
            "<a href='/echo?q=abc'>echo3</a>"
            "<a href='/go?redirect=%2Fsafe'>go</a>"
            "<a href='/go?redirect=%2Fhome'>go2</a>"
            "<a href='/headers'>headers</a><a href='/uploads/'>uploads</a>"
            "<script>var api='/echo?q=1';</script>"
            "<form action='/echo' method='GET'><input name='q' value='1'></form>"
            "</body></html>",
            headers=extra,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8899)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoApp)
    print(f"Nutiscan demo target on http://127.0.0.1:{args.port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
