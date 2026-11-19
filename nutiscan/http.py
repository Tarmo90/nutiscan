"""HTTP transport: token bucket, cookie jar, bounded reads, redirect control."""

from __future__ import annotations

import http.cookiejar
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

_BLOCKED_HEADERS = {"host", "content-length", "connection", "transfer-encoding", "upgrade"}


@dataclass
class Response:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed: float = 0.0
    error: str = ""
    history: list[tuple[int, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 400

    @property
    def text(self) -> str:
        charset = "utf-8"
        content_type = self.headers.get("content-type", "")
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip().strip('"')
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def all_headers(self, name: str) -> list[str]:
        raw = self.headers.get(name.lower() + "\x00all", "")
        return [part for part in raw.split("\x00") if part]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class Client:
    """Serial request client with a shared cookie jar and hard response cap."""

    def __init__(
        self,
        user_agent: str,
        timeout: float = 10.0,
        verify_tls: bool = False,
        rate_limit: float = 8.0,
        max_body: int = 2 * 1024 * 1024,
        retries: int = 1,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_body = max_body
        self.retries = max(0, min(3, retries))
        self.extra_headers = {
            str(k): str(v) for k, v in (headers or {}).items()
            if str(k).lower() not in _BLOCKED_HEADERS
        }

        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        self.cookies = http.cookiejar.CookieJar()
        jar = urllib.request.HTTPCookieProcessor(self.cookies)
        self._direct = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), jar, _NoRedirect()
        )
        self._follow = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), jar
        )

        self._interval = 1.0 / rate_limit if rate_limit > 0 else 0.0
        self._next_slot = 0.0
        self._lock = threading.Lock()

    def _throttle(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_slot - now)
            self._next_slot = max(now, self._next_slot) + self._interval
        if wait:
            time.sleep(wait)

    def request(
        self,
        method: str,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        follow: bool | None = None,
    ) -> Response:
        url = clean_url(url)
        if follow is None:
            follow = False
        opener = self._follow if follow else self._direct
        request = urllib.request.Request(url, data=data, method=method.upper())
        request.add_header("User-Agent", self.user_agent)
        request.add_header("Accept", "text/html,application/json,*/*;q=0.8")
        request.add_header("Accept-Language", "en-US,en;q=0.5")
        for key, value in self.extra_headers.items():
            request.add_header(key, value)
        if data is not None:
            request.add_header("Content-Type", "application/x-www-form-urlencoded")
        for key, value in (headers or {}).items():
            request.add_header(key, str(value))

        history: list[tuple[int, str]] = []
        for attempt in range(self.retries + 1):
            self._throttle()
            started = time.monotonic()
            try:
                with opener.open(request, timeout=self.timeout) as handle:
                    return Response(
                        url=url,
                        status=handle.status,
                        headers=flatten(handle.headers),
                        body=read_capped(handle, self.max_body),
                        elapsed=time.monotonic() - started,
                        history=history,
                    )
            except urllib.error.HTTPError as exc:
                response = Response(
                    url=url,
                    status=exc.code,
                    headers=flatten(exc.headers),
                    body=read_capped(exc, self.max_body),
                    elapsed=time.monotonic() - started,
                    history=history,
                )
                location = response.header("location")
                if follow and 300 <= exc.code < 400 and location:
                    history.append((exc.code, location))
                    next_url = urllib.parse.urljoin(url, location)
                    if len(history) < 6 and same_origin(next_url, url):
                        return self.request("GET", next_url, headers=headers, follow=True)
                exc.close()
                return response
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                error = f"{type(exc).__name__}: {exc}"
                if attempt < self.retries and _retryable(exc):
                    continue
                return Response(url=url, elapsed=time.monotonic() - started, error=error)
        return Response(url=url, error="retry exhausted")

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, form: dict[str, str], **kwargs) -> Response:
        data = urllib.parse.urlencode(form, doseq=True).encode("utf-8")
        return self.request("POST", url, data=data, **kwargs)


def _retryable(exc: BaseException) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in ("timed out", "temporarily", "reset", "refused"))


def read_capped(handle, limit: int) -> bytes:
    try:
        return handle.read(limit) or b""
    except (OSError, ValueError):
        return b""


def flatten(headers) -> dict[str, str]:
    flat: dict[str, str] = {}
    if headers is None:
        return flat
    for key, value in headers.items():
        flat[str(key).lower()] = str(value)
    try:
        cookies = headers.get_all("Set-Cookie") or []
    except AttributeError:
        cookies = []
    if cookies:
        flat["set-cookie\x00all"] = "\x00".join(cookies)
    return flat


def clean_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url.strip())
    if not parts.scheme:
        return url
    netloc = parts.netloc.encode("idna").decode("ascii") if not parts.netloc.isascii() else parts.netloc
    path = urllib.parse.quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = urllib.parse.quote(parts.query, safe="=&%:@!$'()*+,;/?-._~")
    return urllib.parse.urlunsplit((parts.scheme, netloc, path, query, ""))


def same_origin(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def with_params(url: str, params: dict[str, str]) -> str:
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))
