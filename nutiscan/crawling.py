"""Bounded same-origin crawler with form, parameter and script-path extraction."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser

from .http import Client, Response, origin, same_origin

_JS_PATH = re.compile(r"[\"'`](/(?:[A-Za-z0-9_.~/-]+)(?:\?[^\"'`\s]+)?)[\"'`]")


@dataclass
class Form:
    action: str
    method: str
    fields: dict[str, str]


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    source: str = ""


@dataclass
class Page:
    url: str
    status: int
    title: str
    generator: str
    links: list[str]
    forms: list[Form]
    script_paths: list[str]
    comments: list[str]


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[Form] = []
        self.generator = ""
        self.title = ""
        self.base = ""
        self.scripts: list[str] = []
        self.comments: list[str] = []
        self._in_title = False
        self._in_script = False
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attr = {str(k).lower(): (v or "") for k, v in attrs}
        if tag == "base" and attr.get("href"):
            self.base = attr["href"]
        elif tag == "title":
            self._in_title = True
        elif tag == "script":
            self._in_script = True
            if attr.get("src"):
                self.links.append(attr["src"])
        elif tag == "meta" and attr.get("name", "").lower() == "generator":
            self.generator = attr.get("content", "")
        elif tag in ("a", "area", "link") and attr.get("href"):
            self.links.append(attr["href"])
        elif tag in ("iframe", "frame", "embed") and attr.get("src"):
            self.links.append(attr["src"])
        elif tag == "form":
            self._form = {
                "action": attr.get("action", ""),
                "method": (attr.get("method", "GET") or "GET").upper(),
                "fields": {},
            }
        elif tag == "input" and self._form is not None:
            name = attr.get("name")
            kind = attr.get("type", "text").lower()
            if name and kind not in ("submit", "button", "reset", "file", "image"):
                self._form["fields"][name] = attr.get("value", "test")
        elif tag in ("textarea", "select") and self._form is not None:
            name = attr.get("name")
            if name:
                self._form["fields"][name] = "test"

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False
        elif tag == "form" and self._form is not None:
            self.forms.append(
                Form(
                    action=self._form["action"],
                    method=self._form["method"],
                    fields=self._form["fields"],
                )
            )
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.title.strip():
            self.title = data.strip()[:200]
        if self._in_script:
            self.scripts.append(data)
        if "<!--" in data:
            self.comments.append(data[:400])

    def handle_comment(self, data: str) -> None:
        self.comments.append(data[:400])


class Crawler:
    def __init__(self, client: Client, target: str, max_pages: int, max_depth: int) -> None:
        self.client = client
        self.target = target
        self.root_origin = origin(target)
        self.max_pages = max(1, max_pages)
        self.max_depth = max(0, max_depth)

    def crawl(self, on_page=None) -> tuple[list[Page], list[Endpoint]]:
        queue: list[tuple[str, int]] = [(self.target, 0)]
        seen: set[str] = set()
        pages: list[Page] = []
        endpoints: list[Endpoint] = []
        keys: set[tuple[str, str]] = set()

        while queue and len(pages) < self.max_pages:
            url, depth = queue.pop(0)
            key = normalise(url)
            if key in seen:
                continue
            seen.add(key)

            response = self.client.get(url)
            if response.error or not is_html(response):
                continue

            parser = _Parser()
            try:
                parser.feed(response.text)
            except Exception:
                pass

            base = urllib.parse.urljoin(url, parser.base) if parser.base else url
            links = resolve(base, parser.links)
            script_paths = resolve(base, _paths_from_scripts(parser.scripts))

            for raw_form in parser.forms:
                action = urllib.parse.urljoin(base, raw_form.action) if raw_form.action else url
                if not same_origin(action, self.root_origin):
                    continue
                for endpoint in form_endpoints(action, raw_form.method, raw_form.fields):
                    _add(endpoint, keys, endpoints)

            for link in links + script_paths:
                for endpoint in url_endpoints(link):
                    _add(endpoint, keys, endpoints)

            page = Page(
                url=url,
                status=response.status,
                title=parser.title,
                generator=parser.generator,
                links=links,
                forms=[f for f in parser.forms],
                script_paths=script_paths,
                comments=parser.comments,
            )
            pages.append(page)
            if on_page is not None:
                on_page(page)

            if depth < self.max_depth:
                for link in links + script_paths:
                    if normalise(link) not in seen:
                        queue.append((link, depth + 1))

        return pages, endpoints


def _add(endpoint: Endpoint, keys: set, endpoints: list) -> None:
    key = (endpoint.method, endpoint.url)
    if key not in keys:
        keys.add(key)
        endpoints.append(endpoint)


def _paths_from_scripts(scripts: list[str]) -> list[str]:
    found: list[str] = []
    for script in scripts:
        found.extend(match.group(1) for match in _JS_PATH.finditer(script[:200_000]))
    return found[:200]


def resolve(base: str, links: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for raw in links:
        raw = raw.strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        absolute = urllib.parse.urljoin(base, raw)
        parts = urllib.parse.urlsplit(absolute)
        if parts.scheme not in ("http", "https"):
            continue
        if not same_origin(absolute, base):
            continue
        clean = urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path or "/", parts.query, "")
        )
        if clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def url_endpoints(url: str) -> list[Endpoint]:
    parts = urllib.parse.urlsplit(url)
    if not parts.query:
        return []
    params: dict[str, str] = {}
    for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        params.setdefault(key, value)
    if not params:
        return []
    return [Endpoint(url=url, params=params, source="url")]


def form_endpoints(action: str, method: str, fields: dict[str, str]) -> list[Endpoint]:
    if not fields:
        return []
    if method == "GET":
        query = urllib.parse.urlencode(fields)
        separator = "&" if urllib.parse.urlsplit(action).query else "?"
        return [Endpoint(url=action + separator + query, params=dict(fields), source="form")]
    return [Endpoint(url=action, method="POST", params=dict(fields), source="form")]


def normalise(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    path = parts.path.rstrip("/") or "/"
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc.lower(), path, parts.query, ""))


def is_html(response: Response) -> bool:
    content_type = response.header("content-type", "").lower()
    if "html" in content_type:
        return True
    return not content_type and b"<" in response.body[:2048]
