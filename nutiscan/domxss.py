"""Static DOM-XSS check: sources flowing into dangerous JavaScript sinks."""

from __future__ import annotations

import re

from .crawling import Page
from .findings import Finding, Severity

SOURCES = [
    r"location\.(?:search|hash|href)",
    r"document\.(?:URL|referrer|location)",
    r"window\.location",
    r"URLSearchParams",
    r"decodeURIComponent\s*\(",
]

SINKS = [
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"document\.write(?:ln)?\s*\(", "document.write"),
    (r"\beval\s*\(", "eval"),
    (r"new\s+Function\s*\(", "Function"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"\.html\s*\(", "jQuery.html"),
    (r"setAttribute\s*\(\s*['\"]on\w+", "event handler attribute"),
    (r"location\s*=\s*[^;]+location\.", "location assignment"),
]

_SCRIPT_TAG = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)


def check_dom_xss(pages: list[Page], origin: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for page in pages:
        for script in page.scripts:
            if not script.strip():
                continue
            for pattern, sink in SINKS:
                if not re.search(pattern, script):
                    continue
                source_hit = next((src for src in SOURCES if re.search(src, script)), None)
                if not source_hit:
                    continue
                key = (page.url, sink)
                if key in seen:
                    continue
                seen.add(key)
                index = script.find(sink.split(".")[-1][:12])
                excerpt = script[max(0, index - 90): index + 160].strip()[:260]
                findings.append(Finding(
                    title=f"Võimalik DOM-XSS: {sink}",
                    severity=Severity.HIGH,
                    category="Kliendipoolne süüst",
                    url=page.url,
                    detail=f"JavaScriptis voolab kasutaja kontrollitav allikas ({source_hit}) "
                           f"ohtlikku neelu ({sink}).",
                    evidence=excerpt,
                    check="domxss",
                    confidence="tentative",
                    tags=("xss",),
                    request={"method": "GET", "url": page.url, "payload": source_hit},
                    remediation="Kasuta `textContent` või turvalist templaatimist. Ära anna "
                                "URL-i andmeid otse `innerHTML`, `eval` ega `document.write`'le.",
                ))
    return findings


__all__ = ["check_dom_xss", "SOURCES", "SINKS"]
