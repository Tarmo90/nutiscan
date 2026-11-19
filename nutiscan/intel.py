"""Offline CVE banner correlation and CVSS-style scoring helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .findings import Finding

# Small curated offline set. No network calls: every entry is a public,
# well-known advisory. Matching is conservative — version must be present.
BANNER_CVES: list[tuple[str, str, str, str]] = [
    (r"Apache/2\.4\.49\b", "CVE-2021-41773", "critical",
     "Apache HTTP Server 2.4.49 path traversal → remote code execution."),
    (r"Apache/2\.4\.50\b", "CVE-2021-42013", "critical",
     "Apache HTTP Server 2.4.50 path traversal bypass."),
    (r"Apache/2\.2\.", "CVE-2009-3095", "high",
     "Apache mod_proxy reverse proxy exposure (legacy branch)."),
    (r"nginx/1\.[0-6]\.", "CVE-2013-2028", "medium",
     "Old nginx branch with known request-handling flaws."),
    (r"OpenSSL/1\.0\.[01][^0-9]", "CVE-2014-0160", "critical",
     "Heartbleed — memory disclosure via TLS heartbeat."),
    (r"PHP/5\.[0-5]\.", "CVE-2012-1823", "high",
     "Old PHP CGI argument injection (legacy branch)."),
    (r"PHP/7\.[0-3]\.", "CVE-2019-11043", "high",
     "PHP-FPM underflow in certain nginx configurations."),
    (r"ASP\.NET 4\.0\.30319", "CVE-2014-0322", "high",
     "Legacy ASP.NET branch with known vulnerabilities."),
    (r"WordPress 4\.[0-8]\b", "CVE-2016-10033", "high",
     "Old WordPress branch, multiple known issues."),
]

SEVERITY_SCORE = {
    "critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.5,
}


@dataclass
class CveMatch:
    cve: str
    severity: str
    detail: str
    banner: str


def correlate_banner(banner: str) -> list[CveMatch]:
    matches: list[CveMatch] = []
    for pattern, cve, severity, detail in BANNER_CVES:
        if re.search(pattern, banner, re.IGNORECASE):
            matches.append(CveMatch(cve, severity, detail, banner[:200]))
    return matches


def cvss_estimate(finding: Finding) -> float:
    """Deterministic severity-to-score map with confidence and impact tags."""
    base = SEVERITY_SCORE.get(finding.severity.value, 0.0)
    if finding.confidence == "tentative":
        base -= 0.9
    impact_bonus = 0.2 * sum(
        1 for tag in finding.tags if tag in {"rce", "sqli", "xss", "secret", "auth", "source"}
    )
    return round(max(0.0, min(10.0, base + impact_bonus)), 1)


__all__ = ["BANNER_CVES", "CveMatch", "correlate_banner", "cvss_estimate"]
