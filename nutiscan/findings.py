"""Finding model, deterministic risk scoring and stable identities."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHT: dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}

SEVERITY_LABEL: dict[str, str] = {
    "critical": "kriitiline",
    "high": "kõrge",
    "medium": "keskmine",
    "low": "madal",
    "info": "info",
}

_BASE_SCORE: dict[str, float] = {
    "critical": 9.6,
    "high": 7.9,
    "medium": 5.4,
    "low": 3.1,
    "info": 0.8,
}

_IMPACT_TAGS = {"secret", "rce", "sqli", "xss", "auth", "source", "backup", "redirect"}


@dataclass
class Finding:
    """One verified observation. Identity is stable across repeated scans."""

    title: str
    severity: Severity
    category: str
    url: str
    detail: str
    check: str
    evidence: str = ""
    remediation: str = ""
    confidence: str = "firm"          # firm | tentative
    tags: list[str] = field(default_factory=list)
    request: dict[str, str] = field(default_factory=dict)
    id: str = ""
    score: float = 0.0

    def __post_init__(self) -> None:
        if not self.id:
            raw = "|".join((self.check, self.url, self.title, self.evidence[:120]))
            self.id = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:14]
        if not self.score:
            self.score = round(_score(self), 1)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "url": self.url,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "check": self.check,
            "confidence": self.confidence,
            "tags": list(self.tags),
            "request": dict(self.request),
            "score": self.score,
        }


def _score(finding: Finding) -> float:
    value = _BASE_SCORE.get(finding.severity.value, 0.0)
    if finding.confidence == "tentative":
        value *= 0.72
    value += min(0.4, 0.08 * sum(1 for tag in finding.tags if tag in _IMPACT_TAGS))
    return max(0.0, min(10.0, value))


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-f.score, SEVERITY_WEIGHT.get(f.severity.value, 9), f.category, f.url),
    )


def counts(findings: list[Finding]) -> dict[str, int]:
    result = {key: 0 for key in SEVERITY_WEIGHT}
    for finding in findings:
        result[finding.severity.value] += 1
    return result
