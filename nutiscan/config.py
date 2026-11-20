"""Scan configuration. All limits are hard ceilings; no value is trusted blindly."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Config:
    """One process, one set of rules. Per-target values live in ScanJob."""

    user_agent: str = "Nutiscan/2.0 (+standalone web audit)"
    timeout: float = 10.0
    verify_tls: bool = False
    max_body: int = 2 * 1024 * 1024
    retries: int = 1
    rate_limit: float = 8.0
    max_pages: int = 60
    max_depth: int = 2
    max_endpoints: int = 120
    max_params: int = 40
    allow_post: bool = True
    allow_private: bool = False
    follow_redirects: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    checks: list[str] = field(default_factory=list)
    auth: dict | None = None
    enable_idor: bool = False
    enable_oob: bool = False
    oob_wait: float = 3.0
    oob_host: str = "127.0.0.1"
    compare_baseline: str = ""

    def enabled(self, name: str) -> bool:
        if not self.checks:
            return True
        return name in self.checks
