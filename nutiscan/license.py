"""Offline license enforcement for the commercial tiers.

Verification uses only the embedded RSA public key: no network, no backend,
no card data. A missing key falls back to the free Proov tier, so the scanner
always runs. Enforcement happens at the CLI/UI boundary, not inside the
scan engine, so the open core stays usable on its own.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .findings import SEVERITY_WEIGHT
from .public_key import E, N

PREFIX = "NS1."
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
LICENSE_ENV = "NUTISCAN_LICENSE"
FILE_ENV = "NUTISCAN_LICENSE_FILE"
STORE = Path.home() / ".nutiscan" / "license.key"
MAX_KEY_LEN = 8192

# Keep in sync with license_tool.TIERS (vendor side).
TIERS: dict[str, dict] = {
    "proov": {"label": "Proov", "sites": 1, "findings": 5,
              "exports": ["md"], "fixes": False},
    "too": {"label": "Töö", "sites": 5, "findings": None,
            "exports": ["json", "md", "html", "csv", "sarif"], "fixes": True},
    "staar": {"label": "Staar", "sites": 25, "findings": None,
              "exports": ["json", "md", "html", "csv", "sarif"], "fixes": True},
    "ettevotte": {"label": "Ettevõte", "sites": None, "findings": None,
                  "exports": ["json", "md", "html", "csv", "sarif"], "fixes": True},
}


class LicenseError(ValueError):
    """Raised for a malformed, tampered, unknown or expired key."""


@dataclass(frozen=True)
class License:
    tier: str
    label: str
    name: str
    expires: str
    sites: int | None
    findings: int | None
    checks: tuple[str, ...] | None
    exports: tuple[str, ...]
    fixes: bool
    key_id: str = ""
    signed: bool = False

    @property
    def expired(self) -> bool:
        if self.expires == "lifetime":
            return False
        try:
            return dt.date.fromisoformat(self.expires) < dt.date.today()
        except ValueError:
            return True

    @property
    def email_reports(self) -> bool:
        return self.tier in ("staar", "ettevotte")

    @property
    def api_access(self) -> bool:
        return self.tier in ("staar", "ettevotte")

    def allows_format(self, fmt: str) -> bool:
        return fmt in self.exports

    def allows_check(self, name: str) -> bool:
        return self.checks is None or name in self.checks

    def filter_formats(self, formats: list[str]) -> list[str]:
        return [fmt for fmt in formats if self.allows_format(fmt)]

    def filter_checks(self, checks: list[str] | None) -> list[str] | None:
        if checks is None:
            return None
        return [name for name in checks if self.allows_check(name)]

    def require_sites(self, count: int) -> None:
        if self.sites is not None and count > self.sites:
            raise LicenseError(
                f"Pakk '{self.label}' lubab {self.sites} saiti, taotlesid {count}. "
                "Lisa võti või eemalda üleliigsed sihtmärgid."
            )

    def cap_snapshot(self, snapshot: dict) -> dict:
        """Trim findings for the free tier and mark the report as capped."""
        if self.findings is None:
            return snapshot
        items = list(snapshot.get("findings") or [])
        if len(items) <= self.findings:
            return snapshot
        # Keep the most severe findings, not the first ones in scan order.
        items.sort(key=lambda item: (
            SEVERITY_WEIGHT.get(str(item.get("severity", "")), 9),
            -float(item.get("score", 0) or 0),
        ))
        items = items[:self.findings]
        counts = {key: 0 for key in SEVERITY_WEIGHT}
        for item in items:
            severity = str(item.get("severity", ""))
            if severity in counts:
                counts[severity] += 1
        snapshot = dict(snapshot)
        snapshot["findings"] = items
        snapshot["counts"] = counts
        snapshot["licenseLimited"] = True
        snapshot["licenseTier"] = self.label
        return snapshot

    def describe(self) -> dict:
        return {
            "tier": self.tier,
            "label": self.label,
            "name": self.name,
            "expires": self.expires,
            "sites": self.sites,
            "findings": self.findings,
            "exports": list(self.exports),
            "checks": list(self.checks) if self.checks is not None else None,
            "fixes": self.fixes,
            "emailReports": self.email_reports,
            "apiAccess": self.api_access,
            "signed": self.signed,
            "keyId": self.key_id,
            "expired": self.expired,
        }

    def banner(self) -> str:
        sites = str(self.sites) if self.sites is not None else "piiramatu"
        findings = str(self.findings) if self.findings is not None else "piiramatu"
        return (f"[license] {self.label}" + (f" — {self.name}" if self.name else " (tasuta)")
                + f": {sites} saiti, {findings} leidu, eksport {', '.join(self.exports)}")


def _unb64(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:  # noqa: BLE001 - malformed base64 is an invalid key
        raise LicenseError("Võti ei ole korrektne base64") from exc


def _verify(message: bytes, signature: bytes) -> bool:
    k = (N.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em = pow(int.from_bytes(signature, "big"), E, N).to_bytes(k, "big")
    if not em.startswith(b"\x00\x01"):
        return False
    pos = em.find(b"\x00", 2)
    if pos < 10 or any(byte != 0xFF for byte in em[2:pos]):
        return False
    return hmac.compare_digest(em[pos + 1:], SHA256_PREFIX + hashlib.sha256(message).digest())


def free_license() -> License:
    tier = TIERS["proov"]
    return License(
        tier="proov", label=tier["label"], name="", expires="lifetime",
        sites=tier["sites"], findings=tier["findings"], checks=None,
        exports=tuple(tier["exports"]), fixes=tier["fixes"],
    )


def load(key: str | None) -> License:
    """Verify a key and return its limits. Empty key returns the free tier."""
    if not key or not key.strip():
        return free_license()
    token = key.strip()
    if len(token) > MAX_KEY_LEN or not token.startswith(PREFIX):
        raise LicenseError("Tundmatu võtme vorming")
    try:
        body, signature = token.rsplit(".", 1)
        payload = json.loads(_unb64(body[len(PREFIX):]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise LicenseError("Võti on rikutud") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise LicenseError("Võtme versioon ei ühildu")
    if not _verify(body.encode("ascii"), _unb64(signature)):
        raise LicenseError("Võtme allkiri ei kehti")
    tier_key = str(payload.get("t", ""))
    if tier_key not in TIERS:
        raise LicenseError("Võtmes on tundmatu pakett")
    tier = TIERS[tier_key]
    expires = str(payload.get("e", "lifetime"))
    if expires != "lifetime":
        try:
            dt.date.fromisoformat(expires)
        except ValueError as exc:
            raise LicenseError("Võtme aegumiskuupäev on vigane") from exc
    if expires != "lifetime" and dt.date.fromisoformat(expires) < dt.date.today():
        raise LicenseError("Litsentsivõti on aegunud")
    exports = payload.get("x") or tier["exports"]
    checks = payload.get("c")
    permitted = tuple(str(f) for f in exports if str(f) in tier["exports"])
    if not permitted:
        permitted = tuple(tier["exports"])
    return License(
        tier=tier_key,
        label=tier["label"],
        name=str(payload.get("n", ""))[:120],
        expires=expires,
        sites=_cap_int(payload.get("s"), tier["sites"]),
        findings=_cap_int(payload.get("f"), tier["findings"]),
        checks=tuple(str(c) for c in checks) if isinstance(checks, list) else None,
        exports=permitted,
        fixes=bool(payload.get("r", tier["fixes"])),
        key_id=str(payload.get("i", ""))[:16],
        signed=True,
    )


def _cap_int(value, default: int | None) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(1, min(value, 10000))


def read_stored() -> str:
    """Read a persisted key without verifying it (call load separately)."""
    for candidate in (os.environ.get(FILE_ENV, ""), str(STORE)):
        if not candidate:
            continue
        try:
            return Path(candidate).expanduser().read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return ""


def save(key: str) -> Path:
    """Persist a key locally so the web UI keeps it across restarts."""
    STORE.parent.mkdir(parents=True, exist_ok=True)
    STORE.write_text(key.strip() + "\n", encoding="utf-8")
    try:
        os.chmod(STORE, 0o600)
    except OSError:
        pass
    return STORE


def active(key: str | None = None) -> License:
    """Resolve the active license from argument, environment or local file."""
    if key is not None:
        return load(key)
    env = os.environ.get(LICENSE_ENV, "").strip()
    return load(env or read_stored())


__all__ = [
    "License", "LicenseError", "TIERS", "active", "free_license", "load",
    "read_stored", "save",
]
