#!/usr/bin/env python3
"""Vendor tool for Nutiscan license keys. RSA-2048 / PKCS#1 v1.5 / SHA-256.

The private key never enters the repository: ``init`` writes it to
``license_private.key`` (gitignored) and publishes only (n, e) in
``nutiscan/public_key.py``. The scanner verifies with the public key alone.

Commands:
    python license_tool.py init [--force]
    python license_tool.py tiers
    python license_tool.py issue --tier too --name "NutiFix OÜ" --expires 2027-12-31
    python license_tool.py verify NS1....
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRIVATE_PATH = ROOT / "license_private.key"
PUBLIC_PATH = ROOT / "nutiscan" / "public_key.py"
PREFIX = "NS1."
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
E = 65537
KEY_BITS = 2048

TIERS = {
    "proov": {"label": "Proov", "sites": 1, "findings": 5, "exports": ["md"], "fixes": False},
    "too": {"label": "Töö", "sites": 5, "findings": None,
            "exports": ["json", "md", "html", "csv", "sarif"], "fixes": True},
    "staar": {"label": "Staar", "sites": 25, "findings": None,
              "exports": ["json", "md", "html", "csv", "sarif"], "fixes": True},
    "ettevotte": {"label": "Ettevõte", "sites": None, "findings": None,
                  "exports": ["json", "md", "html", "csv", "sarif"], "fixes": True},
}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _is_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(candidate):
            return candidate


def _private() -> tuple[int, int]:
    raw = os.environ.get("NUTISCAN_LICENSE_PRIVATE", "").strip()
    if not raw:
        raw = PRIVATE_PATH.read_text(encoding="ascii").strip()
    d_hex, n_hex = _unb64(raw).decode("ascii").split(":")
    return int(d_hex, 16), int(n_hex, 16)


def _public() -> tuple[int, int]:
    from nutiscan.public_key import E as e, N as n
    return n, e


def _sign(message: bytes, d: int, n: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    digest = hashlib.sha256(message).digest()
    t = SHA256_PREFIX + digest
    if k < len(t) + 11:
        raise ValueError("võti liiga lühike")
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def _verify(message: bytes, signature: bytes, n: int, e: int) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    if not em.startswith(b"\x00\x01"):
        return False
    pos = em.find(b"\x00", 2)
    if pos < 10 or any(byte != 0xFF for byte in em[2:pos]):
        return False
    digest = hashlib.sha256(message).digest()
    return hmac.compare_digest(em[pos + 1:], SHA256_PREFIX + digest)


def _encode(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return PREFIX + _b64(body.encode("utf-8"))


def cmd_init(force: bool) -> int:
    if PRIVATE_PATH.exists() and not force:
        raise SystemExit("license_private.key on olemas — kasuta --force, et asendada (vanad võtmed lakkavad kehtimast).")
    p, q = _gen_prime(KEY_BITS // 2), _gen_prime(KEY_BITS // 2)
    while p == q:
        q = _gen_prime(KEY_BITS // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    if n.bit_length() != KEY_BITS:
        return cmd_init(force)
    d = pow(E, -1, phi)
    PRIVATE_PATH.write_text(_b64((format(d, "x") + ":" + format(n, "x")).encode("ascii")) + "\n", encoding="ascii")
    PUBLIC_PATH.write_text(
        '"""Avalik verifitseerimisvõti — genereeritud license_tool.py init poolt."""\n\n'
        f"N = 0x{format(n, 'x')}\nE = {E}\n",
        encoding="utf-8",
    )
    os.chmod(PRIVATE_PATH, 0o600)
    print(f"Privaatvõti: {PRIVATE_PATH} (ärge lisage git'i)")
    print(f"Avalik võti: {PUBLIC_PATH}")
    return 0


def cmd_tiers() -> int:
    for key, tier in TIERS.items():
        sites = tier["sites"] if tier["sites"] is not None else "piiramatu"
        findings = tier["findings"] if tier["findings"] is not None else "piiramatu"
        print(f"{key:11} {tier['label']:12} saidid={sites!s:10} leiud={findings!s:10} "
              f"eksport={','.join(tier['exports'])} parandusplaat={tier['fixes']}")
    return 0


def cmd_issue(args) -> int:
    if args.tier not in TIERS:
        raise SystemExit(f"Tundmatu tase: {args.tier}. Vali: {', '.join(TIERS)}")
    tier = TIERS[args.tier]
    expires = args.expires
    if expires != "lifetime":
        try:
            dt.date.fromisoformat(expires)
        except ValueError as exc:
            raise SystemExit(f"Kuupäev peab olema YYYY-MM-DD või 'lifetime': {exc}") from exc
    payload = {
        "v": 1, "t": args.tier, "n": args.name, "e": expires,
        "s": args.sites if args.sites is not None else tier["sites"],
        "f": args.findings if args.findings is not None else tier["findings"],
        "c": None, "x": tier["exports"], "r": tier["fixes"],
        "i": secrets.token_hex(4),
    }
    body = _encode(payload)
    d, n = _private()
    signature = _sign(body.encode("ascii"), d, n)
    print(body + "." + _b64(signature))
    return 0


def cmd_verify(token: str) -> int:
    try:
        body, signature = token.rsplit(".", 1)
        payload = json.loads(_unb64(body[len(PREFIX):]).decode("utf-8"))
        n, e = _public()
        valid = body.startswith(PREFIX) and _verify(body.encode("ascii"), _unb64(signature), n, e)
    except (ValueError, KeyError, IndexError) as exc:
        raise SystemExit(f"Vigane võti: {exc}") from exc
    print("Kehtiv: " + ("jah" if valid else "EI"))
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if valid else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Nutiscan license key tool")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="generate a new keypair (run once)")
    init.add_argument("--force", action="store_true")
    sub.add_parser("tiers", help="print tier limits")
    issue = sub.add_parser("issue", help="issue a signed license key")
    issue.add_argument("--tier", required=True, choices=list(TIERS))
    issue.add_argument("--name", required=True, help="customer name")
    issue.add_argument("--expires", required=True, help="YYYY-MM-DD or 'lifetime'")
    issue.add_argument("--sites", type=int)
    issue.add_argument("--findings", type=int)
    verify = sub.add_parser("verify", help="verify and decode a key")
    verify.add_argument("key")

    args = parser.parse_args()
    if args.command == "init":
        return cmd_init(args.force)
    if args.command == "tiers":
        return cmd_tiers()
    if args.command == "issue":
        return cmd_issue(args)
    return cmd_verify(args.key)


if __name__ == "__main__":
    sys.exit(main())
