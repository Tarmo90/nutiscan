"""Authenticated scanning support: session import, login sequences, request signing."""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from .http import Client, Response


@dataclass
class Credential:
    """One form-based login definition."""

    login_url: str
    fields: dict[str, str]
    method: str = "POST"
    success_marker: str = ""
    failure_marker: str = ""

    def to_dict(self) -> dict:
        return {
            "loginUrl": self.login_url,
            "fields": dict(self.fields),
            "method": self.method,
            "successMarker": self.success_marker,
            "failureMarker": self.failure_marker,
        }


@dataclass
class AuthConfig:
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer: str = ""
    basic_user: str = ""
    basic_pass: str = ""
    credentials: list[Credential] = field(default_factory=list)
    cookie_file: str = ""

    @classmethod
    def from_file(cls, path: str) -> "AuthConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "AuthConfig":
        creds = []
        for item in data.get("credentials") or []:
            creds.append(Credential(
                login_url=str(item.get("loginUrl", "")),
                fields={str(k): str(v) for k, v in (item.get("fields") or {}).items()},
                method=str(item.get("method", "POST")).upper(),
                success_marker=str(item.get("successMarker", "")),
                failure_marker=str(item.get("failureMarker", "")),
            ))
        return cls(
            cookies={str(k): str(v) for k, v in (data.get("cookies") or {}).items()},
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            bearer=str(data.get("bearer", "")),
            basic_user=str(data.get("basicUser", "")),
            basic_pass=str(data.get("basicPass", "")),
            credentials=creds,
            cookie_file=str(data.get("cookieFile", "")),
        )

    def to_dict(self) -> dict:
        return {
            "cookies": dict(self.cookies),
            "headers": dict(self.headers),
            "bearer": self.bearer,
            "basicUser": self.basic_user,
            "credentials": [item.to_dict() for item in self.credentials],
            "cookieFile": self.cookie_file,
        }


def apply_auth(client: Client, auth: AuthConfig, origin: str) -> tuple[bool, str]:
    """Apply cookies/headers and run login flows. Returns (ok, detail)."""
    notes: list[str] = []

    if auth.cookie_file:
        try:
            cookies = _parse_cookie_file(auth.cookie_file)
            auth.cookies.update(cookies)
            notes.append(f"imported {len(cookies)} cookies")
        except (OSError, ValueError) as exc:
            return False, f"cookie import failed: {exc}"

    if auth.basic_user:
        import base64
        token = base64.b64encode(f"{auth.basic_user}:{auth.basic_pass}".encode()).decode()
        auth.headers["Authorization"] = "Basic " + token
        notes.append("basic auth set")

    if auth.bearer:
        auth.headers["Authorization"] = "Bearer " + auth.bearer
        notes.append("bearer token set")

    for key, value in auth.cookies.items():
        client.cookies.set_cookie(_make_cookie(origin, key, value))

    for key, value in auth.headers.items():
        client.extra_headers[key] = value

    for cred in auth.credentials:
        if not cred.login_url:
            continue
        success = _perform_login(client, cred)
        notes.append(f"login {cred.login_url}: {'ok' if success else 'unverified'}")
        if cred.failure_marker and not success:
            return False, "; ".join(notes)

    return True, "; ".join(notes) if notes else "no auth configured"


def _make_cookie(origin: str, name: str, value: str):
    import http.cookiejar
    from urllib.parse import urlsplit
    parts = urlsplit(origin)
    domain = parts.hostname or ""
    return http.cookiejar.Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=bool(domain),
        domain_initial_dot=domain.startswith("."),
        path="/",
        path_specified=True,
        secure=parts.scheme == "https",
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={},
        rfc2109=False,
    )


def _parse_cookie_file(path: str) -> dict[str, str]:
    text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except ValueError:
        pass
    result: dict[str, str] = {}
    if "= " in text or "=" in text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                parts = line.split("\t")
                if len(parts) >= 7:
                    result[parts[5]] = parts[6]
                    continue
            if "=" in line:
                key, value = line.split("=", 1)
                result[key.strip()] = value.strip()
    return result


def _perform_login(client: Client, cred: Credential) -> bool:
    if cred.method == "POST":
        response = client.post(cred.login_url, cred.fields, follow=True)
    else:
        # Build GET login URL from fields.
        query = urllib.parse.urlencode(cred.fields)
        separator = "&" if "?" in cred.login_url else "?"
        response = client.get(cred.login_url + separator + query, follow=True)
    if response.error:
        return False
    body = response.text
    if cred.failure_marker and cred.failure_marker.lower() in body.lower():
        return False
    if cred.success_marker:
        return cred.success_marker.lower() in body.lower()
    return response.ok


__all__ = ["AuthConfig", "Credential", "apply_auth"]
