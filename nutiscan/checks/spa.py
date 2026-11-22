"""Shared SPA-fallback detection for static hosts.

Firebase Hosting, Netlify and similar serve /index.html for unknown paths
instead of returning 404. A probe for /composer.json or /api/graphql then
"matches" the site's HTML and produces a false positive. Skip any response
that is the site's index document rather than the probed file itself.
"""

from __future__ import annotations

import re

_DOCTYPE = re.compile(r"^\s*<!doctype\s+html", re.IGNORECASE)
_ROOT = re.compile(r"<div[^>]+id=[\"']root[\"']", re.IGNORECASE)


def is_spa_fallback(response) -> bool:
    ctype = response.header("content-type", "").lower()
    if "text/html" not in ctype:
        return False
    text = response.text[:4000]
    return bool(_DOCTYPE.search(text) and _ROOT.search(text))
