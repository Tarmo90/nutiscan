#!/usr/bin/env python3
"""Create Nutiscan Stripe products, prices and payment links.

Usage (test mode):
    set STRIPE_SECRET_KEY=sk_test_...
    python stripe_setup.py

Usage (live mode, after the account is activated):
    set STRIPE_SECRET_KEY=sk_live_...
    python stripe_setup.py --live

Prints a JSON block. Paste the four URLs into STRIPE_LINKS in index.html.

Standard library only. No Stripe SDK, no backend, no card data on the site.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.stripe.com/v1"

# Amounts in cents. Yearly price = 12x the discounted monthly price.
PLANS = [
    {
        "key": "too",
        "name": "Nutiscan Töö",
        "desc": "Kuni 5 saiti, 15 kontrolli, parandusplaat, kõik 5 eksporti.",
        "monthly": 4900,
        "yearly": 46800,   # 39 EUR/kuu, arveldatakse aastas
    },
    {
        "key": "staar",
        "name": "Nutiscan Staar",
        "desc": "Kuni 25 saiti, API, e-postiraportid, prioriteetne tugi.",
        "monthly": 14900,
        "yearly": 142800,  # 119 EUR/kuu, arveldatakse aastas
    },
]


def post(path, params, key, idem=None):
    """POST form-encoded params to the Stripe API and return parsed JSON."""
    body = urllib.parse.urlencode(params, doseq=True).encode("utf-8")
    req = urllib.request.Request(API + path, data=body, method="POST")
    req.add_header("Authorization", "Bearer " + key)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if idem:
        req.add_header("Idempotency-Key", idem)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise SystemExit("Stripe %s %s -> %s\n%s" % (path, params, exc.code, detail))
    except urllib.error.URLError as exc:
        raise SystemExit("Network error reaching Stripe: %s" % exc.reason)


def make_plan(key, plan, mode, cycle, amount, interval):
    product = post(
        "/products",
        {"name": plan["name"], "description": plan["desc"]},
        key,
        idem="nutiscan-%s-%s-product" % (mode, plan["key"]),
    )
    price = post(
        "/prices",
        {
            "product": product["id"],
            "currency": "eur",
            "unit_amount": amount,
            "recurring[interval]": interval,
            "nickname": plan["name"] + " · " + cycle,
        },
        key,
        idem="nutiscan-%s-%s-%s-price" % (mode, plan["key"], cycle),
    )
    link = post(
        "/payment_links",
        {
            "line_items[0][price]": price["id"],
            "line_items[0][quantity]": 1,
            "allow_promotion_codes": "true",
            "metadata[plan]": plan["key"],
            "metadata[cycle]": cycle,
            "after_completion[type]": "hosted_confirmation",
            "after_completion[hosted_confirmation][custom_message]":
                "Aitäh! Kinnitus ja juurdepääsu juhised saadame e-postiga.",
        },
        key,
        idem="nutiscan-%s-%s-%s-link" % (mode, plan["key"], cycle),
    )
    return link["url"]


def main():
    ap = argparse.ArgumentParser(description="Create Nutiscan Stripe payment links.")
    ap.add_argument("--live", action="store_true", help="use the live key instead of test")
    args = ap.parse_args()

    secret = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not secret:
        raise SystemExit("Set STRIPE_SECRET_KEY first (Stripe Dashboard > Developers > API keys).")
    if not secret.startswith("sk_"):
        raise SystemExit("STRIPE_SECRET_KEY must be a secret key (sk_test_... or sk_live_...).")
    if args.live and not secret.startswith("sk_live_"):
        raise SystemExit("--live needs an sk_live_ key.")
    if not args.live and secret.startswith("sk_live_"):
        raise SystemExit("Live key without --live. Refusing to create live objects by accident.")

    mode = "live" if args.live else "test"
    print("# Stripe mode: %s" % mode, file=sys.stderr)

    out = {}
    for plan in PLANS:
        out[plan["key"]] = {
            "m": make_plan(secret, plan, mode, "m", plan["monthly"], "month"),
            "y": make_plan(secret, plan, mode, "y", plan["yearly"], "year"),
        }
        print("# %s done" % plan["key"], file=sys.stderr)

    print("\nPaste into STRIPE_LINKS in index.html:\n")
    print("  var STRIPE_LINKS = {")
    for k, v in out.items():
        print('    %s: { m: "%s", y: "%s" },' % (k, v["m"], v["y"]))
    print("  };")


if __name__ == "__main__":
    main()
