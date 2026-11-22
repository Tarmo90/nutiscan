#!/usr/bin/env python3
"""Nutiscan command line: scan, batch and re-export."""

from __future__ import annotations

import argparse
import json
import os
import re
import smtplib
import sys
import time
import urllib.parse
from pathlib import Path

from nutiscan import __version__, export
from nutiscan import license as lic
from nutiscan import mailer
from nutiscan.config import Config
from nutiscan.engine import Engine, new_job


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nutiscan", description="Standalone web vulnerability scanner")
    parser.add_argument("--version", action="version", version=f"Nutiscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (("scan", "scan one or more targets"), ("batch", "scan targets from a file")):
        cmd = sub.add_parser(name, help=help_text)
        if name == "scan":
            cmd.add_argument("--target", action="append", required=True)
        else:
            cmd.add_argument("--targets-file", required=True)
        _common(cmd)

    report = sub.add_parser("report", help="re-render a saved raw JSON snapshot")
    report.add_argument("--input", required=True)
    report.add_argument("--formats", default="md,html")
    report.add_argument("--out", default="reports")
    report.add_argument("--license", help="litsentsivõti (või NUTISCAN_LICENSE)")
    report.add_argument("--email", help="saada raport e-postile (Staar ja kõrgem)")
    report.add_argument("--email-format", default="html", choices=list(export.FORMATS))
    return parser


def _common(cmd: argparse.ArgumentParser) -> None:
    cmd.add_argument("--out", default="reports")
    cmd.add_argument("--formats", default="md,html")
    cmd.add_argument("--config-file", help="JSON file overriding Config fields")
    cmd.add_argument("--max-pages", type=int)
    cmd.add_argument("--max-depth", type=int)
    cmd.add_argument("--rate-limit", type=float)
    cmd.add_argument("--timeout", type=float)
    cmd.add_argument("--max-endpoints", type=int)
    cmd.add_argument("--allow-private", action="store_true")
    cmd.add_argument("--allow-post", dest="allow_post", action="store_true", default=None)
    cmd.add_argument("--no-post", dest="allow_post", action="store_false")
    cmd.add_argument("--verify-tls", action="store_true")
    cmd.add_argument("--headers-json", help="JSON object of extra request headers")
    cmd.add_argument("--checks", help="comma separated check names")
    cmd.add_argument("--auth-file", help="JSON file: cookies, bearer, credentials, headers")
    cmd.add_argument("--idor", action="store_true", help="authenticated IDOR differential check")
    cmd.add_argument("--oob", action="store_true", help="out-of-band blind injection check")
    cmd.add_argument("--oob-wait", type=float, default=3.0, help="OOB callback wait seconds")
    cmd.add_argument("--oob-host", default="127.0.0.1", help="OOB listener bind host")
    cmd.add_argument("--license", help="litsentsivõti (või NUTISCAN_LICENSE)")
    cmd.add_argument("--email", help="saada raport e-postile (Staar ja kõrgem)")
    cmd.add_argument("--email-format", default="html", choices=list(export.FORMATS))


def config_from_args(args: argparse.Namespace) -> Config:
    config = Config()
    if args.config_file:
        data = json.loads(Path(args.config_file).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("--config-file peab olema JSON-objekt")
        for key, value in data.items():
            if hasattr(config, key):
                setattr(config, key, value)
    mapping = {
        "max_pages": args.max_pages, "max_depth": args.max_depth,
        "rate_limit": args.rate_limit, "timeout": args.timeout,
        "max_endpoints": args.max_endpoints, "allow_post": args.allow_post,
    }
    for key, value in mapping.items():
        if value is not None:
            setattr(config, key, value)
    if args.allow_private:
        config.allow_private = True
    if args.verify_tls:
        config.verify_tls = True
    if args.headers_json:
        headers = json.loads(args.headers_json)
        if not isinstance(headers, dict):
            raise ValueError("--headers-json peab olema JSON-objekt")
        config.headers = {str(k): str(v) for k, v in headers.items()}
    if args.checks:
        config.checks = [item.strip() for item in args.checks.split(",") if item.strip()]
    if getattr(args, "auth_file", None):
        config.auth = json.loads(Path(args.auth_file).read_text(encoding="utf-8"))
    if getattr(args, "idor", False):
        config.enable_idor = True
    if getattr(args, "oob", False):
        config.enable_oob = True
        config.oob_wait = max(0.5, min(15.0, args.oob_wait))
        config.oob_host = args.oob_host
    return config


def targets_from_args(args: argparse.Namespace) -> list[str]:
    if args.command == "scan":
        targets = list(args.target)
    else:
        targets = [
            line.strip() for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    unique: list[str] = []
    for target in targets:
        if target not in unique:
            unique.append(target)
    return unique


def safe_name(url: str) -> str:
    parts = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    raw = (parts.netloc + parts.path).strip("/") or "target"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)[:90]


def render_all(snapshot: dict, formats: list[str], stem: str, out_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for fmt in formats:
        if fmt not in export.FORMATS:
            raise ValueError(f"Tundmatu formaat: {fmt}")
        _, extension, render = export.FORMATS[fmt]
        path = out_dir / f"{stem}.{extension}"
        path.write_bytes(render(snapshot))
        paths.append(path)
    return paths


def _license_from_args(args: argparse.Namespace) -> lic.License:
    active = lic.active(getattr(args, "license", None))
    if active.expired:
        raise lic.LicenseError("Litsentsivõti on aegunud")
    print(active.banner(), flush=True)
    return active


def _formats(value: str, active: lic.License) -> list[str]:
    formats = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = [fmt for fmt in formats if fmt not in export.FORMATS]
    if unknown:
        raise ValueError(f"Tundmatu formaat: {', '.join(unknown)}")
    allowed = active.filter_formats(formats)
    blocked = [fmt for fmt in formats if fmt not in allowed]
    if blocked:
        print(f"[license] pakett ei luba eksporti: {', '.join(blocked)}", flush=True)
    if not allowed:
        raise lic.LicenseError("Valitud pakett ei luba ühtegi eksporti")
    return allowed


def _email_report(args: argparse.Namespace, active: lic.License, snapshot: dict) -> None:
    recipient = getattr(args, "email", "")
    if not recipient:
        return
    if not active.email_reports:
        raise lic.LicenseError("E-postraportid on saadaval alates Staar paketist")
    fmt = getattr(args, "email_format", "html")
    mailer.send_report(mailer.MailConfig.from_env(), recipient, snapshot, fmt)
    print(f"[email] raport saadetud: {recipient}", flush=True)


def run_scan(args: argparse.Namespace) -> int:
    config = config_from_args(args)
    active = _license_from_args(args)
    targets = targets_from_args(args)
    active.require_sites(len(targets))
    config.checks = active.filter_checks(config.checks)
    formats = _formats(args.formats, active)
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    engine = Engine(config)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    summary: list[dict] = []

    for target in targets:
        print(f"[scan] {target}", flush=True)
        job = new_job(target, config)
        engine.run(job)
        snapshot = active.cap_snapshot(job.snapshot())
        stem = f"{safe_name(target)}-{stamp}"
        raw_path = out_dir / f"{stem}.raw.json"
        raw_path.write_bytes(export.to_json(snapshot))
        paths = render_all(snapshot, formats, stem, out_dir)
        _email_report(args, active, snapshot)
        entry = {
            "target": target,
            "status": job.status,
            "error": job.error,
            "findings": len(job.findings),
            "counts": snapshot["counts"],
            "riskScore": snapshot["triageSummary"].get("riskScore", 0),
            "duration": snapshot["duration"],
            "raw": str(raw_path),
            "reports": [str(path) for path in paths],
        }
        summary.append(entry)
        print(f"  {job.status}: {len(job.findings)} leidu, risk "
              f"{entry['riskScore']}/100 -> {', '.join(path.name for path in paths)}", flush=True)

    summary_path = out_dir / f"summary-{stamp}.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[done] {len(summary)} sihtmärki, kokkuvõte: {summary_path}")
    return 1 if any(item["status"] == "error" for item in summary) else 0


def run_report(args: argparse.Namespace) -> int:
    active = _license_from_args(args)
    snapshot = active.cap_snapshot(json.loads(Path(args.input).read_text(encoding="utf-8")))
    formats = _formats(args.formats, active)
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(args.input).stem.replace(".raw", "")
    for path in render_all(snapshot, formats, stem, out_dir):
        print(path)
    _email_report(args, active, snapshot)
    return 0


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "report":
            return run_report(args)
        return run_scan(args)
    except (ValueError, OSError, json.JSONDecodeError, smtplib.SMTPException) as exc:
        print(f"Viga: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
