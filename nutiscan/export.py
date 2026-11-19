"""Render a scan snapshot to JSON, Markdown, HTML, CSV or SARIF 2.1.0."""

from __future__ import annotations

import csv
import html
import io
import json

from .findings import SEVERITY_WEIGHT

_LABEL = {
    "critical": "kriitiline", "high": "kõrge", "medium": "keskmine",
    "low": "madal", "info": "info",
}


def to_json(snapshot: dict) -> bytes:
    return json.dumps(snapshot, ensure_ascii=False, indent=2).encode("utf-8")


def _ordered(snapshot: dict) -> list[dict]:
    return sorted(
        snapshot.get("findings") or [],
        key=lambda item: (-item.get("score", 0), SEVERITY_WEIGHT.get(item.get("severity", ""), 9)),
    )


def to_markdown(snapshot: dict) -> bytes:
    lines: list[str] = []
    if snapshot.get("triage"):
        lines.append(snapshot["triage"])
        lines += ["", "---", ""]
    lines += [
        f"# Leiud — {snapshot.get('url', '')}", "",
        f"- Staatus: {snapshot.get('status', '')}",
        f"- Kestus: {snapshot.get('duration', 0)} s",
        f"- Lehti: {snapshot.get('pages', 0)}, sisendeid: {snapshot.get('endpoints', 0)}", "",
    ]
    for item in _ordered(snapshot):
        lines += [
            f"## {item['title']}", "",
            f"- **Raskusaste:** {_LABEL.get(item['severity'], item['severity'])} "
            f"({item.get('score', 0)}/10, {item.get('confidence', 'firm')})",
            f"- **Kategooria:** {item.get('category', '')}",
            f"- **Asukoht:** `{item.get('url', '')}`",
            f"- **Kontroll:** `{item.get('check', '')}`", "",
            item.get("detail", ""), "",
        ]
        if item.get("request"):
            request = item["request"]
            lines += ["**Taasesitus**", "", "```text"]
            lines += [f"{key}: {value}" for key, value in request.items()]
            lines += ["```", ""]
        if item.get("evidence"):
            lines += ["**Tõend**", "", "```text", item["evidence"], "```", ""]
        if item.get("remediation"):
            lines += ["**Parandus**", "", item["remediation"], ""]
    return "\n".join(lines).encode("utf-8")


def to_html(snapshot: dict) -> bytes:
    parts = [
        "<!DOCTYPE html><html lang=\"et\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>Nutiscan — {html.escape(str(snapshot.get('url', '')))}</title>",
        "<style>",
        "body{font:14px/1.55 system-ui,sans-serif;max-width:1040px;margin:32px auto;padding:0 16px;color:#e7eef7;background:#0b1018}",
        "h1{font-size:22px}h2{font-size:16px;margin-top:30px;border-bottom:1px solid #263242;padding-bottom:6px}",
        ".sev{font-size:11px;text-transform:uppercase;padding:2px 7px;border-radius:8px}",
        ".critical{background:#771a2c}.high{background:#8a4214}.medium{background:#776114}.low{background:#1f5a44}.info{background:#334055}",
        "code,pre{font-family:Consolas,monospace;background:#121a26;border-radius:4px;padding:2px 5px}",
        "pre{padding:10px;white-space:pre-wrap;overflow:auto}.muted{color:#8fa2ba}.fix{color:#8ce0ad}",
        "</style></head><body>",
        f"<h1>Nutiscan — {html.escape(str(snapshot.get('url', '')))}</h1>",
        f"<p class=\"muted\">Staatus {html.escape(str(snapshot.get('status', '')))} · "
        f"{snapshot.get('duration', 0)} s · {snapshot.get('pages', 0)} lehte · "
        f"{snapshot.get('endpoints', 0)} sisendit</p>",
    ]
    if snapshot.get("triageSummary"):
        parts.append(f"<p><b>Riskiskoor:</b> {html.escape(str(snapshot['triageSummary']))}</p>")
    for item in _ordered(snapshot):
        severity = str(item.get("severity", "info"))
        parts += [
            f"<h2>{html.escape(str(item.get('title', '')))} "
            f"<span class=\"sev {severity}\">{severity}</span></h2>",
            f"<p class=\"muted\">{html.escape(str(item.get('category', '')))} · "
            f"<code>{html.escape(str(item.get('url', '')))}</code> · "
            f"skoor {html.escape(str(item.get('score', 0)))}</p>",
            f"<p>{html.escape(str(item.get('detail', '')))}</p>",
        ]
        if item.get("evidence"):
            parts.append(f"<pre>{html.escape(str(item['evidence']))}</pre>")
        if item.get("remediation"):
            parts.append(f"<p class=\"fix\"><b>Parandus:</b> {html.escape(str(item['remediation']))}</p>")
    parts.append("</body></html>")
    return "\n".join(parts).encode("utf-8")


def to_csv(snapshot: dict) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["id", "severity", "score", "confidence", "category", "title", "url",
                     "check", "detail", "evidence", "remediation"])
    for item in _ordered(snapshot):
        writer.writerow([
            item.get("id", ""), item.get("severity", ""), item.get("score", 0),
            item.get("confidence", ""), item.get("category", ""), item.get("title", ""),
            item.get("url", ""), item.get("check", ""), item.get("detail", ""),
            item.get("evidence", "").replace("\n", " "), item.get("remediation", ""),
        ])
    return output.getvalue().encode("utf-8")


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error", "high": "error", "medium": "warning",
        "low": "note", "info": "note",
    }.get(severity, "note")


def to_sarif(snapshot: dict) -> bytes:
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()
    for item in _ordered(snapshot):
        check = str(item.get("check", "unknown"))
        if check not in seen_rules:
            seen_rules.add(check)
            rules.append({
                "id": check,
                "name": check,
                "shortDescription": {"text": str(item.get("category", ""))},
                "defaultConfiguration": {"level": _sarif_level(str(item.get("severity", "")))},
            })
        request = item.get("request") or {}
        results.append({
            "ruleId": check,
            "level": _sarif_level(str(item.get("severity", ""))),
            "message": {"text": f"{item.get('title', '')} — {item.get('detail', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(item.get("url", ""))},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": str(request.get("parameter", ""))}],
            }],
            "properties": {
                "score": item.get("score", 0),
                "confidence": item.get("confidence", ""),
                "evidence": item.get("evidence", "")[:500],
            },
        })
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Nutiscan", "version": "2.0.0", "rules": rules}},
            "results": results,
            "properties": {"target": snapshot.get("url", ""), "counts": snapshot.get("counts", {})},
        }],
    }
    return json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")


FORMATS = {
    "json": ("application/json; charset=utf-8", "json", to_json),
    "md": ("text/markdown; charset=utf-8", "md", to_markdown),
    "html": ("text/html; charset=utf-8", "html", to_html),
    "csv": ("text/csv; charset=utf-8", "csv", to_csv),
    "sarif": ("application/sarif+json; charset=utf-8", "sarif", to_sarif),
}

__all__ = ["FORMATS", "to_json", "to_markdown", "to_html", "to_csv", "to_sarif"]
