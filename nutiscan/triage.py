"""Deterministic triage: risk score, attack chains, priorities, manual steps."""

from __future__ import annotations

from .findings import Finding, SEVERITY_LABEL, counts, sort_findings

_MANUAL: dict[str, list[str]] = {
    "xss": [
        "Logi sisse ja korda reflekteeruv payload autenditud sessiooniga.",
        "Proovi eri kontekste: atribuut, `<script>`, kommentaar ja JSON-vastus.",
    ],
    "sqli": [
        "Kinnita veapõhine leid `sqlmap`-iga ( `--level=3 --risk=2` ).",
        "Kontrolli boole’i-erinevust käsitsi: `AND 1=1` vs `AND 1=0`.",
    ],
    "traversal": ["Proovi URL-kodeeringut ja topeltkodeeringut.", "Kontrolli, kas fail loetub ka POST-vormist."],
    "redirect": ["Kontrolli OAuth-voogu: kas `redirect_uri` aktsepteerib võõra hosti."],
    "command": ["Kinnita käsuväljund ajaviivitusega (`sleep 5`)."],
    "ssti": ["Proovi {{7*7}} ka teistes mallides ja parameetrites."],
    "crlf": ["Kontrolli, kas süstitud päis jõuab brauserisse või vahemällu."],
    "exposed": ["Kontrolli, kas leitud fail sisaldab kehtivaid saladusi.", "Vaata serveri ligipääsu logisid."],
    "cors": ["Proovi autenditud päringut võõra originiga ja vaata, kas andmed tagastatakse."],
    "cookies": ["Logi sisse ja kontrolli küpsise eluiga ning SameSite'i praktikas."],
    "tls": ["Kontrolli sertifikaadi ahelat `openssl s_client`-iga."],
    "methods": ["Proovi TRACE/PUT autenditud sessiooniga."],
}


def analyze(url: str, findings: list[Finding], stats: dict) -> tuple[str, dict]:
    ordered = sort_findings(findings)
    counted = counts(findings)
    score = _risk_score(ordered)

    if counted["critical"]:
        verdict = "Kriitiline: on otseselt ärakasutatavaid nõrkusi ilma eelneva juurdepääsuta."
    elif counted["high"]:
        verdict = "Kõrge: leitud vigade kombineerimine võib tuua sessiooni ülevõtmise või andmelekke."
    elif counted["medium"]:
        verdict = "Keskmine: üksikud vead ei ole sissemurre, aga lihtsustavad rünnet märgatavalt."
    else:
        verdict = "Madalam risk: leiti peamiselt hügieeni- ja konfiguratsiooniprobleeme."

    lines = [
        "# Nutiscan — turvanalüüs",
        "",
        f"**Sihtmärk:** `{url}`",
        f"**Riskiskoor:** {score}/100 — {verdict}",
        "",
        "## Kokkuvõte",
        "",
        f"Leiti {len(findings)} kinnitatud nõrkust: "
        + ", ".join(f"{SEVERITY_LABEL[key]} {counted[key]}" for key in counted)
        + ".",
        f"Skanniti {stats.get('pages', 0)} lehte ja {stats.get('endpoints', 0)} sisendit "
        f"({stats.get('duration', 0)} s).",
        "",
        "## Ründaja tegevusjärjekord",
        "",
    ]

    chains = _chains(ordered)
    if chains:
        for index, chain in enumerate(chains, start=1):
            lines.append(f"{index}. **{chain['title']}** — {chain['detail']}")
    else:
        lines.append("1. Üksikuid nõrkusi, mis vajavad käsitsi kinnitamist.")

    lines += ["", "## Prioriteedid", ""]
    for index, finding in enumerate(ordered[:12], start=1):
        confidence = "kinnitatud" if finding.confidence == "firm" else "tõenäoline"
        lines.append(
            f"{index}. **{finding.title}** — skoor {finding.score}/10, {confidence}, "
            f"{finding.url}"
        )
        lines.append(f"   {finding.remediation}")

    lines += ["", "## Käsitsi kontrollida", ""]
    seen_steps: set[str] = set()
    for finding in ordered:
        for step in _MANUAL.get(finding.check, []):
            if step not in seen_steps:
                seen_steps.add(step)
                lines.append(f"- **{finding.check}:** {step}")
    if not seen_steps:
        lines.append("- Autenditud ala ja äriloogika vajavad eraldi käsitsi testi.")

    lines += ["", "## Parandusjärjekord", ""]
    immediate = [f for f in ordered if f.severity.value in ("critical", "high")]
    short = [f for f in ordered if f.severity.value == "medium"]
    long_term = [f for f in ordered if f.severity.value in ("low", "info")]
    lines.append(f"1. **Kohe ({(len(immediate))}):** " + "; ".join(f.title for f in immediate[:5]))
    lines.append(f"2. **Lähiajal ({len(short)}):** " + "; ".join(f.title for f in short[:5]))
    lines.append(f"3. **Hügieen ({len(long_term)}):** " + "; ".join(f.title for f in long_term[:5]))

    lines += [
        "",
        "## Katvus ja piirangud",
        "",
        "- Autenditud alasid, IDOR-i ja õiguste eskaleerumist ei testita.",
        "- Äriloogika vead, race condition'd ja krüptograafia jäävad käsitsi tööks.",
        "- Pime ja ajapõhine SQL-süst ning DOM-XSS vajavad eraldi tööriista.",
        "- Tulemused on pinnakontroll, mitte tõestus rakenduse turvalisusest.",
    ]

    return "\n".join(lines), {
        "riskScore": score,
        "verdict": verdict,
        "counts": counted,
        "chains": chains,
        "top": [item.to_dict() for item in ordered[:12]],
    }


def _risk_score(findings: list[Finding]) -> int:
    if not findings:
        return 5
    top = sum(item.score for item in findings[:6])
    return max(1, min(100, int(top * 1.6)))


def _chains(findings: list[Finding]) -> list[dict]:
    by_tag: dict[str, list[Finding]] = {}
    for finding in findings:
        for tag in finding.tags:
            by_tag.setdefault(tag, []).append(finding)

    candidates = [
        ("secret", "source", "Lähtekood ja saladused",
         "Lähtekoodi leke koos konfiguratsioonifailidega annab ründajale otse juurdepääsu andmebaasile."),
        ("sqli", "auth", "Süst ja sessioon",
         "SQL-süst koos nõrkade küpsistega võib tuua kaasa sessiooni ülevõtmise."),
        ("xss", "redirect", "XSS ja ümbersuunamine",
         "Reflekteeruv XSS koos avatud ümbersuunamisega sobib õngitsusahela loomiseks."),
        ("rce", "secret", "Kääsüst ja saladused",
         "Käsusüst võimaldab lugeda serveris asuvaid saladusi otse."),
    ]
    result: list[dict] = []
    for first, second, title, detail in candidates:
        if by_tag.get(first) and by_tag.get(second):
            names = sorted({f.title for f in by_tag[first] + by_tag[second]})
            result.append({"title": title, "detail": detail, "findings": names[:4]})
    return result[:4]
