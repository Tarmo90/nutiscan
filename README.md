# Nutiscan 2.2

Standalone veebihaavatavuse skanner oma mootoriga. Ainult Pythoni standardteek, Python 3.10+.

## Veebiliides (soovitatav)

Topeltklõps töölaual `Nutiscan-Web.bat` või käsureal:

```
python webui/run.py --port 8822
```

Avaneb `http://127.0.0.1:8822/`. Veebiliides:

- **Uus skann** — URL, piirangud, päised, 17 kontrolli valikut, progress ja riskiskoor.
- **Leiud** — otsing, filtrid raskusastme järgi, klõpsatavad detailid.
- **Parandused** — iga leiuga on samm-sammult juhend ja koodinäited (nginx / Apache / Express / PHP / Python / Node / Java / Go).
- **Ajalugu** — varasemad skannid, klõps avab leiud.
- **Eksport** — MD, HTML, CSV, SARIF 2.1.0, JSON otse brauserist.

Serveri andmed: `webui/server.py`, UI: `webui/index.html`, `webui/style.css`, `webui/app.js`,
paranduste raamatukogu: `webui/fixes.py`.

## Käsurea tööriist

```
python scan.py scan --target example.com --formats md,html,csv,sarif,json
python scan.py batch --targets-file targets.txt
python scan.py report --input reports/target.raw.json --formats md,html
```

Valmis exe: `dist\Nutiscan.exe` (ja koopia töölaual). `Nutiscan.exe scan --target example.com`.

## Mootor

- `nutiscan/http.py` — kiirusepiirang, cookie jar, päised, suunad, 2 MB keha piir.
- `nutiscan/crawling.py` — BFS, vormid, parameetrid, JS-i teed.
- `nutiscan/checks/` — 16 kontrolli: turvapeadised, küpsised, CORS, cache, banner, TLS,
  meetodid, 55 avaliku faili probe'i, XSS, SQLi, traversal, redirect, käsu süüst, SSTI, CRLF.
- `nutiscan/domxss.py` — staatiline DOM-XSS: kasutaja allikad → ohtlikud JS-neelud.
- `nutiscan/auth.py` — autenditud skannimine (bearer, basic, küpsised, login-voo).
- `nutiscan/idor.py` — IDOR-i ja naabrus-ID diferentsiaalkontroll.
- `nutiscan/intel.py` — offline CVE-korrelatsioon ja CVSS-hinnang.
- `nutiscan/oob.py` — pime süüst: kohalik HTTP-callback kuulaja, OOB-interaktsioonide tuvastus.
- `nutiscan/triage.py` — riskiskoor, ründeahelad, prioriteedid, käsitsi sammud.
- `nutiscan/export.py` — JSON, Markdown, HTML, CSV, SARIF.

Testid: `python -m unittest discover -s tests -v` — 10/10 läbib, sealhulgas veebiliidese API.

Demo: `python demo_target.py --port 8899` siis skanni `http://127.0.0.1:8899/` (lisa `--allow-private`).

Era-/loopback-aadressid on vaikevalt keelatud; veebiliideses märkeruut "Lokaalne lubatud".
Iga päring on päris päring — skanni ainult enda süsteeme.
