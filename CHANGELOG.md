# Muudatuste logi

## 2.3.1 — 22. november 2026

- Litsentsitasemed Proov / Töö / Staar / Ettevõte; võti allkirjastatakse RSA-2048 võtmega ja verifitseeritakse kohapeal ilma võrguta.
- Tasuta tase: 1 sait, 5 raskemat leidu, ainult Markdown.
- `license_tool.py` võtmete väljastamiseks, `LICENSE_KEYS.md` juhend.
- `license_webhook.py`: Stripe'i webhook, mis saadab makse järel litsentsivõtme e-postiga.
- Staar ja kõrgem: e-postrappordid (`--email`, veebiliidese väli) ja REST API (`/api/v1/`, `X-API-Key`).
- Kasutustingimused ja privaatsuspoliitika eraldi lehtedel.

## 2.3.0 — 21. november 2026

- GraphQL-i kontroll: introspeksioon, aliased query, batching.
- Skannide võrdlus ja SVG-analüütika riskitrendist, raskusastmetest ja kategooriatest.
- SPA-fallbacki tuvastus: `index.html` ei loeta enam valeks leiuks GraphQL-i ja avalike failide kontrollides.
- Igapäevane turvakontroll OpenBot routine'ina.

## 2.2.0 — 21. november 2026

- OOB (out-of-band) pime süüst: kohalik HTTP-callback kuulaja ja interaktsioonide tuvastus.

## 2.1.0 — 21. november 2026

- DOM-XSS-i staatiline analüüs (kasutaja allikast ohtlikku JS-neelu).
- Autenditud skannimine: bearer, basic, küpsised, login-voog.
- IDOR-i ja naabrus-ID diferentsiaalkontroll.
- Offline CVE-korrelatsioon ja CVSS-hinnang.

## 2.0 — 21. november 2026

- Täielikult uus mootor: kiirusepiirang, cookie jar, BFS-crawler, vormid ja parameetrid.
- 16 kontrolli: turvapäised, küpsised, CORS, cache, banner, TLS, meetodid, 55 avaliku faili proovi, XSS, SQLi, traversal, redirect, käsu süüst, SSTI, CRLF, GraphQL.
- Veebiliides skanniks, leiud, parandused, ajalugu ja analüütika.
- Käsurea tööriist `scan`/`batch`/`report`.
- Eksport: JSON, Markdown, HTML, CSV, SARIF 2.1.0.
- Ainult Pythoni standardteek, Python 3.10+.
