# Nutiscan — litsentsivõtmed

Skanner töötab ilma võtmeta **Proov**-tasemel: 1 sait, 5 kõige raskemat leidu, ainult Markdown. Võti avab taseme piirangud. Võtit ei ole vaja aktiveerida serveris — allkirja kontrollitakse kohapeal avaliku võtmega, võrguta.

## Paketid

| Tase | Saidid | Leiud | Eksport | Parandusplaat |
|---|---|---|---|---|
| Proov | 1 | 5 | MD | ei |
| Töö | 5 | piiramatu | kõik 5 | jah |
| Staar | 25 | piiramatu | kõik 5 | jah |
| Ettevõte | piiramatu | piiramatu | kõik 5 | jah |

## Võtmepaar (tee üks kord)

```
python license_tool.py init
```

Loob kaks faili:

- `nutiscan/public_key.py` — **avalik** võti, läheb git'i ja igasse buildi.
- `license_private.key` — **privaat** võti, on `.gitignore`'s. Kaotusel lakkavad kõik väljastatud võtmed kehtimast; uue paari loomisel `init --force` muudab kõik vanad võtmed kehtetuks.

Privaatvõtit tohib hoida ainult sinu masinas. Ära saada seda kliendile, chat'i ega avalikku reposse. Kui kasutad teist masinat, anna võti keskkonnamuutujana `NUTISCAN_LICENSE_PRIVATE`.

## Võtme väljastamine

```
python license_tool.py issue --tier too --name "NutiFix OÜ" --expires 2027-12-31
```

Väljund on üks rida kujul `NS1........`. Kontrollimiseks:

```
python license_tool.py verify NS1........
```

Võtme saab kliendile kätte toimetada kolmel viisil:

1. Käsureal: `python scan.py scan --target ... --license "NS1..."`
2. Keskkonnamuutujana `NUTISCAN_LICENSE`.
3. Veebiliideses: sisesta võti vasakus servas väljale „Rakenda võti". Salvestatakse `~/.nutiscan/license.key` ja püsib restartide vahel.

Võtme eemaldamiseks tühjenda väli või kustuta `~/.nutiscan/license.key` — skanner naaseb Proov-tasemele.

## Müügiühendus

`license_webhook.py` väljastab võtme automaatselt pärast makset ja saadab selle kliendile e-postiga. Seadistus on kirjas [STRIPE.md](STRIPE.md) jaotises 8.

Lühidalt: loo Stripe'is webhook endpoint `https://sinu-domeen/stripe`, vali sündmused `checkout.session.completed` ja `invoice.paid`, sea keskkonnamuutujad (`NUTISCAN_WEBHOOK_SECRET`, SMTP andmed, `NUTISCAN_FROM_EMAIL`) ja käivita `python license_webhook.py`. Võti luuakse paketi ja tsükli järgi ning saadetakse kliendi e-postile, mis tuli Stripe'i kassast. Dubleerimist takistab `webhook-state/events.log`.

Enne live'i minekut vaata STRIPE.md juhendit: testlingid tuleb asendada live-linkidega ja lehel tuleb lisada kasutustingimused, privaatsuspoliitika ning ettevõtte andmed. Need lehed on nüüd olemas (`docs/terms.html`, `docs/privacy.html`) — enne avaldamist tuleb neist asendada registrikoodi, VAT-i ja aadressi kohad.

## E-postraportid (Staar ja kõrgem)

Kui litsents on Staar või Ettevõte, saab raporti saata e-postiga:

```
python scan.py scan --target example.com --license "NS1..." --email "klient@example.com" --email-format html
```

Veebiliideses on väli „E-post raportile (Staar)" jaotises „Täpsemad seaded". Saatmiseks tuleb seada `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` ja `NUTISCAN_FROM_EMAIL` (samad seaded, mida kasutab webhook). Töö ja Proovi tasemel võti lükkab e-posti taotluse tagasi.

## REST API (Staar ja kõrgem)

API on olemas veebiliidese serveris ja nõuab nii Staari võtit kui ka eraldi API-võtit.

API-võtme määramiseks (kaks viisi):

```powershell
$env:NUTISCAN_API_KEYS = "voti1,voti2"
# või fail C:\Users\tarmo\.nutiscan\api-keys (üks võti reas, # kommentaarid)
```

Päringutes kasuta päist `X-API-Key`. Olemasolevad otspunkted:

| Meetod | Otspunkt | Kirjeldus |
|---|---|---|
| GET | `/api/v1/license` | aktiivse litsentsi andmed |
| GET | `/api/v1/history` | viimased skannid |
| POST | `/api/v1/scan` | uue skanni käivitamine (JSON keha nagu veebiliidesel) |
| GET | `/api/v1/scan/{id}` | skanni seisund ja leiud |
| GET | `/api/v1/scan/{id}/export?format=md` | raporti allalaadimine (json, md, html, csv, sarif) |

Vastused on JSON. Ilma API-võtmeta `401`, kui litsents ei ole Staar `403`.

## Piirangute koht koodis

- `nutiscan/license.py` — allkirja verifitseerimine ja piirangud.
- `scan.py` — `--license`, saitide arv, lubatud eksport, leidude kärpimine.
- `webui/server.py` — `/api/license`, `/api/scan` piirang, eksportide lubamine.

Tasuta ja tasuline tase kasutavad sama skannimismootorit. Piirangud rakenduvad ainult väljundis, mitte analüüsis.
