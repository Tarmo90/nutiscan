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

Stripe'i Payment Linkide kinnitus peab saatma kliendile litsentsivõtme. Praegu ütleb kassatekst „juurdepääsu juhised saadame e-postiga", aga saatmist pole automatiseeritud — kuni webhooki või Stripe'i kassasisse laaditud faili lisamiseni tuleb võti saata käsitsi pärast makset.

Enne live'i minekut vaata STRIPE.md juhendit: testlingid tuleb asendada live-linkidega ja lehel tuleb lisada kasutustingimused, privaatsuspoliitika ning ettevõtte andmed.

## Piirangute koht koodis

- `nutiscan/license.py` — allkirja verifitseerimine ja piirangud.
- `scan.py` — `--license`, saitide arv, lubatud eksport, leidude kärpimine.
- `webui/server.py` — `/api/license`, `/api/scan` piirang, eksportide lubamine.

Tasuta ja tasuline tase kasutavad sama skannimismootorit. Piirangud rakenduvad ainult väljundis, mitte analüüsis.
