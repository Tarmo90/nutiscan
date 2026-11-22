# Nutiscan — müügileht

Üks staatiline leht (`index.html`), eesti keeles. Ei vaja build'i, raamistikku ega serverit.

## Kohalik eelvaade

```powershell
python -m http.server 8765 --bind 127.0.0.1 --directory .
```

Ava `http://127.0.0.1:8765`. Või ava `index.html` otse brauseris.

## Maksed

`Osta` nupud avavad Stripe'i hostitud kassa. Lingid on failis `index.html` plokis `STRIPE_LINKS`.

Uued lingid (test või live):

```powershell
$env:STRIPE_SECRET_KEY = "sk_test_..."
python stripe_setup.py            # test
python stripe_setup.py --live      # live, vajab sk_live_ võtit
```

Täpsem juhend: [STRIPE.md](STRIPE.md).

## Struktuur

| Fail | Roll |
|---|---|
| `index.html` | kogu leht: CSS, JS, sisu |
| `terms.html` | kasutustingimused |
| `privacy.html` | privaatsuspoliitika |
| `legal.css` | ühine stiil juriidilistele lehtedele |
| `sample-report.html` | päris skanniaruande näidis |
| `CHANGELOG.md` | muudatuste logi (koopia juurest) |
| `stripe_setup.py` | loob Stripe'is tooted, hinnad ja maksulingid |
| `STRIPE.md` | Stripe'i seadistuse juhend, sh webhook |
| `downloads/Nutiscan-v2.3.1-free.zip` | tasuta build, mida nupp „Laadi alla tasuta" alla laadib |
| `dist/` | avaldamiseks mõeldud koopia (ainult `index.html`, git'is ei ole) |

## Enne avaldamist

- Asenda `hello@nutiscan.ee` oma päris e-postiga (`index.html`, `STRIPE.md`, `terms.html`, `privacy.html`).
- Asenda **FILL** kohad lehtedel `terms.html` ja `privacy.html`: registrikood, VAT-number, äriaadress. Lisa ettevõtte andmed ka `index.html` jalusesse.
- Lisa Stripe'i live-maxelingud `index.html` plokki `STRIPE_LINKS` (juhend `STRIPE.md`).
- Kontrolli hinnad ja pakettide sisu.
