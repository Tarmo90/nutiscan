# Nutiscan — Stripe kassa seadistus

Leht on staatiline (üks `index.html`), seega kaardimakse käib **Stripe Payment Linkide** kaudu: iga nupp avab Stripe'i hostitud kassa. Kaardiandmed ei läbi sinu lehte ega serverit.

## 1. Konto

1. Loo konto: https://dashboard.stripe.com/register
2. Täida ettevõtte/organisatsiooni andmed (nimi, aadress, IBAN väljamakseteks). Eesti OÜ või FIE sobib.
3. Jäta **test mode** sisse (lüliti dashboardi ülanurgas).

## 2. API võti

Dashboard → **Developers → API keys → Secret key** → `Reveal test key`.

Ära pane võtit faili ega chat'i. Sea ainult keskkonnamuutujana:

```powershell
$env:STRIPE_SECRET_KEY = "sk_test_..."
```

## 3. Loo tooted, hinnad ja maksulingid

```powershell
cd C:\Users\tarmo\OpenBot\Agents\agent-fe7aaccd-958f-4c21-ab83-1c4aeccbf83e\Nutiscan\docs
python stripe_setup.py
```

Skript loob:

| Toode | Kuu | Aasta |
|---|---|---|
| Nutiscan Töö | 49 €/kuu | 468 €/aasta (39 €/kuu, −20%) |
| Nutiscan Staar | 149 €/kuu | 1428 €/aasta (119 €/kuu, −20%) |

ja trükib neli URL-i kujul:

```js
  var STRIPE_LINKS = {
    too:   { m: "https://buy.stripe.com/test_...", y: "https://buy.stripe.com/test_..." },
    staar: { m: "https://buy.stripe.com/test_...", y: "https://buy.stripe.com/test_..." },
  };
```

Skript on idempotentne: sama võtmega uuesti jooksutades ei teki duplikaate.

## 4. Kleebi lingid lehele

`index.html` → otsi `var STRIPE_LINKS` (skripti plokk, umbes rida 545) → asenda tühjad stringid URL-idega.

Kui link on täidetud, avaneb `Osta` peale Stripe'i kassa. Kui tühi, läheb nupp senisele kontaktivormile — seega poolik seadistus ei lõhu lehte.

## 5. Testi

1. Ava `http://127.0.0.1:8765`
2. `Osta` → Stripe'i kassa
3. Kaart `4242 4242 4242 4242`, mis tahes tulevikukuupäev, CVC `123`
4. Kontrolli dashboardis: **Payments** näitab õnnestunud makset; **Subscriptions** näitab korduvat tellimust

Testkaardid: https://docs.stripe.com/testing

## 6. Lülita live'i

1. Aktiveeri konto (Stripe küsib äriandmed ja pangakonto).
2. Võta `sk_live_...` võti.
3. `python stripe_setup.py --live`
4. Asenda lehel neli URL-i live-linkidega.
5. Tee üks päris makse väikseima summaga ja tee see ise tagasi (Refund).

## 7. Enne müüki üle vaadata

- **Stripe Tax** (Settings → Tax): EL-is käibemaks. Eestis registreeritud ettevõttel on KMK kohustus alates 40 000 €/aastas; alla selle võib arveid ilma KM-ta väljastada, aga kontrolli oma olukorda raamatupidajaga.
- **Arved**: Stripe saadab automaatse kviitungi; e-arve jaoks on vaja eraldi lahendust (nt Merit Aktiva / e-arveldaja integratsioon).
- **Nõuded**: kasutustingimused ja privaatsuspoliitika lehel (GDPR mainib andmete töötlemist).
- **Tühistamine**: Stripe Customer Portal (Settings → Billing → Customer portal) annab kliendile iseteeninduse. Luba see sisse ja lisa link kinnitusmeilile.
- **Proovipakett** (`0 €`) ja **Ettevõte** (`499 €+`) ei ole Stripe'i lingiga — need jäävad kontaktivormile.

## 8. Kui hosting on maas

`openbot.site` annab hetkel 522. Payment Lingid ei sõltu hostingust — Stripe'i kass töötab ka siis, kui leht on mujal. Avaldamiseks on vaja OpenBoti hostingu taastumist.
