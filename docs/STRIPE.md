# Nutiscan — Stripe kassa seadistus

Leht on staatiline (üks `index.html`), seega kaardimakse käib **Stripe Payment Linkide** kaudu: iga nupp avab Stripe'i hostitud kassa. Kaardiandmed ei läbi sinu lehte ega serverit.

## 1. Konto ja aktiveerimine

1. Loo konto: https://dashboard.stripe.com/register
2. Täida ettevõtte andmed: juriidiline nimi, registrikood, äriaadress, e-post, telefon ja IBAN väljamakseteks. Eesti OÜ või FIE sobib.
3. Lisa pangakonto (IBAN) ja kinnita oma e-post.
4. Tee **identity verification**: Stripe küsib esindaja ees- ja perekonnanime, sünnikuupäeva ning mõnel juhul isikut tõendava dokumendi ja ettevõtte registriväljavõtte. Need andmed antakse otse Stripe'ile, mitte koodile.
5. Kirjelda tegevusala arusaadavas keeles (nt „veebiturvalisuse skanneri tellimused"). Stripe võib küsida saidi lingi — lisa `https://tarmo90.github.io/nutiscan/`.
6. Oota kinnitust. Kui konto on aktiveeritud, kaob testrežiimi märk ja kuvatakse `sk_live_...` võti.
7. Kuni aktiveerimiseni jää **test mode** sisse (lüliti dashboardi ülanurgas). Testrežiimis tehtud makseid ei laeku arvele.

Aktiveerimine võib võtta mõne tunni kuni mõne päeva. Kui Stripe küsib lisadokumente, lae need dashboardi teadetesse — mujalt seda teha ei saa.

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

## 8. Automaatne litsentsivõtme saatmine

Pärast makset peab klient saama võtme. Seda teeb `license_webhook.py` — väike Pythoni teenus, mis kontrollib Stripe'i allkirja, väljastab võtme sinu privaatvõtmega ja saadab e-postiga.

**Stripe'i pool:**

1. Dashboard → **Developers → Webhooks → Add endpoint**.
2. Endpoint URL: `https://sinu-domeen/stripe`. Peab olema HTTPS — `localhost` otse ei tööta; kasuta tunnelit (nt Cloudflare Tunnel) või nginx-i TLS-iga.
3. Vali sündmused: `checkout.session.completed` ja `invoice.paid`. Teine katte uuendused.
4. Ava loodud endpoint → **Reveal signing secret** → kopeeri `whsec_...`.

**E-post:** kasuta oma SMTP-serverit. Gmaili puhul on vaja rakenduseparooli (App Password), mitte tavalist kontoparooli.

**Käivitamine** (samas kaustas, kus on `license_tool.py`):

```powershell
$env:NUTISCAN_WEBHOOK_SECRET = "whsec_..."
$env:SMTP_HOST = "smtp.example.com"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "nuti@example.com"
$env:SMTP_PASS = "rakenduseparool"
$env:NUTISCAN_FROM_EMAIL = "nuti@example.com"
# Kui privaatvõti on mujal:
$env:NUTISCAN_LICENSE_PRIVATE = (Get-Content "D:\Nutiscan-backup\license_private.key" -Raw).Trim()
python license_webhook.py
```

Teenus kuulab vaikimisi `http://127.0.0.1:8833/stripe`. Tervisekontroll: `GET /health`.

**Kuidas see käitub:**

- Võti luuakse paketi (`metadata[plan]`) ja tsükli (`metadata[cycle]`) järgi: kuutasu → 1 kuu + 5 päeva, aastatasu → 12 kuud + 10 päeva.
- Kliendi e-post tuleb Stripe'i kassast (`customer_details.email`).
- Iga sündmus märgitakse ära `webhook-state/events.log` failis — topeltkirja ei tule.
- Kui e-posti saatmine ebaõnnestub, vastab teenus `500` ja Stripe proovib hiljem uuesti.
- `invoice.paid` uuendab võtit ka järgmisel maksperioodil, kui tellimus on active.

**Testimine:** saada Stripe'i dashboardist endpointile test-sündmus või tee testkassas makse kaardiga `4242 4242 4242 4242`. Kiri peab laekuma ja võti peab verifitseeruma käsuga `python license_tool.py verify NS1...`.

**Turvalisus:** `Stripe-Signature` päis peab jõudma teenuseni muutmata. Ära avalda porti 8833 otse internetis — ainult TLS-i taga. Kui `Stripe-Signature` puudub või allkiri ei ühti, vastab teenus `401`.

## 9. Kui hosting on maas

`openbot.site` annab hetkel 522. Payment Lingid ei sõltu hostingust — Stripe'i kass töötab ka siis, kui leht on mujal. Avaldamiseks on vaja OpenBoti hostingu taastumist.
