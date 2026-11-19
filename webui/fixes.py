"""Remediation library keyed by check name and finding title keywords."""

from __future__ import annotations

FIXES: dict[str, dict] = {
    "headers": {
        "title": "Turvapäised",
        "summary": "Brauseri kaitsemehhanismid puuduvad. Lisa vastuse päised serveris või reverse proxy's.",
        "steps": [
            "Nginx: lisa `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;`",
            "Lisa `add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'\" always;`",
            "Lisa `add_header X-Content-Type-Options nosniff always;` ja `add_header Referrer-Policy strict-origin-when-cross-origin always;`",
            "Apache: `Header always set X-Frame-Options DENY` ja `Header always set X-Content-Type-Options nosniff`",
            "Kontrolli päiseid uuesti: `curl -I https://sinu-sait/`",
        ],
        "code": {
            "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                     "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'\" always;\n"
                     "add_header X-Content-Type-Options nosniff always;\n"
                     "add_header Referrer-Policy strict-origin-when-cross-origin always;\n"
                     "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
            "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
                      "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'\"\n"
                      "Header always set X-Content-Type-Options nosniff\n"
                      "Header always set X-Frame-Options DENY\n"
                      "Header always set Referrer-Policy strict-origin-when-cross-origin",
            "express": "app.use((req, res, next) => {\n"
                       "  res.setHeader('X-Content-Type-Options', 'nosniff');\n"
                       "  res.setHeader('X-Frame-Options', 'DENY');\n"
                       "  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');\n"
                       "  res.setHeader('Content-Security-Policy', \"default-src 'self'; script-src 'self'\");\n"
                       "  next();\n"
                       "});",
        },
    },
    "cookies": {
        "title": "Küpsise turvalippud",
        "summary": "Sessiooniküpsis on ilma Secure/HttpOnly/SameSite'ita — ründaja saab selle varastada või saata.",
        "steps": [
            "Sea igal sessiooniküpsisel `HttpOnly`, `Secure` ja `SameSite=Lax` (või `Strict`).",
            "Kui kasutad `__Host-` eesliidet, siis ära sea `Domain` ja sea `Path=/`.",
            "Eemalda tarbetu `Domain`, et küpsis ei lekuks alamdomeenidele.",
            "PHP: `session_set_cookie_params(['httponly'=>true,'secure'=>true,'samesite'=>'Lax']);`",
            "Node: `res.cookie('sid', token, { httpOnly:true, secure:true, sameSite:'lax' });`",
        ],
        "code": {
            "php": "session_set_cookie_params([\n"
                   "  'lifetime' => 3600,\n"
                   "  'path' => '/',\n"
                   "  'secure' => true,\n"
                   "  'httponly' => true,\n"
                   "  'samesite' => 'Lax',\n"
                   "]);\nsession_start();",
            "node": "res.cookie('sid', token, {\n"
                    "  httpOnly: true,\n"
                    "  secure: true,\n"
                    "  sameSite: 'lax',\n"
                    "  path: '/',\n"
                    "  maxAge: 3600000,\n"
                    "});",
            "python": "response.set_cookie('sid', token, httponly=True, secure=True,\n"
                      "                     samesite='Lax', max_age=3600)",
        },
    },
    "cors": {
        "title": "CORS-i väärkonfiguratsioon",
        "summary": "Server peegeldab võõra origini ja lubab credentials-e — iga sait saab lugeda autenditud andmeid.",
        "steps": [
            "Koosta lubatud originite nimekiri ja valideeri saabunud `Origin` selle vastu.",
            "Ära kunagi kasuta `Access-Control-Allow-Origin: *` koos `Access-Control-Allow-Credentials: true`.",
            "Tagasta staatiline lubatud väärtus, mitte sisendist peegeldatud väärtus.",
            "Piira lubatud meetodid ja päised minimaalsega.",
        ],
        "code": {
            "express": "const allowed = new Set(['https://trusted.example']);\n"
                       "app.use((req, res, next) => {\n"
                       "  const origin = req.headers.origin;\n"
                       "  if (allowed.has(origin)) {\n"
                       "    res.setHeader('Access-Control-Allow-Origin', origin);\n"
                       "    res.setHeader('Access-Control-Allow-Credentials', 'true');\n"
                       "    res.setHeader('Vary', 'Origin');\n"
                       "  }\n"
                       "  next();\n"
                       "});",
            "nginx": "if ($http_origin ~* \"^https://trusted\\.example$\") {\n"
                     "  add_header Access-Control-Allow-Origin $http_origin always;\n"
                     "  add_header Access-Control-Allow-Credentials true always;\n"
                     "  add_header Vary Origin always;\n"
                     "}",
        },
    },
    "cache": {
        "title": "Vahemälukaitse puudub",
        "summary": "Sessiooniküpsise seadv vastus võib sattuda jagatud vahemällu.",
        "steps": [
            "Lisa kõigile autenditud vastustele `Cache-Control: no-store, private`.",
            "Lisa `Pragma: no-cache` vanadele vahendajatele.",
            "Veebiserveri tasemel: nginx `add_header Cache-Control \"no-store, private\" always;`",
        ],
        "code": {
            "nginx": "location / {\n"
                     "  add_header Cache-Control \"no-store, private\" always;\n"
                     "  add_header Pragma \"no-cache\" always;\n"
                     "}",
            "express": "app.use((req, res, next) => {\n"
                       "  res.setHeader('Cache-Control', 'no-store, private');\n"
                       "  res.setHeader('Pragma', 'no-cache');\n"
                       "  next();\n"
                       "});",
        },
    },
    "banner": {
        "title": "Versioonileke",
        "summary": "Täpne tarkvaraversioon annab ründajale valmis CVE-nimekirja.",
        "steps": [
            "Nginx: `server_tokens off;`",
            "Apache: `ServerTokens Prod` ja `ServerSignature Off`",
            "ASP.NET: eemalda `X-Powered-By` moodul: `<remove name=\"X-Powered-By\" />`",
            "Eemalda HTML-ist `<meta name=\"generator\" content=\"...\">`.",
            "PHP: `expose_php = Off`.",
        ],
        "code": {
            "nginx": "server_tokens off;\nadd_header X-Powered-By \"\" always;",
            "apache": "ServerTokens Prod\nServerSignature Off",
            "php": "expose_php = Off",
        },
    },
    "tls": {
        "title": "TLS-i probleemid",
        "summary": "Krüpteerimine on nõrk, sertifikaat on vigane või puudub täielikult.",
        "steps": [
            "Luba ainult TLS 1.2 ja TLS 1.3: `ssl_protocols TLSv1.2 TLSv1.3;`",
            "Paigalda kehtiv sertifikaat, mis katab kõik hosti nimed.",
            "Lisa vahepealsed sertifikaadid (full chain), mitte ainult leafsertifikaat.",
            "Sea automaatne uuendamine (Let's Encrypt / certbot).",
            "Suuna kogu HTTP-liiklus 301-ga HTTPS-ile.",
        ],
        "code": {
            "nginx": "ssl_protocols TLSv1.2 TLSv1.3;\n"
                     "ssl_ciphers HIGH:!aNULL:!MD5;\n"
                     "ssl_prefer_server_ciphers on;\n"
                     "ssl_session_cache shared:TLS:10m;",
            "apache": "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                      "SSLCipherSuite HIGH:!aNULL:!MD5",
        },
    },
    "methods": {
        "title": "Ohtlikud HTTP-meetodid",
        "summary": "TRACE, PUT, DELETE või CONNECT on lubatud ja võivad võimaldada rünnet.",
        "steps": [
            "Apache: `TraceEnable Off`",
            "Nginx: `limit_except GET POST HEAD { deny all; }`",
            "IIS: eemalda ebavajalikud meetodid Request Filteringust.",
            "Kontrolli uuesti: `curl -X OPTIONS -I https://sait/` ja `curl -X TRACE -I https://sait/`.",
        ],
        "code": {
            "nginx": "limit_except GET POST HEAD {\n    deny all;\n}",
            "apache": "TraceEnable Off\n"
                      "<LimitExcept GET POST HEAD>\n  Require all denied\n</LimitExcept>",
        },
    },
    "exposed": {
        "title": "Avalikult ligipääsetavad failid",
        "summary": "Saladused, lähtekood või varukoopiad on veebist loetavad.",
        "steps": [
            "Eemalda fail kohe veebijuurest — ära looda ainult juurdepääsukeelule.",
            "Pööra kõik leitud saladused (paroolid, API-võtmed, tokenid) ümber.",
            "Blokeeri veebiserveri tasemel: `location ~ /\\.(git|env|svn|aws|ssh) { deny all; }`",
            "Lisa `.gitignore` ja deploy-script, mis jätab need failid välja.",
            "Kontrolli ligipääsu logisid — võib-olla on fail juba alla laaditud.",
        ],
        "code": {
            "nginx": "location ~ /\\.(git|env|svn|aws|ssh|DS_Store) {\n    deny all;\n    return 404;\n}\n"
                     "location ~ \\.(zip|tar|gz|sql|bak|old)$ {\n    deny all;\n    return 404;\n}",
            "apache": "RedirectMatch 404 /\\.(git|env|svn|aws|ssh|DS_Store)\n"
                      "RedirectMatch 404 \\.(zip|tar|gz|sql|bak|old)$",
        },
    },
    "xss": {
        "title": "Reflekteeruv XSS",
        "summary": "Kasutaja sisend jõuab HTML-i muutmata kujul ja käivitab JavaScripti.",
        "steps": [
            "Kodeeri väljund konteksti järgi: HTML, atribuut, JavaScript, URL, CSS.",
            "Ära ehita HTML-i stringide liitmisega — kasuta templatemootorit automaatse escapinguga.",
            "Lisa CSP `script-src 'self'` ja väldi `unsafe-inline`.",
            "Valideeri sisend lubatud väärtuste nimekirja vastu, kui võimalik.",
            "Kasuta turvalisi API-sid: `textContent`, mitte `innerHTML`.",
        ],
        "code": {
            "javascript": "const div = document.createElement('div');\ndiv.textContent = userInput;\n"
                          "container.appendChild(div);\n\n// EI: container.innerHTML = userInput;",
            "python": "from html import escape\nsafe = escape(user_input, quote=True)\n"
                      "return f'<p>{safe}</p>'",
            "php": "echo htmlspecialchars($input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');",
            "java": "String safe = StringEscapeUtils.escapeHtml4(input);",
        },
    },
    "sqli": {
        "title": "SQL-süst",
        "summary": "Kasutaja sisend jõuab SQL-päringusse — ründaja loeb või muudab andmebaasi.",
        "steps": [
            "Kasuta alati parametriseeritud päringuid (prepared statements).",
            "Ära ehita SQL-i stringide liitmisega ega f-string'idega.",
            "Valideeri ja normaliseeri numbrilised parameetrid.",
            "Lülita tootmises veateated välja — need annavad ründajale skeemi teavet.",
            "Anna andmebaasi kasutajale minimaalsed õigused (mitte DBA).",
        ],
        "code": {
            "python": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            "node": "db.query('SELECT * FROM users WHERE id = $1', [userId])",
            "java": "PreparedStatement ps = conn.prepareStatement(\n"
                    "  'SELECT * FROM users WHERE id = ?');\nps.setInt(1, userId);",
            "php": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
                   "$stmt->execute(['id' => $id]);",
        },
    },
    "traversal": {
        "title": "Path traversal",
        "summary": "Kasutaja sisend jõuab failiteena — ründaja loeb suvalisi faile.",
        "steps": [
            "Ära võta failiteed otse kasutajalt — kasuta ID-d, mis tuletatakse turvaliselt.",
            "Normaliseeri tee ja kontrolli, et see jääb lubatud baaskausta sisse.",
            "Keeldu `..`, null-baitidest ja absoluutsetest teedest.",
            "Kasuta `realpath()` ja võrrelda baaskaustaga enne avamist.",
        ],
        "code": {
            "python": "base = Path('/var/app/uploads').resolve()\n"
                      "target = (base / name).resolve()\n"
                      "if not target.is_relative_to(base):\n"
                      "    raise ValueError('Invalid path')",
            "node": "const path = require('path');\n"
                    "const base = path.resolve('/var/app/uploads');\n"
                    "const target = path.resolve(base, name);\n"
                    "if (!target.startsWith(base + path.sep)) throw new Error('Invalid path');",
            "java": "Path base = Paths.get('/var/app/uploads').toRealPath();\n"
                    "Path target = base.resolve(name).normalize();\n"
                    "if (!target.startsWith(base)) throw new SecurityException();",
        },
    },
    "redirect": {
        "title": "Avatud ümbersuunamine",
        "summary": "Rakendus suunab kasutaja ründaja valitud aadressile — õngitsus ja tokenite vargus.",
        "steps": [
            "Luba ainult suhtelisi teed, mis algavad ühe `/`-ga.",
            "Kui vaja absoluutseid URL-e, valideeri host lubatud nimekirja vastu.",
            "Ära aktsepteeri `//host` ega `\\host` kujulisi sisendeid.",
            "OAuth: registreeri täpsed `redirect_uri` väärtused, ära kasuta wildcard'e.",
        ],
        "code": {
            "javascript": "const next = req.query.next || '/';\n"
                          "if (!next.startsWith('/') || next.startsWith('//')) {\n"
                          "  return res.status(400).send('Invalid redirect');\n"
                          "}\nres.redirect(next);",
            "python": "from urllib.parse import urlparse\n"
                      "parsed = urlparse(url)\n"
                      "if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
                      "    raise ValueError('Invalid redirect')\n"
                      "return url",
        },
    },
    "command": {
        "title": "Käsu süüst",
        "summary": "Kasutaja sisend jõuab kesta käsku — ründaja käivitab suvalisi käske.",
        "steps": [
            "Ära kunagi edasta kasutaja sisendit kestale.",
            "Kui vaja väliseid programme, kasuta fikseeritud käsku ja argumentide massiivi (ilma shell'ita).",
            "Valideeri kõik argumendid ranged lubatud väärtuste vastu.",
            "Jooksuta protsess minimaalse õigusega kasutajana.",
        ],
        "code": {
            "python": "subprocess.run(['/usr/bin/convert', safe_path, output],\n"
                      "             shell=False, check=True, timeout=10)",
            "node": "spawnExec('convert', [safePath, output], { shell: false });",
            "go": "cmd := exec.Command(\"/usr/bin/convert\", safePath, output)\n"
                  "err := cmd.Run()",
        },
    },
    "ssti": {
        "title": "Serveripoolne mallisüst (SSTI)",
        "summary": "Mallimootor hindab kasutaja sisendi koodina — võimalik koodi käivitamine.",
        "steps": [
            "Ära anna kunagi kasutaja sisendit mallina — ainult andmena.",
            "Kasuta staatilisi malle ja kontekstipõhist asendust.",
            "Jinja2: `render_template('page.html', name=user_input)`, mitte `render_template_string`.",
            "Piira mallikeskkond (sandboxed environment), kui dünaamiline mall on vältimatu.",
        ],
        "code": {
            "python": "from flask import render_template\n"
                      "return render_template('page.html', name=user_input)\n\n"
                      "# EI: render_template_string(user_input)",
            "node": "res.render('page', { name: userInput });  // EI: res.send(userInput)",
            "java": "model.addAttribute('name', userInput);  // Thymeleaf template",
        },
    },
    "crlf": {
        "title": "CRLF-päisesüst",
        "summary": "Ründaja sisestab vastusse uue päise — võimalik sessioonihalduse murdmine.",
        "steps": [
            "Keeldu kõigist kontrollimärkidest (`\\r`, `\\n`, null) päistes ja URL-i parameetrites.",
            "Kasuta raamistiku päise-API-sid, mitte raw-string'e.",
            "Uuenda proxy ja veebiserver — vanad versioonid normaliseerivad päisi valesti.",
        ],
        "code": {
            "python": "if any(c in value for c in '\\r\\n\\x00'):\n"
                      "    raise ValueError('Invalid header value')\n"
                      "response.headers['X-Value'] = value",
            "node": "if (/[\\r\\n\\0]/.test(value)) throw new Error('Invalid header');\n"
                    "res.setHeader('X-Value', value);",
        },
    },
    "methods_http": {
        "title": "HTTP-meetodite piirangud",
        "summary": "Piira lubatud meetodid ja kontrolli uuesti pärast muudatust.",
        "steps": ["Vaata `methods` jaotist."],
        "code": {},
    },
}

DEFAULT_FIX = {
    "title": "Üldine parandus",
    "summary": "Kontrolli leiu detaili ja rakenda allpool kirjeldatud sammud.",
    "steps": [
        "Kinnita leid käsitsi enne parandamist.",
        "Uuenda sõltuvused ja veebiserveri konfiguratsioon.",
        "Lisa automaatne kontroll, et sama viga ei tekiks uuesti.",
    ],
    "code": {},
}


def get_fix(check: str) -> dict:
    if check in FIXES:
        return FIXES[check]
    if check == "methods":
        return FIXES["methods"]
    return DEFAULT_FIX
