"""Exposed-file checks with signature confirmation and binary magic detection."""

from __future__ import annotations

import re

from ..crawling import Endpoint
from ..findings import Finding, Severity
from . import Context

KIND = "exposed"
MAX_PROBES = 160


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)


class Probe:
    __slots__ = ("path", "title", "severity", "signature", "magic", "expect_missing",
                 "category", "detail", "remediation", "tags")

    def __init__(
        self, path: str, title: str, severity: Severity, signature: re.Pattern[str],
        detail: str, remediation: str, category: str = "Avalik fail",
        expect_missing: bool = False, magic: bytes = b"",
        tags: tuple[str, ...] = (),
    ) -> None:
        self.path = path
        self.title = title
        self.severity = severity
        self.signature = signature
        self.magic = magic
        self.expect_missing = expect_missing
        self.category = category
        self.detail = detail
        self.remediation = remediation
        self.tags = list(tags)


PROBES: list[Probe] = [
    Probe("/.git/HEAD", "Git-repositoorium on avalik", Severity.CRITICAL,
          _re(r"^ref:\s+refs/(heads|remotes)/"),
          "Kogu lähtekood ja ajalugu on allalaaditav.",
          "Blokeeri `/.git/` ja eemalda see deploy-artefaktist.", "Lähtekoodi leke", tags=("source",)),
    Probe("/.git/config", "Git-konfiguratsioon on loetav", Severity.CRITICAL,
          _re(r"\[core\]|\[remote"),
          "Remote URL võib sisaldada manustatud kasutajat ja tokenit.",
          "Blokeeri `/.git/`, pööra token ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/.git/index", "Git-indeks on loetav", Severity.CRITICAL, _re(r"^"),
          "Git-i indeks on allalaaditav.", "Blokeeri `/.git/`.",
          "Lähtekoodi leke", magic=b"DIRC", tags=("source",)),
    Probe("/.git/logs/HEAD", "Git reflog on avalik", Severity.HIGH,
          _re(r"[0-9a-f]{40} [0-9a-f]{40}"),
          "Reflog paljastab commit-ide ajaloo.", "Blokeeri `/.git/`.", "Lähtekoodi leke"),
    Probe("/.git/refs/heads/master", "Git-i peakommit on loetav", Severity.HIGH,
          _re(r"^[0-9a-f]{40}\s*$"),
          "Commit-i hash on loetav.", "Blokeeri `/.git/`.", "Lähtekoodi leke"),
    Probe("/.svn/entries", "SVN-metandmed on avalikud", Severity.HIGH,
          _re(r"^\d+\s*$|dir\s*$"),
          "Subversioni töökataloog on veebijuures.", "Blokeeri `/.svn/`.", "Lähtekoodi leke"),
    Probe("/.svn/wc.db", "SVN-andmebaas on loetav", Severity.HIGH, _re(r"^"),
          "SVN-i metabaas on allalaaditav.", "Blokeeri `/.svn/`.",
          "Lähtekoodi leke", magic=b"SQLite format 3"),
    Probe("/.env", "`.env` on avalikult loetav", Severity.CRITICAL,
          _re(r"^[A-Z0-9_]{3,}\s*="),
          "Keskkonnafail sisaldab tavaliselt paroolid ja API-võtmed.",
          "Blokeeri punktifailid ja pööra kõik saladused ümber.",
          "Saladuste leke", tags=("secret",)),
    Probe("/.env.local", "`.env.local` on avalikult loetav", Severity.CRITICAL,
          _re(r"^[A-Z0-9_]{3,}\s*="),
          "Lokaalne keskonnafail on veebist loetav.",
          "Blokeeri ja pööra saladused ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/.env.production", "`.env.production` on avalikult loetav", Severity.CRITICAL,
          _re(r"^[A-Z0-9_]{3,}\s*="),
          "Produktsioonikeskkond on lekitatud.",
          "Blokeeri ja pööra saladused ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/.env.backup", "`.env.backup` on avalikult loetav", Severity.CRITICAL,
          _re(r"^[A-Z0-9_]{3,}\s*="),
          "Keskkonnafaili varukoopia on loetav.",
          "Eemalda varukoopia ja pööra saladused ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/.DS_Store", "`.DS_Store` lekitab failinimekirja", Severity.LOW,
          _re(r"Bud1"), "Failinimed on kaardistatavad.",
          "Blokeeri `.DS_Store`.", "Info leke", magic=b"Bud1"),
    Probe("/.htaccess", "`.htaccess` on loetav", Severity.MEDIUM,
          _re(r"<IfModule|RewriteEngine|AuthType"),
          "Apache'i konfiguratsioon on veebist loetav.",
          "Blokeeri punktifailid.", "Info leke"),
    Probe("/web.config", "`web.config` on loetav", Severity.HIGH,
          _re(r"<configuration|<system\.web"),
          "IIS-i konfiguratsioon võib sisaldada connection stringe.",
          "Blokeeri `web.config`, pööra saladused ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/WEB-INF/web.xml", "Java servleti konfiguratsioon on avalik", Severity.MEDIUM,
          _re(r"<web-app|servlet-mapping"),
          "Tomcati kaitsmata konfiguratsioon paljastab struktuuri.",
          "Piira `/WEB-INF/`.", "Info leke"),
    Probe("/META-INF/context.xml", "Tomcat context.xml on avalik", Severity.MEDIUM,
          _re(r"<Context|Resource name="),
          "Tomcat context sisaldab tihti andmebaasi identiteeti.",
          "Piira `/META-INF/`.", "Saladuste leke", tags=("secret",)),
    Probe("/backup.zip", "Varukoopia ZIP on allalaaditav", Severity.CRITICAL, _re(r"^"),
          "ZIP arhiiv võib sisaldada kogu saidi.",
          "Eemalda varukoopiad veebijuurest.", "Varukoopia leke",
          magic=b"PK\x03\x04", tags=("backup",)),
    Probe("/backup.tar.gz", "Varukoopia tar.gz on allalaaditav", Severity.CRITICAL, _re(r"^"),
          "Pakitud varukoopia on allalaaditav.",
          "Eemalda varukoopiad.", "Varukoopia leke", magic=b"\x1f\x8b", tags=("backup",)),
    Probe("/site.zip", "Saidi ZIP on allalaaditav", Severity.CRITICAL, _re(r"^"),
          "Arhiiv võib sisaldada lähtekoodi.",
          "Eemalda arhiiv.", "Varukoopia leke", magic=b"PK\x03\x04", tags=("backup",)),
    Probe("/www.zip", "WWW ZIP on allalaaditav", Severity.CRITICAL, _re(r"^"),
          "Arhiiv võib sisaldada lähtekoodi.",
          "Eemalda arhiiv.", "Varukoopia leke", magic=b"PK\x03\x04", tags=("backup",)),
    Probe("/backup.sql", "SQL-dump on allalaaditav", Severity.CRITICAL,
          _re(r"CREATE TABLE|INSERT INTO|-- MySQL dump"),
          "Andmebaasi sisu on veebist loetav.",
          "Eemalda dump ja pööra parool ümber.", "Varukoopia leke", tags=("secret",)),
    Probe("/db.sqlite", "SQLite-andmebaas on allalaaditav", Severity.CRITICAL, _re(r"^"),
          "Andmebaasifail on veebist loetav.",
          "Eemalda andmebaas veebijuurest.", "Varukoopia leke",
          magic=b"SQLite format 3", tags=("secret",)),
    Probe("/index.php.bak", "PHP varufail on loetav", Severity.HIGH,
          _re(r"<\?php|<\?="),
          "Lähtekood on loetav text/plain-ina.",
          "Eemalda `.bak` failid.", "Lähtekoodi leke", tags=("source",)),
    Probe("/config.php.bak", "Konfiguratsiooni varufail on loetav", Severity.CRITICAL,
          _re(r"(password|secret|db_)\s*[=:]"),
          "Varukonfiguratsioon paljastab saladused.",
          "Eemalda fail ja pööra saladused ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/.git-credentials", "Git-kredentiaalifail on avalik", Severity.CRITICAL,
          _re(r"https?://[^/\s]+:[^@\s]+@"),
          "Salvestatud Git-identiteet on loetav.",
          "Eemalda fail, pööra tokenid ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/.npmrc", "npm-konfiguratsioon on avalik", Severity.HIGH,
          _re(r"_authToken|_auth\s*="),
          "npm-i autentimisvõti on loetav.",
          "Eemalda fail ja pööra token ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/.aws/credentials", "AWS-identiteedifail on avalik", Severity.CRITICAL,
          _re(r"aws_access_key_id|\[default\]"),
          "AWS-i võtmed on veebist loetav.",
          "Pööra võtmed kohe ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/.ssh/id_rsa", "SSH-privaatvõti on avalik", Severity.CRITICAL,
          _re(r"BEGIN [A-Z ]*PRIVATE KEY"),
          "Privaatvõti on allalaaditav.",
          "Pööra võti ümber ja kontrolli logisid.", "Saladuste leke", tags=("secret",)),
    Probe("/wp-config.php", "WordPressi konfiguratsioon on avalik", Severity.CRITICAL,
          _re(r"DB_(NAME|PASSWORD|USER)"),
          "Andmebaasi identiteet on loetav.",
          "Paranda PHP-käsitlemine ja pööra parool ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/wp-config.php.bak", "WordPressi varukonfiguratsioon on avalik", Severity.CRITICAL,
          _re(r"DB_(NAME|PASSWORD|USER)"),
          "Varukonfiguratsioon on loetav.",
          "Eemalda fail ja pööra parool ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/configuration.php", "Joomla konfiguratsioon on avalik", Severity.CRITICAL,
          _re(r"JConfig|public \$|password"),
          "Joomla konfiguratsioon paljastab saladused.",
          "Paranda PHP-käsitlemine.", "Saladuste leke", tags=("secret",)),
    Probe("/config.json", "Konfiguratsioon JSON on avalik", Severity.HIGH,
          _re(r'"(password|secret|api[_-]?key|token)"\s*:'),
          "Konfiguratsioonifail sisaldab saladusi.",
          "Blokeeri fail ja pööra väärtused ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/composer.json", "Composer manifest on avalik", Severity.LOW,
          _re(r'"(name|require)"\s*:'),
          "Sõltuvused on loetavad.", "Eemalda deploy-artefaktist.", "Info leke"),
    Probe("/package.json", "npm manifest on avalik", Severity.LOW,
          _re(r'"(name|dependencies)"\s*:'),
          "Sõltuvused on loetavad.", "Eemalda deploy-artefaktist.", "Info leke"),
    Probe("/Dockerfile", "Dockerfile on avalik", Severity.MEDIUM,
          _re(r"^\s*FROM\s+\S+"),
          "Ehitusjärgud ja baasimage on loetavad.",
          "Eemalda Dockerfile veebijuurest.", "Info leke"),
    Probe("/docker-compose.yml", "Docker Compose konfiguratsioon on avalik", Severity.HIGH,
          _re(r"^\s*(version|services):"),
          "Fail võib sisaldada paroolid ja sisemisi hoste.",
          "Eemalda fail ja pööra saladused ümber.", "Saladuste leke", tags=("secret",)),
    Probe("/proc/self/environ", "Protsessi keskond on loetav", Severity.CRITICAL,
          _re(r"PATH=|HOME="),
          "Serveriprotsessi keskkonnamuutujad on lekitatud.",
          "Piira `/proc/` ligipääs.", "Saladuste leke", tags=("secret",)),
    Probe("/phpinfo.php", "`phpinfo()` on avalik", Severity.HIGH,
          _re(r"PHP Version|phpinfo\(\)"),
          "PHP versioon, laiendused ja keskkonnamuutujad on loetavad.",
          "Kustuta phpinfo.php.", "Info leke", tags=("fingerprint",)),
    Probe("/server-status", "Apache server-status on avalik", Severity.MEDIUM,
          _re(r"Apache Server Status|Server Version:"),
          "Aktiivsed päringud ja kliendid on loetavad.",
          "Sea `Require local`.", "Info leke"),
    Probe("/server-info", "Apache server-info on avalik", Severity.MEDIUM,
          _re(r"Server Version|Apache Configuration"),
          "Serveri konfiguratsioon on loetav.",
          "Piira IP-ga.", "Info leke"),
    Probe("/actuator", "Spring Actuator on avalik", Severity.MEDIUM,
          _re(r'"_links"|"self"'),
          "Haldusendpoints on loetletud.",
          "Sea `exposure.include=health`.", "Info leke"),
    Probe("/actuator/env", "Spring Actuator env on avalik", Severity.CRITICAL,
          _re(r'"propertySources"|"activeProfiles"'),
          "Keskkonnamuutujad ja paroolid on lekitatud.",
          "Piira actuator.", "Saladuste leke", tags=("secret",)),
    Probe("/actuator/heapdump", "Spring heapdump on allalaaditav", Severity.CRITICAL, _re(r"^"),
          "Mäludump sisaldab tokeneid.",
          "Blokeeri endpoint.", "Saladuste leke", magic=b"\x00\x00\x00", tags=("secret",)),
    Probe("/actuator/configprops", "Spring configprops on avalik", Severity.CRITICAL,
          _re(r'"contexts"|"beans"'),
          "Konfiguratsioon on lekitatud.",
          "Piira actuator.", "Saladuste leke", tags=("secret",)),
    Probe("/actuator/httptrace", "Spring httptrace on avalik", Severity.HIGH,
          _re(r'"traces"|"principal"'),
          "Viimased päringud ja sessioonid on loetavad.",
          "Piira actuator.", "Info leke", tags=("auth",)),
    Probe("/swagger-ui.html", "Swagger UI on avalik", Severity.LOW,
          _re(r"swagger-ui|Swagger UI"),
          "API-dokumentatsioon paljastab kõik endpointid.",
          "Piira või lülita välja.", "Info leke"),
    Probe("/openapi.json", "OpenAPI spetsifikatsioon on avalik", Severity.LOW,
          _re(r'"(openapi|swagger)"\s*:'),
          "API skeem on loetav.", "Piira dokumentatsioon.", "Info leke"),
    Probe("/swagger/v1/swagger.json", "Swagger JSON on avalik", Severity.LOW,
          _re(r'"(openapi|swagger)"\s*:'),
          "API skeem on loetav.", "Piira dokumentatsioon.", "Info leke"),
    Probe("/api-docs", "API-dokumentatsioon on avalik", Severity.LOW,
          _re(r'swagger|openapi|"paths"'),
          "API skeem on loetav.", "Piira dokumentatsioon.", "Info leke"),
    Probe("/graphql", "GraphQL-endpoint on avalik", Severity.LOW,
          _re(r"__schema|GraphiQL|GraphQL"),
          "Introspeksioon võib paljastada kogu skeemi.",
          "Lülita introspeksioon välja.", "Info leke"),
    Probe("/phpmyadmin/", "phpMyAdmin on avalik", Severity.MEDIUM,
          _re(r"phpMyAdmin|pmadmin"),
          "Andmebaasi haldusliides on ligipääsetav.",
          "Piira IP-ga.", "Haldusliides"),
    Probe("/adminer.php", "Adminer on avalik", Severity.MEDIUM,
          _re(r"Adminer|adminer"),
          "Andmebaasi haldusvahend on ligipääsetav.",
          "Piira või eemalda.", "Haldusliides"),
    Probe("/elmah.axd", "ELMAH-i logivaatur on avalik", Severity.MEDIUM,
          _re(r"ELMAH|Error Log"),
          "Vealogud võivad sisaldada paroolid.",
          "Blokeeri endpoint.", "Info leke"),
    Probe("/trace.axd", "ASP.NET trace on avalik", Severity.MEDIUM,
          _re(r"Trace Information|Request Details"),
          "Jälgimisandmed on ligipääsetavad.",
          "Lülita trace välja.", "Info leke"),
    Probe("/crossdomain.xml", "Crossdomain policy on avalik", Severity.LOW,
          _re(r"<cross-domain-policy"),
          "Flash/legacy policy võib lubada võõra domeeni ligipääsu.",
          "Piira `allow-access-from`.", "Konfiguratsioon"),
    Probe("/clientaccesspolicy.xml", "Silverlight policy on avalik", Severity.LOW,
          _re(r"<access-policy"),
          "Legacy policy on loetav.", "Piira policy.", "Konfiguratsioon"),
    Probe("/.well-known/jwks.json", "JWKS on avalik", Severity.INFO,
          _re(r'"keys"\s*:\s*\['),
          "Avalikud võtmed on loetavad.",
          "Kontrolli, et privaatvõtmeid pole kaasas.", "Info leke"),
    Probe("/.vscode/settings.json", "VS Code seaded on avalikud", Severity.LOW,
          _re(r'"[A-Za-z_]+\.[A-Za-z_]+"\s*:'),
          "Projekti seaded on loetavad.",
          "Blokeeri punktikaustad.", "Info leke"),
    Probe("/.idea/workspace.xml", "IDE tööruum on avalik", Severity.LOW,
          _re(r"<project|component name="),
          "Arenduskeskkonna andmed on loetavad.",
          "Blokeeri punktikaustad.", "Info leke"),
    Probe("/.well-known/security.txt", "security.txt puudub", Severity.INFO,
          _re(r"Contact:\s*\S+"),
          "Turvahäirete raporteerimise kanal ei ole avalik.",
          "Lisa `Contact:` ja `Expires:`.", "Hügieen", expect_missing=True),
]

DIRECTORY_PATHS = ("/uploads/", "/images/", "/static/", "/files/", "/backup/", "/tmp/", "/assets/")
DIRECTORY_MARKER = _re(r"<title>Index of /|<h1>Index of /|Directory listing for|Index of /")


def _matches(probe: Probe, response) -> bool:
    if probe.magic:
        return probe.magic in response.body[:64]
    body = response.body.decode("latin-1", "replace") if probe.magic else response.text
    present = bool(probe.signature.search(body))
    return (not present) if probe.expect_missing else present


def check_exposed(ctx: Context, _endpoints: list[Endpoint]) -> None:
    probed = 0
    for probe in PROBES:
        if probed >= MAX_PROBES or ctx.stop():
            return
        url = ctx.origin.rstrip("/") + probe.path
        response = ctx.client.get(url)
        probed += 1
        if response.error:
            continue
        if not probe.expect_missing and (response.status >= 400 or not response.body):
            continue
        if not _matches(probe, response):
            continue
        ctx.emit(Finding(
            title=probe.title, severity=probe.severity, category=probe.category,
            url=url, detail=probe.detail,
            evidence=f"HTTP {response.status}, {len(response.body)} baiti, "
                     f"{response.header('content-type', 'puudub')}",
            check="exposed", remediation=probe.remediation, tags=probe.tags,
        ))

    for path in DIRECTORY_PATHS:
        if ctx.stop():
            return
        response = ctx.client.get(ctx.origin.rstrip("/") + path)
        if response.error or response.status != 200:
            continue
        if not DIRECTORY_MARKER.search(response.text[:5000]):
            continue
        ctx.emit(Finding(
            title=f"Kataloogi nimekiri on avatud: `{path}`", severity=Severity.MEDIUM,
            category="Info leke", url=ctx.origin.rstrip("/") + path,
            detail="Server nimetab faile, mida pole kuskil lingitud.",
            check="exposed", remediation="Lülita `autoindex off` või `Options -Indexes`.",
            tags=("info",),
        ))


CHECKS = [{"name": "exposed", "kind": KIND, "run": check_exposed}]
