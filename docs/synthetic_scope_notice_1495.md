# LightUp #1495 — fictieve scopeverklaring vóór handmatige beoordeling

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Dit is een geïsoleerde, niet aangesloten preview voor een menselijke reviewer. Geen toestemming of scan-/uitvoeringsbevoegdheid.

## Wat nu echt werkt

`src/lightup/synthetic_scope_notice_1495.py` levert `render_scope_notice((ScopeProposal(...),), review_at=...)`. De uitvoer is een vaste, beknopte Nederlandstalig te duiden reviewkaart (tekst bewust Engelstalig voor herkenbare STOP-woorden) waarin de voorgestelde fictieve assets, exacte capabilities, risico's, UTC-vensters, hoog-risico-step-up en de exacte woorden **NOT AUTHORIZED** zichtbaar zijn.

- Zonder invoer, met onbegrensde invoer (>32), met duplicate asset+capability, of bij ééń kapot veld volgt **één atomische HOLD** zonder hergebruik/echo van input.
- Alleen strikt kleine synthetische `<subdomain>.example.test` assets zijn toegestaan. Het is onmogelijk om hier echte klantdomeinen als goedgekeurd af te beelden.
- Alleen exacte `str`/ `int` / UTC-`datetime` veldtypes; geen bool-risicoscore, subclassing, IDNA alias, gemengde tijdzones, fold, fractional seconds, verlopen/zeer lange vensters of stilzwijgende normalisatie.
- Geldige gesorteerde voorbeelden geven alleen **REVIEW_ONLY**; `authorized`, `consent_verified`, `dispatch_allowed`, `release_allowed` blijven letterlijk `False`. Dat blijft zo voor risico 4–5.
- Geen data-opslag, netwerk, DNS, HTTP, SQLite, subprocess, toolhandlers, scan of echte identiteits-/consentcontrole. De functie is bewust **unwired**.
- Deterministisch en veilig herhaalbaar, ook als een andere worker aan originele `ScopePolicy`, `ActivationGate`, of `ExecutionPolicy` werkt.

## Synthetisch voorbeeld

```python
from datetime import datetime, timezone, timedelta
from lightup.synthetic_scope_notice_1495 import ScopeProposal, render_scope_notice
now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
example = ScopeProposal(
    asset="test-desk.example.test",
    capability="inventory_read",
    risk=4,
    valid_from=now-timedelta(hours=1),
    valid_until=now+timedelta(hours=1),
)
notice = render_scope_notice((example,), review_at=now)
assert notice.status == "REVIEW_ONLY"
assert not notice.authorized and not notice.dispatch_allowed
print(notice.text)
```

## Bewijs en gates

`python -m unittest discover -s tests -p 'test_synthetic_scope_notice_1495.py' -v` en projectbrede CI op **dezelfde immutable commit**. Lokale ongeverifieerde of oudere runs tellen niet als hosted resultaat. Geen kunstmatig groen claimen wanneer een andere historische test (#301) faalt of wanneer VPS operatorissue #1144 nog open is.

Voor een echte UI-functie is een **afzonderlijke source owner** vereist die authenticatie, klanten-/operatorscope, echte goedkeuring met ondertekende herkomst, intrekking bij gebruik, tenant-isolatie, security/privacy, het echte gedrag van runtime en een geregistreerde VPS-runner vastlegt. Deze fictieve renderfunctie **mag nooit** als consent-verificatie, issuance of dispatch gate worden aangesloten zonder onafhankelijke review.

**Geen merge, deployment, echte grants, clientsystemen, live scans, handlers of release zonder expliciete menselijke GO.**

## Echte opt-in CLI (uitsluitend fictieve stdin)

Naast de pure Python-functie is nu een **apart uitvoerbare** gebruikerspreview toegevoegd (niet aangesloten op productiemodules of toolhandlers):

```bash
python -m lightup.synthetic_scope_notice_cli_1495 --synthetic-only \
  < examples/fictional_scope_notice_1495.json
```

De CLI eist een exact JSON-object met alleen `review_at` en `proposals`, en per fictieve regel `asset`, `capability`, `risk`, `valid_from`, `valid_until`. Alle tijdstippen zijn strikt `YYYY-MM-DDTHH:MM:SSZ`. Dubbele JSON-sleutels, onverwachte velden, verkeerde types, NaN, Unicodefouten, niet-canonieke UTC, >32 regels of >65.536 stdin-bytes veroorzaken volledige HOLD zonder echo van invoer. Er is geen stilzwijgende coercion, parser fallback of gedeeltelijk geaccepteerde batch.

**Exit 2:** een volledig fictieve, geldige `REVIEW_ONLY` kaart met de zichtbare woorden `NOT AUTHORIZED`. **Exit 3:** `HOLD`. **Exit 0 is nooit beschikbaar**; normale output is dus nadrukkelijk geen autorisatie voor een shellscript, CI of tool. 14 extra echte subprocess-methoden testen de CLI inclusief malformed bytes, duplicate keys, fake high risk en exitgedrag. De CLI leest uitsluitend stdin en schrijft een niet-autorisatiepreview naar stdout; geen DNS, netwerk, klantbestanden, database of subprocess binnen de CLI zelf.


## Nederlandstalige operatorweergave (expliciet, behoud niet-autorisatie)

```bash
python -m lightup.synthetic_scope_notice_cli_1495 --synthetic-only --lang nl \
  < examples/fictional_scope_notice_1495.json
```

Pure Python: `render_scope_notice((example,), review_at=now, language="nl")`. Zonder de expliciete keuze blijft Engels de standaard; met `--lang en` is de Engelstalige uitvoer identiek. Ook in het Nederlands blijven **NOT AUTHORIZED** én **NIET GEAUTORISEERD** letterlijk zichtbaar en zijn alle vier authority-vlaggen onvoorwaardelijk `False`. Bevestiging bij een risico van 4–5 is een waarschuwing, **geen** opname in een werkelijk toestemmingssysteem. Andere locale-tags, verdachte extensies of normalisatie worden altijd `HOLD`, niet teruggevallen op een mogelijk verkeerd geïnterpreteerde taal. Tien afzonderlijke Nederlandse/Engelse gewone directe + echte CLI regressietests in `tests/test_synthetic_scope_notice_locale_1495.py`.


## JSON-formaat voor toekomstige, niet-geautoriseerde dashboards

```bash
python -m lightup.synthetic_scope_notice_cli_1495 --synthetic-only --lang nl --format json \
  < examples/fictional_scope_notice_1495.json
```

Opt-in machineleesbare output bevat exact `status`, `notice`, `reviewed`, `elevated_risk` en **vier letterlijke `false` vlaggen**: `authorized`, `consent_verified`, `dispatch_allowed`, `release_allowed`. De `notice` blijft consequent **NOT AUTHORIZED** melden. Geldige fictieve input blijft exit 2; ongeldige JSON/paar-sleutels, privacygevoelige externe assets en andere fouten geven een generiek niet-echoënd JSON-`HOLD` object met exit 3. **Geen 0-exit, geen executie, geen echte autorisatie**. Andere parameterordes, alias-vlaggen of niet-ondersteunde formaten worden atomisch geweigerd.

Twaalf aparte echte subprocess-regressies in `tests/test_synthetic_scope_notice_json_1495.py` bewijzen determinisme, NL/EN, privacy, dubbele JSON-sleutels, 65.536-byte grens, risicoscores, exact machineveld-schema en altijd blijvende vier valse authority-vlaggen. Dit JSON-formaat is uitsluitend een **preview-gegevensvorm**, geen gecertificeerd toestemmingsbewijs. Het mag pas in een werkelijke operator-UI worden geïntegreerd na onafhankelijke review én uitdrukkelijke menselijke GO.


## Echte offline operator-kaart (HTML zonder externe verbindingen)

```bash
python -m lightup.synthetic_scope_notice_cli_1495 --synthetic-only --lang nl --format html \
  < examples/fictional_scope_notice_1495.json > fictieve-scopekaart.html
```

**Let op:** exitcode 2 betekent een synthetische `REVIEW_ONLY`-kaart, **niet** succes of toestemming. Sommige shells beschouwen dat terecht als een niet-nul exitcode. Bij ongeldige invoer wordt een volledig generieke `HOLD`-HTML-kaart (exitcode 3) weergegeven, zonder ongeverifieerde domeinen/andere input te tonen. Open de opgeslagen kaart lokaal als *niet-vertrouwde* preview; er worden geen echte systemen benaderd.

De zuivere bronfunctie `render_synthetic_scope_html(proposals, review_at=now, language="nl")` levert een toegankelijke, responsive Nederlandstalige reviewkaart met prominent bovenaan **NOT AUTHORIZED — NIET GEAUTORISEERD**, gesorteerde fictieve scope-regels, risicobeoordeling (inclusief verplichte onafhankelijke check bij risico 4–5), UTC tijdvensters en vier expliciet onware authority-vlaggen. Er zijn **geen knoppen om iets uit te voeren**, formulieren, links, scripts, webfonts, afbeeldingen of externe CSS; alle weergegeven waarden worden ge-escaped. Een ingebouwde strikte Content-Security-Policy weigert scripts, connecties, afbeeldingen, formulieren en basis-URL's. Dit is géén productiescherm, geverifieerde toestemming of live scaninterface.

Nieuwe strikt offline source- en echte CLI-testklasse `tests/test_synthetic_scope_notice_html_1495.py` dekt onder meer tweetalige output, mobiel-uitklapbare tabel, 32/33-recordgrenzen, invalide/verdubbelde input (atomische HOLD zonder echo), uitsluitend lokale HTML-inhoud, output zonder externe actieve elementen, nonzero exitcodes, determinisme, print-styles en geen file/DNS/socket/SQLite/process in de renderfunctie.

Dezelfde eigenaar-/releasescheiding geldt: **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**, geen merge, deploy, actieve tooling of clientsystemen zonder onafhankelijke security/privacy/eigenaarreview, werkelijk geauthenticeerde toestemming, intrekking op gebruik en menselijke GO.

## Een direct bruikbaar operatoroverzicht (nog steeds geen toestemming)

De offline HTML-kaart toont nu ook drie **afgeleide fictieve cijfers**: aantal verschillende assets, aantal handelingen met risicoscore 4–5 en de vroegste UTC-vervaldatum. Dit helpt een operator om risico en urgentie op een leesbaar scherm te beoordelen zonder met ruwe JSON te hoeven werken. Meerdere capabilities op één voorbeeldasset tellen als één asset maar als afzonderlijke voorgestelde handelingen. Alle tellingen worden pas getoond na dezelfde strikte atomische scopevalidatie; ongeldig bewijs laat **geen** gedetailleerde cijfers, assetnamen of regels zien.

Daaronder staat een zichtbare **altijd-open checklist met vier 'PENDING'-voorwaarden**: (1) onafhankelijke cliënt- én operatoridentiteit, (2) bronhoudervalidatie van exacte scope, tijdvenster en referentie, (3) duurzame intrekking gecontroleerd bij werkelijk gebruik en (4) onafhankelijke security-/privacyreview en expliciete menselijke GO. De kaart kent geen mogelijkheid om deze vinkjes te zetten en geen werkelijke autorisatiestatus; het is een niet-uitvoerende werkvoorbereiding, geen gate voor productie.

De twaalf nieuwe echte brongerichte en subprocess-testmethoden in `tests/test_synthetic_scope_notice_release_gates_1495.py` toetsen NL/EN, aggregatie bij gedeelde assets, correcte risicogroepen, vroegste UTC-verval, 32 voorbeelden, stabiele sortering, afwijzing zonder echo, onveranderlijk PENDING en afwezigheid van uitvoerelementen. Eerst exact-head CI controleren voordat deze tests als geslaagd worden geclaimd.


## Extra veiligheid: geen wijziging van invoer ná de controle

Hoewel `ScopeProposal` een immutable/frozen dataclass is, kan een onbetrouwbare Python-caller via `object.__setattr__` toch de oorspronkelijke velden wijzigen terwijl een kaart opgebouwd wordt. De HTML-module maakt daarom **vóór de vorm-/scopevalidatie één eigen exacte snapshot** van maximaal 32 geldige bronobjecten. Uitsluitend die snapshot wordt beoordeeld én gerenderd; nooit later opnieuw de originele caller-invoer. Ontbrekende slots, onjuiste container/klassen of corruptie leveren volledige HOLD op zonder klantgegevens te echoën.

Tien nieuwe originele tests in `tests/test_synthetic_scope_notice_snapshot_1495.py` muteren daadwerkelijk de originele asset, risicoscore en vervaldatum **tijdens** de validatiefunctie; de kaart blijft uitsluitend de gevalideerde fictieve snapshot tonen. Daarnaast worden ontbrekende dataclassvelden, kwaadaardige objecten die velduitlezing afstraffen, veranderlijke containers, batchprivacy, deterministische volgorde en locale-isolatie gecontroleerd. De tests doen geen echte scans, filewrites, externe calls of grant-mutaties. Deze snapshot-bescherming is uitsluitend tegen onbetrouwbare **previewdata** en claimt geen authentieke toestemming of productionele time-of-check/use-afdekking.


## Machineleesbaar contract en veilig verwerken van niet-vertrouwde JSON (W10)

De fictieve `--format json` uitvoer heeft nu een gedocumenteerd **JSON Schema Draft 2020-12** in `schemas/fictional_scope_notice_1495.schema.json`. Het schema vereist precies acht velden, alleen `HOLD` of `REVIEW_ONLY`, begrensde aantallen en de vier niet-onderhandelbare letterlijke `false` flags voor autorisatie, toestemming, uitvoering en release. `additionalProperties=false` voorkomt stilzwijgende extra claims; `HOLD` vereist nul geaccepteerde regels en geen verhoogd risico. Let op: **schema-validatie is nadrukkelijk geen toestemming**.

Nieuw is ook `decode_fictional_notice_for_display(raw: bytes)` uit `src/lightup/synthetic_scope_notice_consumer_1495.py`. Een toekomstige dashboardcomponent kan ruwe CLI-JSON (maximaal 65.536 bytes) lokaal en zonder netwerk verwerken tot een frozen `FictionalNoticeView` voor uitsluitend weergave, of `None` bij twijfel. Invoer met dubbele JSON-sleutels, extra/missende velden, niet-exacte types (inclusief booleans als integers), surrogaten, control characters, bidi-overschrijvingen, foutieve status/aantallen, op goedkeuring lijkende claims of elke authority-flag anders dan `false` wordt volledig geweigerd. `HOLD` accepteert uitsluitend twee exacte ingebouwde generieke afwijzingsteksten, nooit klantgegevens. Geldige `REVIEW_ONLY` tekst vereist een expliciete fictieve Engelstalige of Nederlandstalige no-authority header, passend voorstel-aantal en de betreffende waarschuwingen dat dit geen grant/consent is.

De consumer controleert *uitsluitend de vorm voor een scherm*: een kwaadwillende met zelfgemaakte inhoud kan nooit via dit hulpmiddel echte operator- of klanttoestemming bewijzen. Koppel dit niet aan grants, executors, scanning of deployment. Er is geen handtekening of vertrouwde bronherkomst. De 26 aparte directe en echte CLI-testmethoden in `tests/test_synthetic_scope_notice_consumer_1495.py` toetsen een volledige tweerichtingsroundtrip en falende/quarantainegevallen. De aparte hosted-only testworkflow controleert ook deze nieuwe tests los van de historische #301 bronfout; de originele volledige productie-CI en VPS blijven afzonderlijke releasevoorwaarden.
