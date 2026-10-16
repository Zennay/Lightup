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

## Volledig offline JSON → veilige HTML-weergave (W11)

De strikt begrensde JSON-consumer wordt nu ook daadwerkelijk gebruikt door een extra zuivere, **niet-aangesloten** schermbrug `render_fictional_envelope_html(raw: bytes)` in `src/lightup/synthetic_scope_notice_display_1495.py`. Daarmee kan de CLI-`--format json` tekst rechtstreeks omgezet worden in een zelfstandige, mobiel leesbare HTML-view. De bridge leest geen bestanden, verricht geen web/DNS/SQLite/process-I/O, bouwt geen gebruikerstoestemming op en kan geen tool of scan starten.

- Eerst wordt exact de eerder geteste `decode_fictional_notice_for_display` uitgevoerd. Ongeldige of verdachte JSON (inclusief vervalste `authorized:true`) resulteert in **alleen** een volledig generieke HOLD-pagina zonder teruggegeven klantinput.
- Bij een geldig, louter fictief `REVIEW_ONLY`-voorbeeld worden NL/EN en het aantal voorgestelde regels getoond onder een prominente **NOT AUTHORIZED**-kop. De tekst wordt volledig als tekst ge-escaped: HTML/JavaScript/URL's kunnen nooit actieve knoppen, scripts of links worden.
- De kaart erft uitsluitend de bestaande vaste lokale CSS en Content-Security-Policy; er is geen live data, geen werkelijk grant, geen operator-approval en geen apart runtime-pad. Alle vier authority-vlaggen staan in iedere weergave letterlijk op `false`. De input-JSON heeft geen digitale handtekening; ook een geldige preview bewijst dus **niet** wie hem heeft aangemaakt of dat iemand toestemming gaf.

Vijftien echte end-to-end en adversarial tests in `tests/test_synthetic_scope_notice_display_1495.py` gebruiken werkelijke CLI-subprocessoutput en controleren daarnaast HTML-injectie, links, dubbele keys, controltekens, privacy, invalid data, NL/EN en steeds behoud van volledige uitvoeringweigering. De aparte minimale GitHub-hosted workflow omvat ook deze testmodule maar vervangt de volledige bronvalidatie en geregistreerde VPS beslist niet.

## W12–W13 · volledige synthetische uitvoercoherentie en onvervulbare vrijgavevoorwaarden

**Gevonden grens:** De oorspronkelijke preview-consumer controleerde de waarschuwende beginzinnen en letterlijke `false`-flags, maar liet afzonderlijk bijgeplakte fictieve klantdomeinen, risicoscores, tijden of extra tekst nog als gewone reviewtekst zien. Dat gaf **geen** werkelijke autorisatie, maar kon een operator wel misleiden.

**Concrete fix:** De decoder valideert nu *de volledige inhoud* van een `REVIEW_ONLY`-bericht. Hij parseert uitsluitend exact de afgesproken `- asset | capability | risk/5 | start UTC | end UTC`-rijen, met het reviewmoment in zuivere UTC. Vervolgens reconstrueert hij de fictieve voorstellen met de bestaande pure `render_scope_notice`-validator en eist hij dat **elk teken van het oorspronkelijke bericht** overeenkomt met de opnieuw gegenereerde tekst, inclusief Nederlands/Engels, waarschuwingen, totale aantallen, sortering, fictieve domeinachtervoegsels, risico-escalatie en geldigheid. Afwijkingen leveren generieke `HOLD` op, zonder echo van klantinput. Dit is **geen** digitale handtekening of authenticatie; een aanvaller kan een consistent fictief `.example.test`-voorbeeld maken, maar alle vier uitvoering-/consentvlaggen blijven onvoorwaardelijk onwaar.

Nieuwe originele 25 pure-/CLI-regressiemethoden in `tests/test_synthetic_scope_notice_coherence_1495.py` controleren uitgeprobeerde vervalsingen zoals echte klantdomeinen, URL-as-asset, punycode, extra rijen, dubbele scope, gewijzigde risicoscores en tijdvensters, niet-UTC of >90 dagen, vervallen scope, herschikte regels en valse toestemmingsclaims. Twee bestaande viewer-tests toetsen nu expliciet de strengere `HOLD` bij aangeplakte HTML/JavaScript in plaats van slechts escaped weergave. Eerste exacte-head gehoste run op `f3d29564c5917d585749f1250df3934e858d9aeb` [#38931597508](https://github.com/Zennay/Lightup/actions/runs/38931597508) is **COMPLETED SUCCESS**, originele Python3.11 en Python3.14 `169 tests / OK` per versie. Dit is alleen de eigen hosted-only CI.

**UI-vervolg:** Ook de HTML-uitvoer van de aparte JSON-viewer toont nu standaard **vier zichtbare `PENDING`-punten** bij een exact geverifieerd `REVIEW_ONLY`: afzonderlijke verificatie van klant/operator, exacte scope en tijdvenster door eigenaar, duurzame intrekking bij gebruik en onafhankelijke security-/privacyreview plus expliciete menselijke GO. Dit is uitsluitend vaste informatie, nooit een checkbox, bevestigingsknop, status uit onbetrouwbare JSON of vrijgaveactie. Ongeldige of HOLD-input toont geen fictieve scope- of checklistdetails. Twaalf nieuwe echte CLI-/viewer-regressiemethoden staan in `tests/test_synthetic_scope_notice_display_gates_1495.py`; ook hiervan geldt dat pas na een originele exacte-head CI-run resultaat als groen mag worden beschreven.

**Status blijft DRAFT/HOLD:** Geen eigendomsovername van #301 (PR #1452), #1144, andere parallelle scope-workers, echte authorization-grants, toolhandlers, echte klanten of VPS. Géén merge, deployment of actieve scan.

## W14: Eigen JSON → HTML commandline-export, uitsluitend fictief en offline

De nieuwste offline UI-keten is nu zonder importscripts aan te roepen. Dit is een **extra, aparte** read-only opdracht naast de bestaande synthetische voorstelgenerator. De eerste opdracht maakt een verifieerbare fictieve JSON-preview, de tweede verwerkt uitsluitend zulke JSON tot een zelfstandige HTML-pagina:

```bash
# Iedere opdracht geeft bewust 2 terug bij REVIEW_ONLY, NIET exitcode 0.
PYTHONPATH=src python -m lightup.synthetic_scope_notice_cli_1495 \
  --synthetic-only --lang nl --format json \
  < examples/fictional_scope_notice_1495.json > fictional-notice.json

PYTHONPATH=src python -m lightup.synthetic_scope_notice_display_cli_1495 \
  --synthetic-json-to-html \
  < fictional-notice.json > fictional-notice.html
```

De nieuwe `synthetic_scope_notice_display_cli_1495` accepteert **uitsluitend** de exacte `--synthetic-json-to-html`-vlag en leest hoogstens 65.537 bytes van standaardinvoer. De decoder weigert meer dan 65.536 bytes; ongeldige JSON of extra CLI-vlaggen geven een vaste, generieke **HOLD-HTML-pagina met exitcode 3**, zonder brongegevens, targets, wachtwoorden of CLI-vlaggen te echoën. Alleen canonieke `REVIEW_ONLY`-JSON geeft een fictieve HTML-pagina met **exitcode 2**. **Exitcode 0, daadwerkelijke toestemming of een uitvoeractie zijn onmogelijk.** De HTML bevat een vaste no-authority-waarschuwing en vier altijd nog open `PENDING`-voorwaarden. Er zijn geen scripts, webcalls, formulieren of uitvoerknoppen. Let op: bij `set -e` of `pipefail` moet de operator zelf rekening houden met de expliciet niet-nul exitcodes.

Dit is werkvoorbereiding; gebruik nooit echte klanten/targetdomeinen en beschouw syntactisch geldige JSON **niet** als een geauthenticeerde handtekening of controle op bestaande grants. Zeventien echte Python-subprocess-methoden in `tests/test_synthetic_scope_notice_display_cli_1495.py` testen beide uitvoerende programma's achter elkaar, EN/NL, corruptie/te grote payloads, vervalste `authorized`-velden, opgenomen klantgegevens, extra vlaggen, dubbel JSON en geen valse exit0. Zoals steeds moet exacte-head CI eerst worden gecontroleerd voor een PASS-claim.

## W15: Veilige offline vergelijking van twee fictieve scopes

Er is nu een echte, onafhankelijke read-only before/after vergelijking. De functie `compare_fictional_scope_envelopes(raw: bytes)` accepteert alleen één JSON-object met precies de sleutels `before` en `after`. Elk veld moet een zelfstandig, volledig geldig fictief REVIEW_ONLY-JSON-document van de eerdere scopegenerator bevatten. Limiet: 131.072 bytes voor het paar en maximaal 32 scopes per kant.

De bestaande strenge consumer reconstrueert eerst volledig en onafhankelijk het oorspronkelijke rapport voor *beide* documenten. Eén ongeldig document (HOLD, echte domeinen, onbekende of dubbele sleutel, vervalste autorisatievlag, verkeerde risicoscore, tijdvenster, extra goedkeuringstekst) veroorzaakt atomische HOLD, zonder data van het andere document te tonen. Alleen volledig valide fictieve voorstellen worden in een inert HTML-overzicht vergeleken; dat toont identieke paren, voorgestelde wijzigingen, alleen in after (NIET VERLEEND), en alleen in before (NIET INGETROKKEN). Verwijderen uit deze preview is géén revocation van echte grants. De vier releasevoorwaarden blijven expliciet PENDING.

De opzettelijk beperkte commandline-interface is: `PYTHONPATH=src python -m lightup.synthetic_scope_notice_compare_cli_1495 --synthetic-pair-to-html < pair.json > comparison.html`. De invoer mag alleen lokaal via stdin worden verstrekt, niet als url, pad naar een target, runtimegrant of scanactie. Een geldige synthetische REVIEW_ONLY geeft exitcode 2; ongeldige invoer genereert een vaste privacyveilige HOLD-pagina en exitcode 3; nooit exitcode 0. Op zichzelf kan deze vergelijking niets authenticeren, toestemming verlenen of intrekken.

Maak een invoerbestand pair.json met vóór- en ná-gegevens die door de bestaande fictieve JSON-scopegenerator zijn geproduceerd:

```bash
PYTHONPATH=src python -m lightup.synthetic_scope_notice_cli_1495 --synthetic-only --format json < examples/fictional_scope_compare_before_1495.json > before.json
PYTHONPATH=src python -m lightup.synthetic_scope_notice_cli_1495 --synthetic-only --format json < examples/fictional_scope_compare_after_1495.json > after.json
python -c 'import json; print(json.dumps({"before":json.load(open("before.json")), "after":json.load(open("after.json"))}))' > pair.json
PYTHONPATH=src python -m lightup.synthetic_scope_notice_compare_cli_1495 --synthetic-pair-to-html < pair.json > comparison.html
```

Deze opdrachten geven bij een synthetisch geldig voorbeeld bewust niet-nul exitcode 2 terug; bij shells met `set -e` is een expliciete afhandeling nodig. Beide JSON-invoerbestanden zijn nu daadwerkelijk in `examples/` aanwezig. Ze tonen exact één gewijzigd fictief risicovenster en één toegevoegde fictieve handeling; een originele CLI→CLI→HTML-proef test beide gecommitte bestanden automatisch. De uitvoer krijgt twee voorgestelde veranderingen maar blijft nadrukkelijk **NOT AUTHORIZED**.

De 26 Python-origineelbron- en 14 echte end-to-endcommandlinetests in `tests/test_synthetic_scope_notice_compare_1495.py` en `tests/test_synthetic_scope_notice_compare_cli_1495.py` toetsen risicowijzigingen, tijdvensters, toegevoegd/verwijderd, internationaal bronmateriaal, strict fail-closed, geen actieve UI en niet-nul status. Exact-head-gehoste CI-bewijs op commit `4544a2cd8dac4b1a4b57a7dfc3cc1958aa849c27`: eigen workflow #38933371968; oorspronkelijke Python 3.11 job `117082656826`, Python 3.14 job `117082657275`; elk **238 tests OK**. Dit is geen volledige LightUp-CI, geen VPS-validatie en geen toestemming. DRAFT/HOLD.
