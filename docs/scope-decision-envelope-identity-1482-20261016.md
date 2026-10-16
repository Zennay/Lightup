# #1482 — ActivationGate decision-envelope trust boundary (offline, draft)

LightUp is **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This artifact is an independently owned, additive source-acceptance experiment, not a live security finding or authorization to scan.

## Exact tested boundary

Original `src/lightup/activation.py` on pinned main (`e73b7445c87ad239bdb03c50a99078ef93163b02`) accepts a `scope_policy` duck-type at construction, and reads `decision.allowed`, `decision.reason.value`, and `decision.normalized_host` from its result. Python annotations on `ScopePolicy` and `ScopeDecision` do not enforce canonical identity or boolean type at runtime. Synthetic in-process tests demonstrate three currently unresolved expected-source-RED acceptance contracts:

1. Constructing a LAB gate with a forged `.decide()` provider must be rejected as a noncanonical policy; currently the constructor accepts it. This is only a programmer-controlled constructed boundary, **not** evidence the real app accepts untrusted policy objects.
2. A synthetic source `ScopePolicy.decide` response with `allowed="yes"` must not satisfy LAB execution admission (it currently evaluates as truthy).
3. A synthetic source response with a `normalized_host` different from the original target must not cause a permit to be stamped for that different host. This test does **not** claim a normal exact `ScopePolicy` produces this result.

Control tests verify legitimate in-memory loopback LAB use, public-name LAB denial, and default PLAN_ONLY denial. No sockets, DNS, target connection, subprocess, handlers, real consent, grants, DB, tests against public internet, or deployment.

## Independent, **not wired** helper

`src/lightup/activation_decision_shape_review_1482.py` exports `review_decision_shape(policy, target, decision)` for *only offline review of supplied objects*. It rejects noncanonical container identities, nonboolean allow flags, wrong enum identities, mismatched normalized host, inconsistent reason/allowed pairs, forged public loopback classification, and overly long target inputs. It **never calls policy.decide**. Its `DecisionShapeReview` result is a `NamedTuple` containing only `status=HOLD` or `status=REVIEW_ONLY`; both its execution/release flags are always false. It does **not** attest the policy's provenance, origin of the decision, customer authorization, tenant, operator approval, revocation, execution safety, CI trust or human GO. It is deliberately not registered with `ActivationGate` or any production caller. In particular, even `REVIEW_ONLY` is **never an execution permit**.

## Reproduction

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_decision_shape_activation_1482_20261016.py' -v
```

Expected partition: **15 ordinary PASS and exactly 3 original-source `expected failure`**, barring additional regressions. Expected failures intentionally remain open: a `unittest.expectedFailure` is not a production repair or green security attestation. Review any unexpected success carefully against exact original SHA before promoting it.

## Ownership / independent prerequisites

This branch adds only three namespaced files (one unused helper, one tests module, one documentation path). Do **not** alter original `src/lightup/activation.py`, `scope.py`, `models.py`, existing test paths or workers #120/#125/#726/#1476/#1480, workflows/runners or production adapters. Source owners must decide immutable trusted policy construction, verifying `ScopeDecision` provenance and target binding, type enforcement, actual caller reachability and revocation. Any future integration must independently test tenant/scope/asset/risk/capability/consent/permit expiry and durable evidence before handler invocation.

**NO MERGE, DEPLOY, REAL GRANTS, ACTIVE TARGETS, SCANS, OR HANDLERS; release requires independent source-owner, client/operator consent, security/privacy, exact-head hosted and permanent VPS CI, and human GO.**

## W2 — verifieerbare exacte offline bronacceptatie

Nieuw opt-in bestand: `scripts/check_scope_1482_source_acceptance_20261016.py`. Het controleert **eerst** de echte Git blob-hashes van de drie onveranderde oorspronkelijke modules (`activation.py`, `scope.py`, `models.py`) en de twee eigen oorspronkelijke reviewer/testmodules. Ontbrekend pad, symlink, oversized data of gewijzigde bytes → `HOLD: source_integrity`, zonder testdiscovery of uitvoering. Daarna eist het precies alle 18 bekende unieke unittest-ID's, precies 3 bekende assertie-gebaseerde originele bron-`expectedFailure` en exact 15 normale successen; fout, skip of onverwacht groen → HOLD. De uitvoer geeft uitsluitend `REVIEW_ONLY` bij die specifieke test-partitie, **nooit toestemming**.

Twee eigen nieuwe bestanden: de strikte CLI en `tests/test_scope_decision_source_verifier_1482_20261016.py` met **9 aparte integriteits-/CLI-tests** (echte gecontroleerde 18-methoden-run, positieve Git blob, verkeerde digest, ontbrekend pad, manifestbescherming en no-discovery-on-drift). Het bron-acceptatiebewijs is **alleen geldig voor exact de vijf gepinde blob-versies**. De git-pinning bewijst niet dat de oorspronkelijke bron veilig is, beschermt niet tegen een kwaadwillende repository-schijver of tegen een gewijzigd script en is geen ondertekend artifact. Een toekomstige bronreparatie vergt onafhankelijke code review en bijgestelde testverwachtingen.

```bash
PYTHONPATH=src python3 scripts/check_scope_1482_source_acceptance_20261016.py
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_decision_source_verifier_1482_20261016.py' -v
```

Op deze eigen branch zijn nu **27 tests**: 24 gewone controles en 3 bewust onverholpen originele bron-REDs. Alleen de allereerste 18 werden op de vorige exacte commit gehost geverifieerd; **voor het nieuwe script en de negen extra tests is een nieuw exacte-HEAD CI-resultaat vereist.** Volledige algemene testpipeline kan nog steeds onafhankelijk falen door de oude #301 datumfixture bij andere eigenaar #1452. Permanente VPS CI kan bovendien nog wachten op de operator #1144. Geen merge/deploy/activering.

## W3 — geïsoleerde originele bronvergelijking en direct synthetisch permitbewijs

Nieuw en geheel afzonderlijk 5-test bestand `tests/test_scope_decision_legacy_constructor_witness_1482_20261016.py` gebruikt exact de echte `ActivationGate` op de huidige bron. In uitsluitend in-process fictieve `public.example.test`-data laat één **bewust source-pinned ordinary canary** zien dat een zelfgebouwde beleidsprovider een **LAB_ONLY ExecutionPermit-record** kan laten stempelen, zonder ooit een handler/netwerk/scan/echte grant te bereiken. Dezelfde fictieve publieke target wordt door de werkelijke `ScopePolicy` afgewezen; PLAN_ONLY wordt zelfs bij de gesimuleerde provider nog afgewezen. De niet-aangesloten reviewer weigert deze custom policy met `HOLD` en roept deze niet opnieuw aan. `socket.socket` en `socket.getaddrinfo` zijn in alle vijf methoden expliciet geblokkeerd. Een permit-record uit deze kunstmatige programmer-constructie is **geen bewijs van onbetrouwbare echte app-input of mogelijke externe exploit**.

Na echte source-ownerreparatie moet de positieve legacy-canary bewust worden vervangen; het is geen vereiste om een onveilig gedrag in toekomstige code te behouden. Deze vijf tests zijn *naast*, niet in, de strikte onveranderlijke 18-methoden bronacceptatie opgenomen. Nieuwe **totale eigen testtelling = 32 (29 gewone incl. vijf extra + drie bedoelde expected-RED)**. **Nieuwere exact-head hosted en canonieke VPS CI worden opnieuw afzonderlijk beoordeeld; eerdere CI is niet overdraagbaar.** Niets uit deze code registreert een werkelijke permit-uitvoering of verleent bevoegdheid.

## W4 — afgebakende, atomaire offline besluitcohortcontrole

Nieuwe **niet-aangesloten** bronmodule `src/lightup/activation_decision_cohort_review_1482.py` en 17 geïsoleerde tests in `tests/test_scope_decision_cohort_review_1482_20261016.py`. `review_decision_cohort(rows)` accepteert alleen een **exacte tuple van 1–64 exacte 3-tuples** `(ScopePolicy, Target, ScopeDecision)`. Geen iterators/generators, geen subklassen/duck types, geen policy-callbacks, geen I/O; per rij wordt de bestaande eigen shape-reviewer hergebruikt. Alle rijen moeten intern reviewbaar en hun genormaliseerde hostnamen uniek zijn, anders geeft de hele batch één generieke `HOLD` met `inspected=0` (geen gedeeltelijke uitkomst of customer identifiers). Bij volledige vorm-coherentie is de enige andere uitkomst `REVIEW_ONLY`; letterlijk **beide autorisatievlaggen altijd false**. Bij een onverwachte helper-exceptie volgt generieke HOLD zonder private argumenten te loggen.

Deze offline vormcontrole **verifieert NIET** dat `ScopePolicy.decide` daadwerkelijk die output gaf, of dat een externe klant, tenant, operator of resource een actuele toestemming heeft gegeven. Zij voorkomt geen spoofing als iemand een geheel nieuw result-object maakt, en is geen vervanging voor scoped runtime re-evaluatie, actuele revocation, evidence, handlerbegrenzing of security/privacyreview. Duplicaatcontrole is conservatief en mag een legitieme herhaling weigeren; de bronhouder moet echte requirements eerst beslissen.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_decision_cohort_review_1482_20261016.py' -v
```

Bewust apart gehouden van originele vijf gepinde bestanden / vaste 18-methoden source-RED checker. Nieuw **49 eigen methoden in totaal: 46 gewone + 3 originele expected RED** op de volledige suite, waarvan 17 NIEUWE methoden na de vorige W3 immutable head. De nieuwste CI voor W4 is *niet* bewezen door W3 en moet op de exacte nieuwe code-SHA onafhankelijk worden beoordeeld. **INCUBATE · DRAFT/HOLD · geen merge/deploy/scan/grants/handlers/echte assets.**

## W5 — beleidmetadata-snapshot en reden-/hosttype-restricties

Het **eigen, nog steeds niet aangesloten** cohort-hulppad weigert nu ook bekende tegenstrijdigheden waar de oorspronkelijke dataclass-annotaties niet tegen beschermen. Per exact `ScopePolicy` leest het de vier oorspronkelijk gedefinieerde velden **één keer** uit een gekopieerde dataclass-`__dict__`. Verwijderde/extra velden, truthy integers in twee boolean-vlaggen, mutable hostsets/netwerklijsten, subclasses en te grote configuraties → `HOLD` zonder gedeeltelijke uitkomst. Grenzering is expliciet reviewbeperking: hoogstens 64 hosts, 64 netwerken, 512 tekens per host of 128 per networkstring; productiebetekenis en legitieme grotere configuraties vereisen eigenaarreview.

Synthetische verkeerde classificaties zoals `PRIVATE_LAB` bij een publiek DNS-hostname of globaal IP, `EXPLICIT_NETWORK` bij een hostname en `EXPLICIT_HOST` bij een IP krijgen nu `reason_host_kind_mismatch`/HOLD. Een niet-globaal IP is **uitdrukkelijk GEEN bewijs van vertrouwde privé-lab-inventaris**; het echte beleid moet #1422/#1424 en exact geauthentiseerde inventaris onafhankelijk behandelen. Nul DNS/sockets/callbacks en altijd twee false uitvoer-/releasevlaggen.

Nieuwe `tests/test_scope_decision_policy_metadata_1482_20261016.py`: **19 normale fictieve tests**, waaronder echte originele `ScopePolicy.decide`-controles, mutable velden, booltypeverwarring, weggehaalde dataclassvelden met class-default fallback, extra attributen en één gedeelde originele snapshot; geen productie-source-owner bestand gewijzigd. **Nieuwe eigen testinventaris: 68 methoden (65 normaal + drie originele expected-RED)**, nog zonder exacte W5 head-hosted/VPS bewijs. 

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_decision_policy_metadata_1482_20261016.py' -v
```

Zelfs een `REVIEW_ONLY`-cohortstatus stelt geen echte beleidsprovenance, grant, cliënt-/operatorconsent, revocation, security review of release vast. **INCUBATE M3/M7 · DRAFT/HOLD · geen merge/deploy/grants/targets/scan/handlers.**

## W6 — deterministische grensmatrix zonder uitvoerrechten

Nieuwe geheel geïsoleerde `tests/test_scope_decision_hostile_matrix_1482_20261016.py`: **7 unittest-methoden**, waaronder uitputtende fictieve host×8 reden×6 allow-typematrix, **2.048 seeded synthetische gemengde records**, 256 gevallen met blokkades voor socket/DNS/process, geen iteratie van kwaadwillende tuple-subclasses, geen `__str__`-callback bij policy-objecten, geen herhaling van klantachtige input in uitkomsten en één 64-rijen-atomaire terugval naar HOLD. Elke gegenereerde uitvoer moet `HOLD` of `REVIEW_ONLY` zijn en beide authority-vlaggen letterlijk false; geen externe input, adapters of netwerkaanroep.

Deze zeven tests stellen **geen echte scanveiligheid, consent of operatorvalidatie** vast. Met eerdere W5 zijn nu **75 eigen unittests** (72 gewoon + drie originele bron-expected REDs). Ze zijn uitsluitend geldig als ze ook op de actuele immutabele CI-HEAD worden uitgevoerd; oudere hosted bewijzen mogen niet worden doorgeschoven.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_decision_hostile_matrix_1482_20261016.py' -v
```

**Blijft INCUBATE M3/M7, DRAFT/HOLD.** Geen edits aan andere workers of originele uitvoering, geen merge/deploy/grants/target/scan.

## W7 — expliciet opt-in originele ScopePolicy differentiële bronproef op fictieve data

Nieuwe afzonderlijke `src/lightup/activation_fictional_source_differential_1482.py` **roept in tegenstelling tot de oorspronkelijke shape-only hulp expliciet één keer** de huidige `ScopePolicy.decide` aan. Dat gebeurt uitsluitend ná een strikte afwijzing van alle niet-fictieve inputs: exacte `ScopePolicy`, `Target` en `ScopeDecision` klassen, ongewijzigde vier beleidmetadatavelden, `allow_private_lab=False`, `require_authorization_for_public=True`, lege expliciete CIDR's, enkel exacte fictieve `*.example.test` hosts of `localhost`/`127.0.0.1`, geen `Authorization`, lege exacte labels en uitsluitend fictieve allowlist entries. Dit zijn **tests van in-process bronbeslissingen zonder I/O**, niet van echte scan- of consentadmission.

De helper vergelijkt het door de echte oorspronkelijke bron gegeven `ScopeDecision` met het aangeboden claim-object en geeft bij verschillen, externe/ongeldige targets, waarden of bronexceptions slechts generieke `HOLD` terug. Een gelijkblijvende oorspronkelijke fictieve beslissing geeft `REVIEW_ONLY` met beide execution-/releasevlaggen **false**, nooit een permit of scan. Het is geen verificatie van een gesigneerde codebron of beschermd tegen gemodificeerde Python-klassen: gebruik alleen in onafhankelijk geverifieerde lokale CI-checkouts. Volledige echte runtime- en scope-/operator-grant-verificatie blijft bij de oorspronkelijke eigenaren.

Nieuwe `tests/test_scope_fictional_source_differential_1482_20261016.py` met **20 offline tests**: echte positieve/negatieve lokale originele beslissingen, geconstrueerde claimvervalsing, verkeerde target, expliciet malformed URL, niet-fictieve grants en metadata, policy bronexception, host admission vóór callback, nul DNS/socket/proces, geen gevoelig detail in HOLD en onwijzigbare false-authority uitkomsten.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_fictional_source_differential_1482_20261016.py' -v
```

Na W6 **75 eigen tests**, plus W7 **20 nieuwe** = **95 tests (92 gewone + drie bekende originele source-RED)**. Alleen exacte huidige HEAD hosted Python 3.11/3.14 en permanente VPS CI kunnen nieuwe conclusies dragen. **Niet geïntegreerd, geen merge/deploy, geen echte klanten/targets/grants/scans.**

## W8 — onafhankelijke, niet-uitvoerende LAB_ONLY binding-referentie

Nieuw volledig eigen `src/lightup/activation_lab_binding_reference_1482.py`: `review_lab_binding(scope_policy, activation_policy, target, claimed_decision)` vergelijkt een **door caller verstrekte** `ScopeDecision` met de *verwachte* LAB_ONLY-betekenis binnen een bewust extreem kleine fictieve sandbox. De functie roept **noch** `ScopePolicy.decide` **noch** `ActivationGate.issue` aan en produceert nooit een `ExecutionPermit`. Zij werkt alleen met exact originele dataclass-vormen met vaste veldkeys en niet-polymorfe primitives. Toegelaten fixtures uitsluitend `localhost`, `127.0.0.1` en streng gevalideerde ASCII-`*.example.test`-domeinen zonder echte toestemming, labels, CIDR's of private-lab-automachtiging. Een exact LAB_ONLY-activatieobject moet een begrensde fictieve auditverwijzing bevatten. Alleen loopback heeft in die onafhankelijke lexical *review reference* het verwacht-allow-veld; fictieve publieke hosts zijn altijd verwacht-deny (expliciet zonder toestemming of buiten scope). Elke afwijking geeft atomaire `HOLD`, geldig ontwerp slechts `REVIEW_ONLY`; **alle retourwaarden `authorizes_execution=false` en `authorizes_release=false`**.

**31 nieuwe regressies** in `tests/test_scope_lab_binding_reference_1482_20261016.py` controleren beide goede loopbacks, expliciet en impliciet afgewezen publieke fictieve hosts, vervalste loopback-host, boolean/int/string-reason-verwarring, hostaliases, ongeldige URL-vormen, echte klantmetadata, labels met kwaadaardige vergelijkingsoperator, verkeerde activatiemodus, malformeerde auditreferenties, ontbrekende of extra frozen-dataclassvelden, dataclass-subklassen, geen `ScopePolicy.decide`, expliciete netwerk-/SQLite-/subprocess-blokkade en onwijzigbare false-authority return. De bronhouder kan referentiegedrag gebruiken voor een echte onafhankelijke constructor/source-fixreview, maar **moet** zelf werkelijke integratie, trust, actuele scope, echte toestemming, revocation, rollen en retries bewijzen.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_lab_binding_reference_1482_20261016.py' -v
```

Na vorige exact gehost geverifieerde **95 tests** zijn er nu **126 eigen methoden op nieuwe SHA** (123 gewone, drie originele bewust open source-REDs), *nog niet bewezen op de nieuwe HEAD*. Geen original source/andere-worker aanpassingen, merge of deployment. **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**

## W9 — een werkelijk uitvoerbare strikte **137-methoden-eigendomssuite** zonder globale CI-GO

Nieuw *opt-in*, niet op production of workflows aangesloten script `scripts/check_scope_1482_all_owned_acceptance_20261016.py` bewaakt **15 vastgepinde originele Git blobs**: originele `activation.py`/`scope.py`/`models.py`, vier eigen pure bronmodules en acht oorspronkelijke eigen acceptatietestbestanden. Alle verwachte **126 exacte unittest-identiteiten** worden gecontroleerd vóór testuitvoering; volledig onverwachte test, duplicaat, ontbrekende module of source-byte drift → `HOLD`. Na uitvoering mogen uitsluitend **123 gewone PASS en de drie exact bekende en bewust niet gerepareerde originele bron-`expectedFailure`** overblijven: geen errors, ordinary failures, skipped, unexpected successes of andersoortige expectedFailure-tracebacks. Zelfs bij volledig correcte uitkomst meldt de standalone CLI uitsluitend **`REVIEW_ONLY`**, geen echte consent, grant of release.

Nieuwe `tests/test_scope_all_owned_acceptance_1482_20261016.py`: **11 aparte gewone integriteits-/subprocess-tests**, waaronder hashconsistentie (Git lege blob), exacte bronpaden, geen testdiscovery bij ontbrekende of veranderde bron, exacte 126 identifiers, niet-autoriserende echte geneste suite-uitvoering, en echte CLI-uitvoering met beknopte output. **Deze elf controles zitten bewust NIET binnen de eigen 126-methoden pinned acceptance**, maar wel binnen GitHub's volledige `unittest discover`, om geen recursieve eigen-CLI-test te creëren. Nieuw totaal op W9: **137 eigen methoden (134 gewone + drie oorspronkelijke source-RED)**; pas na nieuwste exact-head CI kan dit als bewezen worden gerapporteerd.

```bash
PYTHONPATH=src python3 scripts/check_scope_1482_all_owned_acceptance_20261016.py
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_all_owned_acceptance_1482_20261016.py' -v
```

**Beperkingen:** lokaal gepinde Git object bytes zijn *geen* handtekening, codeprovenance of review van geïnstalleerde ingress en runner; script zelf en GitHub-run moeten onafhankelijk vertrouwd en gecontroleerd worden. De standalone CLI is geen CI-releasebewijs, geen bewijs van gerepareerde originele Gate, en houdt source-fixes expliciet tegen totdat oorspronkelijke eigenaren de pin/RED verwachtingen bewust aanpassen na echte reparatie. De bekende aparte `#301` datumfixture en permanente VPS-CI worden **niet** gemaskeerd of als groen opgegeven. Geen productie-/runner-/workflow-/andere-worker edits, merge, deploy, grants of echte scans. **DRAFT/HOLD.**

## W10 — vermijden van bronpad-omleiding tijdens offline acceptatie

De eigen W9-bronchecker had een aantoonbare **review-integriteitslacune**: vóór deze wijziging werden alleen bladbestanden als symlink geweigerd. Een gepinde source-file binnen een **symlinked ouderdirectory** met identieke byte-inhoud kon nog steeds worden geaccepteerd. Die acceptatie was niet voldoende om de verwachte fysieke checkoutstructuur te herkennen. In `scripts/check_scope_1482_all_owned_acceptance_20261016.py` is de pinning nu aangescherpt: vereist daadwerkelijk directory-rootobject, precies vijftien geplande objecten, 40-karakter SHA, geen absoluut pad/`..`-segment, expliciete `is_symlink()`- en `is_dir()`-controles voor *iedere* onderliggende parentdirectory en expliciete `is_file()`/symlink-controle op de leaf voordat bronbytes worden gelezen. Elke ongeldige relatie → `HOLD: source_bytes` vóór enige unittest-discovery. De bestaande SHA- en bestandsgroottecontroles blijven actief.

Nieuwe volledig eigen `tests/test_scope_pinned_path_provenance_1482_20261016.py` bevat **16 negatieve en positieve filesystem-/resultintegriteitstests**, uitsluitend op wegwerpbestanden in tempdirs: geldige 15-blobjes, symlink leaf, eerste en diepere parent, symlink root, verwijderde of gewijzigde bronbyte, minder dan vijftien manifestpaden, `../`-escape, absoluut escape-pad, malformeerde SHA, te groot bronobject, geen discovery bij ontbrekende bron en vals source-expected-RED of onverwachte successen. Alle echte originele bron- en workflowbestanden blijven ongewijzigd.

**Beperking:** dit is *geen* racevrije, cryptografisch getekende of geïsoleerde checkout-verklaring. Een gelijktijdige malafide file-system-writer, Git replace/graft, Python import-cache of gewijzigde verifier kan buiten deze controle vallen; bronattestatie en runner-eigendom blijven bij de originele eigenaren/#1314/#1144. Deze controle bewijst ook geen echte klanttoestemming, revocation, grant of scanveiligheid. Alleen onbedreigende offline vorm-validatie; geen source-owner fix. Na W9 nu **153 eigen unittest-methoden verwacht** (150 gewone + 3 bewust OPEN originele bron-RED); exacte laatste code-HEAD moet afzonderlijk gehost en door echte permanente VPS getest worden. **INCUBATE M3/M7 · DRAFT/HOLD · geen merge/production/deploy/scans/grants/handlers.**
