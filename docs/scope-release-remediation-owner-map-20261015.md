# LightUp scope — overdrachtskaart voor echte vrijgaveblokkades (offline)

**Stand:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. De onderstaande
rollen, oorzaken en bewijsstukken zijn vaste **planningsrichtlijnen**,
geen actuele verklaring dat een issue is opgelost of dat klanttoestemming
bestaat. Dit document en bijbehorende scripts verlenen nooit bevoegdheid.

## Wat kan deze eigen scope-worker veilig doen?

Zelfstandig uitvoerbaar **binnen eigen, niet-geïnstalleerde branch**:
fictieve checklistbestanden strikter valideren, geblokkeerde voorwaarden
uitleggen, verschillen tussen zelfrapportages vergelijken, Nederlandse
reviewteksten leveren en tests in GitHub-hosted CI uitvoeren.

**Niet vanuit deze branch op te heffen:** echte toestemming van een klant,
enige actuele uitvoergrant, het intrekken van rechten in de geïnstalleerde
runtime, aparte risico-5-goedkeuring, SQLite-bewijs vóór een handler,
effectieve productie-ingress/egress, aantoonbaar gerunde VPS-beveiligings-CI,
onafhankelijke security-/privacyreview en menselijke release. Daarvoor
zijn een oorspronkelijke code-/infra-eigenaar of een onafhankelijke mens,
een echte uitvoeringstest en aantoonbare beslissingen nodig.

## Per vrijgavevoorwaarde

| Vereiste | Bevoegde route en technisch werk | Onafhankelijk bewijs voor opheffen |
|---|---|---|
| Klanttoestemming | Klant / schriftelijk gemachtigde opdrachtgever; vastgelegde specifieke toestemming verkrijgen | Gedateerde, onafhankelijk geverifieerde toestemming per klant, doel, capability en tijdvenster |
| Scope en toegestane handelingen | Klant + onafhankelijke scopebeoordelaar; asset-/capability-/risicogrenzen ondertekenen | Exacte, vastgelegde scope en geldigheidsperiode |
| Actuele grant en intrekking | Bronhouder [#107](https://github.com/Zennay/Lightup/pull/107); grant en revocation op uitvoermoment afdwingen | Geïnstalleerde fail-closed bron-/race-tests met tenant, asset en actuele intrekking |
| Risico-5 operatorautorisatie | Bronhouder [#1172](https://github.com/Zennay/Lightup/pull/1172) / [#1173](https://github.com/Zennay/Lightup/issues/1173) en aparte operator; step-up vóór uitvoering | Onafhankelijke operatoridentiteit, actuele approval en intrekkingstests |
| Bewijs vóór handler | Bronhouder [#1454](https://github.com/Zennay/Lightup/issues/1454) / [#1455](https://github.com/Zennay/Lightup/pull/1455); durable transactiereservering vóór handler | Test: geen handler na mislukte bewijscommit of rollback |
| Echte netwerkgrenzen | Deploy-ops; geïnstalleerde ingress/egress, echte loopback/private range afschermen | Tests vanaf werkelijk geïnstalleerde Nginx-/app-/netwerkconfiguratie |
| Permanente VPS CI | Runnerbeheer [#1144](https://github.com/Zennay/Lightup/issues/1144); runner toewijzen en volledige matrix draaien | Originele **voltooide** jobs van de geregistreerde permanente VPS runner, exacte SHA |
| Onafhankelijke security/privacy | Onafhankelijk reviewerteam; hele keten en gegevensbescherming beoordelen | Vastgelegde bevindingen, herstel en afsluitende onafhankelijke beoordeling |
| Menselijke release | Bevoegde releaseverantwoordelijke; pas na alle bewijzen afzonderlijk besluiten | Gedateerde menselijke GO op aantoonbaar volledige scope en controles |

De aparte [#301-testfixture](https://github.com/Zennay/Lightup/issues/301)
is een **CI-blokkade**, geen alternatief voor runtime-veiligheid. Eigenaar
[PR #1452](https://github.com/Zennay/Lightup/pull/1452) kan de verlopen
testtijd in zijn branch repareren; wijzig dat bestand hier niet. Zelfs na
een groene hosted suite blijven echte runtime-, ingress-, klant-, VPS-,
privacy- en menselijke gates vereist.

## Welke code ondersteunt deze uitleg?

`scripts/scope_release_remediation_catalog_20261015.py` is de enkele,
vaste negen-gate rol-/evidencebron. De twee opt-in Nederlandse rapporten
gebruiken diezelfde bron:

    python scripts/scope_release_dependency_nl_20261015.py < docs/fixtures/scope-release-fictional-packet-20261015.json
    python scripts/scope_release_gate_transition_nl_20261015.py < docs/fixtures/scope-release-fictional-transition-20261015.json

Alle uitvoer behoudt letterlijk **Vrijgave: NEE**, de CLI's eindigen met
status **2**, en de onderliggende machine-rapporten geven voor scan,
grant, dispatch, merge, deploy en release altijd `false`. Bij ongeldige
input blijven negen vaste onafhankelijke bewijsvereisten zichtbaar,
zonder de verdachte broninvoer (inclusief geheime opmerkingen) te echoën.
Een `SELF_REPORTED`-veld is slechts een claim, nooit een bewijs of
intrekking van een echte grant.

Run van de nieuwe cross-report contracttests:

    python -m unittest discover -s tests -p 'test_scope_release_remediation_catalog_20261015.py' -v

**Geen deployment of merge.** Deze branch heeft geen echte autorisatie,
klantgegevens, externe scan of bevoegdheden.
