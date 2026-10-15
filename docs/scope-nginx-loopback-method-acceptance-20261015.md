# LightUp #1154 — echte Nginx → WSGI-methodegrens, uitsluitend loopback (15 oktober 2026)

**INCUBATE M3/M7 — DRAFT/HOLD. Geen echte autorisatie, scan, deployment, merge of release.**

## Doel en eigenaarsgrens

Open [#1154](https://github.com/Zennay/Lightup/issues/1154) mist bewijs dat een *echte* reverse proxy schadelijke `X-HTTP-Method-Override`, `X-Method-Override`, `X-Original-Method` en `X-HTTP-Method` niet verandert in WSGI-`REQUEST_METHOD`. De aparte bestaande [PR #1153](https://github.com/Zennay/Lightup/pull/1153) test alleen de app-in-process; [PR #1155](https://github.com/Zennay/Lightup/pull/1155) bezit de Nginx-template-headerfilter. **Dit werk verandert geen van die eigen paden**, geen productiebestanden, Nginx/Gunicorn-service of CI-workflow.

Nieuwe toevoegingen:
- `scripts/scope_nginx_loopback_method_acceptance_20261015.py`: opt-in wegwerp-Nginx plus echte WSGI-echo.
- `tests/test_scope_nginx_loopback_method_20261015.py`: configuratiegrenzen, HOLD zonder Nginx, beide methode-richtingen, doelbewuste upstream `proxy_method GET`-mutant.
- Dit document.

## Wat wordt echt gemeten?

Na installatie van het **nginx-programma op de testomgeving**, zonder de service te starten/herstarten, maakt de helper tijdelijk een eigen config uit de ingelezen repo-template. Alleen de `443 ssl`-listener wordt vervangen door een vrije `127.0.0.1`-poort; de exacte `http://127.0.0.1:8766`-upstream wordt een tweede tijdelijke loopback-poort. Certificate-regels worden alleen uit de tijdelijke kopie verwijderd. Het originele bestand blijft identiek. De upstream is een lokale WSGI-echo uit de Python-standaardbibliotheek. Alle clientverzoeken gaan naar `127.0.0.1`.

De echte proxy moet bij een GET met spoofing naar DELETE nog steeds `REQUEST_METHOD=GET` tonen; een POST met spoofing naar GET moet nog steeds POST zijn. Alle vier methode-override-headers moeten bovendien vóór WSGI verdwijnen. Een bewust geïnjecteerde **alleen-test**-`proxy_method GET` moet juist worden ontdekt, anders blijft alles HOLD. Een echt geïnstalleerde Nginx of upstream-service wordt niet geïnspecteerd of aangeraakt.

## Zelf uitvoeren

```bash
PYTHONPATH=src python -m unittest tests/test_scope_nginx_loopback_method_20261015.py -v
python scripts/scope_nginx_loopback_method_acceptance_20261015.py
```

Dit script heeft alleen Python stdlib en `nginx` in `PATH` nodig. Zonder Nginx is de integratie **SKIP / HOLD — geen bewijs**. Een controle met de ongewijzigde `main`-template die nog geen header-stripping heeft, blijft terecht **HOLD**. De tests creëren daarnaast een kandidaatconfig *alleen in geheugen* met de vier expliciete lege `proxy_set_header`-regels om het positieve scenario én de doelbewuste proxy-rewrite-mutant tegen een echt Nginx-proces te onderscheiden.

Uitvoer is een enkel JSON-object met uitsluitend `HOLD` (exit 2) of `REVIEW_ONLY` (exit 3), en zes letterlijk onware autorisatie-/releasevelden. Er bestaat geen exit 0. Dit bewijs rechtvaardigt **nooit** live acties.

## Acceptatie- en stopcriteria

1. Met nginx aanwezig moeten de twee probe-verzoeken en de negatieve mutant echt draaien; zonder binary telt geen PASS.
2. De bronhouder van #1155 moet de echte uitroltemplate aanpassen én installeren; deze branch wijzigt die niet.
3. Bewijs van de echte geïnstalleerde ingress/proxy+Gunicorn vereist later aparte gecontroleerde labvalidatie; de gegenereerde template-kopie is daarvoor geen substituut.
4. Pas na exact-commit hosted Python 3.11/3.14 en permanente VPS-workflow, onafhankelijke security/privacyreview, klanttoestemming, revocation/destination-binding en menselijke release kan de projectautoriteit opnieuw besluiten.
5. Tot dat moment: **DRAFT/HOLD, geen merge, deploy, scans, echte grants, openbare listeners of externe targets**.

## Grenzen

Lokale TCP-loopback-sockets zijn nodig om de echte Nginx → WSGI-grens te meten. Dit zijn **geen netwerk-scans**; de helper verstuurt uitsluitend twee zelfgemaakte request-berichten naar zijn eigen tijdelijke server. Het is geen bewijs voor werkelijke DNS/TLS, installed ingress configuratie, Nginx-plugins, application sessions, cookies, CSRF of tenant-auditing.

## W2 — transportintegriteit en afzonderlijke headerstrip (15 oktober 2026)

De test is uitgebreid van 10 naar **26 echte requestvarianten per Nginx-proef**: de vier namen elk als GET→DELETE- en POST→GET-poging, hun gecombineerde varianten en per header twee alleen-kleine-/gewisselde hoofdletterwaarden plus dubbele HTTP-headerregels met verschillende casing. De helper gebruikt voor de laatste groep `http.client.putheader` in plaats van een Python-dictionary, omdat een dictionary dubbele keys onzichtbaar zou samenvoegen. De WSGI-echo leest uitsluitend de eigen testbody van 0 of 1 byte en vergelijkt naast de originele methode en het pad ook de POST-body; corrupte requestframing kan dus geen positieve `REVIEW_ONLY` opleveren.

Een extra integratietest start een **echte wegwerp-Nginx** tegen een kandidatenconfig met alle vier lege `proxy_set_header`-waarden, verwijdert vervolgens *één voor één* telkens precies één headerstrip en vereist dat elke corrupte versie door de netwerkproef wordt afgewezen. Dit is geen statische regexclaim. Wanneer `nginx` ontbreekt, wordt de netwerkproef expliciet geskipt en is er **geen Nginx-bewijs**. Alle zes permissievelden blijven letterlijk `false`, ook wanneer de synthetische positieve fixture slaagt.

De echte op de VPS geïnstalleerde proxyconfig is nog niet op deze manier geaudit; geen productierelease. Deze uitbreiding is volledig in de drie reeds eigen nieuwe bestanden gebleven. Vorige CI-resultaten op oudere SHA's blijven uitdrukkelijk ongeldig als bewijs voor de nieuwe code.

## W3 — valideer de echte kandidaatconfig van de ingress-eigenaar, zonder die te wijzigen

De offline CLI ondersteunt nu één expliciete, optionele read-only invoer: `python scripts/scope_nginx_loopback_method_acceptance_20261015.py --candidate-file /pad/naar/lokale/nginx.conf`. De standaardmodus blijft de **ongewijzigde** bronconfig lezen en blijft HOLD zolang de vier strips nog ontbreken. De kandidaatmodus leest maximaal 65.536 bytes uit een regulier lokaal bestand, zonder symlink of fifo/socket/directory, met controle van apparaat/inode/grootte/timestamps vóór en na het lezen. Onbekende parameters, foutieve invoer, ongeldige UTF-8 en inputveranderingen geven één generieke HOLD zonder pad of gegevens te echoën. Dit is *geen* security sandbox of klanttoestemming.

Vervolgens draaien exact dezelfde werkelijke loopback Nginx→WSGI-proeven en de verplichte opzettelijk-foute proxy-mutant; het originele bestand en geïnstalleerde services worden nooit geschreven of ge(re)start. Nieuwe echte subprocess/CLI-tests verifiëren dat een volledig veilige **synthetische** kandidaat uitsluitend een onbetrouwbare `REVIEW_ONLY` oplevert (exit 3, zes letterlijke `false` autorisatiestatussen), en de variant met één ontbrekend filter `HOLD` (exit 2). Daarnaast weigeren lokale symlinks, ongeldige argumenten, FIFOs, directories en oversized input zonder klantnamen, paden of bestandsinhoud in het receipt.

Dit maakt het mogelijk om de kandidaat uit de aparte eigenaar-[PR #1155](https://github.com/Zennay/Lightup/pull/1155) later **zonder cherry-pick of wijziging aan diens branch** optioneel te verifiëren. Het is nog steeds geen bewijs dat de *geïnstalleerde* proxy dezelfde configuratie draait of dat klantoperator-toestemming geldig is. DRAFT/HOLD en issue #1154 blijven staan.
