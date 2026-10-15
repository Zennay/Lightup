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

## W4 — geen foutieve proxy-evidence bij kapotte upstreamresponse

Ook de *eigen* tijdelijke WSGI-echo is niet automatisch een betrouwbare bron. Daarom valideert de helper het exacte JSON-schema met vier verplichte veldnamen, drie letterlijk `str`-waarden, een echte lege `dict` voor gestripte headerwaarden, de juiste GET/POST-body en **geen extra velden**. Een lijst, bool, ontbrekend veld, toegevoegde nepautorisatie of typeverwarring kan niet langer op een `.get`-exception stranden of als geldig resultaat worden beschouwd: elk levert een onbetrouwbare HOLD op. Een afgebroken HTTP-body (`http.client.IncompleteRead`) wordt eveneens omgezet naar een algemene HOLD zonder clientdiagnostiek. Extra regressietests bevatten opzettelijk vervalste WSGI-pakketten en een gesimuleerde afgebroken upstream.

Dit is een **veiligheidscheck op de eigen offline testhelper**, niet op geïnstalleerde Nginx, Gunicorn, klantgrant of echte scans. Er blijven zes letterlijk valse uitvoerings-/releasevelden en nooit een autoriserende exitcode.

## W5 — canonieke templatevolgorde in plaats van alleen bekende regels (15 oktober 2026)

Een allowlist per regel bleek onvoldoende: exact bekende configuratie-instructies konden dubbel voorkomen, worden weggelaten of naar de verkeerde Nginx-scope verhuizen. De renderfunctie staat daarom nu alleen het **volledig bekende, exact geordende main-basisskelet** toe. De vier optionele methode-stripregels mogen maximaal één keer per naam voorkomen en uitsluitend binnen de gereserveerde `Forwarded`-tot-`proxy_request_buffering`-sectie. De originele main-template zonder strips wordt nog toegestaan **uitsluitend om met een echte netwerkproef de ontbrekende beveiliging af te wijzen**; die main-template mag geen `REVIEW_ONLY` opleveren.

Nieuwe regressies omvatten verplaatste stripregels (server-scope en na de location), duplicate headers, ontbrekende Host/body-buffering, gewijzigde directive-volgorde en een mutation sweep over **alle 26 originele basisregels**, elk afzonderlijk verwijderd én dubbel gemaakt. Positief blijven zowel de ongewijzigde template als een *uit de broncode gereconstrueerd* PR-#1155-patroon geldig. Dat PR-#1155-patroon wordt ook door echte tijdelijke Nginx over loopback geproefd, inclusief de read-only `--candidate-file`-CLI. Dit bewijst **niet** dat de werkelijke PR of geïnstalleerde proxy op dezelfde SHA is getest: de leverancier-/eigenaarbron blijft afzonderlijk, draft en ongewijzigd.

Een nieuw bestand met gewijzigde productiebinds, extra proxy-modules of afwijkende serverconfig kan bewust niet met deze fixture worden getest. De helper is géén algemene Nginx-linter, heeft geen targetscanbevoegdheid en kan niet als releasesignaal dienen. Ook bij volledig groene gehoste tests: **DRAFT/HOLD**, geen merge/deploy/klantgrant/release.

## W6 — echte LightUp-webapp achter de tijdelijke proxy

De bestaande Nginx/WSGI-echo test ruwe transportmetadata. **Aanvullend** kan exact dezelfde wegwerp-Nginx een echte `create_app(DomainStore(...))` achter zich krijgen. Alle SQLite-records zijn fictief, staan in `TemporaryDirectory` en bevatten geen doelwitautorisaties. De netwerkpoort blijft alleen `127.0.0.1`; er wordt geen productie-WSGI-code aangepast.

De extra end-to-endtest gebruikt echte tijdelijke operatorsessies, een eigen klantaccount en geldige/ongeldige CSRF-tokens. Voor elk van de vier methode-overrideheaders controleren daadwerkelijke HTTP-requests dat een ingelogde operator de dashboard-GET mag bekijken, een anonieme bezoeker naar de login wordt verwezen, een klantgebruiker de operatorpagina niet mag lezen en dat een operator-POST met vervalst CSRF **geen nieuwe klant** maakt. Ook een klant-POST met zijn echte eigen CSRF mag geen operatorclient aanmaken. Een echt geldige operator-POST met spoofed GET maakt daarentegen precies één **fictieve** klant aan; zo blijft de bedoelde schrijfroute werken. De doelbewust onveilige tijdelijke `proxy_method GET`-mutant moet ook bij deze echte app-controle als fout worden gedetecteerd.

Dit geeft sterkere onafhankelijke labacceptatie voor issue #1154 dan alleen de WSGI-echo, maar blijft gescheiden van de productiewebapp-eigenaar #182, de Nginx-template-eigenaar #1155 en de geïnstalleerde Nginx/Gunicorn-stack. **DRAFT/HOLD, geen live targetautoriteit of release.**

## W7 — eigen testproces neemt geen CI-/cloudgeheimen over

De tijdelijke Nginx-probe ontving eerder ongemerkt de standaardomgeving van de gehoste of VPS-runner. Het is geen productie-kwetsbaarheid, maar onnodige blootstelling voor een los subprocess. Zowel de disposable `nginx -t` als de daadwerkelijke disposable `nginx` krijgen nu een **gesloten environment** met alleen `HOME` en `TMPDIR` op hun eigen wegwerpmap en `LANG/LC_ALL=C`. `GITHUB_TOKEN`, AWS-credentials, proxyinstellingen, LightUp-databasepaden of andere runner-omgevingsvariabelen worden niet doorgestuurd. Een regressie bewijst deze noninheritance met uitsluitend synthetische tokens.

Ook dit blijft uitsluitend veilig lokaal testmateriaal voor [#1154](https://github.com/Zennay/Lightup/issues/1154), **niet** een release-gate voor echte targets: productiebeveiliging, geregistreerde permanente VPS-acceptatie, onafhankelijke review en echte toestemming zijn ongewijzigd vereist.

## W8 — sessie-intrekking mag niet door header-spoofing worden omzeild

De werkelijke LightUp-webapp-test via het tijdelijke Nginx-proces controleert nu ook per ieder van de vier methode-overrideheaders dat een vervalste `POST /logout` met verkeerd CSRF **403** teruggeeft en de operator-sessie werkelijk **actief laat** in de tijdelijke SQLite-bron. Daarna moet een geldig `POST /logout` met de originele sessie-CSRF ondanks de vervalste GET-header precies die operator-sessie **intrekken** (`303`, token niet meer vindbaar, volgende `GET /` terug naar `/login`). Dit is geen alleen-in-process WSGI-test: de requests doorlopen daadwerkelijk de eigen tijdelijke Nginx-listener. Alle namen en logins zijn fictief.

Dit sluit een aanvullend aspect van [#1154](https://github.com/Zennay/Lightup/issues/1154) af in de **synthetische labacceptatie**, niet in de geïnstalleerde productie-infrastructuur. Opt-in, geen echte grants, geen scans, geen release.

## W9 — autorisatieverzoeken, tenantgrenzen en productie-achtig origin/CSRF-pad (15 oktober 2026)

De echte LightUp WSGI-app op wegwerp-SQLite achter dezelfde tijdelijke Nginx-fixture wordt uitgebreid met **de werkelijke klantportaalroute** `/portal/<fictional-client>/requests`. Elk van de vier overrideheaders wordt als GET→POST en POST→GET via echte HTTP-requests gestuurd. Een GET mag geen assessment request maken; een POST met vervalst CSRF mag evenmin een verzoek maken. Een klantgebruiker mag met zijn **echte** eigen CSRF bovendien niet voor een tweede fictieve tenant indienen. Als positieve controle mag een echte POST met geldige eigen client-CSRF precies één fictief assessment request aanmaken. Dit is een aanvraag, **geen toestemming of uitvoerbaar grant**.

Een aanvullende afzonderlijke, uitsluitend lokale **productie-achtige** test gebruikt de echte `WebSecurity(public_origin="https://lightup.example.com")` boven dezelfde tijdelijk gestarte Nginx. Alleen de proxy **simuleert** HTTPS-forwarding: het testverkeer zelf en de fictieve host zijn lokaal, zonder echte TLS-certificaten of customer host. De WSGI-app moet via het echte productiecontrolepad de oorspronkelijke GET-methode, host/HTTPS/loopback-peer, en HSTS bewaken; de vier POST→GET spoofheaders mogen niet langs CSRF glippen. Zelfs met een correcte CSRF moeten onjuist `Origin` en `Sec-Fetch-Site: cross-site` worden afgewezen, zonder een nieuwe fictieve klant. Positief mag één correct origin+CSRF-verzoek ondanks spoofed GET door de canonieke POST-route gaan. Een doelbewust gewijzigde `proxy_method GET` moet deze echte app-proef negatief maken.

**Belangrijk:** dit raakt geen bestaande producer-WSGI-, proxy- of grantcode; het zijn alleen geïsoleerde regressies binnen eigen nieuw bestand. Het bewijst niet het werkelijk geïnstalleerde Nginx/Gunicorn-proces, een echte TLS-handshake of klant/partnergoedkeuring. **DRAFT/HOLD; geen merge, externe activiteit, grants of scans.**

## W10 — dubbele, anders gespelde wire-headers raken echte app-/CSRF-routes niet

De eerder geteste `X-HTTP-Method-Override`, `X-Method-Override`, `X-Original-Method` en `X-HTTP-Method` konden al bij een **echo-WSGI** aantoonbaar verdwijnen. Als extra onafhankelijke negatieve controle laat de echte LightUp-app-suite nu met `http.client.putheader` voor iedere headernaam **twee daadwerkelijk verzonden HTTP/1.1-regels met dezelfde naam, maar andere hoofdletters** door tijdelijke Nginx lopen. Het dashboard blijft GET/200, de fictieve klant-aanmaakroute blijft bij POST met ongeldige CSRF / dubbele spoof metadata **403**, en de tijdelijke SQLite-cliëntentabel groeit niet. Omdat de low-level HTTP-client de regels afzonderlijk doorstuurt, wordt de aanval niet vooraf door een Python-dictionary platgeslagen. Dit is een *synthetische lokale* acceptatieproef en geen bewijs voor productie-ingress.

Alle metadata die authority lijkt te geven blijven op `false`. Geen andere workers-branches of productiecode aangeraakt, geen echte targets of scans.
