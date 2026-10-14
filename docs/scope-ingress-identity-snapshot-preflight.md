# Non-authorizing effective ingress identity snapshot preflight (#1164)

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/ACTIVE SCANS.**

This isolated optional offline checker is a **partial prerequisite**, not completion
of issue #1164. The original [offline WSGI test PR #1163](https://github.com/Zennay/Lightup/pull/1163)
demonstrates rejection of untrusted WSGI request metadata, but not what a
real installed Nginx/Gunicorn boundary passes to the application. This tool
does **not** contact Nginx, Gunicorn, a socket, a domain, a customer, an
authentication provider or a scan target. It does not change any application,
Nginx/Gunicorn source, service or deployed configuration.

## Input and reproducible, deliberately conservative check

The entry point is:

```sh
python scripts/scope_ingress_identity_snapshot_preflight.py \
  --nginx-effective /path/to/LOCAL_REDACTED_nginx_T_snapshot.txt \
  --gunicorn-effective /path/to/LOCAL_REDACTED_gunicorn_print_config_snapshot.txt
```

Both files must already be available locally. **Do not put actual effective
configuration, credentials, environment files, cookies or redaction keys in the
repository, GitHub Actions artifacts, issue comments or PRs.** An authorized
operator must handle production-derived configuration privately and review
redactions for semantic loss. The program reads at most 256 KiB + 1 byte per
input, requires ordinary non-symlink local files (rejects FIFOs/devices and
changing size/mtime during the read), never prints source lines, input paths
or error strings, and reports
only an optional pair of SHA-256 digests on a small accepted static fixture
shape. These digests are merely fingerprints of the *supplied bytes*, not
cryptographic authentication of installed process identity or provenance.

The reference now validates **every recognized Nginx directive in its exact block and requires balanced complete nesting**: exactly one synthetic HTTPS server with one valid canonical DNS name, exactly one location / inside that server, exactly one 443 listener, and six exact location-scope proxy statements. Duplicate listeners, duplicate names, extra server or location blocks, out-of-scope directives, unbalanced braces, multiple statements on a line, carriage-return rewriting and hidden control characters all result in HOLD. Matching individual lines in the wrong blocks is no longer sufficient. The strict Gunicorn reference also refuses carriage returns, vertical tabs, Unicode line separators and any unexpected setting that might change the eventual WSGI identity. Tests use synthetic marker-bearing fixtures and prove no target/grant/identity bytes are ever echoed in rejected receipts.\n\nThe deliberately narrow reference **rejects every unrecognized Nginx directive and every unrecognized Gunicorn setting**, including potential extension modules and middleware variables. A complete real `nginx -T`/`gunicorn --print-config` dump will commonly contain additional legitimate settings and therefore HOLD pending a dedicated installed-ingress review; REVIEW_ONLY is *only* a miniature static fixture compatibility signal. Do not strip real effective settings merely to obtain REVIEW_ONLY.\n\nThe restricted syntactic shape uses a `nginx -T`-style provenance marker,
one HTTPS server and one exact `location /` routing to
`http://127.0.0.1:8766`. The location requires request-header pass-through
to be disabled, explicit canonical Cookie and Host bindings, and bounded
direct X-Forwarded-Proto and X-Forwarded-For values. Forwarded or alternative
Cookie/identity headers are not allowed to become outbound headers.
The Gunicorn dump must contain exact, unique loopback bind, empty
forwarded_allow_ips, empty secure_scheme_headers and synchronous worker-class
settings. Unknown/complex Nginx transformations are intentionally HOLD.
A syntactically identical attacker-authored snapshot could still return
REVIEW_ONLY: the source is *never authenticated*.

The existing `deploy/nginx.conf.example` currently lacks
`proxy_pass_request_headers off` and a dedicated canonical Cookie binding.
It therefore receives **HOLD**, not an implicit "secure in production" claim.
This tool proposes no change to that shared template (owned by ingress
maintainers), and **does not recommend deploying the synthetic example**
without an ingress owner validating all request semantics.

Receipt states: `HOLD` (exit **2**) or `REVIEW_ONLY` (exit **3**).
`REVIEW_ONLY` is **not PASSED/SAFE/AUTHORIZED** and there is never exit 0.
The exact five authorization/permit/execution/merge/release flags are freshly
returned as literal false, even for REVIEW_ONLY. No source lines, header
contents, supplied filenames or exception details appear in receipts.

## What is still required for #1164

1. Authorized ingress owner captures **redacted, provenance-bound, installed**
   Nginx/Gunicorn version, effective configuration, service unit and deployment
   commit/hash; separately establishes authenticity of each snapshot.
2. Independent owner performs real **loopback-only, disposable** actual
   proxy+WSGI negative tests with absent/revoked/client/operator/CSRF Cookie
   controls, conflicting alternate Cookie and identity headers, before/after
   traces and zero durable grant/session changes. The offline checker and
   WSGI-only tests cannot replace this proof.
3. Explicitly audit upstream auth/rewrite/middleware behavior and request
   transformations; inspect request and response bytes with secrets redacted.
4. Obtain immutable exact-head GitHub-hosted Python 3.11/3.14 and **actual
   registered permanent VPS runner** job evidence, independent source and
   privacy/security review, and explicit human release decision.
5. No merge, deploy, real grant issuance, live scan or activation until the
   original source-owner and independent trust-boundary gates are met.

The new tests are static/fake-only. No actual proxies, customer identities,
bearer tokens, or target networking are exercised. Cross-check issue
[#1164](https://github.com/Zennay/Lightup/issues/1164), existing WSGI
[#1163](https://github.com/Zennay/Lightup/pull/1163) and separate method/path
ingress boundaries #1154/#1158/#1161 before any future integration.


## W59: opt-in werkelijke lokale Nginx → Gunicorn → synthetische WSGI-proef

Nieuwe zelfstandige uitvoering: scripts/scope_ingress_identity_loopback_proof.py.
Vereist dat Nginx en Python Gunicorn al lokaal geïnstalleerd zijn. Het start
uitsluitend twee nieuwe tijdelijke processen op twee door het OS aangewezen
hoge 127.0.0.1-poorten, met zelfgegenereerde Nginx-configuratie in een tijdelijke
directory en een fictieve WSGI-app zonder LightUp-import of database. Er wordt
geen geïnstalleerde /etc/nginx- of /etc/lightup-configuratie geopend, geen
productieservice herstart, geen echte klant geraakt en geen echte grant gemaakt.
Beide processen worden gegarandeerd gestopt na de controle of bij falen.

Vijftien echte (maar volledig fictieve) HTTP-fixturecases controleren anonymous,
ieder van acht alternatieve Cookie-/identiteitsheaders afzonderlijk plus
alle acht gecombineerd, revoked Cookie, client Cookie,
operator zonder CSRF, operator met een uitsluitend fictieve WOULD_ALLOW
zonder mutatie en fictieve client-portal-read. De fake WSGI-app retourneert
uitsluitend identiteitcategorie, status, aanwezigheid van onbetrouwbare headers
en nul schrijfacties. Geen tokens, cookies, volledige headers of wachtwoorden.
De evaluatie is atomair: ontbrekende of foutieve cases produceren HOLD.
Onbekende alternatieve headerselectors worden geweigerd voordat een HTTP-
client wordt gemaakt; elk individueel geval heeft een apart uniek bewijslabel.

Uitvoering: python scripts/scope_ingress_identity_loopback_proof.py

HOLD = exitcode 2; synthetische REVIEW_ONLY = exitcode 3. Ook bij REVIEW_ONLY
zijn de vijf machtigings-/permit-/uitvoerings-/merge-/releasevlaggen letterlijk
false. Er is nooit exitcode 0 of een echte autorisatie.

De reguliere unit-tests toetsen de WSGI-fixture en veilige CLI zonder
automatisch Nginx te starten. De werkelijke tijdelijke subprocess-proef is
alleen in de test-suite geactiveerd bij de omgevingsvariabele
LIGHTUP_REAL_NGINX_GUNICORN_LOOPBACK=1. Ontbrekende binaries geven dan
een testfout in plaats van een valse groenclaim.

**Grenzen:** echte localhost-fixture ≠ geïnstalleerde LightUp Nginx/Gunicorn,
geen authentiek geïnstalleerd configuratie-/TLS-/proxybewijs, geen echte
LightUp operator/session/CSRF-evaluatie en geen productie-acceptatie.
Open #1164 vereist nog een onafhankelijke geïnstalleerde proxy-/WSGI-proef,
exact-head hosted en feitelijke geregistreerde VPS-jobs, security/privacy
en expliciete menselijke vrijgave. INCUBATE M3/M7 · PLAN/LAB ONLY ·
DRAFT/HOLD; GEEN MERGE, DEPLOY, KLANTGRANTS OF ACTIEVE SCANS.


## W60: procesisolatie en client-identiteit monotone uitwerking

De tijdelijke echte localhost-fixture heeft nu **23 onderscheiden synthetische HTTP-cases**:
de eerdere 15 plus acht nieuwe negatieven waarin een al bestaande, fictieve
client-cookie samen met ieder van de acht onbevoegde identiteit- of
Cookie-doorgeefheaders wordt aangeboden. De check vereist expliciet dat een
client een client blijft, een operator-grant wordt geweigerd en zowel echte
als fictieve state writes nul blijven. De WSGI-test bevestigt onafhankelijk
dat zelfs bij losse direct aangeleverde client+spoof-hints geen operatorrol
of synthetische toestemming verschijnt.

Nginx- en Gunicorn-subprocessen van de optionele proef starten met een
nieuw minimaal omgevingswoordenboek zonder geërfde `GUNICORN_CMD_ARGS`,
`PYTHONPATH`, `PYTHONINSPECT`, `PYTHONSTARTUP`, `LD_PRELOAD`, externe
proxy-instellingen of shell-hooks. Het lokale Nginx PID-configuratiepad moet
uit een absoluut en uitsluitend syntactisch veilig TMPDIR-pad bestaan;
spaties, puntkomma's, dollar-variabelen, newlines, accolades en commentaar-
tekens kunnen zo geen instructie in het config-bestand injecteren.
Adversariële regressies toetsen zowel de positieve veilige vorm als
vroegtijdige weigering en de scheiding van omgevingsvariabelen.

Geen productie- of geïnstalleerde service wordt gestart of herladen.
Reguliere hosted tests bewijzen alléén de offline contracten; de optionele
reële twee-processen-fixture blijft een aparte uitvoeringsstap. Zelfs een
geslaagde echte *disposable* localhost-proef geeft geen toestemming voor
installed ingress, klantgrants, merge, release of scans. **DRAFT/HOLD.**


## W61–W62: orkestratie-integriteit en uitvoerbare binary-locatie

Twee test-only scenario's voeren `run_fixture()` met gecontroleerde
testdubbel-processen volledig uit, zonder echte Nginx-, Gunicorn- of
netwerkoperaties. De **23 afzonderlijke** synthetische gevallen, drie identieke
minimale subprocess-omgevingen (Nginx-configcheck, Gunicorn, Nginx),
localhost-poortbinding en omgekeerde procesopruiming worden getoetst. Een
test levert opzettelijk een verboden doorgestuurde identiteit terug:
het hele resultaat wordt afgewezen en **beide processen worden alsnog
opgeruimd**. De gewone Python-unit-suite beoordeelt dus niet alleen losse
helpers maar ook de echte orchestrator-aanroepstructuur. Dit is bewust
**geen bewijs van daadwerkelijke proxybinary-uitvoering**.

Ook de Nginx-binarylocatie wordt voortaan alleen via de vaste lokale
systeemzoekpaden geselecteerd. Een extern ingestelde PATH mag de optionele
test niet naar een willekeurige executable sturen. De tests eisen hetzelfde
vaste pad voor lookup en voor de geïsoleerde subprocessomgeving. Dit is
slechts een trust-beperking voor de tijdelijke fixture, **geen attestatie van
geïnstalleerde Nginx-binary, productie-TLS, Gunicorn of LightUp**.

Na ieder commit gelden alleen CI-logs van die exacte immutable HEAD.
Eerdere testsuccessen tellen niet mee voor latere branches. Productie,
klantgrants, deployment, merge en actieve scans blijven DRAFT/HOLD.


## W63: gegarandeerde cleanup-poging bij gedeeltelijke subprocessfout

De optionele lokale proef probeert nu **alle** eigen tijdelijke processen
in omgekeerde startvolgorde te stoppen, ook wanneer de eerste beëindiging
een OS-/procesfout geeft. Een onvolledig opgeruimde fixture wordt nooit
als REVIEW_ONLY behandeld maar faalt met HOLD. Unit-tests gebruiken uitsluitend
gecontroleerde nep-processen en simuleren exact deze fout, inclusief de
bevestiging dat het andere proces nog wel een cleanup-poging krijgt.
Dit biedt **geen bewijs dat echte Nginx/Gunicorn-processen al gedraaid hebben**.

Vanzelfsprekend blijft de normale CI zonder externe netwerk- of
processenactiviteit. Ook na succesvolle tests zijn echte geïnstalleerde
proxy- en LightUp-authenticatiechecks en menselijke releasegoedkeuring open.


## W64: echte Nginx-only observatie + per-run authenticatie van fixture-antwoorden

**Werkelijk lokaal uitgevoerd op 14 oktober 2026, niet op de permanente
VPS-runner:** Nginx **1.26.3** is gestart met een uitsluitend tijdelijk eigen
Nginx-bestand en twee 127.0.0.1-poorten, met Python-stdlib
`ThreadingHTTPServer` als upstream (dus **niet Gunicorn** en **niet de
LightUp-webapp**). De eenmalige lokale probe verwerkte **20/20 echte
HTTP-verzoeken**: anoniem, alle acht onvertrouwde Cookie-/identity-headers
apart en gecombineerd, alle acht ook bij een fictieve client-cookie, en
fictieve client- en operator-cookie controles. Onbetrouwbare headers werden
niet doorgestuurd; het upstream-cookiegedrag stemde overeen met de
verwachting. Gedocumenteerde response: `REVIEW_ONLY`, `case_count=20`,
`grants_written=0`, `gunicorn_exercised=false`,
`lightup_webapp_exercised=false` en **vijf machtigings-/releasevlaggen
letterlijk false**. Processen na de test beëindigd. Dit is een
**lokaal repro-resultaat**, geen beveiligingsattest van productie, Gunicorn,
de geïntegreerde 23-case repo-fixture of de geregistreerde VPS-runner.
De uitgevoerde lokale probe is als afzonderlijk gesprekbestand bewaard
met script-SHA256
`040218cb5530c2b41ae04aa32d9a4d5410348f6986074077487765abfbdedb25`
en ontvangst-SHA256
`15df273449ff0f757bcef45fd2f2ebc33182904fc489b69ff953a624fb6c1618`.
Op dezelfde geïsoleerde container is de eigen standaardbibliotheek-
upstream naderhand voorzien van een per-run willekeurige nonce in een echte
HTTP-responseheader. De **20 daadwerkelijke** Nginx→Python-HTTP-verzoeken
haalden opnieuw 20/20; de client verifieerde bij elk antwoord deze header,
terwijl `per_run_response_identity_verified=true` is vastgelegd zonder
noncewaarde of requestgeheim te publiceren. Definitieve lokale probe-
SHA256: `610bf9eee124f47ea8bcc95eb776caa1fa8ea0e0d81f7a0af3351e596f6918ba`.
Definitieve gesaneerde ontvangst-SHA256:
`7120d708bf98039cdf8f0508cbadf599310595c69642e1808cfab5d35cec933f`.
De eerdere hashes hierboven horen bij de eerste, nonce-loze uitvoering.
Opnieuw: lokale Nginx 1.26.3 met Python-stdlib HTTP, **niet Gunicorn**, niet
de LightUp WSGI, geen echte tenant-/grants-/auth-verificatie en geen VPS.
Deze hashes bewijzen uitsluitend de bytes van die lokale bestanden, niet
de authenticiteit van de geïnstalleerde ingress.

Bij audit van de nog NIET gedraaide twee-binary repo-fixture is een extra
veiligheidsgat gevonden: dynamisch vrijgekomen loopback-poorten kunnen door
een ander tijdelijk proces worden ingenomen. Daarom heeft iedere
`run_fixture()` voortaan een eigen cryptografisch willekeurige
**48-hexadecimale process-nonce**. Die wordt alleen in de tijdelijke
synthetische WSGI-code geschreven en in een upstream-responseheader gezet.
De echte HTTP-client accepteert het antwoord uitsluitend bij de verwachte
exacte nonce. Onjuiste/ontbrekende/misvormde nonce is atomair HOLD en
wordt niet uitgegeven in een stdout-receipt. Regressies toetsen noncevorm,
het geweigerde antwoord vóór iedere verdere acceptatie, dat alle 23
dezelfde run-nonce gebruiken en dat WSGI die nonce werkelijk terugstuurt.

**Niet bewezen:** de geïnstalleerde Nginx+Gunicorn-keten, de opt-in
23-gevallen repo-fixture op een echte Gunicorn-host, echte LightUp
sessions/CSRF/tenant-grants, permanente VPS-runner, onafhankelijke
security/privacy-review en menselijke toestemming. **INCUBATE M3/M7 ·
PLAN/LAB ONLY · DRAFT/HOLD; geen merge, deploy, echte grants of scans.**


### W64 aanvullend: twee echte negatieve Nginx-injectiecontroles

Naast de 20/20 veilige Nginx-only localhost-proeven is in dezelfde
tijdelijke container twee keer een **bewust onveilig Nginx-testbestand**
uitgevoerd (alleen op 127.0.0.1; eigen subprocessen; geen productieservice):
(1) `proxy_pass_request_headers on;` in plaats van `off;`; en
(2) `proxy_set_header Cookie $http_x_original_cookie;` in plaats van de
canonieke `$http_cookie`. Beide simuleren precies een grensoverschrijding
die een client/operator Cookie of een onbevoegde identiteitsheader
ten onrechte zou kunnen doen gelden. **Beide werkelijke HTTP-proeven
eindigden HOLD, diagnostic_code RuntimeError; vijf machtigingsvlaggen
blijven false. Daarnaast werd een **derde werkelijke negatieve localhost-
proef** uitgevoerd: de tijdelijke Python-HTTP-upstream antwoordde met een
onjuiste `X-Fixture-Probe-Id`-nonce. Ook dit werd op de echte Nginx-
proxyroute expliciet **HOLD**; er kwam geen onverwachte acceptatie of
toestemming. Een extra nieuwe mock-orkestratietest eist nu bovendien dat
na deze nonce-mismatch beide tijdelijke Nginx/Gunicorn-processen nog een
opruimpoging krijgen.** Geen echte tokens, SQL of grant-mutaties, en geen netwerk
buiten de lokale host.

Dat geeft een betekenisvolle positieve (20/20 REVIEW_ONLY) plus twee
negatieve (2/2 HOLD) controles voor de *tijdelijke Nginx→Python-stdlib*
route. Dit blijft een ander executiepad dan de nog niet uitgevoerde
Nginx→Gunicorn→LightUp fixture en is geen installed-config attestatie,
geen CI/VPS-bewijs en geen toestemming voor scans of release.


## W66: geen standaard Gunicorn-proxyvertrouwen in echte opt-in fixture

Verdere review van de niet-geactiveerde localhost Nginx→Gunicorn→synthetische
WSGI-proef wees op een daadwerkelijk open gat: de vorige Gunicorn CLI gebruikte
de standaardinstellingen voor vertrouwde forwarded IP's en schemeheaders.
Dat is ongeschikt als positief bewijs van een strikte ingress-grens.

De fixture genereert daarom nu een **eigen tijdelijk Python-configbestand**
voor uitsluitend haar eigen nieuwe Gunicorn-child, met expliciet
`bind='127.0.0.1:<ephemeral>'`, `workers=1`, `worker_class='sync'`,
`forwarded_allow_ips=''`, `secure_scheme_headers={}`, plus geen
accesslogs. Gunicorn start met `--config <eigen-tempbestand>`; de globale
omgeving blijft afgesloten van process hooks en `GUNICORN_CMD_ARGS`.
Nieuwe tests eisen exact de zeven vertrouwde instellingen en weigeren
publieke/lage/ongeldige poorten en andere defaults. De mock-orkestratie
controleert dat het eigen configuratiepad werkelijk naar de nieuwe
Gunicorn-child wordt doorgegeven. Er is nog niets aan het bestaande
`deploy/gunicorn.conf.py` of de productieapp gewijzigd.

**Status:** deze aanvullende Gunicorn-grens is code + tests, **nog geen
bewijs dat echte Gunicorn-binaries op localhost hebben gedraaid**.
De werkelijk uitgevoerde twintig Nginx-only HTTP-tests en drie negatieve
mutanten blijven een aparte, smallere bewijslijn. De echte LightUp-app en
permanent geregistreerde VPS-runner zijn niet gevalideerd. Nog steeds
PLAN/LAB ONLY · DRAFT/HOLD, zonder autorisatie, merge, deploy of scans.
