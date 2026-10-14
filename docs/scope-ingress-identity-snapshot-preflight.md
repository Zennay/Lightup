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
