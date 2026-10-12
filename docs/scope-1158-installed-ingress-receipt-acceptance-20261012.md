# #1158 supplied installed-ingress receipt contract — offline reference

**Incubate M3/M7; DRAFT/HOLD/NO MERGE/NO DEPLOY.** This is a non-authorizing
offline validator of *supplied metadata*, **not** a packet recorder, Nginx/Gunicorn
test, parser validator, customer scan, deployed control or release certification.

## Why this supplement is independent

[PR #1156](https://github.com/Zennay/Lightup/pull/1156) proves in-process WSGI
`PATH_INFO` non-authority only.
[PR #1248](https://github.com/Zennay/Lightup/pull/1248) adds an initial
static check of the checked-in example Nginx root-location header stripping.
Neither can certify the installed ingress or trust supplied claims about the
backend route. The existing scope, auth, WSGI, proxy and Nginx source owners
remain solely responsible for production changes and actual environment tests.

This supplementary **add-only tests-only** implementation provides
`tests/scope_1158_ingress_receipt_reference.py` and
`tests/test_scope_1158_ingress_receipt_reference_20261012.py`.

## Strict, synthetic review cases

An independent owner of an *isolated localhost fixture* can later supply
**12** precisely identified sanitized observations:

- Seven `GET /nonexistent` cases, each with one of:
  `X-Original-URL`, `X-Rewrite-URL`, `X-Original-URI`,
  `X-Forwarded-URI`, `X-Forwarded-Path`, `X-Forwarded-Prefix`,
  `X-Script-Name`. Each must capture original and backend path
  `/nonexistent`, explicit backend route `not_found`, HTTP 404,
  zero writes (not a generic 403 masking a rewrite).
- One `GET /nonexistent` with all seven contradictory hints, still true
  `not_found` and zero writes.
- One authenticated, CSRF-valid synthetic operator `POST /nonexistent`
  with a path hint: no write, true 404.
- One correctly authenticated/CSRF-valid synthetic `POST /clients`:
  real backend `clients_created` control, precisely one disposable
  write and configured 303 redirection.
- One synthetic cross-tenant `GET /clients/foreign`: backend route
  `tenant_denied`, HTTP 403, zero writes.
- One synthetic authenticated/CSRF-valid `POST /logout`: backend
  `logout`, 303, recorded session invalidation.

The receipt must pin exact lowercase 64-hex repository commit and a
SHA-256 string for the **installed** loaded Nginx config and backend capture,
nonempty bounded Nginx/Gunicorn versions, and exact environment label
`disposable-loopback-lab`. It demands the **adversarial hinted path values**, not just header names:
all seven individual header cases and the unknown-path POST must carry
`/clients`; the conflicting-header control alternates `/clients` and
`/logout`. Benign hints to `/nonexistent` do not count as tests of
upstream rewriting. It denies missing/duplicate case IDs, wrong
path or route, mismatch to original request, status-only claims, unvalidated
CSRF controls, missing logout/session invalidation, unintended writes, unknown
hint names and noncanonical types. Input remains unmodified. The validator
returns `None` even on structural success: **no grant, permit or deployed
security acceptance is produced**.

## Additional bounded local digest cross-check (W4)

An optional, pure, tests-only `check_locally_supplied_fixture_digests`
function first requires the complete structural receipt and then compares
`SHA-256` over two explicitly provided **in-memory, redacted synthetic**
fixtures with the receipt's config/capture digests, rejecting mismatch,
empty, mutable/non-builtin byte types and objects over **1 MiB**.
The helper never opens files, writes files, logs fixtures or makes requests.
This establishes consistency **between the caller's own supplied bytes and
claimed digests**, not that the bytes came from the installed Nginx/Gunicorn
stack or that a backend route was observed. Independent capture provenance
and privacy review remain mandatory. Nothing may automatically promote the
receipt into authorization, an active test, a real-client claim or release.

## CRITICAL trust/operational limitations

The structural checker does **not**:
1. compute actual hashes from installed Nginx or proxy files;
2. authenticate the author, timestamp, signature or origin of capture metadata;
3. read HTTP wires, parse WSGI, launch nginx/gunicorn, open sockets or assert
   backend provenance;
4. verify real proxy modules, route inheritance, all HTTP header syntax, method
   overrides, cookies, TLS/Host/origin, actual network policy or state races;
5. authorize clients/assets/capabilities or resolve tenant/grant revocation;
6. accept an actual deployed or public target, or authorize a merge/deploy.

Do **not** synthesize these supplied records and then call them observed
acceptance. Dummy records in tests only prove that the *reviewer's own matrix*
is internally consistent. A reviewer must bind a trusted, immutable actual
capture and loaded configuration externally; for example, preserve restricted
locally available raw capture and independently hash it, redacting any
credentials, cookies, CSRF tokens, customer identifiers and request payloads
from all PR/CI/Notion comments. The checked-in shape has no secrets or
raw request data. Never treat a typed `actor_class` string as authentication.

## Release and collision guard

- Run isolated stdlib tests with:
  `PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_scope_1158_ingress_receipt_reference_20261012.py' -v`.
- Require a source-owner-owned **installed local-only** Nginx→Gunicorn
  fixture plus verified captured backend `PATH_INFO`, loaded config,
  binary versions/modules, route and DB effects. Confirm compatible actual
  redirect codes in that environment; hardcoded 303 values here are a
  lab-only contract, not universal HTTP semantics.
- Require distinct exact-head hosted Python 3.11/3.14 jobs and **permanent
  registered VPS** CI, independent security/privacy/tenant review, integration
  against latest main and explicit human release approval.
- Keep #1158 OPEN, PR #1248 DRAFT/HOLD, no modifications to
  `deploy/nginx.conf.example`, `webapp`, `ai/orchestration.py`,
  `main`, or any other scope worker branch. No target interaction,
  scanning, real customer sessions, grants, service reload or deployment.
