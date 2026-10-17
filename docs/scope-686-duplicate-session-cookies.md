# Scope authorization #686 — duplicate session-cookie ambiguity

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an owner-isolated acceptance contract, **not** a production fix or authorization to scan, issue grants, dispatch handlers, merge, deploy, or release.

## Original behavior verified

At `src/lightup/webapp/app.py`, `LightUpWebApp._authenticate` currently loads the raw `HTTP_COOKIE` field with `http.cookies.SimpleCookie`, then selects `cookie.get("lightup_session")` and calls `DomainStore.session_context(morsel.value)`. Duplicate occurrences collapse into a selected credential. For an operator token plus a client token the interpreted caller can depend on header ordering, instead of being denied as ambiguous. This is a real request-authentication ambiguity, not evidence of an externally exploitable network weakness; actual reverse-proxy forwarding is separately unverified.

## Ownership isolation

This branch edits **only**
- `tests/test_scope_686_duplicate_session_cookies.py` (new independent original-source WSGI/SQLite acceptance),
- `docs/scope-686-duplicate-session-cookies.md` (this document).

It does **not** touch the active [web source owner PR #182](https://github.com/Zennay/Lightup/pull/182), [opt-in CookieEnvelopeGuard PR #1169](https://github.com/Zennay/Lightup/pull/1169), any redaction source owned by #671/#672/#674/#675/#677, session reconstruction #670, operational ingress, scope, activation, CI workflows, runner, or deployment.

## Acceptance matrix and RED discipline

Standalone full-source regression uses **only disposable local SQLite** and fictional operator/client sessions. Tests with a single valid operator or client cookie, unrelated cookies, an invalid token and no session cookie are ordinary GREEN controls. Duplicate session credentials are recorded as **thirteen specific original-source expectedFailure tests**, including identical repeated values, reverse-order valid client/operator tokens, unrelated surrounding cookies, invalid followed by valid, protected WSGI GET, POST logout and POST tenant creation. For the POST cases, `revoke_session` and `create_client` are mocked; the regression never actually revokes a session or writes a client.

All duplicate cases require rejection **before** `DomainStore.session_context`. Denial must occur **before reading any request body** and must not change either live session or emit a `Set-Cookie`; one unambiguous credential plus unrelated cookies must continue to work. Denial must not depend on which duplicate appears first.

### Test-only source-owner repair oracle (not runtime code)

The expanded suite includes **13 deliberately unresolved original-source expectedFailures** and **10 ordinary passing test methods**. `test_owner_fix_rehearsal_turns_thirteen_original_source_reds_green` temporarily replaces one *test app instance's* `_authenticate` binding and the synthetic WSGI trust-boundary `WebSecurity.validate` class hook with minimal duplicate-occurrence denial. It calls **all 13 red method bodies directly** (so that the `expectedFailure` decorator cannot hide errors), retests valid operator/client authentication and repeated unrelated cookies, then checks **128 seeded adversarial duplicate combinations**. A deliberately incomplete values-only duplicate check must still fail on two equal session credentials.

A separate ordinary mutation check proves an `_authenticate`-only patch still permits public login session creation and allows premature POST-body reads. An additional direct RED specifically checks public `POST /login` against mocked session creation and revocation; its current original-source failure shows an actual **source code trust-boundary gap**, not an observed live exploit. An ingress guard gives a generic `403` and must leave original sessions intact; a test-only `_authenticate` patch alone would not protect the public login path.

This is a **bounded behavioral repair rehearsal**, **not** a complete `Cookie` grammar parser, source-owner patch, installed middleware, real proxy evidence, or live consent. Its simplistic semicolon counting is confined to the fictional test fixture and MUST NOT be copied into production. Production parsing must independently handle RFC cookie quoting, controls, exact cookie-name identity, maximum sizes, malformed envelope types, and intermediary normalization, together with ingress owner #1169/#1170.

Run:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_686_duplicate_session_cookies.py' -v
```

The thirteen expected failures are an explicit *source-owner TODO*, **not** evidence that the flaw is fixed. An actual source fix should remove the `expectedFailure` decorators and make all 23 (or more) ordinary PASS, with strict no-session-lookup assertion preserved. A future unexpected success under `expectedFailure` is a migration signal and must be reviewed, not silently accepted.

## Source-owner handoff (do not implement here)

1. Reject any ambiguous `lightup_session` duplicate **at the WSGI ingress before form parsing, public login routing, generic `SimpleCookie` normalization, or any durable session lookup**. Returning `ANONYMOUS` from `_authenticate` alone is NOT sufficient: public `POST /login` can still mint a session from supplied credentials. The dedicated source-RED checks require no `create_session`, `revoke_session`, or `Set-Cookie` on ambiguous login requests. Include same-value duplicates and reversed operator/client order; do not use first- or last-wins selection.
2. Make raw-header parser behavior explicit and test alongside the *actual* production WSGI entrypoint. If using PR #1169's standalone guard, wire it only through the appropriate web/ingress owner and independently review path/charset/quote semantics.
3. Keep rejection side-effect-free: no session lookup, session revocation, tenant mutation or cookie-setting. Preserve successful single-token authentication and tenant access isolation.
4. Capture edge-to-Gunicorn normalization separately under [ingress issue #1170](https://github.com/Zennay/Lightup/issues/1170); WSGI-level tests cannot prove proxy treatment of two physical Cookie headers.

## Separate installed opt-in owner proof — read-only branch composition

On a **separate, disposable, clean checkout** of the unchanged [cookie-guard owner PR #1169](https://github.com/Zennay/Lightup/pull/1169) exact SHA `31055e7f5de9046405afea14bc945feb8f21d8be`, an independent Python3.14 script constructed synthetic real `DomainStore` operator/client sessions and exercised the **existing** opt-in `CookieEnvelopeGuard(create_app(store))` without changing owner files. It verified:
- **8 ambiguous session envelope cases** -> exact `400 Bad Request`, zero `session_context` / `create_session` / `revoke_session` calls, no `Set-Cookie`.
- **public `POST /login` with valid fictional credentials and duplicate cookies** -> `400`, zero lookup, zero session creation/revocation and no `Set-Cookie`.
- **3 legitimate single-token controls** -> operator `200 OK`, operator plus duplicated unrelated theme cookies `200 OK`, client operator-route denial `403 Forbidden`.
- Both original synthetic session records remain valid. Checkout `git status --porcelain` empty.

Result: `REAL_OWNER_GUARD=PASS; DIVERSE_DUPLICATES=8; LOGIN_NO_SESSION_SIDE_EFFECT=PASS; VALID_CONTROLS=3; AUTHENTIC_SESSION_PRESERVATION=PASS; NO_TARGET_IO`.

This is **actual existing opt-in guard functionality** in a disposal-only fixture, stronger than a hypothetical monkeypatch; it is **NOT the installed Gunicorn/production-entrypoint wiring**, not independent real proxy-header field proof and cannot authorize a merge, live scanning or grants. The unchanged production `create_app` still needs intentional admission integration by the web/ingress owner, plus #1170 edge normalization evidence.

## Original-source RED failure identity

The new ordinary acceptance method enumerates **exactly 13 intentionally red source tests**, calls them directly and confirms each fails via an `AssertionError` containing a relevant session-lookup/HTTP/authentication assertion, **not** an unrelated exception masked by `@expectedFailure`. The twelfth case exercises valid-then-invalid duplicate order; the thirteenth additionally requires rejection **before POST form-body I/O**. All thirteen remain unresolved in unchanged production `app.py`. The witness itself must be removed or migrated when the source owner fixes the production boundary.

## Four-owner isolated whole-project composition — passing, not merged

On connected `vps-bb300bba` Python 3.14.4, a **disposable, never-pushed** checkout combined:
1. Own [draft #1555](https://github.com/Zennay/Lightup/pull/1555) test source at exact `55442a534091c83fe921a41972753615c1901afd` (additive acceptance files, no deployed auth changes).
2. The existing [#301 owner fixture correction PR #1452](https://github.com/Zennay/Lightup/pull/1452) at `89c7973a330550cd5b8fad23abb54e4a81f85639` (one **temporary** original unit-fixture overlay; correct frozen-clock test only, does not resolve #301 authorization source REDs).
3. The unchanged [#182 web-input owner](https://github.com/Zennay/Lightup/pull/182) `app.py` at `8c97eb0490bc0d5d1bfdb883c9d1434f6b21749c` (temporary file overlay).
4. The unchanged [#1169 opt-in cookie-guard owner](https://github.com/Zennay/Lightup/pull/1169) `session_cookie_guard.py` at `31055e7f5de9046405afea14bc945feb8f21d8be` (temporary untracked file, **not** application-entrypoint wiring).

The true **whole installed-source unit discovery** in that temporary 4-owner composition:
```
PYTHONPATH=src python3 -m unittest discover -s tests -q
Ran 1280 tests in 56.645s
OK (expected failures=46)
FOUR_OWNER_EXACT_686_HEAD_FULL_EXIT=0
```
Dedicated current #686 module: **23 methods, 10 ordinary PASS and 13 intentionally unresolved source expectedFailures**. Existing original producer integration: **86/86 PASS**, safety canaries PASS, original webapp 23/23 PASS. The existing opt-in guard demonstrably denied a duplicate-cookie public POST **before any WSGI body read** (a counting stream recorded `0` reads), with zero session lookups/writes and intact sessions.

**Important provenance limit:** the exact **own #1555 source commit** is verifiable, but these three owner file overlays were **never committed as a single reviewed release SHA**. A private filesystem composition exit 0 is **not** equivalent to GitHub-hosted Python3.11/3.14 exact-head green or permanent named-VPS Actions CI. The original own-only branch still contains the uncorrected time-bomb fixture #301 and fails whole-suite CI for that known reason. No upstream PR branches, production code, runner registration, live API, credentials, targets or installed proxies were modified in the proof.

## Release requirements

Independent source owner fix, dedicated regression ordinary GREEN on that exact source commit, full original Python 3.11/3.14 hosted preflight and named permanent self-hosted VPS CI on the approved release SHA, separate truly authenticated client and operator consent with at-use revocation, independent security/privacy review, and explicit human GO.

Until then: **DRAFT/HOLD; no merge, deploy, scan, grant, handler dispatch or release.**
