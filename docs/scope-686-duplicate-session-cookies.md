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

## Reproducible offline source-owner composition — executable, not a release gate

This branch now owns five **new isolated verifier/CI files**, in addition to the original two test/document paths, with no overlap with source owners:
- `scripts/scope_686_owner_composition_offline.py`: no-network composition builder, strict 40-character commit and SHA-1 Git blob pinning, clean-root prerequisite, symlink/non-regular-file refusal, disposable checkout, real smoke or full test discovery and machine-readable **HOLD-only** receipt.
- `scripts/scope_686_guard_probe_offline.py`: actual opt-in `CookieEnvelopeGuard(create_app(store))` against disposable operator/client SQLite sessions, **nine** ambiguous-cookie POSTs and a valid-credential public login POST denied **before any body read / session lookup or mutation**, three normal positive controls, no real target I/O.
- `tests/test_scope_686_owner_composition_offline.py`: **25 isolated ordinary PASS tests** of wrong SHA/ref, malicious path, mismatching pinned tree/blob, dirty source, missing evidence, nonzero test exits, coverage and expected-RED drift, leaked exception text, unsafe forged guard receipt, or attempts to treat `HOLD` as `GO`.

- `scripts/scope_686_guard_mutants_offline.py`: seven executable *fictional* guard mutations (removed guard, normal/line/buffer/value/iterator early body reads, Set-Cookie mutation). Their **seven denials must succeed under each of `python -O` and `python -OO`**; missing guard checks cannot silently vanish under optimized Python. The normal guard probe now uses explicit `GuardProbeHold`, **not Python `assert`**, and counts alternate stream I/O access patterns.
- `.github/workflows/scope-686-owner-compat.yml`: unique, read-only hosted 3.11/3.14 candidate-only workflow on the owned branch; never changes old CI or permanent runner, and cannot confer GO/release authority. Workflow submission is not proof it actually ran; confirm GitHub Actions jobs separately.

The runner pins **four separate existing ownership blobs**, without editing those owners or changing the installed production entrypoint: #1452 frozen-clock `#301` test fixture, #182 web app source, #1169 unwired WSGI cookie guard, and #1536 Python3.14 warning-safe registry report source. The last pin is essential: an earlier legitimate full run **failed four independent legacy native-I/O guard tests** with unsafe exit code 92 due to existing Python3.14 `SyntaxWarning`; exactly the already-owned source correction in #1536 resolved that block without removing or weakening the tripwire.

Run from a clean local checkout containing all four pinned commits (no auto-fetch or network):
```sh
HEAD="$(git rev-parse HEAD)"
python3 scripts/scope_686_owner_composition_offline.py --source "$PWD" --head "$HEAD" --mode smoke
python3 scripts/scope_686_owner_composition_offline.py --source "$PWD" --head "$HEAD" --mode full
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_686_owner_composition_offline.py' -q
```
The CLI emits exactly one structured JSON object, with `status:"HOLD"`, `release_authorized:false`, `real_target_interaction_authorized:false`. An absent pin, invalid tree/hash, unclean source, incorrect test counts, unexpected or missing deliberate expectedFailures, malformed probe receipt, unit/test failure or timeout produces exit code **2** with compatibility **FAIL** and no release authority. Known test failure names, but **not exception values, cookie values or private paths**, may appear in the reason.

**Observed reproducible full owner composition on connected zSSH, Python3.14.4**, own runner SHA `2f6469773b58e05bc6bcaa8963dc463e0c549215`: `1,305` full tests, **46 intentionally unresolved source expectedFailures**, no unexpected failures, producer integration **86/86 PASS**, nine guard duplicates denied pre-body, **14 optimized-mode guard mutations rejected (7 each on `-O` and `-OO`)**, normal role isolation retained, clean source checkout, receipt `candidate_compatibility:"PASS",status:"HOLD",release_authorized:false`. This is a **synthetic candidate composition** with pinned bytes in a local, transient checkout, NOT a signed combined Git commit, independent source review, actual proxy wire proof, full hosted Python 3.11/3.14 approved-release CI, permanent named VPS workflow receipt, or real authenticated consent. Do not run it against public targets or treat it as authority.

## Release requirements

Independent source owner fix, dedicated regression ordinary GREEN on that exact source commit, full original Python 3.11/3.14 hosted preflight and named permanent self-hosted VPS CI on the approved release SHA, separate truly authenticated client and operator consent with at-use revocation, independent security/privacy review, and explicit human GO.

Until then: **DRAFT/HOLD; no merge, deploy, scan, grant, handler dispatch or release.**
