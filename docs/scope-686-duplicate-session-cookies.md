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

Standalone full-source regression uses **only disposable local SQLite** and fictional operator/client sessions. Tests with a single valid operator or client cookie, unrelated cookies, an invalid token and no session cookie are ordinary GREEN controls. Duplicate session credentials are recorded as **eight specific original-source expectedFailure tests**, including identical repeated values, reverse-order valid client/operator tokens, unrelated surrounding cookies, invalid followed by valid, protected WSGI GET, POST logout and POST tenant creation. For the POST cases, `revoke_session` and `create_client` are mocked; the regression never actually revokes a session or writes a client.

All duplicate cases require rejection **before** `DomainStore.session_context`. Denial must not change either live session or emit a `Set-Cookie`; one unambiguous credential plus unrelated cookies must continue to work. Denial must not depend on which duplicate appears first.

Run:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_scope_686_duplicate_session_cookies.py' -v
```

The eight expected failures are an explicit *source-owner TODO*, **not** evidence that the flaw is fixed. An actual source fix should remove the `expectedFailure` decorators and make all 14 (or more) ordinary PASS, with strict no-session-lookup assertion preserved. A future unexpected success under `expectedFailure` is a migration signal and must be reviewed, not silently accepted.

## Source-owner handoff (do not implement here)

1. Reject any ambiguous `lightup_session` duplicate **before** generic `SimpleCookie` normalization or any durable session lookup. Include same-value duplicates and reversed operator/client order; do not use first- or last-wins selection.
2. Make raw-header parser behavior explicit and test alongside the *actual* production WSGI entrypoint. If using PR #1169's standalone guard, wire it only through the appropriate web/ingress owner and independently review path/charset/quote semantics.
3. Keep rejection side-effect-free: no session lookup, session revocation, tenant mutation or cookie-setting. Preserve successful single-token authentication and tenant access isolation.
4. Capture edge-to-Gunicorn normalization separately under [ingress issue #1170](https://github.com/Zennay/Lightup/issues/1170); WSGI-level tests cannot prove proxy treatment of two physical Cookie headers.

## Release requirements

Independent source owner fix, dedicated regression ordinary GREEN on that exact source commit, full original Python 3.11/3.14 hosted preflight and named permanent self-hosted VPS CI on the approved release SHA, separate truly authenticated client and operator consent with at-use revocation, independent security/privacy review, and explicit human GO.

Until then: **DRAFT/HOLD; no merge, deploy, scan, grant, handler dispatch or release.**
