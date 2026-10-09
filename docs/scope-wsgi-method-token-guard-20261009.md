# Opt-in WSGI HTTP method-token guard (scope authorization, 2026-10-09)

## Finding and why this is needed
The current `LightUpWebApp.__call__` normalizes `REQUEST_METHOD` with
`.upper()` before route lookup. HTTP method tokens are case-sensitive; an
in-process WSGI `post` can be upgraded to privileged `POST` given an otherwise
valid operator session and CSRF. Existing independent RED canaries are in
[PR #1157](https://github.com/Zennay/Lightup/pull/1157).
This is **not** proof that installed Nginx/Gunicorn passes malformed methods.

## Isolated producer
- `src/lightup/webapp/method_guard.py` exports `canonical_request_method`
  and `CanonicalMethodGuard`. It accepts exact built-in `GET`/`POST`
  only, **before** body reads, authentication or route dispatch.
- Unknown well-formed method tokens receive 405/Allow; malformed, missing,
  polymorphic, oversized or control-character tokens receive 400. No case-folding.
- Denials use generic text, `no-store`, restrictive response headers, no
  cookies or session effects; exact `production=True` retains HSTS.
- `src/lightup/webapp/method_guarded_production.py` is a separate
  **opt-in factory** composing the existing fail-closed production factory.
  The installed Gunicorn entrypoint is unchanged.
- `tests/test_scope_wsgi_method_guard_integration_20261009.py` uses actual
  application + temporary SQLite (development and simulated HTTPS/loopback
  production) to verify absence of session lookup, downstream entry, body
  read, logout effects, operator client writes and role/CSRF bypass on denied
  methods. Authorized GET/POST still work.
- No outbound sockets, external targets, active scans, grant issuance or
  network changes.

## Owner coordination / integration requirement
This PR introduces **new filenames only**. It deliberately does **not**
edit `src/lightup/webapp/app.py` (owned by PR #182),
`src/lightup/webapp/security.py` (#202), Nginx configuration (#1155),
`src/lightup/webapp/forms.py` (#1162) or tests owned by #1157.
Likewise, the canonical PATH_INFO guard and guarded-production factory in
[PR #1167](https://github.com/Zennay/Lightup/pull/1167) remain independent.

The app/entrypoint owner must integrate a **composed** early method + path
guard at **every** deployed and testable WSGI entrypoint; a standalone,
unwired alternate factory is not production protection. Ensure no route
layer reintroduces method normalization. Re-run #1157 RED cases as plain
passing assertions against the final integrated app; remove no xfail until
the failure is actually resolved. Preserve proxy trust, normal role/CSRF,
proper HSTS, and deny before any body/session lookup. Confirm installed
Nginx/Gunicorn behavior separately with synthetic authorized/local-only
tests, including method-case behavior. Coordinate with issue #1166.

## Acceptance / stop gates
1. Review exact changed paths for ownership overlap **again** just before
   promotion; parallel PRs are moving.
2. On the exact final commit, run hosted offline Python 3.11 + 3.14 preflight
   and real-producer integration, plus canonical permanent self-hosted VPS CI.
   Earlier SHA receipts do **not** certify a later commit.
3. Production owner must wire the combined boundary and convert #1157's
   case-variant RED tests to genuinely passing denial tests on integrated SHA.
4. Independent security review and installed ingress verification required.
5. Until all gates pass, **DRAFT/HOLD**: no merge, deploy, live target,
   active execution, grant issuance, proxy reload or claims of production
   coverage. This is local/plan/lab-only defense-in-depth.
