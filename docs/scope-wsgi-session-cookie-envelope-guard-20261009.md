# Scope authorization: WSGI session-cookie envelope guard (2026-10-09)

## Isolated producer, not production activation

Branch: chatgpt/scope-cookie-envelope-guard-20261009-1726. Created from immutable main
dd4072cdd1a2bc44a752ccbb7b1d0b6d56559da1.

Only new files are within this PR:
- src/lightup/webapp/session_cookie_guard.py
- tests/test_scope_wsgi_session_cookie_guard_20261009.py
- docs/scope-wsgi-session-cookie-envelope-guard-20261009.md

Owner constraints: never edit app.py (active #182), security.py (#202), forms.py
(#1162), production.py or the Nginx template (#1155). No other active PR is
assumed merged. This is not wired into the default production application.

## Why this boundary matters

The current web application resolves the privileged "lightup_session" value
with Python SimpleCookie. Ambiguous or repeated Cookie fields can cause
different parsing decisions across client, proxy and application layers. In
particular, a concatenated "lightup_session=client; lightup_session=operator"
must **not** be allowed to select a privileged session in a later parser.
This isolated guard rejects ambiguity before the wrapped WSGI application
touches the session store, consumes a request body or mutates state.

This is a defense-in-depth contract and *not* evidence of remotely reachable
session smuggling. It does not prove how installed Nginx/Gunicorn handles
duplicate wire Cookie fields.

## Contract

- Missing Cookie and empty Cookie are allowed as anonymous.
- Non-built-in-string Cookie, unencodable Unicode, C0/DEL controls, oversized
  (>8192 ISO-8859-1 bytes), quoted/backslash escaped/comma-joined, whitespace-concatenated or malformed
  cookie-pairs receive 400 before delegating.
- A second exact "lightup_session" name is refused, regardless of its value.
- Single canonical cookies and unrelated ordinary cookie pairs pass through
  unchanged. No session is created or authorized by this guard itself.
- Denial is generic, no-store, framed with CSP/frame/no-sniff/referrer
  controls and **no Set-Cookie**. Simulated production rejections retain HSTS.
- Flag "production" is accepted only as a built-in bool. The opt-in
  create_cookie_guarded_production_app validates production configuration via
  the existing factory; it does not alter Gunicorn's configured entry point.
- Nothing here broadens scope, creates grants, contacts targets or launches
  scanners. The Notion authorization and risk-level gate remains supreme.

Conservative parsing may reject legitimate unrelated quoted or comma-bearing
Cookie headers; before promoting this wrapper, source owner must document
supported browser cookies and confirm compatibility.

## Offline real-app evidence

The new unittest runs against real LightUpWebApp and an ephemeral DomainStore
SQLite file in both development and simulated HTTPS/loopback production.

- A duplicate session header carrying both a client and an operator token is
  denied before Store.session_context and revoke_session, including privileged
  POST /clients, GET / and POST /logout. Database client count unchanged,
  session tokens preserved and malicious body stream unread.
- Malformed/oversize/control-byte headers are refused with no Set-Cookie or
  leaked tenant content.
- Valid single operator cookie retains role/CSRF requirements. Client cookies
  cannot perform operator POST, incorrect/missing CSRF cannot write, and
  valid operator POST creates exactly one client.
- Production factory rejects missing or insecure configuration.
- Unit-level stub proves invalid metadata never reaches the wrapped app.

No network listener or target interaction is used. CI tests do **not** inspect
the installed reverse-proxy wire parser; that requires separate owner-approved
synthetic ingress checks and provenance. Also compose #1167 PATH_INFO and
#1168 method-token guards only after their owner approvals; this producer is
independent of those unmerged branches.

## Promotion gates (all remain REQUIRED)

1. Exact final commit SHA Python 3.11 and 3.14 offline preflight and producer
   integration success; green tests on older commits do not count.
2. Canonical permanent self-hosted vps-bb300bba GitHub runner success on the
   same final SHA (hosted preflight cannot replace it).
3. Independent web/security owner review of cookie grammar and compatible
   cookies; no overlap with active #182 app and #202 security ownership.
4. Source-owner wiring at the *real* WSGI entry point; ordinary passing
   production-entry integration tests without expectedFailure/xpass.
5. Installed Nginx/Gunicorn synthetic rejection review for duplicate
   raw wire Cookie fields, merged headers and proxy normalization,
   separately tracked before any deployment signoff.
6. Existing authorization approval, per-tenant/asset risk scope,
   operator-approved activation and no-live-target gate remain unchanged.

**DRAFT/HOLD**. No merge, production switch, proxy reload, real-target
interaction, grants, scans or activation. Safe work is offline-only until
all applicable approvals and evidence gates are complete.
