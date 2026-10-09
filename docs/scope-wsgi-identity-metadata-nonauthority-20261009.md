# WSGI identity metadata is not LightUp authorization

**Status:** isolated, offline real-app regression; **DRAFT/HOLD**. All test data is synthetic and locally stored in a temporary SQLite database. No network requests, real targets, grants, scans, credentials, proxy reloads or deployment.

## Why this boundary matters

Some reverse proxies and WSGI servers can provide principal-looking fields such as `REMOTE_USER`, `AUTH_TYPE`, `X-Auth-Request-User` or `X-Forwarded-User`. In LightUp, those fields must **not** supply a principal, tenant, operator role, session or CSRF approval. Even when a proxy injects a field, the current app has no contract for accepting it as an authenticated identity.

The real `LightUpWebApp` uses the `lightup_session` cookie to resolve a server-side session, and independently validates the form CSRF value for protected POST routes. The regression is about **non-authority**: a transport identity label must not upgrade a user.

## Exact acceptance exercised

Run in development and simulated trusted-loopback production WSGI contexts (includes synthetic client requests, review decisions and risk elevation records):

```sh
PYTHONPATH=src python -m unittest discover -s tests -p test_scope_wsgi_identity_metadata_nonauthority_20261009.py -v
```

- No session + identity-looking WSGI environ or HTTP headers: GET protected operator and cross-client portal paths redirect to sign-in. No protected tenant names leak.
- No session + genuine operator CSRF in POST body + spoofed identity: new-client POST redirects to sign-in; no client creation and no revocation of unrelated operator session.
- Real **client** session + operator-looking metadata: operator dashboard, cross-tenant portal and operator POST stay forbidden even with the client's correct form CSRF token.
- Real operator session + CSRF supplied **only by `X-CSRF-Token`** (or invalid body CSRF): POST forbidden, no client created.
- Anonymous POST logout + identity-looking metadata: does not revoke active operator or client sessions, and emits no logout cookie.
- Revoked operator session + spoofed WSGI identity: no protected read; cannot revive a revoked session.
- A **real** operator cookie copied into `X-Forwarded-Cookie`, `X-Original-Cookie`, `X-Auth-Request-Cookie` or `Cookie2` (without a canonical `Cookie`) grants no session or client write.
- The actual operator-only **authorization-grant recording WSGI route**, using a disposable in-memory-context/temporary-SQLite engagement, must reject anonymous and client-role callers with forged identity metadata; no grant rows are recorded. The positive operator/session/form-CSRF route may record only the local synthetic fixture grant; this does **not** constitute consent to contact `fixture.invalid` or any target.
- The **assessment-request decision route** must not accept anonymous/client-session impostors even if all proxy identity hints claim they are an operator; persisted request status stays `submitted`, with no `decided_by` or `decided_at` until a real operator cookie + body CSRF approves. A request approval does not create an engagement or authorization grant.
- The **risk-elevation decision route** must remain `pending` against those impostors, without decision provenance, and only the genuine operator cookie + CSRF may approve. Even a legitimate review approval must not automatically create any target grant.
- A real tenant A client cookie + valid CSRF plus identity-spoofing headers cannot create an **assessment request for tenant B**. A tenant A request positive control remains `submitted` with no approval provenance. This tests submission isolation, not target authorization.
- Positive control: genuine operator cookie **and** genuine body CSRF can create one synthetic client in each mode even with contradictory client-looking headers; protecting the boundary does not accidentally disable legitimate operator actions.

The fixture tests `REMOTE_USER`, `AUTH_TYPE`, `Authorization`, `X-Remote-User`, `X-Auth-Request-User`, `X-Forwarded-User`, `X-Forwarded-Email`, `X-User` and `X-Api-Key`, plus a standalone forged `X-CSRF-Token`. These fields are not alternative login channels. A request that includes a valid **cookie** still follows normal cookie/session rules; this is not a ban on all requests containing these headers.

## Proof limitations and owner boundaries

These are **real in-process WSGI** tests, not an installed Nginx/Gunicorn test and not proof against an upstream component that itself synthesizes a `Cookie` or rewrites authenticated sessions. No active target executor is exposed or exercised. Authentication strength, stale-session revocation races, cross-process cache behavior and upstream identity/HTTP header stripping still need their own integration evidence.

Paths intentionally untouched: `src/lightup/webapp/app.py` (#182 owner), `src/lightup/webapp/security.py` (#202 owner), production `ToolExecutor` (#107 owner), Nginx ingress template (#1155 owner), method/path/framing WSGI suites (#1153/#1156/#1157/#1160 owners), and worker path-overlap preflight (#1159 owner). This PR adds only its uniquely named test file and this note. Do not copy these cases into another worker's files without coordination.

## Promotion gate

1. Review the exact current branch HEAD and verify **both** files are new and disjoint from all open PR file paths; GitHub's open PR list may change after inspection.
2. Require full hosted offline preflight (Python 3.11 and 3.14) **and** canonical permanent VPS CI on the same immutable SHA; queued/cancelled/obsolete runs are not success.
3. Require independent security/source-owner review of whether the tests exercise actual deployments and whether an upstream trusted identity integration is even intended.
4. Remain **DRAFT/HOLD**: no merge, deploy, live authorization, scans or active real-target interaction based on these in-process tests. Explicit customer authorization, allowed assets and capabilities, risk bounds and final pre-I/O revocation are separate and mandatory before real execution.
