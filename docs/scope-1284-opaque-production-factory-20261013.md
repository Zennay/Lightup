# LightUp #1284 W3 — synthetic HTTPS/proxy-shaped opt-in WSGI factory

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO DEPLOY.** This does not authorize anything or contact a host. All interactions below are **in-process WSGI calls** with a disposable SQLite database, fixed synthetic examples and no listening socket, proxy, browser, scanner, model or customer data.

## Collision-free implementation

Parent is immutable [DRAFT #1286](https://github.com/Zennay/Lightup/pull/1286) exact `33fd5c0b5015fccf8a5110390e9cd179d71ffc03`. This isolated follow-up adds:
1. `src/lightup/webapp/production_opaque_optin.py`: explicit `create_opaque_production_app(environ=None)` that invokes the existing validated `create_production_app` and wraps its exact `LightUpWebApp` instance in the opt-in `OpaqueErrorWSGI`.
2. `tests/test_production_opaque_optin_1284.py`: **15 real in-process, production-shaped WSGI integration cases** against disposable SQLite.
3. This documentation. No edits to default `production.py`, `app.py`, `security.py`, `domain.py`, existing tests, other workers, `main`, installed Gunicorn/Nginx or target/execution sources.

## Explicit API only

```python
from lightup.webapp.production_opaque_optin import create_opaque_production_app
app = create_opaque_production_app({
    "LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example.test",
    "LIGHTUP_DB": "/absolute/path/to/disposable-synthetic-lab.sqlite3",
})
```

**Do not install this factory in Gunicorn or put customer data in the lab.** The snippet documents a constructor, not permission to activate production. The default `lightup.webapp.production.create_production_app` remains unchanged and continues its existing raw error-detail behavior. This optional factory is the first full production-**shaped** entrypoint for the previously validated 400-privacy adapter, not proof of an installed proxy/HTTPS path.

## Acceptance: real app behavior in-process

- A real persisted operator and client session/CSRF/roles, original DomainStore, and valid origin/loopback-proxy metadata.
- Real authenticated 400 from unknown client and invalid client creation; **no internal ID, domain exception message, redirect or cookie in replaced 400**, retained no-store/CSP/frame protections/HSTS and exact UTF-8 length/type.
- Exact original production factory **still unguarded** as a negative control; non-400 normal GET identical between old/new app.
- Real valid same-origin operator POST still persists, and bad/missing CSRF, client role, hostile Origin, cross-site Fetch Metadata, spoofed proxy/source IP, HTTP proto and bad Host still deny **without database mutations**.
- Anonymous redirect/tenant role boundaries, secure HttpOnly SameSite cookies on login, logout with permanent session revocation, active session preserved after sanitized error.
- Invalid origin/proxy/relative SQLite configuration rejected **before invoking DomainStore**, exactly as the production factory already promises.

## Limitations and owner gates

No live TLS, Nginx/Gunicorn installed routing, browser/frontend, complete HTTP/1.1 header parsing or production deployment is exercised. This is not evidence of a customer leak. The optional adapter does not stop creation of sensitive exception data *inside* the default source or defend non-400 errors, and is not an authorization grant. Original source owner should preferably integrate a generic error response **before** constructing potentially sensitive HTML and convert parent #1285 two intentionally unresolved expected RED to normal passing tests. Separate independent privacy/security review, latest-main composition, final exact-head GitHub-hosted Python 3.11/3.14, registered permanent VPS runner [self-hosted, zcloud, vps] and explicit human release approval remain required. No merge/deploy until then.
