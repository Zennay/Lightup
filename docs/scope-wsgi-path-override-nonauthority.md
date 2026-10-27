# WSGI path-override non-authority (offline, 2026-10-09)

**Status: DRAFT/HOLD — regression contract, not a deployed reverse-proxy proof.**

## Threat model and owned boundary

Clients can supply headers such as `X-Original-URL`, `X-Rewrite-URL`,
`X-Original-URI`, `X-Forwarded-URI`, `X-Forwarded-Path`,
`X-Forwarded-Prefix`, and `X-Script-Name`. Some upstream
components interpret such values for rewrites or mounts; in this
application they must not override the **actual** WSGI `PATH_INFO`.
They are not evidence of an operator, customer, scope grant, or permission
to execute a route. The canonical `REQUEST_METHOD` boundary is owned
separately by #1153, and its Nginx ingress template hardening by #1155.

An attacker must not turn a request for an unknown path into a valid
operator POST by injecting a routing hint. Likewise, a tenant must not use
a synthetic path header to access another tenant's portal.

## Executable coverage

`tests/test_scope_path_override_wsgi_non_authority_20261009.py`
uses the real `create_app`, real `DomainStore` and a temporary SQLite
database, and never starts a listener or uses an external target.

1. Development-loopback and production HTTPS/loopback-trusted-proxy WSGI
   fixtures both ignore each individual path-hint header on an unknown path.
2. Simultaneous contradictory hints cannot change the missing-route result.
3. Cross-tenant portal requests remain forbidden even when hints name the
   caller's own portal; legitimate own-tenant routing remains accessible.
4. A fully authenticated, CSRF-valid operator POST on an unknown path does
   not create a client, regardless of hinted `/clients`.
5. A real `/clients` POST still requires operator role and CSRF even when
   synthetic path metadata points at `/login`.
6. An anonymous real `/clients` POST remains unauthenticated and cannot
   write, even when hints say `/login`.
7. Positive control: the actual operator POST on the real `/clients` path
   still creates exactly one client, independent of misleading path hints.
8. Path hints cannot sign the user out from a different path or suppress
   real `/logout`; the persisted session is checked after each request.

The suite is deterministic and offline:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p test_scope_path_override_wsgi_non_authority_20261009.py -v
```

## Release boundaries

**This does not prove installed Nginx/Gunicorn behavior.** An upstream proxy
may rewrite the HTTP path *before* constructing `PATH_INFO`; tests against
the already-constructed WSGI environment cannot detect that. The ingress
owner should separately confirm, on a synthetic loopback-only fixture:

- Incoming path-hint headers are stripped or provably ignored by the
  *installed* proxy configuration, including any optional modules/rewrites.
- A client asking for `/nonexistent` while supplying a `/clients` override
  cannot reach an operator route upstream, with read/write positive controls.
- Native method, host, HTTPS and `Origin` checks continue to pass; actual
  server-side routing and CSRF remain authoritative.
- The exact deployed configuration and binary/module versions are recorded
  as immutable, reviewable evidence (the example file alone is insufficient).

The source-owner `#107` still owns durable per-tenant consent, trusted
destination binding, final pre-I/O revocation and zero-effect denials for
active tools. This WSGI test neither touches those controls nor grants
active target authority. `#1155` owns the Nginx example; do **not** modify
that concurrently. Hosted **and** canonical permanent self-hosted VPS CI
must pass for this exact commit, followed by an independent review, before
promotion. No real targets, grant issuance, deployment or merge in this
isolated worker branch.
