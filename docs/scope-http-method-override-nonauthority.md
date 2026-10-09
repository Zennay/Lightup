# Scope authorization: HTTP method override has no authority

**Phase:** M7 / ST5; offline WSGI authorization regression only. **Status:** draft pending exact-HEAD CI and independent review.

## Boundary

The wire-visible WSGI `REQUEST_METHOD` selects a route; neither `X-HTTP-Method-Override`, `X-Method-Override` nor `X-Original-Method` is a trusted method selector or an alternate authorization input. Frameworks and reverse proxies must not silently reinterpret these headers outside the LightUp WSGI boundary.

Tests execute the **real** `lightup.webapp.create_app` and its `WebSecurity`, session, operator/tenant and CSRF guards against a temporary SQLite `DomainStore`. Inert forms only; no listening socket, HTTP client, external target, authorization grant issuance or target-active capability.

## Acceptance matrix

| WSGI method/path | Spoofed header | Session / CSRF | Expected behavior |
| --- | --- | --- | --- |
| GET /clients | POST | operator | Read-only 200; no new client |
| POST /clients | GET | operator without CSRF | 403; no new client |
| POST /clients | GET | client user with valid own CSRF | 403; no new client |
| POST /clients | GET | anonymous | Redirect to login; no new client |
| GET /logout | POST | operator, CSRF in ignored GET body | 404; original session remains valid |
| POST /logout | GET | operator without CSRF | 403; session remains valid |
| POST /clients | conflicting GET/DELETE/PATCH headers | operator without CSRF | 403; no new client |
| POST /clients | GET | operator with valid CSRF | Normal 303 and one new client (positive control) |

Every single-header case is repeated for the three common aliases. Positive control confirms that the requested path is actually writable when the legitimate WSGI request has valid credentials; it **does not** make the header authoritative.

Run locally (no network target): `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_http_method_override_non_authority.py' -v`.

## Collision/ownership

Only a new regression module and this document are changed. Does **not** edit `webapp/app.py`, `webapp/security.py`, `domain.py`, `execution_policy.py`, `scope.py`, `orchestration.py`, active authorization source-owner #107, duplicate arguments #966, lab marker #1150, typed arguments #1146, deployment or any other active worker branch.

The invariant is intentionally narrow: it does not establish the trustworthiness of an upstream reverse proxy, a deployed HTTP server or an actual target-active executor. If an upstream component changes `REQUEST_METHOD` before WSGI, these tests cannot detect it. Production promotion requires the exact commit SHA, successful hosted and canonical self-hosted VPS safety jobs, review and separately approved durable consent/destination/revocation gates. Remain **DRAFT/HOLD**; no real-target activation or deployment.
