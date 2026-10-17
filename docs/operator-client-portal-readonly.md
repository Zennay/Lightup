# Operator read-only client portal — opt-in web integration

**Issue:** [#673](https://github.com/Zennay/Lightup/issues/673). **Posture:** INCUBATE M3/M7, PLAN/LAB ONLY. This is a client-request provenance safeguard, not permission to scan targets, issue grants, deploy, or ship a production release.

## Product behavior

The existing operator account can open `GET /portal/<client_id>` to inspect a client's findings and assessment requests. The existing normal web shell also lets that operator submit `POST /portal/<client_id>/requests` through a synthetic `CLIENT_ADMIN` view context. That permits an operator-originated request to appear as though it came from the client.

`OperatorReadOnlyWebApp` introduces an opt-in WSGI integration that separates these roles:

- An operator can **read** any client portal but sees a "Client action only" status instead of the assessment request form.
- Every **operator POST** to any `/portal/` path returns HTTP **403**, before the underlying route handler can submit or change a request. This also protects future portal POST routes.
- The assessment request handler requires a real, session-derived `AccessContext` with `CLIENT_ADMIN` or `CLIENT_MEMBER` and an *exactly matching client ID*. It does not use the operator-to-client display-context conversion for mutations.
- Authenticated, same-tenant clients retain the normal request form and request-submission path, including existing CSRF protection and domain-level tenant isolation.
- Operator-owned `/assessments/...` review and approval routes are unchanged. No database schema, grant lifecycle, real-target capability, network scanner or execution authority is changed.

## Local use (explicit opt in)

From a checkout with LightUp installed on the Python import path:

```sh
PYTHONPATH=src python -m lightup.webapp.operator_readonly --db lightup.db --host 127.0.0.1 --port 8767
```

The development launcher **only accepts loopback IP addresses**. It does not attempt to deploy anything.

Embedding in existing WSGI applications:

```python
from lightup.domain import DomainStore
from lightup.webapp.operator_readonly import create_readonly_app

application = create_readonly_app(DomainStore("lightup.db"))
```

For an **explicitly configured** production WSGI application (not a deployment instruction):

```python
from lightup.webapp.operator_readonly import create_production_readonly_app

application = create_production_readonly_app()
```

The production factory delegates to LightUp's existing mandatory HTTPS public-origin, absolute database path and trusted-loopback-proxy validation. It requires `LIGHTUP_PUBLIC_ORIGIN` and `LIGHTUP_DB` and optionally accepts `LIGHTUP_TRUSTED_PROXY_IP`. It does not create users or grant authorization.

## Boundaries and integration

This intentionally **does not alter** `src/lightup/webapp/app.py`, which is still owned by [PR #182](https://github.com/Zennay/Lightup/pull/182), or `src/lightup/domain.py` / consent sources owned by other workers. The original unguarded `create_app` and its default development/production entrypoints are unchanged. To gain this behavior, consumers must **explicitly switch** to the guarded factory or launcher. The default application remains affected until the web source owner integrates an equivalent guard after collision-free review.

This branch is an implementation candidate, **not** a release/consent certificate. Do not merge or deploy under the current HOLD posture without the existing independently authenticated client/operator consent and revocation requirements, security/privacy review, exact approved release-head hosted and registered VPS CI, and explicit human GO. No new QA or regression suite is included in this deliverable.
